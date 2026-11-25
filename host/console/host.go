package main

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ---------------------------------------------------------------- systemd 服务

type Service struct {
	Unit        string  `json:"unit"`
	Description string  `json:"description"`
	Active      string  `json:"active"`
	Sub         string  `json:"sub"`
	Category    string  `json:"category"` // app | infra | ops
	MemBytes    int64   `json:"mem_bytes"`
	CPUPct      float64 `json:"cpu_pct"`
	Since       string  `json:"since"`
	MainPID     int     `json:"main_pid"`
	Restarts    int     `json:"restarts"`
	Protected   bool    `json:"protected"` // 只允许重启，不允许停止
	cgroup      string
}

func (s Service) cgroupPath() string {
	if s.cgroup == "" {
		return ""
	}
	return "/sys/fs/cgroup" + s.cgroup
}

// 平台基础设施（不在 /etc/systemd/system 下但需要关注）
var infraUnits = []string{"caddy.service", "docker.service", "containerd.service", "podman.service", "mysql.service",
	"redis-server.service", "ntfy.service", "ssh.service", "systemd-journald.service"}

// 停掉会导致失联或失去面板的服务：面板只允许重启
var protectedUnits = map[string]bool{"ssh.service": true, "moon-console.service": true, "moon-firewall.service": true,
	"caddy.service": true, "docker.service": true, "containerd.service": true, "systemd-journald.service": true, "easytier-moon.service": true}

var opsPrefixes = []string{"moon-deployd", "moon-console", "moon-firewall", "moon-diskguard", "moon-pg-backup", "moon-docker-gc", "dev-guard", "easytier", "three-host", "moon-build", "moon-geodns"}

var unitRe = regexp.MustCompile(`^[a-zA-Z0-9@._:-]+\.service$`)

func listServices(ctx context.Context) ([]Service, error) {
	out, err := run(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain")
	if err != nil {
		return nil, err
	}
	units := map[string]bool{}
	for _, u := range infraUnits {
		units[u] = true
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && unitRe.MatchString(f[0]) {
			units[f[0]] = true
		}
	}
	names := make([]string, 0, len(units))
	for u := range units {
		names = append(names, u)
	}
	sort.Strings(names)
	args := append([]string{"show", "--no-pager", "-p", "Id,Description,ActiveState,SubState,MemoryCurrent,ControlGroup,FragmentPath,ActiveEnterTimestamp,MainPID,NRestarts,LoadState"}, names...)
	out, err = run(ctx, "systemctl", args...)
	if err != nil {
		return nil, err
	}
	var svcs []Service
	for _, block := range strings.Split(string(out), "\n\n") {
		kv := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				kv[k] = v
			}
		}
		id := kv["Id"]
		if id == "" || kv["LoadState"] != "loaded" {
			continue
		}
		infra := false
		for _, u := range infraUnits {
			if u == id {
				infra = true
			}
		}
		custom := strings.HasPrefix(kv["FragmentPath"], "/etc/systemd/system/")
		if !infra && !custom {
			continue
		}
		s := Service{Unit: id, Description: kv["Description"], Active: kv["ActiveState"], Sub: kv["SubState"],
			Since: kv["ActiveEnterTimestamp"], cgroup: kv["ControlGroup"], Protected: protectedUnits[id]}
		s.MemBytes, _ = strconv.ParseInt(kv["MemoryCurrent"], 10, 64)
		if kv["MemoryCurrent"] == "[not set]" {
			s.MemBytes = 0
		}
		s.MainPID, _ = strconv.Atoi(kv["MainPID"])
		s.Restarts, _ = strconv.Atoi(kv["NRestarts"])
		switch {
		case infra:
			s.Category = "infra"
		case hasAnyPrefix(id, opsPrefixes):
			s.Category = "ops"
		default:
			s.Category = "app"
		}
		svcs = append(svcs, s)
	}
	return svcs, nil
}

func hasAnyPrefix(s string, ps []string) bool {
	for _, p := range ps {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func (s *server) knownService(unit string) (Service, bool) {
	_, svcs, _, _ := s.sampler.snapshot()
	for _, sv := range svcs {
		if sv.Unit == unit {
			return sv, true
		}
	}
	return Service{}, false
}

func (s *server) handleServices(w http.ResponseWriter, r *http.Request) {
	_, svcs, _, at := s.sampler.snapshot()
	writeJSON(w, map[string]any{"services": svcs, "updated_at": at})
}

func (s *server) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	unit, action := r.PathValue("unit"), r.PathValue("action")
	sv, ok := s.knownService(unit)
	if !ok || !unitRe.MatchString(unit) {
		writeErr(w, http.StatusNotFound, "未知服务")
		return
	}
	switch action {
	case "restart", "start":
	case "stop":
		if sv.Protected {
			writeErr(w, http.StatusForbidden, unit+" 是关键服务，面板只允许重启")
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "不支持的操作")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if _, err := run(ctx, "sudo", "-n", "/usr/bin/systemctl", action, unit); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	logAudit(r, s, fmt.Sprintf("service %s %s", action, unit))
	writeJSON(w, map[string]string{"ok": action + " " + unit})
}

// ---------------------------------------------------------------- 日志（SSE）

func sseStart(w http.ResponseWriter) (func(event, data string) error, bool) {
	f, ok := w.(http.Flusher)
	if !ok {
		return nil, false
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	f.Flush()
	return func(event, data string) error {
		var b strings.Builder
		b.WriteString("event: " + event + "\n")
		for _, l := range strings.Split(data, "\n") {
			b.WriteString("data: " + l + "\n")
		}
		b.WriteString("\n")
		if _, err := w.Write([]byte(b.String())); err != nil {
			return err
		}
		f.Flush()
		return nil
	}, true
}

func tailParam(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("tail"))
	if n <= 0 || n > 5000 {
		n = 300
	}
	return n
}

func (s *server) handleServiceLogs(w http.ResponseWriter, r *http.Request) {
	unit := r.PathValue("unit")
	if _, ok := s.knownService(unit); !ok || !unitRe.MatchString(unit) {
		writeErr(w, http.StatusNotFound, "未知服务")
		return
	}
	emit, ok := sseStart(w)
	if !ok {
		return
	}
	args := []string{"-u", unit, "-n", strconv.Itoa(tailParam(r)), "-o", "short-iso", "--no-pager", "--no-hostname"}
	if r.URL.Query().Get("follow") == "1" {
		args = append(args, "-f")
	}
	cmd := exec.CommandContext(r.Context(), "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		emit("error", "无法读取日志")
		return
	}
	defer cmd.Wait()
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if emit("line", sc.Text()) != nil {
			cmd.Process.Kill()
			return
		}
	}
	emit("end", "")
}

func (s *server) handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	rt, id := r.PathValue("rt"), r.PathValue("id")
	if !s.knownContainer(rt, id) {
		writeErr(w, http.StatusNotFound, "未知容器")
		return
	}
	emit, ok := sseStart(w)
	if !ok {
		return
	}
	err := s.runtime.logs(r.Context(), rt, id, tailParam(r), r.URL.Query().Get("follow") == "1", func(stream, line string) error {
		return emit(stream, line)
	})
	if err != nil && r.Context().Err() == nil {
		emit("error", err.Error())
		return
	}
	emit("end", "")
}

func (s *server) knownContainer(rt, id string) bool {
	cs, _, _, _ := s.sampler.snapshot()
	for _, c := range cs {
		if c.Runtime == rt && c.ID == id {
			return true
		}
	}
	return false
}

func (s *server) handleContainers(w http.ResponseWriter, r *http.Request) {
	cs, _, e, at := s.sampler.snapshot()
	writeJSON(w, map[string]any{"containers": cs, "error": e, "updated_at": at})
}

func (s *server) handleContainerAction(w http.ResponseWriter, r *http.Request) {
	rt, id, action := r.PathValue("rt"), r.PathValue("id"), r.PathValue("action")
	if !s.knownContainer(rt, id) {
		writeErr(w, http.StatusNotFound, "未知容器")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := s.runtime.action(ctx, rt, id, action); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	logAudit(r, s, fmt.Sprintf("container %s %s/%s", action, rt, id[:12]))
	go s.sampler.tick(context.Background())
	writeJSON(w, map[string]string{"ok": action})
}

func logAudit(r *http.Request, s *server, what string) {
	user := "?"
	if ss := s.auth.currentSession(r); ss != nil {
		user = ss.Username
	}
	fmt.Fprintf(os.Stderr, "AUDIT user=%s action=%q\n", user, what)
}

// ---------------------------------------------------------------- 概览

type sliceUsage struct {
	Name    string `json:"name"`
	Label   string `json:"label"`
	Current int64  `json:"current"`
	High    int64  `json:"high"`
	Max     int64  `json:"max"`
}

func meminfo() map[string]int64 {
	m := map[string]int64{}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fs := strings.Fields(v)
		if len(fs) > 0 {
			n, _ := strconv.ParseInt(fs[0], 10, 64)
			m[k] = n * 1024
		}
	}
	return m
}

func cpuTimes() (idle, total uint64) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return
	}
	line, _, _ := strings.Cut(string(b), "\n")
	for i, f := range strings.Fields(line)[1:] {
		n, _ := strconv.ParseUint(f, 10, 64)
		total += n
		if i == 3 || i == 4 {
			idle += n
		}
	}
	return
}

func (s *server) handleOverview(w http.ResponseWriter, r *http.Request) {
	i1, t1 := cpuTimes()
	time.Sleep(300 * time.Millisecond)
	i2, t2 := cpuTimes()
	cpu := 0.0
	if t2 > t1 {
		cpu = 100 * (1 - float64(i2-i1)/float64(t2-t1))
	}
	host, _ := os.Hostname()
	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	up, _ := os.ReadFile("/proc/uptime")
	load, _ := os.ReadFile("/proc/loadavg")
	upSec, _ := strconv.ParseFloat(strings.Fields(string(up) + " 0")[0], 64)
	mi := meminfo()
	var st syscall.Statfs_t
	syscall.Statfs("/", &st)
	diskTotal := int64(st.Blocks) * st.Bsize
	diskAvail := int64(st.Bavail) * st.Bsize
	diskUsed := diskTotal - int64(st.Bfree)*st.Bsize

	slices := []sliceUsage{
		{Name: "system.slice", Label: "宿主服务"},
		{Name: "moonapps.slice", Label: "Docker 应用"},
		{Name: "machine.slice", Label: "podman 容器"},
		{Name: "user.slice/user-1001.slice", Label: "dev 开发环境"},
	}
	for i := range slices {
		base := "/sys/fs/cgroup/" + slices[i].Name
		slices[i].Current = readInt(base + "/memory.current")
		slices[i].High = readInt(base + "/memory.high")
		slices[i].Max = readInt(base + "/memory.max")
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	alertsRaw, _ := run(ctx, "journalctl", "-t", "moon-diskguard", "--grep", "ALERT", "-n", "15", "-o", "short-iso", "--no-pager", "--no-hostname")
	var alerts []string
	for _, l := range strings.Split(strings.TrimSpace(string(alertsRaw)), "\n") {
		if l != "" && !strings.HasPrefix(l, "--") {
			alerts = append(alerts, l)
		}
	}
	cs, svcs, _, at := s.sampler.snapshot()
	running, unhealthy := 0, 0
	for _, c := range cs {
		if c.State == "running" {
			running++
		}
		if c.Health == "unhealthy" || (c.State != "running" && c.Managed != "manual") {
			unhealthy++
		}
	}
	active, failed := 0, 0
	for _, sv := range svcs {
		switch sv.Active {
		case "active":
			active++
		case "failed":
			failed++
		}
	}
	fwOut, _ := run(ctx, "systemctl", "is-active", "moon-firewall.service")
	_, rebootErr := os.Stat("/var/run/reboot-required")

	writeJSON(w, map[string]any{
		"host":       map[string]any{"name": host, "kernel": strings.TrimSpace(string(kernel)), "uptime_s": int64(upSec), "load": strings.Fields(string(load))[:3], "cpus": runtime.NumCPU(), "cpu_pct": cpu},
		"memory":     map[string]any{"total": mi["MemTotal"], "available": mi["MemAvailable"], "swap_total": mi["SwapTotal"], "swap_free": mi["SwapFree"]},
		"disk":       map[string]any{"total": diskTotal, "used": diskUsed, "avail": diskAvail},
		"slices":     slices,
		"counts":     map[string]int{"containers": len(cs), "running": running, "unhealthy": unhealthy, "services": len(svcs), "services_active": active, "services_failed": failed},
		"security":   map[string]any{"firewall": strings.TrimSpace(string(fwOut)), "reboot_required": rebootErr == nil},
		"alerts":     alerts,
		"sampled_at": at,
	})
}
