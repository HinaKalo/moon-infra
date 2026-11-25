package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------- Docker 兼容 API（Docker 与 podman 共用）

type engine struct {
	name   string // docker | podman
	client *http.Client
	stream *http.Client
}

func newEngine(name, sock string) *engine {
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}
	return &engine{
		name:   name,
		client: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: dial, MaxIdleConns: 4}},
		stream: &http.Client{Transport: &http.Transport{DialContext: dial}},
	}
}

func (e *engine) do(ctx context.Context, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, "http://"+e.name+path, nil)
	if err != nil {
		return err
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var m struct{ Message string }
		if json.Unmarshal(b, &m) == nil && m.Message != "" {
			return fmt.Errorf("%s: %s", e.name, m.Message)
		}
		return fmt.Errorf("%s: HTTP %d", e.name, resp.StatusCode)
	}
	if out == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type apiContainer struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Created int64             `json:"Created"`
	Labels  map[string]string `json:"Labels"`
	Ports   []struct {
		IP          string `json:"IP"`
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

type inspect struct {
	State struct {
		Pid       int    `json:"Pid"`
		StartedAt string `json:"StartedAt"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
		RestartCount int `json:"-"`
	} `json:"State"`
	RestartCount int `json:"RestartCount"`
	HostConfig   struct {
		Memory int64 `json:"Memory"`
	} `json:"HostConfig"`
}

// Container 是面板展示用的统一模型
type Container struct {
	Runtime   string  `json:"runtime"`
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Project   string  `json:"project"`
	Image     string  `json:"image"`
	State     string  `json:"state"`
	Status    string  `json:"status"`
	Health    string  `json:"health"`
	Created   int64   `json:"created"`
	StartedAt string  `json:"started_at"`
	Restarts  int     `json:"restarts"`
	Ports     string  `json:"ports"`
	MemBytes  int64   `json:"mem_bytes"`
	MemLimit  int64   `json:"mem_limit"`
	CPUPct    float64 `json:"cpu_pct"`
	Managed   string  `json:"managed"` // cicd | platform | podman-systemd | manual
}

type runtimes struct {
	cfg     config
	engines map[string]*engine
}

func newRuntimes(cfg config) *runtimes {
	r := &runtimes{cfg: cfg, engines: map[string]*engine{}}
	if _, err := os.Stat(cfg.DockerSock); err == nil {
		r.engines["docker"] = newEngine("docker", cfg.DockerSock)
	}
	if _, err := os.Stat(cfg.PodmanSock); err == nil {
		r.engines["podman"] = newEngine("podman", cfg.PodmanSock)
	}
	return r
}

func (r *runtimes) list(ctx context.Context) ([]Container, map[string]int, error) {
	var out []Container
	pids := map[string]int{}
	for name, e := range r.engines {
		var cs []apiContainer
		if err := e.do(ctx, "GET", "/containers/json?all=1", &cs); err != nil {
			return nil, nil, err
		}
		for _, c := range cs {
			n := ""
			if len(c.Names) > 0 {
				n = strings.TrimPrefix(c.Names[0], "/")
			}
			ct := Container{Runtime: name, ID: c.ID, Name: n, Image: c.Image, State: c.State, Status: c.Status, Created: c.Created}
			ct.Project = c.Labels["com.docker.compose.project"]
			if ct.Project == "" {
				ct.Project = c.Labels["io.podman.compose.project"]
			}
			switch {
			case c.Labels["cloud.moonl.project"] != "":
				ct.Managed = "cicd"
			case ct.Project == "moon-platform":
				ct.Managed = "platform"
			case name == "podman" && c.Labels["PODMAN_SYSTEMD_UNIT"] != "":
				ct.Managed = "podman-systemd"
			default:
				ct.Managed = "manual"
			}
			var ports []string
			for _, p := range c.Ports {
				if p.PublicPort > 0 {
					ports = append(ports, fmt.Sprintf("%s:%d→%d/%s", p.IP, p.PublicPort, p.PrivatePort, p.Type))
				}
			}
			sort.Strings(ports)
			ct.Ports = strings.Join(ports, ", ")
			if c.State == "running" {
				var in inspect
				if err := e.do(ctx, "GET", "/containers/"+c.ID+"/json", &in); err == nil {
					pids[name+"/"+c.ID] = in.State.Pid
					ct.StartedAt = in.State.StartedAt
					ct.Restarts = in.RestartCount
					ct.MemLimit = in.HostConfig.Memory
					if in.State.Health != nil {
						ct.Health = in.State.Health.Status
					}
				}
			}
			out = append(out, ct)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Project != out[j].Project {
			return out[i].Project < out[j].Project
		}
		return out[i].Name < out[j].Name
	})
	return out, pids, nil
}

func (r *runtimes) action(ctx context.Context, rt, id, action string) error {
	e := r.engines[rt]
	if e == nil {
		return fmt.Errorf("unknown runtime %s", rt)
	}
	switch action {
	case "start", "stop", "restart":
	default:
		return fmt.Errorf("unsupported action %s", action)
	}
	q := ""
	if action != "start" {
		q = "?t=15"
	}
	return e.do(ctx, "POST", "/containers/"+id+"/"+action+q, nil)
}

// logs 以 SSE 推送容器日志（非 TTY 容器的多路复用帧）
func (r *runtimes) logs(ctx context.Context, rt, id string, tail int, follow bool, emit func(stream, line string) error) error {
	e := r.engines[rt]
	if e == nil {
		return fmt.Errorf("unknown runtime %s", rt)
	}
	path := fmt.Sprintf("/containers/%s/logs?stdout=1&stderr=1&timestamps=1&tail=%d&follow=%t", id, tail, follow)
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+rt+path, nil)
	resp, err := e.stream.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("logs: HTTP %d", resp.StatusCode)
	}
	br := bufio.NewReaderSize(resp.Body, 64<<10)
	hdr, err := br.Peek(8)
	multiplexed := err == nil && (hdr[0] == 1 || hdr[0] == 2) && hdr[1] == 0 && hdr[2] == 0 && hdr[3] == 0
	if !multiplexed {
		sc := bufio.NewScanner(br)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			if err := emit("stdout", sc.Text()); err != nil {
				return err
			}
		}
		return sc.Err()
	}
	h := make([]byte, 8)
	for {
		if _, err := io.ReadFull(br, h); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		n := binary.BigEndian.Uint32(h[4:])
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return err
		}
		stream := "stdout"
		if h[0] == 2 {
			stream = "stderr"
		}
		for _, line := range strings.Split(strings.TrimRight(string(buf), "\n"), "\n") {
			if err := emit(stream, line); err != nil {
				return err
			}
		}
	}
}

// ---------------------------------------------------------------- cgroup 采样

func cgroupOfPid(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::") {
			return "/sys/fs/cgroup" + strings.TrimPrefix(line, "0::")
		}
	}
	return ""
}

func readInt(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(b))
	if s == "max" {
		return -1
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func cpuUsec(cg string) int64 {
	f, err := os.Open(filepath.Join(cg, "cpu.stat"))
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "usage_usec "); ok {
			n, _ := strconv.ParseInt(v, 10, 64)
			return n
		}
	}
	return 0
}

type sample struct {
	usec int64
	at   time.Time
}

type sampler struct {
	rt *runtimes

	mu         sync.RWMutex
	containers []Container
	services   []Service
	err        string
	updated    time.Time
	prev       map[string]sample
}

func newSampler(rt *runtimes) *sampler { return &sampler{rt: rt, prev: map[string]sample{}} }

func (s *sampler) cpuPct(key, cg string, now time.Time) float64 {
	u := cpuUsec(cg)
	p, ok := s.prev[key]
	s.prev[key] = sample{u, now}
	if !ok || u < p.usec {
		return 0
	}
	dt := now.Sub(p.at).Microseconds()
	if dt <= 0 {
		return 0
	}
	return float64(u-p.usec) * 100 / float64(dt)
}

func (s *sampler) run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		s.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *sampler) tick(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	now := time.Now()
	cs, pids, err := s.rt.list(cctx)
	svcs, serr := listServices(cctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	if err == nil {
		for i := range cs {
			key := cs[i].Runtime + "/" + cs[i].ID
			if pid := pids[key]; pid > 0 {
				if cg := cgroupOfPid(pid); cg != "" {
					cs[i].MemBytes = readInt(filepath.Join(cg, "memory.current"))
					if lim := readInt(filepath.Join(cg, "memory.max")); lim > 0 && cs[i].MemLimit == 0 {
						cs[i].MemLimit = lim
					}
					cs[i].CPUPct = s.cpuPct(key, cg, now)
					seen[key] = true
				}
			}
		}
		s.containers = cs
		s.err = ""
	} else {
		s.err = err.Error()
	}
	if serr == nil {
		for i := range svcs {
			key := "svc/" + svcs[i].Unit
			if cg := svcs[i].cgroupPath(); cg != "" && svcs[i].Active == "active" {
				svcs[i].CPUPct = s.cpuPct(key, cg, now)
				seen[key] = true
			}
		}
		s.services = svcs
		// 由 systemd 服务直接 `podman run` 的容器（容器名与服务同名）归为 systemd 托管
		units := map[string]bool{}
		for _, sv := range svcs {
			units[sv.Unit] = true
		}
		for i := range s.containers {
			if s.containers[i].Managed == "manual" && units[s.containers[i].Name+".service"] {
				s.containers[i].Managed = "podman-systemd"
			}
		}
	}
	for k := range s.prev {
		if !seen[k] {
			delete(s.prev, k)
		}
	}
	s.updated = now
}

func (s *sampler) snapshot() ([]Container, []Service, string, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.containers, s.services, s.err, s.updated
}

// ---------------------------------------------------------------- 辅助：执行命令

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return b, fmt.Errorf("%s: %v %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return b, nil
}
