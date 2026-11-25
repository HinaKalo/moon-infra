package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------- CI/CD 项目

type Deploy struct {
	At       string `json:"at"`
	SHA      string `json:"sha"`
	Actor    string `json:"actor"`
	RunID    string `json:"run_id"`
	Result   string `json:"result"`
	Seconds  int    `json:"seconds"`
	Error    string `json:"error,omitempty"`
}

type Project struct {
	Name       string      `json:"name"`
	Repo       string      `json:"repo"`
	Domain     string      `json:"domain"`
	Port       int         `json:"port"`
	Image      string      `json:"image"`
	MemBudget  int64       `json:"mem_budget"`
	MemUsed    int64       `json:"mem_used"`
	DeployedAt string      `json:"deployed_at"`
	Containers []Container `json:"containers"`
	History    []Deploy    `json:"history"`
}

func readKV(path string) map[string]string {
	m := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok && !strings.HasPrefix(k, "#") {
			m[k] = v
		}
	}
	return m
}

func readHistory(path string, n int) []Deploy {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var out []Deploy
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		var d Deploy
		if json.Unmarshal([]byte(lines[i]), &d) == nil {
			out = append(out, d)
		}
	}
	return out
}

func (s *server) handleProjects(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(s.cfg.AppsDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cs, _, _, _ := s.sampler.snapshot()
	var out []Project
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		dir := filepath.Join(s.cfg.AppsDir, e.Name())
		env := readKV(filepath.Join(dir, ".env"))
		p := Project{Name: e.Name(), Image: env["IMAGE"]}
		if img := env["IMAGE"]; strings.HasPrefix(img, "ghcr.io/") {
			p.Repo = strings.SplitN(strings.TrimPrefix(img, "ghcr.io/"), "@", 2)[0]
		}
		if b, err := os.ReadFile(filepath.Join(dir, "app.port")); err == nil {
			p.Port, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		}
		if b, err := os.ReadFile(filepath.Join(dir, ".moon-mem")); err == nil {
			p.MemBudget, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		}
		if b, err := os.ReadFile(filepath.Join("/etc/caddy/apps", e.Name()+".caddy")); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if strings.HasSuffix(strings.TrimSpace(l), "{") && !strings.HasPrefix(strings.TrimSpace(l), "#") && strings.Contains(l, ".") {
					p.Domain = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(l), "{"))
					break
				}
			}
		}
		if st, err := os.Stat(filepath.Join(dir, ".env")); err == nil {
			p.DeployedAt = st.ModTime().UTC().Format(time.RFC3339)
		}
		for _, c := range cs {
			if c.Project == e.Name() && c.Runtime == "docker" {
				p.Containers = append(p.Containers, c)
				p.MemUsed += c.MemBytes
			}
		}
		p.History = readHistory(filepath.Join(dir, "history.jsonl"), 10)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, map[string]any{"projects": out})
}

// ---------------------------------------------------------------- 数据库

type pgDB struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	Connections int    `json:"connections"`
}

func (s *server) handleDatabases(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	res := map[string]any{}

	pg := map[string]any{"container": s.cfg.PostgresCtr}
	q := `SELECT d.datname, pg_database_size(d.datname), (SELECT count(*) FROM pg_stat_activity a WHERE a.datname = d.datname)
	      FROM pg_database d WHERE NOT d.datistemplate ORDER BY 2 DESC`
	if out, err := run(ctx, "docker", "exec", s.cfg.PostgresCtr, "psql", "-U", "postgres", "-AtF", "\t", "-c", q); err == nil {
		var dbs []pgDB
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			f := strings.Split(l, "\t")
			if len(f) == 3 {
				sz, _ := strconv.ParseInt(f[1], 10, 64)
				cn, _ := strconv.Atoi(f[2])
				dbs = append(dbs, pgDB{f[0], sz, cn})
			}
		}
		pg["databases"] = dbs
		info := `SELECT current_setting('server_version'), current_setting('max_connections'), (SELECT count(*) FROM pg_stat_activity),
		         extract(epoch FROM now() - pg_postmaster_start_time())::bigint,
		         coalesce(round(100.0 * sum(blks_hit) / nullif(sum(blks_hit) + sum(blks_read), 0), 2), 100) FROM pg_stat_database`
		if out, err := run(ctx, "docker", "exec", s.cfg.PostgresCtr, "psql", "-U", "postgres", "-AtF", "\t", "-c", info); err == nil {
			f := strings.Split(strings.TrimSpace(string(out)), "\t")
			if len(f) == 5 {
				pg["version"], pg["max_connections"], pg["connections"], pg["uptime_s"], pg["cache_hit_pct"] = f[0], f[1], f[2], f[3], f[4]
			}
		}
	} else {
		pg["error"] = err.Error()
	}
	res["postgres"] = pg

	vk := map[string]any{"container": s.cfg.ValkeyCtr}
	if out, err := run(ctx, "docker", "exec", s.cfg.ValkeyCtr, "sh", "-c", `valkey-cli --no-auth-warning -a "$VALKEY_PASSWORD" info`); err == nil {
		kv := map[string]string{}
		keyspace := map[string]string{}
		for _, l := range strings.Split(string(out), "\n") {
			l = strings.TrimSpace(l)
			if k, v, ok := strings.Cut(l, ":"); ok {
				if strings.HasPrefix(k, "db") {
					keyspace[k] = v
				} else {
					kv[k] = v
				}
			}
		}
		for _, k := range []string{"valkey_version", "used_memory", "used_memory_human", "maxmemory", "maxmemory_human", "connected_clients", "uptime_in_seconds", "maxmemory_policy"} {
			vk[k] = kv[k]
		}
		vk["keyspace"] = keyspace
	} else {
		vk["error"] = err.Error()
	}
	res["valkey"] = vk

	var backups []map[string]any
	if entries, err := os.ReadDir(s.cfg.BackupsDir); err == nil {
		for _, e := range entries {
			if info, err := e.Info(); err == nil && !e.IsDir() {
				backups = append(backups, map[string]any{"name": e.Name(), "size": info.Size(), "at": info.ModTime().UTC().Format(time.RFC3339)})
			}
		}
		sort.Slice(backups, func(i, j int) bool { return backups[i]["at"].(string) > backups[j]["at"].(string) })
	}
	res["backups"] = backups
	writeJSON(w, res)
}

// ---------------------------------------------------------------- 磁盘

func (s *server) handleDisk(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(s.cfg.DiskStatus)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "diskguard 状态暂不可用")
		return
	}
	var st map[string]any
	if err := json.Unmarshal(b, &st); err != nil {
		writeErr(w, http.StatusInternalServerError, "状态文件损坏")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	active, _ := run(ctx, "systemctl", "is-active", "moon-diskguard-clean.service")
	st["clean_running"] = strings.TrimSpace(string(active)) == "activating"
	writeJSON(w, st)
}

func (s *server) handleDiskClean(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if _, err := run(ctx, "sudo", "-n", "/usr/bin/systemctl", "start", "--no-block", "moon-diskguard-clean.service"); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	logAudit(r, s, "disk clean")
	writeJSON(w, map[string]string{"ok": "已开始清理"})
}
