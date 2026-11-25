// moon-deployd: GitHub Actions OIDC 认证的部署代理。
//
// 流程：GitHub Actions（中央可复用工作流）在 GitHub 托管机器上构建镜像并推送到 GHCR，
// 然后携带 OIDC 令牌调用本服务；本服务校验令牌签名与声明（账号、main 分支、中央工作流），
// 用 docker compose 解析、校验、改写项目编排，拉取镜像并滚动更新，失败自动回滚。
//
// 防重复与资源治理：
//   - 每个仓库对应固定的 compose 项目名，部署全局串行，--remove-orphans 清理残留
//   - 每个服务默认内存/进程数上限，按全局预算校验；所有容器位于 moonapps.slice
//   - 数据库/缓存统一由共享平台（Postgres、Valkey）提供，项目自带数据库镜像会被拒绝
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type config struct {
	Listen         string
	Owner          string
	WorkflowPrefix string
	Audience       string
	AppsDir        string
	CaddyDir       string
	DomainSuffix   string
	BudgetMB       int64
	DefaultMemMB   int64
	DefaultPids    int64
	PostgresCtr    string
	ValkeyCtr      string
	SharedNet      string
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

var cfg = config{
	Listen:         env("MOON_LISTEN", "127.0.0.1:19700"),
	Owner:          env("MOON_OWNER", "HinaKalo"),
	WorkflowPrefix: env("MOON_WORKFLOW_PREFIX", "HinaKalo/moon-infra/.github/workflows/deploy.yml@refs/heads/main"),
	Audience:       env("MOON_AUDIENCE", "moon-deploy"),
	AppsDir:        env("MOON_APPS_DIR", "/srv/apps"),
	CaddyDir:       env("MOON_CADDY_DIR", "/etc/caddy/apps"),
	DomainSuffix:   env("MOON_DOMAIN_SUFFIX", "moonl.cloud"),
	BudgetMB:       envInt("MOON_APPS_BUDGET_MB", 2900),
	DefaultMemMB:   envInt("MOON_DEFAULT_MEM_MB", 512),
	DefaultPids:    envInt("MOON_DEFAULT_PIDS", 512),
	PostgresCtr:    env("MOON_POSTGRES_CONTAINER", "moon-postgres"),
	ValkeyCtr:      env("MOON_VALKEY_CONTAINER", "moon-valkey"),
	SharedNet:      env("MOON_SHARED_NETWORK", "moon-shared"),
}

const issuer = "https://token.actions.githubusercontent.com"

// ---------------------------------------------------------------- OIDC

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type keyCache struct {
	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

var keys = &keyCache{keys: map[string]*rsa.PublicKey{}}

func (c *keyCache) get(kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if k, ok := c.keys[kid]; ok && time.Since(c.fetched) < 6*time.Hour {
		return k, nil
	}
	if time.Since(c.fetched) > 30*time.Second {
		if err := c.refresh(); err != nil {
			return nil, err
		}
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown signing key %q", kid)
}

func (c *keyCache) refresh() error {
	cl := &http.Client{Timeout: 10 * time.Second}
	resp, err := cl.Get(issuer + "/.well-known/jwks")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("jwks: HTTP %d", resp.StatusCode)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return err
	}
	m := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nb, err1 := base64.RawURLEncoding.DecodeString(k.N)
		eb, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		m[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
	}
	if len(m) == 0 {
		return errors.New("jwks: no RSA keys")
	}
	c.keys = m
	c.fetched = time.Now()
	return nil
}

type claims map[string]any

func (c claims) str(k string) string { s, _ := c[k].(string); return s }

func (c claims) num(k string) float64 { f, _ := c[k].(float64); return f }

func verifyToken(tok string) (claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &hdr) != nil {
		return nil, errors.New("bad token header")
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported alg %q", hdr.Alg)
	}
	pub, err := keys.get(hdr.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("bad signature encoding")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return nil, errors.New("signature verification failed")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("bad payload encoding")
	}
	var c claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, errors.New("bad payload")
	}
	now := float64(time.Now().Unix())
	if c.str("iss") != issuer {
		return nil, errors.New("wrong issuer")
	}
	if !audOK(c["aud"]) {
		return nil, errors.New("wrong audience")
	}
	if exp := c.num("exp"); exp == 0 || now > exp+30 {
		return nil, errors.New("token expired")
	}
	if nbf := c.num("nbf"); nbf != 0 && now+30 < nbf {
		return nil, errors.New("token not yet valid")
	}
	if !strings.EqualFold(c.str("repository_owner"), cfg.Owner) {
		return nil, errors.New("repository owner not allowed")
	}
	if c.str("ref") != "refs/heads/main" {
		return nil, errors.New("only refs/heads/main may deploy")
	}
	switch c.str("event_name") {
	case "push", "workflow_dispatch":
	default:
		return nil, fmt.Errorf("event %q may not deploy", c.str("event_name"))
	}
	if !strings.HasPrefix(c.str("job_workflow_ref"), cfg.WorkflowPrefix) {
		return nil, errors.New("deploy must run through the central moon-infra workflow")
	}
	return c, nil
}

func audOK(a any) bool {
	switch v := a.(type) {
	case string:
		return v == cfg.Audience
	case []any:
		for _, x := range v {
			if s, _ := x.(string); s == cfg.Audience {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------- HTTP

type deployReq struct {
	Image         string `json:"image"`
	Compose       string `json:"compose"`
	RegistryUser  string `json:"registry_user"`
	RegistryToken string `json:"registry_token"`
}

var (
	deployMu  sync.Mutex
	nameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	labelRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	upstreamRe = regexp.MustCompile(`^(127\.0\.0\.1|localhost):[0-9]{2,5}$`)
	reserved  = map[string]bool{"moon-platform": true, "platform": true, "deploy": true, "moon-infra": true, "console": true}
)

type streamWriter struct {
	w http.ResponseWriter
	f http.Flusher
	mu sync.Mutex
}

func (s *streamWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.w.Write(p)
	if s.f != nil {
		s.f.Flush()
	}
	return n, err
}

func (s *streamWriter) logf(format string, a ...any) {
	fmt.Fprintf(s, format+"\n", a...)
}

func handleDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	c, err := verifyToken(strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		log.Printf("auth rejected from %s: %v", r.RemoteAddr, err)
		http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}
	var req deployReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	repo := strings.ToLower(c.str("repository"))
	name := repo[strings.Index(repo, "/")+1:]
	if !nameRe.MatchString(name) || reserved[name] {
		http.Error(w, "repository name not deployable: "+name, http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(req.Image, "ghcr.io/"+repo+"@sha256:") {
		http.Error(w, "image must be ghcr.io/"+repo+"@sha256:<digest>", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Compose) == "" {
		http.Error(w, "compose file is empty", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	f, _ := w.(http.Flusher)
	out := &streamWriter{w: w, f: f}

	out.logf("moon-deployd: %s @ %s (run %v, actor %s)", repo, shortSHA(c.str("sha")), c["run_id"], c.str("actor"))
	if !deployMu.TryLock() {
		out.logf("另一个部署正在进行，排队等待…")
		deployMu.Lock()
	}
	defer deployMu.Unlock()

	start := time.Now()
	url, err := deploy(context.Background(), out, name, repo, req)
	recordHistory(name, c, start, err)
	if err != nil {
		log.Printf("deploy %s failed: %v", name, err)
		out.logf("\n✗ 部署失败: %v", err)
		out.logf("MOON_DEPLOY_RESULT=failed")
		return
	}
	log.Printf("deploy %s ok in %s", name, time.Since(start).Round(time.Second))
	out.logf("\n✓ 部署成功，用时 %s", time.Since(start).Round(time.Second))
	out.logf("MOON_DEPLOY_RESULT=ok")
	if url != "" {
		out.logf("MOON_DEPLOY_URL=%s", url)
	}
}

// recordHistory 追加一条部署记录到 /srv/apps/<name>/history.jsonl（保留最近 200 条），供运维面板展示
func recordHistory(name string, c claims, start time.Time, derr error) {
	dir := filepath.Join(cfg.AppsDir, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return
	}
	rec := map[string]any{
		"at": start.UTC().Format(time.RFC3339), "sha": c.str("sha"), "actor": c.str("actor"),
		"run_id": fmt.Sprint(c["run_id"]), "result": "ok", "seconds": int(time.Since(start).Seconds()),
	}
	if derr != nil {
		rec["result"] = "failed"
		msg := derr.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		rec["error"] = msg
	}
	line, _ := json.Marshal(rec)
	path := filepath.Join(dir, "history.jsonl")
	old, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(old)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	lines = append(lines, string(line))
	if len(lines) > 200 {
		lines = lines[len(lines)-200:]
	}
	os.WriteFile(path+".tmp", []byte(strings.Join(lines, "\n")+"\n"), 0o640)
	os.Rename(path+".tmp", path)
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// ---------------------------------------------------------------- deploy

type xmoon struct {
	Domain           string   `json:"domain"`
	Upstream         string   `json:"upstream"`
	Needs            []string `json:"needs"`
	AllowPublicPorts bool     `json:"allow_public_ports"`
	AllowPrivateDB   bool     `json:"allow_private_db"`
	AllowHostBinds   bool     `json:"allow_host_binds"`
}

var dbImages = map[string]bool{"postgres": true, "postgis": true, "mysql": true, "mariadb": true, "redis": true, "valkey": true, "mongo": true, "mongodb": true, "keydb": true}

func imageBase(img string) string {
	img = strings.ToLower(img)
	if i := strings.Index(img, "@"); i >= 0 {
		img = img[:i]
	}
	if i := strings.LastIndex(img, ":"); i > strings.LastIndex(img, "/") {
		img = img[:i]
	}
	return img[strings.LastIndex(img, "/")+1:]
}

func run(ctx context.Context, out io.Writer, dir string, envv []string, stdin []byte, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), envv...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
}

func output(ctx context.Context, dir string, envv []string, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), envv...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return b, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return b, nil
}

// 项目目录内会被部署改动的文件；失败时整体恢复
var managed = []string{"compose.yaml", ".env", "compose.resolved.json", ".moon-mem"}

// appPort 为项目分配固定的本机端口（首次部署时分配，之后一直复用），供 compose 中的 ${APP_PORT} 使用
func appPort(dir, self string) (int, error) {
	pf := filepath.Join(dir, "app.port")
	if b, err := os.ReadFile(pf); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 {
			return n, nil
		}
	}
	used := map[int]bool{}
	entries, _ := os.ReadDir(cfg.AppsDir)
	for _, e := range entries {
		if b, err := os.ReadFile(filepath.Join(cfg.AppsDir, e.Name(), "app.port")); err == nil {
			n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
			used[n] = true
		}
	}
	for p := 18100; p <= 18999; p++ {
		if used[p] {
			continue
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue // 已被其它进程占用
		}
		ln.Close()
		if err := os.WriteFile(pf, []byte(strconv.Itoa(p)+"\n"), 0o640); err != nil {
			return 0, err
		}
		return p, nil
	}
	return 0, errors.New("18100–18999 端口已全部分配")
}

func backup(dir string) {
	for _, f := range managed {
		p := filepath.Join(dir, f)
		os.Remove(p + ".prev")
		if _, err := os.Stat(p); err == nil {
			os.Rename(p, p+".prev")
		}
	}
}

func restore(dir string) bool {
	had := false
	for _, f := range managed {
		p := filepath.Join(dir, f)
		if _, err := os.Stat(p + ".prev"); err == nil {
			os.Remove(p)
			os.Rename(p+".prev", p)
			had = true
		} else {
			os.Remove(p)
		}
	}
	return had
}

func deploy(ctx context.Context, out *streamWriter, name, repo string, req deployReq) (string, error) {
	dir := filepath.Join(cfg.AppsDir, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	_, statErr := os.Stat(filepath.Join(dir, "compose.resolved.json"))
	firstDeploy := statErr != nil
	backup(dir)
	committed := false
	defer func() {
		if !committed {
			restore(dir)
		}
	}()

	port, err := appPort(dir, name)
	if err != nil {
		return "", err
	}
	domainDefault := name + "." + cfg.DomainSuffix
	envFile := fmt.Sprintf("IMAGE=%s\nAPP_NAME=%s\nAPP_DOMAIN=%s\nAPP_URL=https://%s\nAPP_PORT=%d\n", req.Image, name, domainDefault, domainDefault, port)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(envFile), 0o640); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(req.Compose), 0o640); err != nil {
		return "", err
	}

	out.logf("\n▶ 解析 compose.yaml")
	raw, err := output(ctx, dir, nil, nil, "docker", "compose", "-p", name, "-f", "compose.yaml", "config", "--format", "json")
	if err != nil {
		return "", fmt.Errorf("compose.yaml 无效: %v", err)
	}
	var model map[string]any
	if err := json.Unmarshal(raw, &model); err != nil {
		return "", fmt.Errorf("解析 compose 输出失败: %v", err)
	}
	var xm xmoon
	if v, ok := model["x-moon"]; ok {
		b, _ := json.Marshal(v)
		if err := json.Unmarshal(b, &xm); err != nil {
			return "", fmt.Errorf("x-moon 字段格式错误: %v", err)
		}
	}
	services, _ := model["services"].(map[string]any)
	if len(services) == 0 {
		return "", errors.New("compose.yaml 没有任何 services")
	}

	// ---- 策略校验 + 默认限额
	out.logf("▶ 策略校验与资源预算")
	var memTotal int64
	names := make([]string, 0, len(services))
	for s := range services {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, sn := range names {
		svc, _ := services[sn].(map[string]any)
		img, _ := svc["image"].(string)
		if _, hasBuild := svc["build"]; hasBuild {
			return "", fmt.Errorf("服务 %s 使用了 build：镜像必须由 CI 构建，请改为 image: ${IMAGE}", sn)
		}
		if dbImages[imageBase(img)] && !xm.AllowPrivateDB {
			return "", fmt.Errorf("服务 %s 自带数据库镜像 %s：请删除它并改用共享平台 x-moon.needs: [postgres] / [redis]（确需独立实例时设 x-moon.allow_private_db: true）", sn, img)
		}
		if p, _ := svc["privileged"].(bool); p {
			return "", fmt.Errorf("服务 %s 不允许 privileged", sn)
		}
		for _, k := range []string{"network_mode", "pid", "ipc"} {
			if v, _ := svc[k].(string); v == "host" {
				return "", fmt.Errorf("服务 %s 不允许 %s: host", sn, k)
			}
		}
		if ports, _ := svc["ports"].([]any); len(ports) > 0 && !xm.AllowPublicPorts {
			for _, pv := range ports {
				pm, _ := pv.(map[string]any)
				hip, _ := pm["host_ip"].(string)
				if pub, _ := pm["published"].(string); pub != "" && hip != "127.0.0.1" && hip != "::1" {
					return "", fmt.Errorf("服务 %s 的端口 %s 对公网暴露：请写成 \"127.0.0.1:%s:<容器端口>\"，由 Caddy 提供 HTTPS 入口", sn, pub, pub)
				}
			}
		}
		if vols, _ := svc["volumes"].([]any); len(vols) > 0 && !xm.AllowHostBinds {
			for _, vv := range vols {
				vm, _ := vv.(map[string]any)
				if t, _ := vm["type"].(string); t == "bind" {
					src, _ := vm["source"].(string)
					if !strings.HasPrefix(filepath.Clean(src)+"/", dir+"/") {
						return "", fmt.Errorf("服务 %s 挂载了项目目录外的宿主路径 %s：请用命名卷或 ./ 相对路径", sn, src)
					}
				}
			}
		}

		mem := parseBytes(svc["mem_limit"])
		if dep, _ := svc["deploy"].(map[string]any); dep != nil {
			if res, _ := dep["resources"].(map[string]any); res != nil {
				if lim, _ := res["limits"].(map[string]any); lim != nil {
					if m := parseBytes(lim["memory"]); m > 0 && (mem == 0 || m < mem) {
						mem = m
					}
				}
			}
		}
		if mem == 0 {
			mem = cfg.DefaultMemMB << 20
			svc["mem_limit"] = strconv.FormatInt(mem, 10)
		}
		svc["memswap_limit"] = strconv.FormatInt(mem, 10)
		replicas := int64(1)
		if dep, _ := svc["deploy"].(map[string]any); dep != nil {
			if r, ok := dep["replicas"].(float64); ok && r >= 1 {
				replicas = int64(r)
			}
		}
		if pl, _ := svc["pids_limit"].(float64); pl == 0 {
			svc["pids_limit"] = cfg.DefaultPids
		}
		if rs, _ := svc["restart"].(string); rs == "" {
			svc["restart"] = "unless-stopped"
		}
		labels, _ := svc["labels"].(map[string]any)
		if labels == nil {
			labels = map[string]any{}
		}
		labels["cloud.moonl.project"] = name
		labels["cloud.moonl.repo"] = repo
		svc["labels"] = labels
		memTotal += mem * replicas
		out.logf("  %-16s 内存上限 %4d MiB × %d", sn, mem>>20, replicas)
	}

	others, err := otherAppsMem(name)
	if err != nil {
		return "", err
	}
	budget := cfg.BudgetMB << 20
	out.logf("  本项目 %d MiB，其它项目 %d MiB，应用总预算 %d MiB", memTotal>>20, others>>20, budget>>20)
	if memTotal+others > budget {
		return "", fmt.Errorf("内存预算不足：本项目需要 %d MiB，剩余 %d MiB。请调低 mem_limit 或下线不用的项目", memTotal>>20, (budget-others)>>20)
	}

	// ---- 共享平台
	platformEnv := map[string]string{}
	if len(xm.Needs) > 0 {
		out.logf("▶ 共享平台: %s", strings.Join(xm.Needs, ", "))
		pe, err := provision(ctx, dir, name, xm.Needs)
		if err != nil {
			return "", err
		}
		platformEnv = pe
		nets, _ := model["networks"].(map[string]any)
		if nets == nil {
			nets = map[string]any{}
		}
		nets[cfg.SharedNet] = map[string]any{"name": cfg.SharedNet, "external": true}
		model["networks"] = nets
	}
	for _, sn := range names {
		svc, _ := services[sn].(map[string]any)
		if len(platformEnv) > 0 {
			envm, _ := svc["environment"].(map[string]any)
			if envm == nil {
				envm = map[string]any{}
			}
			for k, v := range platformEnv {
				if _, exists := envm[k]; !exists {
					envm[k] = v
				}
			}
			svc["environment"] = envm
			sn2, _ := svc["networks"].(map[string]any)
			if sn2 == nil {
				sn2 = map[string]any{"default": nil}
			}
			if _, ok := sn2[cfg.SharedNet]; !ok {
				sn2[cfg.SharedNet] = nil
			}
			svc["networks"] = sn2
		}
	}

	resolved, _ := json.MarshalIndent(model, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "compose.resolved.json"), resolved, 0o600); err != nil {
		return "", err
	}
	if _, err := output(ctx, dir, nil, nil, "docker", "compose", "-p", name, "-f", "compose.resolved.json", "config", "-q"); err != nil {
		return "", fmt.Errorf("改写后的编排无效: %v", err)
	}

	// ---- 拉取镜像（临时凭据，用完即删）
	out.logf("▶ 拉取镜像")
	tmp, err := os.MkdirTemp("", "moon-docker-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	denv := []string{"DOCKER_CONFIG=" + tmp}
	if req.RegistryToken != "" {
		if _, err := output(ctx, dir, denv, []byte(req.RegistryToken), "docker", "login", "ghcr.io", "-u", req.RegistryUser, "--password-stdin"); err != nil {
			return "", fmt.Errorf("登录 GHCR 失败: %v", err)
		}
	}
	if err := run(ctx, out, dir, denv, nil, "docker", "compose", "-p", name, "-f", "compose.resolved.json", "pull", "--quiet"); err != nil {
		return "", fmt.Errorf("拉取镜像失败: %v", err)
	}

	// ---- 启动并等待健康
	out.logf("▶ 启动服务（等待健康检查，最长 180 秒）")
	upErr := run(ctx, out, dir, nil, nil, "docker", "compose", "-p", name, "-f", "compose.resolved.json", "up", "-d", "--remove-orphans", "--wait", "--wait-timeout", "180")
	if upErr != nil {
		out.logf("\n服务未能健康启动，最近日志：")
		run(ctx, out, dir, nil, nil, "docker", "compose", "-p", name, "-f", "compose.resolved.json", "ps", "-a")
		run(ctx, out, dir, nil, nil, "docker", "compose", "-p", name, "-f", "compose.resolved.json", "logs", "--no-color", "--tail", "60")
		rollback(ctx, out, dir, name, firstDeploy)
		committed = true // rollback() 已处理文件
		return "", fmt.Errorf("启动失败，已回滚: %v", upErr)
	}

	// ---- 入口路由
	url := ""
	if xm.Upstream != "" {
		domain := xm.Domain
		if domain == "" {
			domain = domainDefault
		}
		if err := routeApp(ctx, out, name, domain, xm.Upstream); err != nil {
			rollback(ctx, out, dir, name, firstDeploy)
			committed = true
			return "", err
		}
		url = "https://" + domain
	} else if err := unrouteApp(ctx, out, name); err != nil {
		return "", err
	}

	os.WriteFile(filepath.Join(dir, ".moon-mem"), []byte(strconv.FormatInt(memTotal, 10)), 0o640)
	for _, f := range managed {
		os.Remove(filepath.Join(dir, f+".prev"))
	}
	committed = true
	run(ctx, io.Discard, dir, nil, nil, "docker", "image", "prune", "-f")
	out.logf("\n▶ 当前状态")
	run(ctx, out, dir, nil, nil, "docker", "compose", "-p", name, "-f", "compose.resolved.json", "ps", "--format", "table {{.Service}}\t{{.Status}}\t{{.Ports}}")
	return url, nil
}

func rollback(ctx context.Context, out *streamWriter, dir, name string, firstDeploy bool) {
	if firstDeploy {
		out.logf("\n▶ 首次部署失败，清理本次创建的容器")
		run(ctx, out, dir, nil, nil, "docker", "compose", "-p", name, "-f", "compose.resolved.json", "down", "--remove-orphans")
		restore(dir)
		return
	}
	out.logf("\n▶ 回滚到上一个版本")
	restore(dir)
	if err := run(ctx, out, dir, nil, nil, "docker", "compose", "-p", name, "-f", "compose.resolved.json", "up", "-d", "--remove-orphans", "--wait", "--wait-timeout", "180"); err != nil {
		out.logf("⚠ 回滚后的服务也未能健康启动: %v", err)
	} else {
		out.logf("已恢复上一个版本")
	}
}

func parseBytes(v any) int64 {
	switch x := v.(type) {
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	case float64:
		return int64(x)
	}
	return 0
}

func otherAppsMem(self string) (int64, error) {
	entries, err := os.ReadDir(cfg.AppsDir)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range entries {
		if !e.IsDir() || e.Name() == self {
			continue
		}
		b, err := os.ReadFile(filepath.Join(cfg.AppsDir, e.Name(), ".moon-mem"))
		if err != nil {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		total += n
	}
	return total, nil
}

// ---------------------------------------------------------------- 共享平台

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
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
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			m[line[:i]] = line[i+1:]
		}
	}
	return m
}

func writeKV(path string, m map[string]string) error {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var b strings.Builder
	b.WriteString("# 由 moon-deployd 生成：共享平台连接信息（每次部署复用，不要提交到 Git）\n")
	for _, k := range ks {
		fmt.Fprintf(&b, "%s=%s\n", k, m[k])
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func provision(ctx context.Context, dir, name string, needs []string) (map[string]string, error) {
	path := filepath.Join(dir, "platform.env")
	st := readKV(path)
	ident := strings.ReplaceAll(name, "-", "_")
	result := map[string]string{}
	for _, n := range needs {
		switch strings.ToLower(n) {
		case "postgres", "postgresql":
			if st["PG_PASSWORD"] == "" {
				st["PG_PASSWORD"] = randHex(24)
			}
			pw := st["PG_PASSWORD"]
			sql := fmt.Sprintf(`DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%[1]s') THEN
    CREATE ROLE "%[1]s" LOGIN PASSWORD '%[2]s' CONNECTION LIMIT 50;
  ELSE
    ALTER ROLE "%[1]s" WITH LOGIN PASSWORD '%[2]s';
  END IF;
END $$;
SELECT 'CREATE DATABASE "%[1]s" OWNER "%[1]s"' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '%[1]s')\gexec
REVOKE ALL ON DATABASE "%[1]s" FROM PUBLIC;
GRANT ALL ON DATABASE "%[1]s" TO "%[1]s";
`, ident, pw)
			if _, err := output(ctx, dir, nil, []byte(sql), "docker", "exec", "-i", cfg.PostgresCtr, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-q"); err != nil {
				return nil, fmt.Errorf("Postgres 开户失败: %v", err)
			}
			result["DATABASE_URL"] = fmt.Sprintf("postgres://%s:%s@postgres:5432/%s?sslmode=disable", ident, pw, ident)
			result["PGHOST"] = "postgres"
			result["PGPORT"] = "5432"
			result["PGUSER"] = ident
			result["PGPASSWORD"] = pw
			result["PGDATABASE"] = ident
		case "redis", "valkey":
			if st["REDIS_PASSWORD"] == "" {
				st["REDIS_PASSWORD"] = randHex(24)
			}
			if st["REDIS_DB"] == "" {
				idx, err := freeRedisDB(name)
				if err != nil {
					return nil, err
				}
				st["REDIS_DB"] = strconv.Itoa(idx)
			}
			pw := st["REDIS_PASSWORD"]
			cmds := fmt.Sprintf("ACL SETUSER %s reset on >%s ~* &* +@all -@admin -@dangerous +info +select\nACL SAVE\n", ident, pw)
			if b, err := output(ctx, dir, nil, []byte(cmds), "docker", "exec", "-i", cfg.ValkeyCtr, "sh", "-c", `valkey-cli --no-auth-warning -a "$VALKEY_PASSWORD"`); err != nil || strings.Contains(string(b), "ERR") {
				return nil, fmt.Errorf("Valkey 开户失败: %v %s", err, strings.TrimSpace(string(b)))
			}
			result["REDIS_URL"] = fmt.Sprintf("redis://%s:%s@valkey:6379/%s", ident, pw, st["REDIS_DB"])
		default:
			return nil, fmt.Errorf("未知的共享依赖 %q（支持 postgres、redis）", n)
		}
	}
	if err := writeKV(path, st); err != nil {
		return nil, err
	}
	return result, nil
}

func freeRedisDB(self string) (int, error) {
	used := map[int]bool{0: true}
	entries, err := os.ReadDir(cfg.AppsDir)
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == self {
			continue
		}
		if v := readKV(filepath.Join(cfg.AppsDir, e.Name(), "platform.env"))["REDIS_DB"]; v != "" {
			n, _ := strconv.Atoi(v)
			used[n] = true
		}
	}
	for i := 1; i < 64; i++ {
		if !used[i] {
			return i, nil
		}
	}
	return 0, errors.New("Valkey 的 63 个数据库编号已用完")
}

// ---------------------------------------------------------------- Caddy

func caddyValidate(ctx context.Context) error {
	_, err := output(ctx, "/", nil, nil, "sudo", "-n", "-u", "caddy", "/usr/bin/caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
	return err
}

func caddyReload(ctx context.Context) error {
	_, err := output(ctx, "/", nil, nil, "sudo", "-n", "/usr/bin/systemctl", "reload", "caddy")
	return err
}

func routeApp(ctx context.Context, out *streamWriter, name, domain, upstream string) error {
	domain = strings.ToLower(domain)
	if !strings.HasSuffix(domain, "."+cfg.DomainSuffix) || !labelRe.MatchString(strings.TrimSuffix(domain, "."+cfg.DomainSuffix)) {
		return fmt.Errorf("域名 %s 不合法：只能使用 <名称>.%s", domain, cfg.DomainSuffix)
	}
	if !upstreamRe.MatchString(upstream) {
		return fmt.Errorf("upstream %s 不合法：应为 127.0.0.1:<端口>", upstream)
	}
	entries, _ := os.ReadDir(cfg.CaddyDir)
	for _, e := range entries {
		if e.Name() == name+".caddy" {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(cfg.CaddyDir, e.Name()))
		if strings.HasPrefix(strings.TrimSpace(string(b)), "# moon-deployd") && strings.Contains(string(b), "\n"+domain+" {") {
			return fmt.Errorf("域名 %s 已被项目 %s 使用", domain, strings.TrimSuffix(e.Name(), ".caddy"))
		}
	}
	site := fmt.Sprintf(`# moon-deployd: %s（自动生成，勿手改）
%s {
	encode zstd gzip
	header {
		Strict-Transport-Security "max-age=63072000"
		X-Content-Type-Options nosniff
		Referrer-Policy strict-origin-when-cross-origin
		-Server
	}
	reverse_proxy %s {
		fail_duration 10s
	}
}
`, name, domain, upstream)
	path := filepath.Join(cfg.CaddyDir, name+".caddy")
	old, oldErr := os.ReadFile(path)
	if oldErr == nil && string(old) == site {
		out.logf("▶ 入口 https://%s 不变", domain)
		return nil
	}
	out.logf("▶ 配置入口 https://%s → %s", domain, upstream)
	if err := os.WriteFile(path, []byte(site), 0o644); err != nil {
		return err
	}
	if err := caddyValidate(ctx); err != nil {
		if oldErr == nil {
			os.WriteFile(path, old, 0o644)
		} else {
			os.Remove(path)
		}
		return fmt.Errorf("Caddy 配置校验失败（已撤销路由改动）: %v", err)
	}
	if err := caddyReload(ctx); err != nil {
		return fmt.Errorf("Caddy 重载失败: %v", err)
	}
	return nil
}

func unrouteApp(ctx context.Context, out *streamWriter, name string) error {
	path := filepath.Join(cfg.CaddyDir, name+".caddy")
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	out.logf("▶ 项目不再声明 upstream，移除公网入口")
	os.Remove(path)
	if err := caddyValidate(ctx); err != nil {
		return fmt.Errorf("Caddy 配置校验失败: %v", err)
	}
	return caddyReload(ctx)
}

// ---------------------------------------------------------------- main

func main() {
	log.SetFlags(0)
	if err := keys.refresh(); err != nil {
		log.Printf("warning: initial JWKS fetch failed: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/deploy", handleDeploy)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("moon-deployd listening on %s (owner=%s, budget=%dMiB)", cfg.Listen, cfg.Owner, cfg.BudgetMB)
	log.Fatal(srv.ListenAndServe())
}
