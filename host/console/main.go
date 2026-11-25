// moon-console：moon 服务器运维面板。
//
// 以宿主机原生服务运行（Docker 故障时依然可用于排障），只监听 127.0.0.1，由 Caddy 提供 HTTPS。
// 登录走 moon-sso（OIDC 授权码 + PKCE），只放行配置的 sub。
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed web
var webFS embed.FS

type config struct {
	Listen      string
	PublicURL   string
	Issuer      string
	ClientID    string
	AllowedSubs map[string]bool
	AllowedUser string
	StateDir    string
	AppsDir     string
	DiskStatus  string
	BackupsDir  string
	PostgresCtr string
	ValkeyCtr   string
	DockerSock  string
	PodmanSock  string
	SessionTTL  time.Duration
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func loadConfig() config {
	subs := map[string]bool{}
	for _, s := range strings.Split(env("OIDC_ALLOWED_SUBS", ""), ",") {
		if s = strings.TrimSpace(s); s != "" {
			subs[s] = true
		}
	}
	ttl, _ := strconv.Atoi(env("SESSION_TTL_HOURS", "12"))
	return config{
		Listen:      env("CONSOLE_LISTEN", "127.0.0.1:19710"),
		PublicURL:   strings.TrimRight(env("CONSOLE_PUBLIC_URL", "https://console.moonl.cloud"), "/"),
		Issuer:      strings.TrimRight(env("OIDC_ISSUER", "https://sso.moonl.cloud"), "/"),
		ClientID:    env("OIDC_CLIENT_ID", ""),
		AllowedSubs: subs,
		AllowedUser: strings.ToLower(env("OIDC_ALLOWED_USERNAME", "")),
		StateDir:    env("CONSOLE_STATE_DIR", "/var/lib/moon-console"),
		AppsDir:     env("MOON_APPS_DIR", "/srv/apps"),
		DiskStatus:  env("DISKGUARD_STATUS", "/var/lib/moon-diskguard/status.json"),
		BackupsDir:  env("BACKUPS_DIR", "/srv/platform/backups"),
		PostgresCtr: env("POSTGRES_CONTAINER", "moon-postgres"),
		ValkeyCtr:   env("VALKEY_CONTAINER", "moon-valkey"),
		DockerSock:  env("DOCKER_SOCK", "/var/run/docker.sock"),
		PodmanSock:  env("PODMAN_SOCK", "/run/podman/podman.sock"),
		SessionTTL:  time.Duration(ttl) * time.Hour,
	}
}

type server struct {
	cfg     config
	auth    *authenticator
	runtime *runtimes
	sampler *sampler
}

func main() {
	log.SetFlags(0)
	cfg := loadConfig()
	if cfg.ClientID == "" || len(cfg.AllowedSubs) == 0 {
		log.Fatal("OIDC_CLIENT_ID 与 OIDC_ALLOWED_SUBS 必须配置")
	}
	auth, err := newAuthenticator(cfg)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}
	rt := newRuntimes(cfg)
	s := &server{cfg: cfg, auth: auth, runtime: rt, sampler: newSampler(rt)}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go s.sampler.run(ctx)

	static, _ := fs.Sub(webFS, "web")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", s.auth.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.auth.handleCallback)
	mux.HandleFunc("POST /auth/logout", s.auth.handleLogout)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })

	api := http.NewServeMux()
	api.HandleFunc("GET /api/me", s.handleMe)
	api.HandleFunc("GET /api/overview", s.handleOverview)
	api.HandleFunc("GET /api/containers", s.handleContainers)
	api.HandleFunc("POST /api/containers/{rt}/{id}/{action}", s.handleContainerAction)
	api.HandleFunc("GET /api/containers/{rt}/{id}/logs", s.handleContainerLogs)
	api.HandleFunc("GET /api/services", s.handleServices)
	api.HandleFunc("POST /api/services/{unit}/{action}", s.handleServiceAction)
	api.HandleFunc("GET /api/services/{unit}/logs", s.handleServiceLogs)
	api.HandleFunc("GET /api/projects", s.handleProjects)
	api.HandleFunc("GET /api/databases", s.handleDatabases)
	api.HandleFunc("GET /api/disk", s.handleDisk)
	api.HandleFunc("POST /api/disk/clean", s.handleDiskClean)
	mux.Handle("/api/", s.auth.require(s.csrf(api)))

	files := http.FileServerFS(static)
	mux.Handle("/", s.auth.requirePage(securityHeaders(files)))

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           logRequests(mux),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	log.Printf("moon-console listening on %s (%s)", cfg.Listen, cfg.PublicURL)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// csrf：写操作必须来自本站页面（Origin 校验 + 自定义头，跨站表单无法携带）
func (s *server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" && o != s.cfg.PublicURL {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
			if r.Header.Get("X-Moon-Console") != "1" {
				http.Error(w, "missing X-Moon-Console header", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// 脚本严格限制为同源文件；样式允许内联属性（进度条宽度），不加载任何外部资源
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		start := time.Now()
		next.ServeHTTP(rec, r)
		if r.Method != http.MethodGet || rec.code >= 400 {
			log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.code, time.Since(start).Round(time.Millisecond))
		}
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
