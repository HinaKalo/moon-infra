package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type discovery struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	JWKSURL     string `json:"jwks_uri"`
	EndSession  string `json:"end_session_endpoint"`
}

type authenticator struct {
	cfg    config
	key    []byte
	client *http.Client

	mu      sync.Mutex
	disc    *discovery
	discAt  time.Time
	jwks    map[string]*rsa.PublicKey
	jwksAt  time.Time
}

type session struct {
	Sub      string `json:"sub"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Exp      int64  `json:"exp"`
}

type oauthState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
	Exp      int64  `json:"e"`
}

const (
	sessionCookie = "mc_session"
	oauthCookie   = "mc_oauth"
)

func newAuthenticator(cfg config) (*authenticator, error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	kp := filepath.Join(cfg.StateDir, "session.key")
	key, err := os.ReadFile(kp)
	if err != nil || len(key) < 32 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(kp, key, 0o600); err != nil {
			return nil, err
		}
	}
	return &authenticator{cfg: cfg, key: key, client: &http.Client{Timeout: 10 * time.Second}}, nil
}

// ---------------------------------------------------------------- 签名 cookie

func (a *authenticator) sign(v any) string {
	b, _ := json.Marshal(v)
	p := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (a *authenticator) verify(tok string, v any) error {
	p, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return errors.New("malformed")
	}
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(p))
	want := m.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || subtle.ConstantTimeCompare(want, got) != 1 {
		return errors.New("bad signature")
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (a *authenticator) currentSession(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	var s session
	if a.verify(c.Value, &s) != nil || time.Now().Unix() > s.Exp || !a.cfg.AllowedSubs[s.Sub] {
		return nil
	}
	return &s
}

func (a *authenticator) setCookie(w http.ResponseWriter, name, value, path string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: path, MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

// ---------------------------------------------------------------- 中间件

type ctxKey struct{}

func (a *authenticator) require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.currentSession(r) == nil {
			writeErr(w, http.StatusUnauthorized, "未登录或会话已过期")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *authenticator) requirePage(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.currentSession(r) == nil {
			next := r.URL.Path
			if r.URL.RawQuery != "" {
				next += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(next), http.StatusFound)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------- OIDC

func (a *authenticator) discovery() (*discovery, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.disc != nil && time.Since(a.discAt) < time.Hour {
		return a.disc, nil
	}
	resp, err := a.client.Get(a.cfg.Issuer + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var d discovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return nil, err
	}
	if d.Issuer != a.cfg.Issuer || d.AuthURL == "" || d.TokenURL == "" || d.JWKSURL == "" {
		return nil, errors.New("invalid discovery document")
	}
	a.disc, a.discAt = &d, time.Now()
	return &d, nil
}

func (a *authenticator) key4(kid string) (*rsa.PublicKey, error) {
	d, err := a.discovery()
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if k, ok := a.jwks[kid]; ok && time.Since(a.jwksAt) < 6*time.Hour {
		return k, nil
	}
	if time.Since(a.jwksAt) < 10*time.Second {
		return nil, fmt.Errorf("unknown key %q", kid)
	}
	resp, err := a.client.Get(d.JWKSURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var set struct {
		Keys []struct{ Kid, Kty, N, E string } `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, err
	}
	m := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nb, e1 := base64.RawURLEncoding.DecodeString(k.N)
		eb, e2 := base64.RawURLEncoding.DecodeString(k.E)
		if e1 == nil && e2 == nil {
			m[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
		}
	}
	a.jwks, a.jwksAt = m, time.Now()
	if k, ok := m[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown key %q", kid)
}

func randToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *authenticator) redirectURI() string { return a.cfg.PublicURL + "/auth/callback" }

func (a *authenticator) handleLogin(w http.ResponseWriter, r *http.Request) {
	d, err := a.discovery()
	if err != nil {
		log.Printf("discovery: %v", err)
		authPage(w, http.StatusBadGateway, "无法连接 SSO", "moon-sso 暂时不可用，请稍后重试。")
		return
	}
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	st := oauthState{State: randToken(24), Nonce: randToken(24), Verifier: randToken(48), Next: next, Exp: time.Now().Add(10 * time.Minute).Unix()}
	a.setCookie(w, oauthCookie, a.sign(st), "/auth/", 600)
	sum := sha256.Sum256([]byte(st.Verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {a.cfg.ClientID},
		"redirect_uri":          {a.redirectURI()},
		"scope":                 {"openid profile"},
		"state":                 {st.State},
		"nonce":                 {st.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, d.AuthURL+"?"+q.Encode(), http.StatusFound)
}

func (a *authenticator) handleCallback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(oauthCookie)
	var st oauthState
	if err != nil || a.verify(c.Value, &st) != nil || time.Now().Unix() > st.Exp {
		authPage(w, http.StatusBadRequest, "登录已过期", "请重新登录。")
		return
	}
	a.setCookie(w, oauthCookie, "", "/auth/", -1)
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		authPage(w, http.StatusForbidden, "登录被取消", q.Get("error_description"))
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		authPage(w, http.StatusBadRequest, "登录校验失败", "state 不匹配，请重新登录。")
		return
	}
	claims, err := a.exchange(q.Get("code"), st)
	if err != nil {
		log.Printf("login failed: %v", err)
		authPage(w, http.StatusForbidden, "登录失败", "身份令牌校验未通过。")
		return
	}
	sub, _ := claims["sub"].(string)
	user, _ := claims["preferred_username"].(string)
	name, _ := claims["name"].(string)
	if !a.cfg.AllowedSubs[sub] {
		log.Printf("denied login: sub=%s username=%s", sub, user)
		authPage(w, http.StatusForbidden, "没有访问权限", "当前账号不是 moon 的管理员。")
		return
	}
	if a.cfg.AllowedUser != "" && strings.ToLower(user) != a.cfg.AllowedUser {
		log.Printf("note: allowed sub %s logged in with username %q", sub, user)
	}
	s := session{Sub: sub, Username: user, Name: name, Exp: time.Now().Add(a.cfg.SessionTTL).Unix()}
	a.setCookie(w, sessionCookie, a.sign(s), "/", int(a.cfg.SessionTTL.Seconds()))
	log.Printf("login: %s (%s)", user, sub)
	http.Redirect(w, r, st.Next, http.StatusFound)
}

func (a *authenticator) exchange(code string, st oauthState) (map[string]any, error) {
	d, err := a.discovery()
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {a.redirectURI()},
		"client_id":     {a.cfg.ClientID},
		"code_verifier": {st.Verifier},
	}
	resp, err := a.client.PostForm(d.TokenURL, form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token endpoint %d: %s", resp.StatusCode, body)
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.IDToken == "" {
		return nil, errors.New("no id_token")
	}
	return a.verifyIDToken(tr.IDToken, st.Nonce)
}

func (a *authenticator) verifyIDToken(tok, nonce string) (map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed id_token")
	}
	var hdr struct{ Alg, Kid string }
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &hdr) != nil {
		return nil, errors.New("bad header")
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported alg %s", hdr.Alg)
	}
	pub, err := a.key4(hdr.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return nil, errors.New("signature verification failed")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var c map[string]any
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, err
	}
	now := float64(time.Now().Unix())
	if iss, _ := c["iss"].(string); iss != a.cfg.Issuer {
		return nil, errors.New("wrong issuer")
	}
	if !audContains(c["aud"], a.cfg.ClientID) {
		return nil, errors.New("wrong audience")
	}
	if exp, _ := c["exp"].(float64); exp == 0 || now > exp+30 {
		return nil, errors.New("expired")
	}
	if n, _ := c["nonce"].(string); subtle.ConstantTimeCompare([]byte(n), []byte(nonce)) != 1 {
		return nil, errors.New("nonce mismatch")
	}
	return c, nil
}

func audContains(a any, want string) bool {
	switch v := a.(type) {
	case string:
		return v == want
	case []any:
		for _, x := range v {
			if s, _ := x.(string); s == want {
				return true
			}
		}
	}
	return false
}

func (a *authenticator) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Moon-Console") != "1" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	a.setCookie(w, sessionCookie, "", "/", -1)
	target := a.cfg.PublicURL + "/"
	if d, err := a.discovery(); err == nil && d.EndSession != "" {
		target = d.EndSession + "?" + url.Values{"client_id": {a.cfg.ClientID}, "post_logout_redirect_uri": {a.cfg.PublicURL + "/"}}.Encode()
	}
	writeJSON(w, map[string]string{"redirect": target})
}

var authTpl = template.Must(template.New("auth").Parse(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}} · Moon Console</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;font:15px/1.6 system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;background:#f6f7fb;color:#1f2433}
.card{background:#fff;border:1px solid #e4e7ef;border-radius:14px;padding:32px 36px;max-width:420px;box-shadow:0 8px 30px rgba(30,40,80,.06)}h1{font-size:20px;margin:0 0 8px}p{margin:0 0 20px;color:#5b6276}a{display:inline-block;background:#4f46e5;color:#fff;text-decoration:none;padding:9px 18px;border-radius:9px;font-weight:600}</style></head>
<body><div class="card"><h1>{{.Title}}</h1><p>{{.Msg}}</p><a href="/auth/login">重新登录</a></div></body></html>`))

func authPage(w http.ResponseWriter, code int, title, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	authTpl.Execute(w, map[string]string{"Title": title, "Msg": msg})
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	ss := s.auth.currentSession(r)
	writeJSON(w, map[string]any{"sub": ss.Sub, "username": ss.Username, "name": ss.Name, "expires_at": ss.Exp})
}
