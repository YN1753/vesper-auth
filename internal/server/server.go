package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/YN1753/vesper-auth/internal/auth"
	"github.com/YN1753/vesper-auth/internal/config"
	"github.com/YN1753/vesper-auth/internal/notify"
	"github.com/YN1753/vesper-auth/internal/oidc"
	"github.com/YN1753/vesper-auth/internal/store"
)

const defaultCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"

// Server wires HTTP routes, auth/session handlers, admin APIs, and OIDC endpoints.
type Server struct {
	cfg      *config.Config
	store    *store.Store
	keys     *oidc.KeySet
	sessions *auth.SessionManager
	passkeys *auth.PasskeyManager
	limiter  *auth.RateLimiter
	notifier *notify.Notifier
	oidc     *oidc.Service
	renderer *Renderer
	mux      *http.ServeMux
	issuer   *url.URL
	version  string
}

// New constructs a configured Server ready to handle HTTP traffic.
func New(cfg *config.Config, st *store.Store) (*Server, error) {
	keys, err := oidc.LoadOrCreateKeySet(st)
	if err != nil {
		return nil, err
	}
	sessions, err := auth.NewSessionManager(st, cfg.SessionTTL, cfg.CookieSecure)
	if err != nil {
		return nil, err
	}
	sessions.SetTrustedProxyCheck(func(r *http.Request) bool {
		return cfg.IsTrustedProxy(r.RemoteAddr)
	})

	passkeys, err := auth.NewPasskeyManager(st, cfg.RPID, cfg.RPDisplayName, cfg.RPOrigins)
	if err != nil {
		return nil, err
	}
	renderer, err := NewRenderer()
	if err != nil {
		return nil, err
	}
	parsedIssuer, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, err
	}

	limiter := auth.NewRateLimiter(cfg.RateLimitMaxAttempts, cfg.RateLimitWindow, cfg.RateLimitLockout)
	if cfg.RateLimitMaxBuckets > 0 {
		limiter.SetMaxBuckets(cfg.RateLimitMaxBuckets)
	}

	notifier := notify.NewNotifier(cfg.Issuer, cfg.AlertWebhookURL, cfg.AlertWebhookSecret)

	srv := &Server{
		cfg:      cfg,
		store:    st,
		keys:     keys,
		sessions: sessions,
		passkeys: passkeys,
		limiter:  limiter,
		notifier: notifier,
		renderer: renderer,
		mux:      http.NewServeMux(),
		issuer:   parsedIssuer,
		version:  "dev",
	}
	srv.oidc = oidc.NewService(cfg, st, keys, sessions, limiter, notifier, renderer, srv.clientIP)
	srv.registerRoutes()
	return srv, nil
}

// SetVersion sets the build version label displayed in /healthz and the admin console footer.
func (s *Server) SetVersion(v string) {
	if strings.TrimSpace(v) != "" {
		s.version = strings.TrimSpace(v)
	}
}

// Close flushes background workers such as the security webhook notifier.
func (s *Server) Close() {
	if s.notifier != nil {
		s.notifier.Close()
	}
}

// Handler returns the root http.Handler wrapped with security headers and CORS support.
func (s *Server) Handler() http.Handler {
	return s.securityHeaders(s.oidcCORS(s.mux))
}

func (s *Server) registerRoutes() {
	// Static assets and health probe
	s.mux.Handle("GET /static/", s.renderer.StaticHandler())
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Standard OAuth 2.0 / OIDC endpoints
	s.mux.HandleFunc("GET /.well-known/openid-configuration", s.oidc.Discovery)
	s.mux.HandleFunc("GET /.well-known/jwks.json", s.oidc.JWKS)
	s.mux.HandleFunc("GET /oauth2/authorize", s.oidc.AuthorizeGet)
	s.mux.HandleFunc("POST /oauth2/authorize", s.oidc.AuthorizePost)
	s.mux.HandleFunc("POST /oauth2/token", s.oidc.Token)
	s.mux.HandleFunc("GET /oauth2/userinfo", s.oidc.UserInfo)
	s.mux.HandleFunc("POST /oauth2/userinfo", s.oidc.UserInfo)
	s.mux.HandleFunc("POST /oauth2/introspect", s.oidc.Introspect)
	s.mux.HandleFunc("POST /oauth2/revoke", s.oidc.Revoke)
	s.mux.HandleFunc("GET /oauth2/logout", s.oidc.Logout)
	s.mux.HandleFunc("POST /oauth2/logout", s.oidc.Logout)

	// Authentication UI & APIs
	s.mux.HandleFunc("GET /setup", s.handleSetupPage)
	s.mux.HandleFunc("POST /api/auth/setup", s.handleSetupAPI)
	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("POST /api/auth/login", s.handlePasswordLogin)
	s.mux.HandleFunc("POST /api/auth/passkey/login/begin", s.handlePasskeyLoginBegin)
	s.mux.HandleFunc("POST /api/auth/passkey/login/conditional", s.handlePasskeyConditionalBegin)
	s.mux.HandleFunc("POST /api/auth/passkey/login/finish", s.handlePasskeyLoginFinish)
	s.mux.HandleFunc("POST /api/auth/logout", s.withAdmin(true, s.handleLogoutAPI))

	// Management Console & Admin APIs
	s.mux.HandleFunc("GET /{$}", s.handleAdminPage)
	s.mux.HandleFunc("GET /api/admin/overview", s.withAdmin(false, s.handleAdminOverview))
	s.mux.HandleFunc("POST /api/admin/profile", s.withAdmin(true, s.handleUpdateProfile))
	s.mux.HandleFunc("POST /api/admin/password", s.withAdmin(true, s.handleChangePassword))

	// Sudo re-authentication endpoints
	s.mux.HandleFunc("POST /api/admin/sudo/password", s.withAdmin(true, s.handleSudoPassword))
	s.mux.HandleFunc("POST /api/admin/sudo/passkey/begin", s.withAdmin(true, s.handleSudoPasskeyBegin))
	s.mux.HandleFunc("POST /api/admin/sudo/passkey/finish", s.withAdmin(true, s.handleSudoPasskeyFinish))

	// Passkey management
	s.mux.HandleFunc("GET /api/admin/passkeys", s.withAdmin(false, s.handleListPasskeys))
	s.mux.HandleFunc("POST /api/admin/passkeys/register/begin", s.withAdmin(true, s.handlePasskeyRegisterBegin))
	s.mux.HandleFunc("POST /api/admin/passkeys/register/finish", s.withAdmin(true, s.handlePasskeyRegisterFinish))
	s.mux.HandleFunc("PATCH /api/admin/passkeys/{id}", s.withAdmin(true, s.handleRenamePasskey))
	s.mux.HandleFunc("DELETE /api/admin/passkeys/{id}", s.withAdmin(true, s.withSudo(s.handleDeletePasskey)))

	// Signing key management
	s.mux.HandleFunc("GET /api/admin/keys", s.withAdmin(false, s.handleListKeys))
	s.mux.HandleFunc("POST /api/admin/keys/rotate", s.withAdmin(true, s.withSudo(s.handleRotateKey)))

	// Session management
	s.mux.HandleFunc("GET /api/admin/sessions", s.withAdmin(false, s.handleListSessions))
	s.mux.HandleFunc("DELETE /api/admin/sessions/others", s.withAdmin(true, s.handleRevokeOtherSessions))
	s.mux.HandleFunc("DELETE /api/admin/sessions/{id}", s.withAdmin(true, s.handleRevokeSession))

	// OAuth client management
	s.mux.HandleFunc("GET /api/admin/clients", s.withAdmin(false, s.handleListClients))
	s.mux.HandleFunc("POST /api/admin/clients", s.withAdmin(true, s.handleCreateClient))
	s.mux.HandleFunc("PUT /api/admin/clients/{id}", s.withAdmin(true, s.handleUpdateClient))
	s.mux.HandleFunc("POST /api/admin/clients/{id}/rotate", s.withAdmin(true, s.withSudo(s.handleRotateClientSecret)))
	s.mux.HandleFunc("DELETE /api/admin/clients/{id}", s.withAdmin(true, s.withSudo(s.handleDeleteClient)))

	// Audit log query
	s.mux.HandleFunc("GET /api/admin/audit", s.withAdmin(false, s.handleListAudit))
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "degraded",
			"error":  "database unreachable",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": s.version,
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self), publickey-credentials-create=(self)")
		w.Header().Set("Content-Security-Policy", defaultCSP)
		if s.sessions.IsHTTPS(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) oidcCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		origin := strings.TrimSpace(r.Header.Get("Origin"))

		if path == "/.well-known/openid-configuration" || path == "/.well-known/jwks.json" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		if origin != "" && (path == "/oauth2/token" || path == "/oauth2/userinfo" || path == "/oauth2/revoke" || path == "/oauth2/introspect") {
			if strings.EqualFold(origin, s.cfg.Issuer) || s.store.IsClientOriginAllowed(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.IsTrustedProxy(r.RemoteAddr) {
		if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
			if ip := net.ParseIP(cf); ip != nil {
				return ip.String()
			}
		}
		if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if ip := net.ParseIP(first); ip != nil {
				return ip.String()
			}
		}
		if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
			if ip := net.ParseIP(xri); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
