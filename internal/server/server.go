package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/YN1753/vesper-auth/internal/auth"
	"github.com/YN1753/vesper-auth/internal/config"
	"github.com/YN1753/vesper-auth/internal/oidc"
	"github.com/YN1753/vesper-auth/internal/store"
)

// Server wires HTTP routes, auth/session handlers, admin APIs, and OIDC endpoints.
type Server struct {
	cfg      *config.Config
	store    *store.Store
	keys     *oidc.KeySet
	sessions *auth.SessionManager
	passkeys *auth.PasskeyManager
	limiter  *auth.RateLimiter
	oidc     *oidc.Service
	renderer *Renderer
	mux      *http.ServeMux
	issuer   *url.URL
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

	srv := &Server{
		cfg:      cfg,
		store:    st,
		keys:     keys,
		sessions: sessions,
		passkeys: passkeys,
		limiter:  limiter,
		renderer: renderer,
		mux:      http.NewServeMux(),
		issuer:   parsedIssuer,
	}
	srv.oidc = oidc.NewService(cfg, st, keys, sessions, limiter, renderer, srv.clientIP)
	srv.registerRoutes()
	return srv, nil
}

// Handler returns the root http.Handler wrapped with security headers.
func (s *Server) Handler() http.Handler {
	return s.securityHeaders(s.mux)
}

func (s *Server) registerRoutes() {
	// Static assets and health
	s.mux.Handle("GET /static/", s.renderer.StaticHandler())
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Standard OAuth 2.0 / OIDC endpoints
	s.mux.HandleFunc("GET /.well-known/openid-configuration", s.oidc.Discovery)
	s.mux.HandleFunc("GET /.well-known/jwks.json", s.oidc.JWKS)
	s.mux.HandleFunc("GET /oauth2/authorize", s.oidc.AuthorizeGet)
	s.mux.HandleFunc("POST /oauth2/authorize", s.oidc.AuthorizePost)
	s.mux.HandleFunc("POST /oauth2/token", s.oidc.Token)
	s.mux.HandleFunc("GET /oauth2/userinfo", s.oidc.UserInfo)
	s.mux.HandleFunc("POST /oauth2/userinfo", s.oidc.UserInfo)
	s.mux.HandleFunc("POST /oauth2/revoke", s.oidc.Revoke)
	s.mux.HandleFunc("GET /oauth2/logout", s.oidc.Logout)
	s.mux.HandleFunc("POST /oauth2/logout", s.oidc.Logout)

	// Authentication UI & APIs
	s.mux.HandleFunc("GET /setup", s.handleSetupPage)
	s.mux.HandleFunc("POST /api/auth/setup", s.handleSetupAPI)
	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("POST /api/auth/login", s.handlePasswordLogin)
	s.mux.HandleFunc("POST /api/auth/passkey/login/begin", s.handlePasskeyLoginBegin)
	s.mux.HandleFunc("POST /api/auth/passkey/login/finish", s.handlePasskeyLoginFinish)
	s.mux.HandleFunc("POST /api/auth/logout", s.handleLogoutAPI)

	// Management Console & Admin APIs
	s.mux.HandleFunc("GET /{$}", s.handleAdminPage)
	s.mux.HandleFunc("GET /api/admin/overview", s.withAdmin(false, s.handleAdminOverview))
	s.mux.HandleFunc("POST /api/admin/profile", s.withAdmin(true, s.handleUpdateProfile))
	s.mux.HandleFunc("POST /api/admin/password", s.withAdmin(true, s.handleChangePassword))

	s.mux.HandleFunc("GET /api/admin/passkeys", s.withAdmin(false, s.handleListPasskeys))
	s.mux.HandleFunc("POST /api/admin/passkeys/register/begin", s.withAdmin(true, s.handlePasskeyRegisterBegin))
	s.mux.HandleFunc("POST /api/admin/passkeys/register/finish", s.withAdmin(true, s.handlePasskeyRegisterFinish))
	s.mux.HandleFunc("PATCH /api/admin/passkeys/{id}", s.withAdmin(true, s.handleRenamePasskey))
	s.mux.HandleFunc("DELETE /api/admin/passkeys/{id}", s.withAdmin(true, s.handleDeletePasskey))

	s.mux.HandleFunc("GET /api/admin/sessions", s.withAdmin(false, s.handleListSessions))
	s.mux.HandleFunc("DELETE /api/admin/sessions/others", s.withAdmin(true, s.handleRevokeOtherSessions))
	s.mux.HandleFunc("DELETE /api/admin/sessions/{id}", s.withAdmin(true, s.handleRevokeSession))

	s.mux.HandleFunc("GET /api/admin/clients", s.withAdmin(false, s.handleListClients))
	s.mux.HandleFunc("POST /api/admin/clients", s.withAdmin(true, s.handleCreateClient))
	s.mux.HandleFunc("PUT /api/admin/clients/{id}", s.withAdmin(true, s.handleUpdateClient))
	s.mux.HandleFunc("POST /api/admin/clients/{id}/rotate", s.withAdmin(true, s.handleRotateClientSecret))
	s.mux.HandleFunc("DELETE /api/admin/clients/{id}", s.withAdmin(true, s.handleDeleteClient))

	s.mux.HandleFunc("GET /api/admin/audit", s.withAdmin(false, s.handleListAudit))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
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
