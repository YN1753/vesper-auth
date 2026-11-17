package oidc

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/YN1753/vesper-auth/internal/auth"
	"github.com/YN1753/vesper-auth/internal/config"
	"github.com/YN1753/vesper-auth/internal/notify"
	"github.com/YN1753/vesper-auth/internal/store"
)

// TemplateRenderer renders HTML templates for consent, logout confirmation, and error screens.
type TemplateRenderer interface {
	RenderConsent(w http.ResponseWriter, data ConsentViewData)
	RenderLogoutConfirm(w http.ResponseWriter, data LogoutConfirmViewData)
	RenderError(w http.ResponseWriter, status int, title, message string)
}

// ConsentViewData supplies data to the OAuth2 consent confirmation screen.
type ConsentViewData struct {
	ClientName   string
	ClientID     string
	CallbackHost string
	RedirectURI  string
	Scopes       []ScopeInfo
	ScopeRaw     string
	RequestID    string
	CSRFToken    string
	Username     string
	Email        string
}

// LogoutConfirmViewData supplies data to the OIDC logout confirmation screen.
type LogoutConfirmViewData struct {
	Username              string
	Email                 string
	ClientID              string
	PostLogoutRedirectURI string
	State                 string
	CSRFToken             string
}

// ScopeInfo describes a requested OAuth2/OIDC scope for the user.
type ScopeInfo struct {
	Name        string
	Description string
}

// Service implements OAuth 2.0 and OpenID Connect endpoints.
type Service struct {
	cfg      *config.Config
	store    *store.Store
	keys     *KeySet
	sessions *auth.SessionManager
	limiter  *auth.RateLimiter
	notifier *notify.Notifier
	renderer TemplateRenderer
	clientIP func(*http.Request) string
}

// NewService constructs an OIDC/OAuth2 Service.
func NewService(
	cfg *config.Config,
	st *store.Store,
	keys *KeySet,
	sessions *auth.SessionManager,
	limiter *auth.RateLimiter,
	notifier *notify.Notifier,
	renderer TemplateRenderer,
	clientIP func(*http.Request) string,
) *Service {
	return &Service{
		cfg:      cfg,
		store:    st,
		keys:     keys,
		sessions: sessions,
		limiter:  limiter,
		notifier: notifier,
		renderer: renderer,
		clientIP: clientIP,
	}
}

// Discovery handles GET /.well-known/openid-configuration.
func (s *Service) Discovery(w http.ResponseWriter, r *http.Request) {
	iss := s.cfg.Issuer
	doc := map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/oauth2/authorize",
		"token_endpoint":                        iss + "/oauth2/token",
		"userinfo_endpoint":                     iss + "/oauth2/userinfo",
		"jwks_uri":                              iss + "/.well-known/jwks.json",
		"revocation_endpoint":                   iss + "/oauth2/revoke",
		"introspection_endpoint":                iss + "/oauth2/introspect",
		"end_session_endpoint":                  iss + "/oauth2/logout",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "name", "preferred_username", "email", "email_verified", "role"},
		"code_challenge_methods_supported":      []string{"S256"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"prompt_values_supported":               []string{"none", "login", "consent"},
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, doc)
}

// JWKS handles GET /.well-known/jwks.json.
func (s *Service) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, s.keys.JWKS())
}

// AuthorizeGet handles GET /oauth2/authorize.
func (s *Service) AuthorizeGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var req *store.AuthRequest
	var client *store.OAuthClient
	var err error

	if reqID := strings.TrimSpace(q.Get("req")); reqID != "" {
		req, err = s.store.GetAuthRequest(reqID)
		if err != nil {
			s.renderErr(w, http.StatusBadRequest, "授权请求无效或已过期", "请返回原应用重新发起登录授权。")
			return
		}
		client, err = s.store.GetOAuthClient(req.ClientID)
		if err != nil {
			s.renderErr(w, http.StatusBadRequest, "应用不存在", "请求授权的客户端 ID 未注册。")
			return
		}
	} else {
		clientID := strings.TrimSpace(q.Get("client_id"))
		redirectURI := strings.TrimSpace(q.Get("redirect_uri"))
		client, err = s.store.GetOAuthClient(clientID)
		if err != nil {
			s.renderErr(w, http.StatusBadRequest, "未知的 OAuth 应用", "client_id 未在 Vesper Auth 中注册。")
			return
		}
		if !IsRedirectURIAllowed(client, redirectURI) {
			s.renderErr(w, http.StatusBadRequest, "回调地址未授权", "redirect_uri 与该应用配置的允许回调列表不匹配。")
			return
		}

		responseType := strings.TrimSpace(q.Get("response_type"))
		state := q.Get("state")
		nonce := q.Get("nonce")
		scope := normalizeScopes(q.Get("scope"))
		challenge := strings.TrimSpace(q.Get("code_challenge"))
		challengeMethod := strings.TrimSpace(q.Get("code_challenge_method"))
		prompt, promptErr := parsePrompt(q.Get("prompt"))
		maxAge, maxAgeErr := parseMaxAge(q.Get("max_age"))

		if responseType != "code" {
			redirectAuthError(w, r, redirectURI, "unsupported_response_type", "only response_type=code is supported", state)
			return
		}
		if promptErr != nil {
			redirectAuthError(w, r, redirectURI, "invalid_request", promptErr.Error(), state)
			return
		}
		if maxAgeErr != nil {
			redirectAuthError(w, r, redirectURI, "invalid_request", maxAgeErr.Error(), state)
			return
		}
		if challenge != "" && challengeMethod != "S256" {
			redirectAuthError(w, r, redirectURI, "invalid_request", "only S256 code_challenge_method is supported", state)
			return
		}
		if (client.PKCERequired || client.IsPublic) && challenge == "" {
			redirectAuthError(w, r, redirectURI, "invalid_request", "code_challenge is required for this client", state)
			return
		}

		reqID, err := store.RandomHex(16)
		if err != nil {
			s.renderErr(w, http.StatusInternalServerError, "系统错误", "无法创建授权上下文。")
			return
		}
		req = &store.AuthRequest{
			ID:                  reqID,
			ClientID:            client.ID,
			RedirectURI:         redirectURI,
			ResponseType:        responseType,
			Scope:               scope,
			State:               state,
			Nonce:               nonce,
			CodeChallenge:       challenge,
			CodeChallengeMethod: challengeMethod,
			Prompt:              prompt,
			MaxAge:              maxAge,
			ExpiresAt:           time.Now().Add(10 * time.Minute).Unix(),
		}
		if err := s.store.CreateAuthRequest(req); err != nil {
			s.renderErr(w, http.StatusInternalServerError, "系统错误", "无法保存授权上下文。")
			return
		}
	}

	ses, user, err := s.sessions.Authenticate(r)
	if err != nil {
		if hasPrompt(req.Prompt, "none") {
			_ = s.store.DeleteAuthRequest(req.ID)
			redirectAuthError(w, r, req.RedirectURI, "login_required", "authentication required for prompt=none", req.State)
			return
		}
		http.Redirect(w, r, "/login?req="+url.QueryEscape(req.ID), http.StatusFound)
		return
	}

	// Check OIDC prompt=login or max_age expiration.
	needsReauth := hasPrompt(req.Prompt, "login")
	if !needsReauth && req.MaxAge >= 0 {
		if req.MaxAge == 0 || time.Now().Unix()-ses.CreatedAt > req.MaxAge {
			needsReauth = true
		}
	}
	if needsReauth {
		if hasPrompt(req.Prompt, "none") {
			_ = s.store.DeleteAuthRequest(req.ID)
			redirectAuthError(w, r, req.RedirectURI, "login_required", "session exceeds max_age", req.State)
			return
		}
		http.Redirect(w, r, "/login?req="+url.QueryEscape(req.ID)+"&reauth=1", http.StatusFound)
		return
	}

	forceConsent := hasPrompt(req.Prompt, "consent")
	if client.Trusted && !forceConsent {
		_ = s.store.DeleteAuthRequest(req.ID)
		s.issueCodeAndRedirect(w, r, client, user, ses, req)
		return
	}

	if hasPrompt(req.Prompt, "none") {
		_ = s.store.DeleteAuthRequest(req.ID)
		redirectAuthError(w, r, req.RedirectURI, "consent_required", "user consent required", req.State)
		return
	}

	if s.renderer == nil {
		s.renderErr(w, http.StatusInternalServerError, "模板未配置", "缺少授权确认页面渲染器。")
		return
	}

	callbackHost := req.RedirectURI
	if u, pErr := url.Parse(req.RedirectURI); pErr == nil && u.Host != "" {
		callbackHost = u.Scheme + "://" + u.Host
	}

	s.renderer.RenderConsent(w, ConsentViewData{
		ClientName:   client.Name,
		ClientID:     client.ID,
		CallbackHost: callbackHost,
		RedirectURI:  req.RedirectURI,
		Scopes:       describeScopes(req.Scope),
		ScopeRaw:     req.Scope,
		RequestID:    req.ID,
		CSRFToken:    s.sessions.CSRFToken(ses.ID),
		Username:     user.Username,
		Email:        user.Email,
	})
}

// AuthorizePost handles POST /oauth2/authorize when the user approves or denies consent.
func (s *Service) AuthorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderErr(w, http.StatusBadRequest, "请求格式错误", "无法解析表单数据。")
		return
	}

	ses, user, err := s.sessions.Authenticate(r)
	if err != nil {
		reqID := strings.TrimSpace(r.FormValue("req"))
		if reqID != "" {
			http.Redirect(w, r, "/login?req="+url.QueryEscape(reqID), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if !s.sessions.VerifyCSRF(ses.ID, r.FormValue("csrf_token")) {
		s.renderErr(w, http.StatusForbidden, "CSRF 校验失败", "请刷新授权页面后重试。")
		return
	}

	reqID := strings.TrimSpace(r.FormValue("req"))
	req, err := s.store.GetAuthRequest(reqID)
	if err != nil {
		s.renderErr(w, http.StatusBadRequest, "授权请求已过期", "请返回原应用重新发起授权。")
		return
	}
	client, err := s.store.GetOAuthClient(req.ClientID)
	if err != nil {
		s.renderErr(w, http.StatusBadRequest, "应用不存在", "未找到该应用配置。")
		return
	}
	_ = s.store.DeleteAuthRequest(req.ID)

	decision := strings.TrimSpace(r.FormValue("decision"))
	if decision != "approve" {
		_ = s.store.RecordAudit("oauth.authorize_denied", user.Username, s.clientIP(r), r.UserAgent(), client.Name, "user denied authorization", "failure")
		redirectAuthError(w, r, req.RedirectURI, "access_denied", "user denied authorization", req.State)
		return
	}

	s.issueCodeAndRedirect(w, r, client, user, ses, req)
}

func (s *Service) issueCodeAndRedirect(w http.ResponseWriter, r *http.Request, client *store.OAuthClient, user *store.AdminUser, ses *store.Session, req *store.AuthRequest) {
	rawCode, err := store.RandomHex(24)
	if err != nil {
		s.renderErr(w, http.StatusInternalServerError, "系统错误", "无法生成授权码。")
		return
	}

	ac := &store.AuthCode{
		CodeHash:            store.HashToken(rawCode),
		ClientID:            client.ID,
		UserID:              user.ID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		AuthTime:            ses.CreatedAt,
		ExpiresAt:           time.Now().Add(s.cfg.AuthCodeTTL).Unix(),
	}
	if err := s.store.CreateAuthCode(ac); err != nil {
		s.renderErr(w, http.StatusInternalServerError, "系统错误", "无法保存授权码。")
		return
	}

	_ = s.store.RecordAudit("oauth.authorize", user.Username, s.clientIP(r), r.UserAgent(), client.Name, fmt.Sprintf("scope=%s trusted=%t", req.Scope, client.Trusted), "success")

	target, err := url.Parse(req.RedirectURI)
	if err != nil {
		s.renderErr(w, http.StatusInternalServerError, "回调地址异常", "无法解析回调 URL。")
		return
	}
	qv := target.Query()
	qv.Set("code", rawCode)
	if req.State != "" {
		qv.Set("state", req.State)
	}
	target.RawQuery = qv.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// Token handles POST /oauth2/token for authorization_code and refresh_token grants.
func (s *Service) Token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	ip := s.clientIP(r)
	clientID, clientSecret, usedBasic := extractClientCredentials(r)
	rlKeys := []string{"token:ip:" + ip}
	if clientID != "" {
		rlKeys = append(rlKeys, "token:client:"+clientID)
	}
	if ok, wait := s.limiter.Check(rlKeys...); !ok {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())+1))
		writeOAuthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many failed token requests")
		return
	}

	if clientID == "" {
		s.limiter.RecordFailure(rlKeys...)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "missing client_id")
		return
	}

	client, err := s.store.GetOAuthClient(clientID)
	if err != nil {
		if locked, _ := s.limiter.RecordFailure(rlKeys...); locked && s.notifier != nil {
			s.notifier.Notify("oauth.token_rate_limited", "warning", clientID, ip, clientID, "repeated unknown client token attempts")
		}
		_ = s.store.RecordAudit("oauth.token", clientID, ip, r.UserAgent(), clientID, "unknown client", "failure")
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	if !client.IsPublic {
		if clientSecret == "" || !verifyClientSecret(clientSecret, client.SecretHash) {
			if locked, _ := s.limiter.RecordFailure(rlKeys...); locked && s.notifier != nil {
				s.notifier.Notify("oauth.token_rate_limited", "warning", client.Name, ip, client.ID, "repeated invalid client_secret attempts")
			}
			_ = s.store.RecordAudit("oauth.token", client.Name, ip, r.UserAgent(), client.ID, "invalid client secret", "failure")
			if usedBasic {
				w.Header().Set("WWW-Authenticate", `Basic realm="vesper-auth"`)
			}
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}
	}

	grantType := strings.TrimSpace(r.FormValue("grant_type"))
	switch grantType {
	case "authorization_code":
		s.handleAuthCodeGrant(w, r, client, ip, rlKeys)
	case "refresh_token":
		s.handleRefreshGrant(w, r, client, ip, rlKeys)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "supported grant_type values: authorization_code, refresh_token")
	}
}

func (s *Service) handleAuthCodeGrant(w http.ResponseWriter, r *http.Request, client *store.OAuthClient, ip string, rlKeys []string) {
	code := strings.TrimSpace(r.FormValue("code"))
	redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))
	codeVerifier := strings.TrimSpace(r.FormValue("code_verifier"))

	if code == "" || redirectURI == "" {
		s.limiter.RecordFailure(rlKeys...)
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code and redirect_uri are required")
		return
	}

	ac, err := s.store.ConsumeAuthCode(code)
	if err != nil {
		s.limiter.RecordFailure(rlKeys...)
		detail := "invalid or expired authorization code"
		if errors.Is(err, store.ErrCodeAlreadyUsed) {
			detail = "authorization code replay detected"
		}
		_ = s.store.RecordAudit("oauth.token", client.Name, ip, r.UserAgent(), client.ID, detail, "failure")
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", detail)
		return
	}

	if ac.ClientID != client.ID || ac.RedirectURI != redirectURI {
		s.limiter.RecordFailure(rlKeys...)
		_ = s.store.RecordAudit("oauth.token", client.Name, ip, r.UserAgent(), client.ID, "client_id or redirect_uri mismatch", "failure")
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id or redirect_uri mismatch")
		return
	}

	if ac.CodeChallenge != "" || client.PKCERequired || client.IsPublic {
		if !VerifyPKCE(ac.CodeChallenge, ac.CodeChallengeMethod, codeVerifier) || ac.CodeChallenge == "" {
			s.limiter.RecordFailure(rlKeys...)
			_ = s.store.RecordAudit("oauth.token", client.Name, ip, r.UserAgent(), client.ID, "PKCE verification failed", "failure")
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	}

	user, err := s.store.GetAdminByID(ac.UserID)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "user not found")
		return
	}

	s.limiter.Reset(rlKeys...)
	familyID, err := store.RandomHex(16)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to generate token family")
		return
	}

	var rawRefresh string
	if hasScope(ac.Scope, "offline_access") {
		rawRefresh, err = s.issueNewRefreshToken(familyID, client.ID, user.ID, ac.Scope, ac.AuthTime)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue refresh token")
			return
		}
	}

	s.writeTokenResponse(w, r, client, user, ac.Scope, ac.Nonce, ac.AuthTime, rawRefresh, "oauth.token_issued")
}

func (s *Service) handleRefreshGrant(w http.ResponseWriter, r *http.Request, client *store.OAuthClient, ip string, rlKeys []string) {
	rawRT := strings.TrimSpace(r.FormValue("refresh_token"))
	if rawRT == "" {
		s.limiter.RecordFailure(rlKeys...)
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	newRawRT, err := generateRefreshToken()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to generate refresh token")
		return
	}
	nextRec := &store.RefreshTokenRecord{
		TokenHash: store.HashToken(newRawRT),
		ExpiresAt: time.Now().Add(s.cfg.RefreshTokenTTL).Unix(),
	}

	oldRec, err := s.store.RotateRefreshToken(rawRT, client.ID, nextRec)
	if err != nil {
		s.limiter.RecordFailure(rlKeys...)
		if errors.Is(err, store.ErrTokenReused) {
			_ = s.store.RecordAudit("oauth.refresh_reuse", client.Name, ip, r.UserAgent(), client.ID, "refresh token reuse detected; family revoked", "failure")
			if s.notifier != nil {
				s.notifier.Notify("oauth.refresh_reuse", "critical", client.Name, ip, client.ID, "refresh token replay detected; entire token family revoked")
			}
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected")
			return
		}
		_ = s.store.RecordAudit("oauth.token_refresh", client.Name, ip, r.UserAgent(), client.ID, "invalid or expired refresh token", "failure")
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
		return
	}

	user, err := s.store.GetAdminByID(oldRec.UserID)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "user not found")
		return
	}

	s.limiter.Reset(rlKeys...)
	s.writeTokenResponse(w, r, client, user, oldRec.Scope, "", oldRec.AuthTime, newRawRT, "oauth.token_refreshed")
}

func (s *Service) writeTokenResponse(w http.ResponseWriter, r *http.Request, client *store.OAuthClient, user *store.AdminUser, scope, nonce string, authTime int64, rawRefresh, auditEvent string) {
	jti, err := store.RandomHex(16)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to generate jti")
		return
	}

	accessToken, expUnix, err := SignAccessToken(s.keys, s.cfg.Issuer, client.ID, jti, scope, user, s.cfg.AccessTokenTTL)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to sign access token")
		return
	}

	if err := s.store.CreateAccessToken(&store.AccessTokenRecord{
		JTI:       jti,
		ClientID:  client.ID,
		UserID:    user.ID,
		Scope:     scope,
		ExpiresAt: expUnix,
	}); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to persist access token")
		return
	}

	resp := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int64(s.cfg.AccessTokenTTL.Seconds()),
		"scope":        scope,
	}

	if hasScope(scope, "openid") {
		idToken, err := SignIDToken(s.keys, s.cfg.Issuer, client.ID, nonce, accessToken, authTime, user, s.cfg.IDTokenTTL)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to sign id token")
			return
		}
		resp["id_token"] = idToken
	}

	if rawRefresh != "" {
		resp["refresh_token"] = rawRefresh
	}

	_ = s.store.RecordAudit(auditEvent, user.Username, s.clientIP(r), r.UserAgent(), client.Name, "scope="+scope, "success")
	writeJSON(w, http.StatusOK, resp)
}

func (s *Service) issueNewRefreshToken(familyID, clientID, userID, scope string, authTime int64) (string, error) {
	raw, err := generateRefreshToken()
	if err != nil {
		return "", err
	}
	err = s.store.CreateRefreshToken(&store.RefreshTokenRecord{
		TokenHash: store.HashToken(raw),
		FamilyID:  familyID,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		AuthTime:  authTime,
		ExpiresAt: time.Now().Add(s.cfg.RefreshTokenTTL).Unix(),
	})
	if err != nil {
		return "", err
	}
	return raw, nil
}

func generateRefreshToken() (string, error) {
	rnd, err := store.RandomHex(32)
	if err != nil {
		return "", err
	}
	return "rt_" + rnd, nil
}

// UserInfo handles GET and POST /oauth2/userinfo.
func (s *Service) UserInfo(w http.ResponseWriter, r *http.Request) {
	rawToken := extractBearerToken(r)
	if rawToken == "" && r.Method == http.MethodPost {
		_ = r.ParseForm()
		rawToken = strings.TrimSpace(r.FormValue("access_token"))
	}
	if rawToken == "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="missing bearer token"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "missing bearer token")
		return
	}

	claims, err := VerifyAccessToken(s.keys, s.cfg.Issuer, rawToken)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="token verification failed"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired access token")
		return
	}

	active, err := s.store.IsAccessTokenActive(claims.ID)
	if err != nil || !active {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="token revoked or inactive"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "token revoked or expired")
		return
	}

	user, err := s.store.GetAdminByID(claims.Subject)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "subject not found")
		return
	}

	displayName := user.DisplayName
	if displayName == "" {
		displayName = user.Username
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":                user.ID,
		"name":               displayName,
		"preferred_username": user.Username,
		"email":              user.Email,
		"email_verified":     true,
		"role":               "admin",
	})
}

// Introspect handles POST /oauth2/introspect per RFC 7662.
func (s *Service) Introspect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	clientID, clientSecret, usedBasic := extractClientCredentials(r)
	if clientID == "" {
		if usedBasic {
			w.Header().Set("WWW-Authenticate", `Basic realm="vesper-auth"`)
		}
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication required")
		return
	}
	client, err := s.store.GetOAuthClient(clientID)
	if err != nil {
		if usedBasic {
			w.Header().Set("WWW-Authenticate", `Basic realm="vesper-auth"`)
		}
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}
	if !client.IsPublic && (clientSecret == "" || !verifyClientSecret(clientSecret, client.SecretHash)) {
		if usedBasic {
			w.Header().Set("WWW-Authenticate", `Basic realm="vesper-auth"`)
		}
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	rawToken := strings.TrimSpace(r.FormValue("token"))
	if rawToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token parameter is required")
		return
	}

	now := time.Now().Unix()

	// Check as Refresh Token if prefixed or matching DB.
	if strings.HasPrefix(rawToken, "rt_") {
		rec, err := s.store.GetRefreshTokenByRaw(rawToken)
		if err != nil || rec.Revoked || rec.Rotated || rec.ExpiresAt <= now {
			writeJSON(w, http.StatusOK, map[string]any{"active": false})
			return
		}
		user, uErr := s.store.GetAdminByID(rec.UserID)
		username := ""
		if uErr == nil {
			username = user.Username
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"active":     true,
			"token_type": "refresh_token",
			"client_id":  rec.ClientID,
			"sub":        rec.UserID,
			"username":   username,
			"scope":      rec.Scope,
			"exp":        rec.ExpiresAt,
			"iat":        rec.CreatedAt,
			"iss":        s.cfg.Issuer,
		})
		return
	}

	// Check as RS256 Access Token.
	claims, err := VerifyAccessToken(s.keys, s.cfg.Issuer, rawToken)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	rec, err := s.store.GetAccessTokenRecord(claims.ID)
	if err != nil || rec.Revoked || rec.ExpiresAt <= now {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	user, uErr := s.store.GetAdminByID(claims.Subject)
	username := ""
	if uErr == nil {
		username = user.Username
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active":     true,
		"token_type": "Bearer",
		"client_id":  claims.ClientID,
		"sub":        claims.Subject,
		"username":   username,
		"role":       claims.Role,
		"scope":      claims.Scope,
		"exp":        rec.ExpiresAt,
		"iat":        rec.CreatedAt,
		"iss":        s.cfg.Issuer,
		"jti":        claims.ID,
	})
}

// Revoke handles POST /oauth2/revoke per RFC 7009.
func (s *Service) Revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	clientID, clientSecret, _ := extractClientCredentials(r)
	if clientID != "" {
		client, err := s.store.GetOAuthClient(clientID)
		if err != nil {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
			return
		}
		if !client.IsPublic && (clientSecret == "" || !verifyClientSecret(clientSecret, client.SecretHash)) {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}
	}

	rawToken := strings.TrimSpace(r.FormValue("token"))
	if rawToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token parameter is required")
		return
	}

	revoked := false
	if ok, err := s.store.RevokeRefreshToken(rawToken, clientID); err == nil && ok {
		revoked = true
	}
	if !revoked {
		if claims, err := VerifyAccessToken(s.keys, s.cfg.Issuer, rawToken); err == nil {
			if clientID == "" || claims.ClientID == clientID {
				_ = s.store.RevokeAccessToken(claims.ID)
				revoked = true
			}
		}
	}

	if revoked {
		_ = s.store.RecordAudit("oauth.token_revoked", clientID, s.clientIP(r), r.UserAgent(), clientID, "token revoked via /oauth2/revoke", "success")
	}
	w.WriteHeader(http.StatusOK)
}

// Logout handles GET and POST /oauth2/logout (OIDC RP-Initiated Logout with anti-CSRF confirmation).
func (s *Service) Logout(w http.ResponseWriter, r *http.Request) {
	ses, user, sesErr := s.sessions.Authenticate(r)

	q := r.URL.Query()
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		for k, v := range r.Form {
			if _, exists := q[k]; !exists {
				q[k] = v
			}
		}
	}

	postLogoutURI := strings.TrimSpace(q.Get("post_logout_redirect_uri"))
	state := q.Get("state")
	clientID := strings.TrimSpace(q.Get("client_id"))
	idTokenHint := strings.TrimSpace(q.Get("id_token_hint"))
	csrfToken := strings.TrimSpace(q.Get("csrf_token"))

	hintValid := false
	if idTokenHint != "" {
		if claims, err := VerifyIDToken(s.keys, s.cfg.Issuer, idTokenHint, true); err == nil {
			hintValid = true
			if clientID == "" && len(claims.Audience) > 0 {
				clientID = claims.Audience[0]
			}
		}
	}

	// If the user is actively signed in and no verified id_token_hint was passed:
	// - On GET without client_id/post_logout_redirect_uri or without id_token_hint: require interactive confirmation
	//   unless post_logout_redirect_uri belongs to a registered client AND client_id matches a trusted client!
	// Wait: let's check OIDC RP-Initiated Logout:
	// - Trusted personal apps (like Nezha/Alist) might redirect to /oauth2/logout?client_id=...&post_logout_redirect_uri=...
	//   without id_token_hint, OR an attacker page might embed <img src="https://auth.starryheavens.uk/oauth2/logout">.
	// Requiring interactive confirmation on GET whenever hintValid == false (unless POST with valid csrf_token)
	// completely blocks <img src="..."> CSRF logout, while rendering a clean 1-click confirm card in the browser!
	if sesErr == nil && user != nil && !hintValid {
		if r.Method == http.MethodPost {
			if !s.sessions.VerifyCSRF(ses.ID, csrfToken) {
				s.renderErr(w, http.StatusForbidden, "CSRF 校验失败", "退出登录校验失败，请重试。")
				return
			}
		} else if s.renderer != nil {
			s.renderer.RenderLogoutConfirm(w, LogoutConfirmViewData{
				Username:              user.Username,
				Email:                 user.Email,
				ClientID:              clientID,
				PostLogoutRedirectURI: postLogoutURI,
				State:                 state,
				CSRFToken:             s.sessions.CSRFToken(ses.ID),
			})
			return
		}
	}

	s.sessions.Clear(w, r)
	if sesErr == nil && user != nil {
		_ = s.store.RecordAudit("auth.logout", user.Username, s.clientIP(r), r.UserAgent(), "session", "OIDC end_session logout", "success")
	}

	if postLogoutURI != "" && s.isPostLogoutURIAllowed(clientID, postLogoutURI) {
		u, err := url.Parse(postLogoutURI)
		if err == nil {
			if state != "" {
				qv := u.Query()
				qv.Set("state", state)
				u.RawQuery = qv.Encode()
			}
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}

	http.Redirect(w, r, "/login?logged_out=1", http.StatusFound)
}

func (s *Service) isPostLogoutURIAllowed(clientID, targetURI string) bool {
	target, err := url.Parse(targetURI)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return false
	}

	checkClient := func(c *store.OAuthClient) bool {
		for _, reg := range c.RedirectURIs {
			if reg == targetURI {
				return true
			}
			ru, err := url.Parse(reg)
			if err == nil && strings.EqualFold(ru.Scheme, target.Scheme) && strings.EqualFold(ru.Host, target.Host) {
				return true
			}
		}
		return false
	}

	if clientID != "" {
		c, err := s.store.GetOAuthClient(clientID)
		if err != nil {
			return false
		}
		return checkClient(c)
	}

	clients, err := s.store.ListOAuthClients()
	if err != nil {
		return false
	}
	for i := range clients {
		if checkClient(&clients[i]) {
			return true
		}
	}
	return false
}

func (s *Service) renderErr(w http.ResponseWriter, status int, title, message string) {
	if s.renderer != nil {
		s.renderer.RenderError(w, status, title, message)
		return
	}
	http.Error(w, template.HTMLEscapeString(title+": "+message), status)
}

func extractClientCredentials(r *http.Request) (clientID, clientSecret string, usedBasic bool) {
	if id, sec, ok := r.BasicAuth(); ok {
		if unescapedID, err := url.QueryUnescape(id); err == nil {
			id = unescapedID
		}
		if unescapedSec, err := url.QueryUnescape(sec); err == nil {
			sec = unescapedSec
		}
		return strings.TrimSpace(id), sec, true
	}
	return strings.TrimSpace(r.FormValue("client_id")), r.FormValue("client_secret"), false
}

func verifyClientSecret(rawSecret, storedHash string) bool {
	if storedHash == "" {
		return false
	}
	computed := store.HashToken(rawSecret)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(storedHash)) == 1
}

func extractBearerToken(r *http.Request) string {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authz) > 7 && strings.EqualFold(authz[:7], "Bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	return ""
}

// IsRedirectURIAllowed checks exact match against client.RedirectURIs, plus RFC 8252 Section 7.3
// dynamic loopback port matching for public native clients.
func IsRedirectURIAllowed(client *store.OAuthClient, candidate string) bool {
	if candidate == "" {
		return false
	}
	for _, allowed := range client.RedirectURIs {
		if allowed == candidate {
			return true
		}
	}
	if !client.IsPublic {
		return false
	}

	cu, err := url.Parse(candidate)
	if err != nil || !strings.EqualFold(cu.Scheme, "http") || cu.User != nil || cu.Fragment != "" {
		return false
	}
	cHost := cu.Hostname()
	if !isLoopbackHost(cHost) {
		return false
	}
	if portStr := cu.Port(); portStr != "" {
		p, pErr := strconv.Atoi(portStr)
		if pErr != nil || p < 1 || p > 65535 {
			return false
		}
	}

	for _, allowed := range client.RedirectURIs {
		au, aErr := url.Parse(allowed)
		if aErr != nil || !strings.EqualFold(au.Scheme, "http") {
			continue
		}
		// Dynamic port allowed when the registered loopback URI omits an explicit port.
		if au.Port() == "" && strings.EqualFold(au.Hostname(), cHost) && au.Path == cu.Path {
			return true
		}
	}
	return false
}

func isLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost")
}

func parsePrompt(raw string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) == 0 {
		return "", nil
	}
	seen := make(map[string]bool, len(fields))
	var out []string
	for _, f := range fields {
		switch f {
		case "none", "login", "consent", "select_account":
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		default:
			return "", fmt.Errorf("unsupported prompt value %q", f)
		}
	}
	if seen["none"] && len(out) > 1 {
		return "", errors.New("prompt=none cannot be combined with other values")
	}
	return strings.Join(out, " "), nil
}

func parseMaxAge(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return -1, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return -1, errors.New("invalid max_age parameter")
	}
	return n, nil
}

func hasPrompt(promptList, target string) bool {
	for _, f := range strings.Fields(promptList) {
		if f == target {
			return true
		}
	}
	return false
}

func normalizeScopes(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "openid"
	}
	seen := make(map[string]struct{}, len(fields))
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if _, ok := seen[f]; !ok {
			seen[f] = struct{}{}
			out = append(out, f)
		}
	}
	return strings.Join(out, " ")
}

func hasScope(scopeList, target string) bool {
	for _, f := range strings.Fields(scopeList) {
		if f == target {
			return true
		}
	}
	return false
}

func describeScopes(scopeList string) []ScopeInfo {
	descriptions := map[string]string{
		"openid":         "验证你的唯一身份标识 (sub)",
		"profile":        "读取你的用户名与显示名称",
		"email":          "读取你的电子邮箱地址",
		"offline_access": "保持长期登录状态并刷新访问令牌",
	}
	fields := strings.Fields(scopeList)
	out := make([]ScopeInfo, 0, len(fields))
	for _, f := range fields {
		desc, ok := descriptions[f]
		if !ok {
			desc = "访问附加权限范围: " + f
		}
		out = append(out, ScopeInfo{Name: f, Description: desc})
	}
	return out
}

func redirectAuthError(w http.ResponseWriter, r *http.Request, redirectURI, errCode, errDesc, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, errCode+": "+errDesc, http.StatusBadRequest)
		return
	}
	qv := u.Query()
	qv.Set("error", errCode)
	if errDesc != "" {
		qv.Set("error_description", errDesc)
	}
	if state != "" {
		qv.Set("state", state)
	}
	u.RawQuery = qv.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func writeOAuthError(w http.ResponseWriter, status int, errCode, description string) {
	writeJSON(w, status, map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
