package server

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/YN1753/vesper-auth/internal/auth"
	"github.com/YN1753/vesper-auth/internal/config"
	"github.com/YN1753/vesper-auth/internal/oidc"
	"github.com/YN1753/vesper-auth/internal/store"
)

func newTestServer(t *testing.T) (*Server, *store.Store, *httptest.Server) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	var ts *httptest.Server
	cfg := &config.Config{
		Issuer:               "https://auth.starryheavens.uk",
		ListenAddr:           "127.0.0.1:0",
		DBPath:               ":memory:",
		AdminUsername:        "starry",
		AdminEmail:           "starry@starryheavens.uk",
		RPID:                 "auth.starryheavens.uk",
		RPDisplayName:        "Vesper Auth",
		RPOrigins:            []string{"https://auth.starryheavens.uk"},
		SessionTTL:           time.Hour,
		AccessTokenTTL:       time.Hour,
		IDTokenTTL:           time.Hour,
		RefreshTokenTTL:      24 * time.Hour,
		AuthCodeTTL:          5 * time.Minute,
		CookieSecure:         false, // httptest uses plain HTTP
		TrustProxy:           true,
		RateLimitMaxAttempts: 3,
		RateLimitWindow:      5 * time.Minute,
		RateLimitLockout:     5 * time.Minute,
	}

	srv, err := New(cfg, st)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts = httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, st, ts
}

func newNoRedirectClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func bootstrapTestAdmin(t *testing.T, st *store.Store) *store.AdminUser {
	t.Helper()
	hash, err := auth.HashPassword("VesperMasterPass123!")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user, err := st.CreateAdmin("starry", "starry@starryheavens.uk", "Starry", hash)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	return user
}

func TestDiscoveryAndJWKS(t *testing.T) {
	_, _, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if doc["issuer"] != "https://auth.starryheavens.uk" {
		t.Fatalf("unexpected issuer: %v", doc["issuer"])
	}
	if doc["jwks_uri"] != "https://auth.starryheavens.uk/.well-known/jwks.json" {
		t.Fatalf("unexpected jwks_uri: %v", doc["jwks_uri"])
	}
	if doc["token_endpoint"] != "https://auth.starryheavens.uk/oauth2/token" {
		t.Fatalf("unexpected token_endpoint: %v", doc["token_endpoint"])
	}

	jwksResp, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer jwksResp.Body.Close()
	if jwksResp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status = %d", jwksResp.StatusCode)
	}
	var jwks struct {
		Keys []oidc.JWK `json:"keys"`
	}
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(jwks.Keys) != 1 || jwks.Keys[0].Alg != "RS256" || jwks.Keys[0].N == "" {
		t.Fatalf("unexpected jwks payload: %+v", jwks)
	}
}

func TestSingleAdminSetupLockdownAndLoginRateLimit(t *testing.T) {
	_, _, ts := newTestServer(t)
	client := newNoRedirectClient(t)

	// First setup succeeds.
	setupBody := `{"username":"starry","email":"starry@starryheavens.uk","display_name":"Starry","password":"StrongPass12345"}`
	resp, err := client.Post(ts.URL+"/api/auth/setup", "application/json", strings.NewReader(setupBody))
	if err != nil {
		t.Fatalf("setup post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 on initial setup, got %d", resp.StatusCode)
	}

	// Second setup attempt must be forbidden (no public registration).
	resp2, err := http.Post(ts.URL+"/api/auth/setup", "application/json", strings.NewReader(setupBody))
	if err != nil {
		t.Fatalf("second setup post: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on second setup, got %d", resp2.StatusCode)
	}

	// Trigger rate limit (maxAttempts = 3).
	badClient := newNoRedirectClient(t)
	for i := 0; i < 3; i++ {
		r, err := badClient.Post(ts.URL+"/api/auth/login", "application/json",
			strings.NewReader(`{"identifier":"starry","password":"wrong-password"}`))
		if err != nil {
			t.Fatalf("login attempt %d: %v", i, err)
		}
		r.Body.Close()
		if i < 2 && r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d expected 401, got %d", i, r.StatusCode)
		}
		if i == 2 && r.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("attempt %d expected 429, got %d", i, r.StatusCode)
		}
	}
}

func TestFullAuthorizationCodePKCEAndRefreshRotationFlow(t *testing.T) {
	_, st, ts := newTestServer(t)
	user := bootstrapTestAdmin(t, st)

	// Register a trusted Public PKCE client (simulating BotHub Android).
	redirectURI := "uk.starryheavens.bothub://oauth/callback"
	pubClient, err := st.CreateOAuthClient("va_bothub_android", "BotHub Android", "", "", []string{redirectURI}, true, true, true)
	if err != nil {
		t.Fatalf("create public client: %v", err)
	}

	hc := newNoRedirectClient(t)
	verifier := "VesperAuth-PKCE-Verifier-Example-0123456789abcdef"
	challenge := oidc.ComputeS256Challenge(verifier)

	// 1. Start /oauth2/authorize while unauthenticated -> should redirect to /login?req=...
	authURL := ts.URL + "/oauth2/authorize?" + url.Values{
		"client_id":             {pubClient.ID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email offline_access"},
		"state":                 {"state-123"},
		"nonce":                 {"nonce-abc"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	authResp, err := hc.Get(authURL)
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 to /login, got %d", authResp.StatusCode)
	}
	loc := authResp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/login?req=") {
		t.Fatalf("expected redirect to /login?req=..., got %q", loc)
	}
	reqID := strings.TrimPrefix(loc, "/login?req=")

	// 2. Log in via /api/auth/login carrying reqID.
	loginPayload, _ := json.Marshal(map[string]string{
		"identifier": "starry",
		"password":   "VesperMasterPass123!",
		"req":        reqID,
	})
	loginResp, err := hc.Post(ts.URL+"/api/auth/login", "application/json", bytes.NewReader(loginPayload))
	if err != nil {
		t.Fatalf("POST login: %v", err)
	}
	var loginResult map[string]string
	_ = json.NewDecoder(loginResp.Body).Decode(&loginResult)
	loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 login, got %d", loginResp.StatusCode)
	}
	if !strings.HasPrefix(loginResult["redirect"], "/oauth2/authorize?req=") {
		t.Fatalf("unexpected login redirect: %q", loginResult["redirect"])
	}

	// 3. Follow redirect back to /oauth2/authorize -> trusted client silently issues code & redirects.
	cbResp, err := hc.Get(ts.URL + loginResult["redirect"])
	if err != nil {
		t.Fatalf("GET authorize after login: %v", err)
	}
	cbResp.Body.Close()
	if cbResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 callback redirect, got %d", cbResp.StatusCode)
	}
	cbLoc, err := url.Parse(cbResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse callback location: %v", err)
	}
	if cbLoc.Query().Get("state") != "state-123" {
		t.Fatalf("state mismatch: %q", cbLoc.Query().Get("state"))
	}
	code := cbLoc.Query().Get("code")
	if code == "" {
		t.Fatal("missing authorization code")
	}

	// 4. Verify PKCE failure with wrong code_verifier does NOT consume/succeed (Wait: code is single-use, so test PKCE failure separately, here use valid verifier).
	tokenResp, err := http.PostForm(ts.URL+"/oauth2/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {pubClient.ID},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	var tokData map[string]any
	_ = json.NewDecoder(tokenResp.Body).Decode(&tokData)
	tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange failed (%d): %v", tokenResp.StatusCode, tokData)
	}

	accessToken, _ := tokData["access_token"].(string)
	idToken, _ := tokData["id_token"].(string)
	refreshToken1, _ := tokData["refresh_token"].(string)
	if accessToken == "" || idToken == "" || refreshToken1 == "" {
		t.Fatalf("missing expected tokens: %+v", tokData)
	}

	// Replay of same authorization code must fail.
	replayResp, err := http.PostForm(ts.URL+"/oauth2/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {pubClient.ID},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
	if err != nil {
		t.Fatalf("replay POST token: %v", err)
	}
	replayResp.Body.Close()
	if replayResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on code replay, got %d", replayResp.StatusCode)
	}

	// 5. Verify RS256 ID Token against JWKS endpoint.
	jwksResp, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	var jwks struct {
		Keys []oidc.JWK `json:"keys"`
	}
	_ = json.NewDecoder(jwksResp.Body).Decode(&jwks)
	jwksResp.Body.Close()
	nBytes, _ := base64.RawURLEncoding.DecodeString(jwks.Keys[0].N)
	eBytes, _ := base64.RawURLEncoding.DecodeString(jwks.Keys[0].E)
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	idClaims := &oidc.IDTokenClaims{}
	parsedID, err := jwt.ParseWithClaims(idToken, idClaims, func(t *jwt.Token) (any, error) {
		return pubKey, nil
	}, jwt.WithIssuer("https://auth.starryheavens.uk"), jwt.WithAudience(pubClient.ID))
	if err != nil || !parsedID.Valid {
		t.Fatalf("verify id_token failed: %v", err)
	}
	if idClaims.Subject != user.ID || idClaims.Nonce != "nonce-abc" || idClaims.PreferredUsername != "starry" || idClaims.Role != "admin" {
		t.Fatalf("unexpected id_token claims: %+v", idClaims)
	}

	// 6. Call /oauth2/userinfo with access_token.
	uiReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/oauth2/userinfo", nil)
	uiReq.Header.Set("Authorization", "Bearer "+accessToken)
	uiResp, err := http.DefaultClient.Do(uiReq)
	if err != nil {
		t.Fatalf("GET userinfo: %v", err)
	}
	var uiData map[string]any
	_ = json.NewDecoder(uiResp.Body).Decode(&uiData)
	uiResp.Body.Close()
	if uiResp.StatusCode != http.StatusOK || uiData["sub"] != user.ID || uiData["email"] != "starry@starryheavens.uk" {
		t.Fatalf("unexpected userinfo (%d): %+v", uiResp.StatusCode, uiData)
	}

	// 7. Rotate refresh_token -> get refreshToken2.
	rtResp, err := http.PostForm(ts.URL+"/oauth2/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {pubClient.ID},
		"refresh_token": {refreshToken1},
	})
	if err != nil {
		t.Fatalf("POST refresh: %v", err)
	}
	var rtData map[string]any
	_ = json.NewDecoder(rtResp.Body).Decode(&rtData)
	rtResp.Body.Close()
	if rtResp.StatusCode != http.StatusOK {
		t.Fatalf("refresh failed (%d): %+v", rtResp.StatusCode, rtData)
	}
	refreshToken2, _ := rtData["refresh_token"].(string)
	if refreshToken2 == "" || refreshToken2 == refreshToken1 {
		t.Fatal("expected rotated refresh_token to differ from old token")
	}

	// 8. Reuse detection: replaying refreshToken1 must fail AND revoke refreshToken2!
	reuseResp, err := http.PostForm(ts.URL+"/oauth2/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {pubClient.ID},
		"refresh_token": {refreshToken1},
	})
	if err != nil {
		t.Fatalf("reuse POST refresh: %v", err)
	}
	reuseResp.Body.Close()
	if reuseResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on refresh token reuse, got %d", reuseResp.StatusCode)
	}

	revokedFamilyResp, err := http.PostForm(ts.URL+"/oauth2/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {pubClient.ID},
		"refresh_token": {refreshToken2},
	})
	if err != nil {
		t.Fatalf("post-reuse refreshToken2 check: %v", err)
	}
	revokedFamilyResp.Body.Close()
	if revokedFamilyResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected family revocation after reuse, got %d", revokedFamilyResp.StatusCode)
	}

	// 9. Revoke access token via /oauth2/revoke and verify /oauth2/userinfo rejects it.
	revResp, err := http.PostForm(ts.URL+"/oauth2/revoke", url.Values{
		"client_id": {pubClient.ID},
		"token":     {accessToken},
	})
	if err != nil {
		t.Fatalf("POST revoke: %v", err)
	}
	revResp.Body.Close()
	if revResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on revoke, got %d", revResp.StatusCode)
	}

	uiReq2, _ := http.NewRequest(http.MethodGet, ts.URL+"/oauth2/userinfo", nil)
	uiReq2.Header.Set("Authorization", "Bearer "+accessToken)
	uiResp2, err := http.DefaultClient.Do(uiReq2)
	if err != nil {
		t.Fatalf("GET userinfo after revoke: %v", err)
	}
	uiResp2.Body.Close()
	if uiResp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after token revoke, got %d", uiResp2.StatusCode)
	}
}

func TestConfidentialClientAuthConsentAndLogout(t *testing.T) {
	_, st, ts := newTestServer(t)
	bootstrapTestAdmin(t, st)

	plainSecret := "vs_test_secret_123456"
	redirectURI := "https://dash.starryheavens.uk/oauth2/callback"
	client, err := st.CreateOAuthClient("va_nezha", "哪吒监控", "", store.HashToken(plainSecret), []string{redirectURI}, false, false, false)
	if err != nil {
		t.Fatalf("create confidential client: %v", err)
	}

	hc := newNoRedirectClient(t)
	// Authenticate browser session first.
	lResp, err := hc.Post(ts.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"identifier":"starry","password":"VesperMasterPass123!"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	lResp.Body.Close()
	if lResp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", lResp.StatusCode)
	}

	// Untrusted client -> GET /oauth2/authorize returns consent HTML (200 OK).
	authURL := ts.URL + "/oauth2/authorize?" + url.Values{
		"client_id":     {client.ID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {"st_nezha"},
	}.Encode()

	consentResp, err := hc.Get(authURL)
	if err != nil {
		t.Fatalf("GET consent: %v", err)
	}
	var bodyBuf bytes.Buffer
	_, _ = bodyBuf.ReadFrom(consentResp.Body)
	consentResp.Body.Close()
	if consentResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 consent page, got %d", consentResp.StatusCode)
	}

	htmlBody := bodyBuf.String()
	reqMatch := regexp.MustCompile(`name="req"\s+value="([^"]+)"`).FindStringSubmatch(htmlBody)
	csrfMatch := regexp.MustCompile(`name="csrf_token"\s+value="([^"]+)"`).FindStringSubmatch(htmlBody)
	if len(reqMatch) != 2 || len(csrfMatch) != 2 {
		t.Fatalf("failed to extract req/csrf_token from consent page")
	}

	// Approve consent via POST /oauth2/authorize.
	postResp, err := hc.PostForm(ts.URL+"/oauth2/authorize", url.Values{
		"req":        {reqMatch[1]},
		"csrf_token": {csrfMatch[1]},
		"decision":   {"approve"},
	})
	if err != nil {
		t.Fatalf("POST approve: %v", err)
	}
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 redirect after approve, got %d", postResp.StatusCode)
	}
	cbURL, _ := url.Parse(postResp.Header.Get("Location"))
	code := cbURL.Query().Get("code")
	if code == "" {
		t.Fatal("missing code after consent approval")
	}

	// Exchange code using HTTP Basic Auth (client_secret_basic).
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}
	tokReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth2/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokReq.SetBasicAuth(client.ID, plainSecret)

	tokResp, err := http.DefaultClient.Do(tokReq)
	if err != nil {
		t.Fatalf("POST token basic auth: %v", err)
	}
	var tokOut map[string]any
	_ = json.NewDecoder(tokResp.Body).Decode(&tokOut)
	tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK || tokOut["id_token"] == "" {
		t.Fatalf("basic auth token exchange failed (%d): %+v", tokResp.StatusCode, tokOut)
	}

	// Test /oauth2/logout with post_logout_redirect_uri matching registered origin.
	logoutURL := ts.URL + "/oauth2/logout?" + url.Values{
		"client_id":                {client.ID},
		"post_logout_redirect_uri": {"https://dash.starryheavens.uk/"},
		"state":                    {"bye"},
	}.Encode()
	logoutResp, err := hc.Get(logoutURL)
	if err != nil {
		t.Fatalf("GET logout: %v", err)
	}
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusFound || logoutResp.Header.Get("Location") != "https://dash.starryheavens.uk/?state=bye" {
		t.Fatalf("unexpected logout redirect: status=%d loc=%q", logoutResp.StatusCode, logoutResp.Header.Get("Location"))
	}

	// Verify session cookie was invalidated by /oauth2/logout.
	adminResp, err := hc.Get(ts.URL + "/api/admin/overview")
	if err != nil {
		t.Fatalf("GET overview after logout: %v", err)
	}
	adminResp.Body.Close()
	if adminResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d", adminResp.StatusCode)
	}
}

func TestAdminClientCRUDAndSessionAuditAPIs(t *testing.T) {
	_, st, ts := newTestServer(t)
	bootstrapTestAdmin(t, st)

	hc1 := newNoRedirectClient(t)
	hc2 := newNoRedirectClient(t)

	// Log in with two separate browser clients so there are 2 active sessions.
	for _, hc := range []*http.Client{hc1, hc2} {
		r, err := hc.Post(ts.URL+"/api/auth/login", "application/json",
			strings.NewReader(`{"identifier":"starry","password":"VesperMasterPass123!"}`))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("login status = %d", r.StatusCode)
		}
	}

	// Extract CSRF token from GET / HTML.
	homeResp, err := hc1.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(homeResp.Body)
	homeResp.Body.Close()
	if homeResp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d", homeResp.StatusCode)
	}
	csrfMatch := regexp.MustCompile(`csrfToken:\s*"([^"]+)"`).FindStringSubmatch(buf.String())
	if len(csrfMatch) != 2 {
		t.Fatalf("failed to extract csrfToken from admin HTML")
	}
	csrf := csrfMatch[1]

	// Create client via API.
	createReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/clients", strings.NewReader(`{
		"name":"Alist 网盘",
		"description":"pan.starryheavens.uk",
		"redirect_uris":["https://pan.starryheavens.uk/api/auth/sso_callback"],
		"trusted":true,
		"pkce_required":false,
		"is_public":false
	}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("X-CSRF-Token", csrf)
	cResp, err := hc1.Do(createReq)
	if err != nil {
		t.Fatalf("POST /api/admin/clients: %v", err)
	}
	var createOut struct {
		Client       store.OAuthClient `json:"client"`
		ClientSecret string            `json:"client_secret"`
	}
	_ = json.NewDecoder(cResp.Body).Decode(&createOut)
	cResp.Body.Close()
	if cResp.StatusCode != http.StatusCreated || createOut.Client.ID == "" || createOut.ClientSecret == "" {
		t.Fatalf("unexpected create client response (%d): %+v", cResp.StatusCode, createOut)
	}

	// Rotate client secret.
	rotReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/clients/"+createOut.Client.ID+"/rotate", nil)
	rotReq.Header.Set("X-CSRF-Token", csrf)
	rotResp, err := hc1.Do(rotReq)
	if err != nil {
		t.Fatalf("rotate secret: %v", err)
	}
	var rotOut map[string]string
	_ = json.NewDecoder(rotResp.Body).Decode(&rotOut)
	rotResp.Body.Close()
	if rotResp.StatusCode != http.StatusOK || rotOut["client_secret"] == "" || rotOut["client_secret"] == createOut.ClientSecret {
		t.Fatalf("unexpected rotate response (%d): %+v", rotResp.StatusCode, rotOut)
	}

	// Revoke other sessions (should kick hc2 while keeping hc1).
	revOthersReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/admin/sessions/others", nil)
	revOthersReq.Header.Set("X-CSRF-Token", csrf)
	revOthersResp, err := hc1.Do(revOthersReq)
	if err != nil {
		t.Fatalf("DELETE /api/admin/sessions/others: %v", err)
	}
	revOthersResp.Body.Close()
	if revOthersResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on revoke others, got %d", revOthersResp.StatusCode)
	}

	hc2Check, err := hc2.Get(ts.URL + "/api/admin/overview")
	if err != nil {
		t.Fatalf("hc2 overview: %v", err)
	}
	hc2Check.Body.Close()
	if hc2Check.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected hc2 session to be kicked (401), got %d", hc2Check.StatusCode)
	}

	// Verify audit logs recorded events.
	auditResp, err := hc1.Get(ts.URL + "/api/admin/audit?limit=10&offset=0")
	if err != nil {
		t.Fatalf("GET audit: %v", err)
	}
	var auditOut struct {
		Logs  []store.AuditLog `json:"logs"`
		Total int              `json:"total"`
	}
	_ = json.NewDecoder(auditResp.Body).Decode(&auditOut)
	auditResp.Body.Close()
	if auditResp.StatusCode != http.StatusOK || auditOut.Total < 4 || len(auditOut.Logs) == 0 {
		t.Fatalf("unexpected audit response (%d): total=%d len=%d", auditResp.StatusCode, auditOut.Total, len(auditOut.Logs))
	}
}

func TestReverseProxyHTTPSCookieAndClientIP(t *testing.T) {
	srv, st, ts := newTestServer(t)
	bootstrapTestAdmin(t, st)

	// Simulate HTTP Nginx -> 127.0.0.1:8090 behind Cloudflare (r.TLS == nil, X-Forwarded-Proto: https).
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/login",
		strings.NewReader(`{"identifier":"starry","password":"VesperMasterPass123!"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("CF-Connecting-IP", "203.0.113.42")
	req.Header.Set("X-Real-IP", "172.68.10.5")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 login, got %d", resp.StatusCode)
	}

	var sesCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookieName {
			sesCookie = c
		}
	}
	if sesCookie == nil {
		t.Fatal("missing session cookie")
	}
	if !sesCookie.Secure || !sesCookie.HttpOnly || sesCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected cookie attributes: Secure=%v HttpOnly=%v SameSite=%v", sesCookie.Secure, sesCookie.HttpOnly, sesCookie.SameSite)
	}

	// Verify CF-Connecting-IP was recorded on the active session instead of proxy IP.
	user, err := st.GetAdmin()
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}
	sessions, err := st.ListActiveSessions(user.ID, "")
	if err != nil || len(sessions) != 1 {
		t.Fatalf("list sessions: %v len=%d", err, len(sessions))
	}
	if sessions[0].IP != "203.0.113.42" {
		t.Fatalf("expected CF-Connecting-IP 203.0.113.42, got %q", sessions[0].IP)
	}

	// Verify WebAuthn RP config remains bound to HTTPS AUTH_ISSUER.
	if srv.cfg.RPID != "auth.starryheavens.uk" || len(srv.cfg.RPOrigins) != 1 || srv.cfg.RPOrigins[0] != "https://auth.starryheavens.uk" {
		t.Fatalf("unexpected RP config: RPID=%q origins=%v", srv.cfg.RPID, srv.cfg.RPOrigins)
	}
}


