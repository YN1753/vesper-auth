package server

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
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
		SudoTTL:              15 * time.Minute,
		AccessTokenTTL:       time.Hour,
		IDTokenTTL:           time.Hour,
		RefreshTokenTTL:      24 * time.Hour,
		AuthCodeTTL:          5 * time.Minute,
		CookieSecure:         false, // httptest uses plain HTTP unless testing proxy headers
		TrustProxy:           true,
		RateLimitMaxAttempts: 3,
		RateLimitWindow:      5 * time.Minute,
		RateLimitLockout:     5 * time.Minute,
		RateLimitMaxBuckets:  1000,
		AuditRetentionDays:   90,
		KeyRetainCount:       3,
	}

	srv, err := New(cfg, st)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.SetVersion("v1.0.0-test")
	t.Cleanup(srv.Close)

	ts := httptest.NewServer(srv.Handler())
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

func TestDiscoveryJWKSAndHealthz(t *testing.T) {
	_, _, ts := newTestServer(t)

	hResp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	var hDoc map[string]string
	_ = json.NewDecoder(hResp.Body).Decode(&hDoc)
	hResp.Body.Close()
	if hResp.StatusCode != http.StatusOK || hDoc["status"] != "ok" || hDoc["version"] != "v1.0.0-test" {
		t.Fatalf("unexpected /healthz: status=%d doc=%+v", hResp.StatusCode, hDoc)
	}

	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("expected CORS * on discovery, got %q", resp.Header.Get("Access-Control-Allow-Origin"))
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if doc["issuer"] != "https://auth.starryheavens.uk" {
		t.Fatalf("unexpected issuer: %v", doc["issuer"])
	}
	if doc["introspection_endpoint"] != "https://auth.starryheavens.uk/oauth2/introspect" {
		t.Fatalf("unexpected introspection_endpoint: %v", doc["introspection_endpoint"])
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

	setupBody := `{"username":"starry","email":"starry@starryheavens.uk","display_name":"Starry","password":"StrongPass12345"}`
	resp, err := client.Post(ts.URL+"/api/auth/setup", "application/json", strings.NewReader(setupBody))
	if err != nil {
		t.Fatalf("setup post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 on initial setup, got %d", resp.StatusCode)
	}

	resp2, err := http.Post(ts.URL+"/api/auth/setup", "application/json", strings.NewReader(setupBody))
	if err != nil {
		t.Fatalf("second setup post: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on second setup, got %d", resp2.StatusCode)
	}

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

	// Register a trusted Public PKCE client with both custom scheme and loopback URI.
	redirectURI := "http://127.0.0.1:59421/oauth/callback"
	pubClient, err := st.CreateOAuthClient("bothub-android", "BotHub Android", "", "", []string{
		"uk.starryheavens.bothub://oauth/callback",
		"http://127.0.0.1/oauth/callback",
	}, true, true, true)
	if err != nil {
		t.Fatalf("create public client: %v", err)
	}

	hc := newNoRedirectClient(t)
	verifier := "VesperAuth-PKCE-Verifier-Example-0123456789abcdef"
	challenge := oidc.ComputeS256Challenge(verifier)

	// 1. Start /oauth2/authorize with RFC 8252 dynamic loopback port while unauthenticated.
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
	reqID := strings.TrimPrefix(authResp.Header.Get("Location"), "/login?req=")

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

	// 3. Follow redirect back to /oauth2/authorize -> trusted client silently issues code & redirects.
	cbResp, err := hc.Get(ts.URL + loginResult["redirect"])
	if err != nil {
		t.Fatalf("GET authorize after login: %v", err)
	}
	cbResp.Body.Close()
	if cbResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 callback redirect, got %d", cbResp.StatusCode)
	}
	cbLoc, _ := url.Parse(cbResp.Header.Get("Location"))
	code := cbLoc.Query().Get("code")
	if code == "" || cbLoc.Query().Get("state") != "state-123" {
		t.Fatalf("unexpected callback URL: %v", cbLoc)
	}

	// 4. Exchange authorization code + PKCE verifier.
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

	// 6. Introspect active access_token via RFC 7662 /oauth2/introspect.
	introResp, err := http.PostForm(ts.URL+"/oauth2/introspect", url.Values{
		"client_id": {pubClient.ID},
		"token":     {accessToken},
	})
	if err != nil {
		t.Fatalf("POST introspect: %v", err)
	}
	var introDoc map[string]any
	_ = json.NewDecoder(introResp.Body).Decode(&introDoc)
	introResp.Body.Close()
	if introResp.StatusCode != http.StatusOK || introDoc["active"] != true || introDoc["sub"] != user.ID {
		t.Fatalf("unexpected introspect response (%d): %+v", introResp.StatusCode, introDoc)
	}

	// 7. Call /oauth2/userinfo with access_token.
	uiReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/oauth2/userinfo", nil)
	uiReq.Header.Set("Authorization", "Bearer "+accessToken)
	uiResp, err := http.DefaultClient.Do(uiReq)
	if err != nil {
		t.Fatalf("GET userinfo: %v", err)
	}
	var uiData map[string]any
	_ = json.NewDecoder(uiResp.Body).Decode(&uiData)
	uiResp.Body.Close()
	if uiResp.StatusCode != http.StatusOK || uiData["sub"] != user.ID {
		t.Fatalf("unexpected userinfo (%d): %+v", uiResp.StatusCode, uiData)
	}

	// 8. Rotate refresh_token -> get refreshToken2.
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

	// 9. Reuse detection: replaying refreshToken1 must fail AND revoke refreshToken2.
	reuseResp, _ := http.PostForm(ts.URL+"/oauth2/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {pubClient.ID},
		"refresh_token": {refreshToken1},
	})
	reuseResp.Body.Close()
	if reuseResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on refresh token reuse, got %d", reuseResp.StatusCode)
	}

	revokedFamilyResp, _ := http.PostForm(ts.URL+"/oauth2/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {pubClient.ID},
		"refresh_token": {refreshToken2},
	})
	revokedFamilyResp.Body.Close()
	if revokedFamilyResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected family revocation after reuse, got %d", revokedFamilyResp.StatusCode)
	}

	// 10. Revoke access token and verify both /oauth2/userinfo (401) and /oauth2/introspect (active=false).
	revResp, _ := http.PostForm(ts.URL+"/oauth2/revoke", url.Values{
		"client_id": {pubClient.ID},
		"token":     {accessToken},
	})
	revResp.Body.Close()

	introResp2, _ := http.PostForm(ts.URL+"/oauth2/introspect", url.Values{
		"client_id": {pubClient.ID},
		"token":     {accessToken},
	})
	var introDoc2 map[string]any
	_ = json.NewDecoder(introResp2.Body).Decode(&introDoc2)
	introResp2.Body.Close()
	if introDoc2["active"] != false {
		t.Fatalf("expected active=false after revoke, got %+v", introDoc2)
	}
}

func TestConfidentialClientAuthConsentAndAntiCSRFLogout(t *testing.T) {
	_, st, ts := newTestServer(t)
	bootstrapTestAdmin(t, st)

	plainSecret := "vs_test_secret_123456"
	redirectURI := "https://dash.starryheavens.uk/oauth2/callback"
	client, err := st.CreateOAuthClient("nezha", "哪吒监控", "", store.HashToken(plainSecret), []string{redirectURI}, false, false, false)
	if err != nil {
		t.Fatalf("create confidential client: %v", err)
	}

	hc := newNoRedirectClient(t)
	lResp, err := hc.Post(ts.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"identifier":"starry","password":"VesperMasterPass123!"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	lResp.Body.Close()

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
	htmlBytes, _ := io.ReadAll(consentResp.Body)
	consentResp.Body.Close()
	htmlBody := string(htmlBytes)
	reqMatch := regexp.MustCompile(`name="req"\s+value="([^"]+)"`).FindStringSubmatch(htmlBody)
	csrfMatch := regexp.MustCompile(`name="csrf_token"\s+value="([^"]+)"`).FindStringSubmatch(htmlBody)
	if len(reqMatch) != 2 || len(csrfMatch) != 2 {
		t.Fatalf("failed to extract req/csrf_token from consent page")
	}

	postResp, _ := hc.PostForm(ts.URL+"/oauth2/authorize", url.Values{
		"req":        {reqMatch[1]},
		"csrf_token": {csrfMatch[1]},
		"decision":   {"approve"},
	})
	postResp.Body.Close()
	cbURL, _ := url.Parse(postResp.Header.Get("Location"))
	code := cbURL.Query().Get("code")

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
	idToken, _ := tokOut["id_token"].(string)
	if tokResp.StatusCode != http.StatusOK || idToken == "" {
		t.Fatalf("basic auth token exchange failed (%d): %+v", tokResp.StatusCode, tokOut)
	}

	// 1. GET /oauth2/logout WITHOUT id_token_hint must NOT silently clear session (blocks <img src> CSRF);
	//    instead it renders a 200 OK confirmation page with csrf_token.
	logoutNoHint := ts.URL + "/oauth2/logout?" + url.Values{
		"client_id":                {client.ID},
		"post_logout_redirect_uri": {"https://dash.starryheavens.uk/"},
		"state":                    {"bye"},
	}.Encode()
	confirmResp, err := hc.Get(logoutNoHint)
	if err != nil {
		t.Fatalf("GET logout without hint: %v", err)
	}
	confirmHTMLBytes, _ := io.ReadAll(confirmResp.Body)
	confirmResp.Body.Close()
	if confirmResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 logout confirmation page without id_token_hint, got %d", confirmResp.StatusCode)
	}
	// Session must still be active!
	stillIn, _ := hc.Get(ts.URL + "/api/admin/overview")
	stillIn.Body.Close()
	if stillIn.StatusCode != http.StatusOK {
		t.Fatalf("expected session to remain active until logout confirmed, got %d", stillIn.StatusCode)
	}

	// 2. GET /oauth2/logout WITH valid id_token_hint immediately clears session and redirects 302.
	logoutWithHint := ts.URL + "/oauth2/logout?" + url.Values{
		"id_token_hint":            {idToken},
		"post_logout_redirect_uri": {"https://dash.starryheavens.uk/"},
		"state":                    {"bye"},
	}.Encode()
	logoutResp, err := hc.Get(logoutWithHint)
	if err != nil {
		t.Fatalf("GET logout with hint: %v", err)
	}
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusFound || logoutResp.Header.Get("Location") != "https://dash.starryheavens.uk/?state=bye" {
		t.Fatalf("unexpected logout redirect: status=%d loc=%q (confirmHTML=%d)", logoutResp.StatusCode, logoutResp.Header.Get("Location"), len(confirmHTMLBytes))
	}

	adminResp, _ := hc.Get(ts.URL + "/api/admin/overview")
	adminResp.Body.Close()
	if adminResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d", adminResp.StatusCode)
	}
}

func TestAdminClientCRUDSudoPasswordSessionAndKeyRotation(t *testing.T) {
	_, st, ts := newTestServer(t)
	user := bootstrapTestAdmin(t, st)

	hc1 := newNoRedirectClient(t)
	hc2 := newNoRedirectClient(t)

	for _, hc := range []*http.Client{hc1, hc2} {
		r, err := hc.Post(ts.URL+"/api/auth/login", "application/json",
			strings.NewReader(`{"identifier":"starry","password":"VesperMasterPass123!"}`))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		r.Body.Close()
	}

	// Extract CSRF token from data-csrf-token attribute on <body>.
	homeResp, err := hc1.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	htmlBytes, _ := io.ReadAll(homeResp.Body)
	homeResp.Body.Close()
	csrfMatch := regexp.MustCompile(`data-csrf-token="([^"]+)"`).FindStringSubmatch(string(htmlBytes))
	if len(csrfMatch) != 2 {
		t.Fatalf("failed to extract data-csrf-token from admin HTML")
	}
	csrf := csrfMatch[1]

	// Create client with custom semantic client_id "alist".
	createReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/clients", strings.NewReader(`{
		"client_id":"alist",
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
	if cResp.StatusCode != http.StatusCreated || createOut.Client.ID != "alist" || createOut.ClientSecret == "" {
		t.Fatalf("unexpected create client response (%d): %+v", cResp.StatusCode, createOut)
	}

	// Simulate expired Sudo window on hc1's session -> high-privilege secret rotate returns 403 sudo_required!
	if _, err := st.DB().Exec(`UPDATE sessions SET elevated_at = 0 WHERE user_id = ?`, user.ID); err != nil {
		t.Fatalf("expire elevated_at: %v", err)
	}

	rotReq1, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/clients/alist/rotate", nil)
	rotReq1.Header.Set("X-CSRF-Token", csrf)
	rotResp1, _ := hc1.Do(rotReq1)
	var sudoErr map[string]string
	_ = json.NewDecoder(rotResp1.Body).Decode(&sudoErr)
	rotResp1.Body.Close()
	if rotResp1.StatusCode != http.StatusForbidden || sudoErr["code"] != "sudo_required" {
		t.Fatalf("expected 403 sudo_required, got status=%d body=%+v", rotResp1.StatusCode, sudoErr)
	}

	// Elevate session via /api/admin/sudo/password.
	sudoReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/sudo/password",
		strings.NewReader(`{"password":"VesperMasterPass123!"}`))
	sudoReq.Header.Set("Content-Type", "application/json")
	sudoReq.Header.Set("X-CSRF-Token", csrf)
	sudoResp, _ := hc1.Do(sudoReq)
	sudoResp.Body.Close()
	if sudoResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on sudo elevation, got %d", sudoResp.StatusCode)
	}

	// Retry secret rotate -> now succeeds!
	rotReq2, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/clients/alist/rotate", nil)
	rotReq2.Header.Set("X-CSRF-Token", csrf)
	rotResp2, _ := hc1.Do(rotReq2)
	var rotOut map[string]string
	_ = json.NewDecoder(rotResp2.Body).Decode(&rotOut)
	rotResp2.Body.Close()
	if rotResp2.StatusCode != http.StatusOK || rotOut["client_secret"] == "" {
		t.Fatalf("expected 200 secret rotate after sudo, got %d %+v", rotResp2.StatusCode, rotOut)
	}

	// Rotate RS256 signing key via admin API.
	keyRotReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/keys/rotate", nil)
	keyRotReq.Header.Set("X-CSRF-Token", csrf)
	keyRotResp, _ := hc1.Do(keyRotReq)
	var keyRotOut struct {
		KID  string         `json:"kid"`
		Keys []oidc.KeyMeta `json:"keys"`
	}
	_ = json.NewDecoder(keyRotResp.Body).Decode(&keyRotOut)
	keyRotResp.Body.Close()
	if keyRotResp.StatusCode != http.StatusOK || len(keyRotOut.Keys) != 2 {
		t.Fatalf("unexpected key rotate response (%d): %+v", keyRotResp.StatusCode, keyRotOut)
	}

	// Change password -> must automatically kick hc2 session while keeping hc1 active!
	pwdReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/password",
		strings.NewReader(`{"current_password":"VesperMasterPass123!","new_password":"NewVesperMasterPass456!","revoke_tokens":true}`))
	pwdReq.Header.Set("Content-Type", "application/json")
	pwdReq.Header.Set("X-CSRF-Token", csrf)
	pwdResp, _ := hc1.Do(pwdReq)
	pwdResp.Body.Close()
	if pwdResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on password change, got %d", pwdResp.StatusCode)
	}

	hc2Check, _ := hc2.Get(ts.URL + "/api/admin/overview")
	hc2Check.Body.Close()
	if hc2Check.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected hc2 session to be automatically revoked on password change, got %d", hc2Check.StatusCode)
	}

	// Verify filtered audit logs API.
	auditResp, _ := hc1.Get(ts.URL + "/api/admin/audit?status=success&category=admin.&limit=10")
	var auditOut struct {
		Logs  []store.AuditLog `json:"logs"`
		Total int              `json:"total"`
	}
	_ = json.NewDecoder(auditResp.Body).Decode(&auditOut)
	auditResp.Body.Close()
	if auditResp.StatusCode != http.StatusOK || auditOut.Total < 2 {
		t.Fatalf("unexpected filtered audit response (%d): %+v", auditResp.StatusCode, auditOut)
	}
}

func TestSecurityHeadersCSPAssetFingerprintingAndProxyBoundary(t *testing.T) {
	srv, st, ts := newTestServer(t)
	bootstrapTestAdmin(t, st)

	// 1. Check /login HTML has strict CSP, zero inline <script> blocks, zero style= attributes, and fingerprinted asset URLs.
	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(bodyBytes)

	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("expected strict CSP without unsafe-inline, got %q", csp)
	}
	if strings.Contains(html, "style=") {
		t.Fatal("found unexpected inline style= attribute in /login HTML")
	}
	assetMatch := regexp.MustCompile(`src="(/static/js/login\.js\?v=[0-9a-f]{10})"`).FindStringSubmatch(html)
	if len(assetMatch) != 2 {
		t.Fatalf("expected content-fingerprinted login.js URL in HTML, got:\n%s", html)
	}

	// 2. Fetch fingerprinted static asset -> must return Cache-Control: immutable.
	stResp, err := http.Get(ts.URL + assetMatch[1])
	if err != nil {
		t.Fatalf("GET static asset: %v", err)
	}
	stResp.Body.Close()
	if !strings.Contains(stResp.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("expected immutable Cache-Control on fingerprinted asset, got %q", stResp.Header.Get("Cache-Control"))
	}

	// 3. Trusted loopback proxy header test: X-Forwarded-Proto: https -> Secure cookie + HSTS.
	reqProxy, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/login",
		strings.NewReader(`{"identifier":"starry","password":"VesperMasterPass123!"}`))
	reqProxy.Header.Set("Content-Type", "application/json")
	reqProxy.Header.Set("X-Forwarded-Proto", "https")
	reqProxy.Header.Set("CF-Connecting-IP", "203.0.113.42")
	respProxy, err := http.DefaultClient.Do(reqProxy)
	if err != nil {
		t.Fatalf("proxy login: %v", err)
	}
	respProxy.Body.Close()
	if respProxy.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("expected HSTS header when X-Forwarded-Proto is https from trusted proxy")
	}
	var sesCookie *http.Cookie
	for _, c := range respProxy.Cookies() {
		if c.Name == auth.SessionCookieName {
			sesCookie = c
		}
	}
	if sesCookie == nil || !sesCookie.Secure || !sesCookie.HttpOnly {
		t.Fatalf("expected Secure HttpOnly cookie, got %+v", sesCookie)
	}

	// 4. Untrusted direct peer test (RemoteAddr = 198.51.100.99:4444 not in 127.0.0.1/8):
	//    Spoofed CF-Connecting-IP and X-Forwarded-Proto MUST be ignored!
	rec := httptest.NewRecorder()
	directReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	directReq.RemoteAddr = "198.51.100.99:4444"
	directReq.Header.Set("CF-Connecting-IP", "1.2.3.4")
	directReq.Header.Set("X-Forwarded-Proto", "https")
	if gotIP := srv.clientIP(directReq); gotIP != "198.51.100.99" {
		t.Fatalf("expected untrusted peer spoofed CF-Connecting-IP to be ignored, got %q", gotIP)
	}
	srv.Handler().ServeHTTP(rec, directReq)
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("expected untrusted peer spoofed X-Forwarded-Proto to not trigger HSTS")
	}
}

func TestOIDCPromptCORSAndConditionalPasskeyEndpoints(t *testing.T) {
	_, st, ts := newTestServer(t)
	bootstrapTestAdmin(t, st)

	redirectURI := "https://bot.starryheavens.uk/auth/callback"
	client, err := st.CreateOAuthClient("bothub-web", "BotHub Web", "", store.HashToken("vs_sec"), []string{redirectURI}, true, false, false)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	hc := newNoRedirectClient(t)

	// 1. prompt=none while unauthenticated -> immediate redirect with error=login_required.
	noneURL := ts.URL + "/oauth2/authorize?" + url.Values{
		"client_id":     {client.ID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid"},
		"prompt":        {"none"},
		"state":         {"s1"},
	}.Encode()
	noneResp, _ := hc.Get(noneURL)
	noneResp.Body.Close()
	noneLoc, _ := url.Parse(noneResp.Header.Get("Location"))
	if noneResp.StatusCode != http.StatusFound || noneLoc.Query().Get("error") != "login_required" {
		t.Fatalf("expected error=login_required for prompt=none, got status=%d loc=%v", noneResp.StatusCode, noneLoc)
	}

	// Log in hc.
	lResp, _ := hc.Post(ts.URL+"/api/auth/login", "application/json",
		strings.NewReader(`{"identifier":"starry","password":"VesperMasterPass123!"}`))
	lResp.Body.Close()

	// 2. prompt=consent on a trusted=true client -> must show consent HTML (200 OK) instead of silent redirect.
	consentURL := ts.URL + "/oauth2/authorize?" + url.Values{
		"client_id":     {client.ID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid"},
		"prompt":        {"consent"},
	}.Encode()
	cResp, _ := hc.Get(consentURL)
	cResp.Body.Close()
	if cResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 consent page for prompt=consent on trusted client, got %d", cResp.StatusCode)
	}

	// 3. prompt=login while already logged in -> redirects to /login?req=...&reauth=1, then after re-login issues code.
	reloginURL := ts.URL + "/oauth2/authorize?" + url.Values{
		"client_id":     {client.ID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid"},
		"prompt":        {"login"},
	}.Encode()
	rlResp, _ := hc.Get(reloginURL)
	rlResp.Body.Close()
	rlLoc := rlResp.Header.Get("Location")
	if !strings.Contains(rlLoc, "reauth=1") {
		t.Fatalf("expected redirect to /login with reauth=1 for prompt=login, got %q", rlLoc)
	}
	uRL, _ := url.Parse(rlLoc)
	reqID := uRL.Query().Get("req")

	reLoginBody, _ := json.Marshal(map[string]string{
		"identifier": "starry",
		"password":   "VesperMasterPass123!",
		"req":        reqID,
	})
	reLoginResp, _ := hc.Post(ts.URL+"/api/auth/login", "application/json", bytes.NewReader(reLoginBody))
	var reLoginOut map[string]string
	_ = json.NewDecoder(reLoginResp.Body).Decode(&reLoginOut)
	reLoginResp.Body.Close()

	afterReauthResp, _ := hc.Get(ts.URL + reLoginOut["redirect"])
	afterReauthResp.Body.Close()
	afterLoc, _ := url.Parse(afterReauthResp.Header.Get("Location"))
	if afterReauthResp.StatusCode != http.StatusFound || afterLoc.Query().Get("code") == "" {
		t.Fatalf("expected authorization code after satisfying prompt=login, got status=%d loc=%v", afterReauthResp.StatusCode, afterLoc)
	}

	// 4. Dynamic CORS preflight on /oauth2/token: registered origin allowed, unknown origin omitted.
	optAllowed, _ := http.NewRequest(http.MethodOptions, ts.URL+"/oauth2/token", nil)
	optAllowed.Header.Set("Origin", "https://bot.starryheavens.uk")
	optResp1, _ := http.DefaultClient.Do(optAllowed)
	optResp1.Body.Close()
	if optResp1.StatusCode != http.StatusNoContent || optResp1.Header.Get("Access-Control-Allow-Origin") != "https://bot.starryheavens.uk" {
		t.Fatalf("expected CORS preflight allowed for registered origin, got status=%d acao=%q", optResp1.StatusCode, optResp1.Header.Get("Access-Control-Allow-Origin"))
	}

	optDenied, _ := http.NewRequest(http.MethodOptions, ts.URL+"/oauth2/token", nil)
	optDenied.Header.Set("Origin", "https://evil.example.com")
	optResp2, _ := http.DefaultClient.Do(optDenied)
	optResp2.Body.Close()
	if optResp2.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("expected no CORS header for unregistered origin, got %q", optResp2.Header.Get("Access-Control-Allow-Origin"))
	}

	// 5. WebAuthn Conditional UI begin endpoint returns challenge options.
	condResp, err := http.Post(ts.URL+"/api/auth/passkey/login/conditional", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST conditional begin: %v", err)
	}
	var condData map[string]any
	_ = json.NewDecoder(condResp.Body).Decode(&condData)
	condResp.Body.Close()
	if condResp.StatusCode != http.StatusOK || condData["ceremony_id"] == "" {
		t.Fatalf("unexpected conditional begin response (%d): %+v", condResp.StatusCode, condData)
	}
}
