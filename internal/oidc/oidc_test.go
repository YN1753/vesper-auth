package oidc

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/YN1753/vesper-auth/internal/store"
)

func TestKeySetPersistenceAndJWKS(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st1, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store 1: %v", err)
	}
	ks1, err := LoadOrCreateKeySet(st1)
	if err != nil {
		t.Fatalf("LoadOrCreateKeySet 1: %v", err)
	}
	kid1 := ks1.Active().KID
	jwks1 := ks1.JWKS()["keys"]
	if len(jwks1) != 1 || jwks1[0].Alg != "RS256" || jwks1[0].Kty != "RSA" {
		t.Fatalf("unexpected JWKS: %+v", jwks1)
	}
	_ = st1.Close()

	st2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store 2: %v", err)
	}
	defer st2.Close()

	ks2, err := LoadOrCreateKeySet(st2)
	if err != nil {
		t.Fatalf("LoadOrCreateKeySet 2: %v", err)
	}
	if ks2.Active().KID != kid1 {
		t.Fatalf("KID changed across restart: got %s want %s", ks2.Active().KID, kid1)
	}
	jwks2 := ks2.JWKS()["keys"]
	if jwks2[0].N != jwks1[0].N || jwks2[0].E != jwks1[0].E {
		t.Fatal("JWK modulus/exponent mismatch across restart")
	}
}

func TestKeySetZeroDowntimeRotation(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	ks, err := LoadOrCreateKeySet(st)
	if err != nil {
		t.Fatalf("LoadOrCreateKeySet: %v", err)
	}
	kid1 := ks.Active().KID

	user := &store.AdminUser{ID: "usr_1", Username: "starry", Email: "starry@starryheavens.uk"}
	issuer := "https://auth.starryheavens.uk"

	// Sign access token with key 1 before rotation.
	tokBefore, _, err := SignAccessToken(ks, issuer, "nezha", "jti_old", "openid", user, time.Hour)
	if err != nil {
		t.Fatalf("SignAccessToken before rotate: %v", err)
	}

	// Rotate to key 2 retaining up to 2 keys.
	rk2, err := ks.Rotate(st, 2)
	if err != nil {
		t.Fatalf("Rotate 1: %v", err)
	}
	if rk2.KID == kid1 || ks.Active().KID != rk2.KID {
		t.Fatal("expected active KID to switch to rotated key")
	}
	if len(ks.JWKS()["keys"]) != 2 {
		t.Fatalf("expected 2 keys in JWKS during grace period, got %d", len(ks.JWKS()["keys"]))
	}

	// Pre-rotation token must still verify seamlessly!
	if _, err := VerifyAccessToken(ks, issuer, tokBefore); err != nil {
		t.Fatalf("token signed prior to rotation failed verification: %v", err)
	}

	// Rotate again with retainCount=2 -> key 1 is pruned, key 2 and key 3 remain.
	rk3, err := ks.Rotate(st, 2)
	if err != nil {
		t.Fatalf("Rotate 2: %v", err)
	}
	if len(ks.JWKS()["keys"]) != 2 {
		t.Fatalf("expected retainCount=2 to prune oldest key, got %d", len(ks.JWKS()["keys"]))
	}
	if _, ok := ks.Lookup(kid1); ok {
		t.Fatal("expected oldest key kid1 to be pruned after exceeding retainCount=2")
	}
	if _, ok := ks.Lookup(rk2.KID); !ok || ks.Active().KID != rk3.KID {
		t.Fatal("expected rk2 retained and rk3 active")
	}
}

func TestRS256IDTokenSigningAndJWKVerification(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	ks, err := LoadOrCreateKeySet(st)
	if err != nil {
		t.Fatalf("LoadOrCreateKeySet: %v", err)
	}

	user := &store.AdminUser{
		ID:          "usr_01",
		Username:    "starry",
		Email:       "starry@starryheavens.uk",
		DisplayName: "Starry",
	}
	issuer := "https://auth.starryheavens.uk"
	clientID := "va_nezha"

	at, _, err := SignAccessToken(ks, issuer, clientID, "jti_123", "openid profile email", user, time.Hour)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	idt, err := SignIDToken(ks, issuer, clientID, "nonce-xyz", at, 1700000000, user, time.Hour)
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}

	jwk := ks.JWKS()["keys"][0]
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatalf("decode JWK N: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		t.Fatalf("decode JWK E: %v", err)
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	claims := &IDTokenClaims{}
	parsed, err := jwt.ParseWithClaims(idt, claims, func(tok *jwt.Token) (any, error) {
		if tok.Header["kid"] != jwk.Kid {
			t.Fatalf("unexpected kid: %v", tok.Header["kid"])
		}
		return pub, nil
	}, jwt.WithIssuer(issuer), jwt.WithAudience(clientID))
	if err != nil || !parsed.Valid {
		t.Fatalf("failed to verify ID token with JWK: %v", err)
	}

	if claims.Subject != user.ID || claims.PreferredUsername != user.Username || claims.Email != user.Email || claims.Role != "admin" || claims.Nonce != "nonce-xyz" {
		t.Fatalf("unexpected ID token claims: %+v", claims)
	}
	if claims.AtHash == "" {
		t.Fatal("expected non-empty at_hash claim")
	}
}

func TestPKCES256Verification(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := ComputeS256Challenge(verifier)

	if !VerifyPKCE(challenge, "S256", verifier) {
		t.Fatal("expected valid PKCE S256 verification to succeed")
	}
	if VerifyPKCE(challenge, "S256", "wrong-verifier-with-sufficient-length-1234567890") {
		t.Fatal("expected mismatched code_verifier to fail")
	}
	if VerifyPKCE(challenge, "plain", verifier) {
		t.Fatal("expected plain code_challenge_method to fail")
	}
	if VerifyPKCE(challenge, "S256", "too-short") {
		t.Fatal("expected short code_verifier to fail")
	}
}

func TestLoopbackDynamicPortMatching(t *testing.T) {
	pubClient := &store.OAuthClient{
		ID:           "bothub-cli",
		IsPublic:     true,
		RedirectURIs: []string{"http://127.0.0.1/oauth/callback", "http://[::1]/oauth/callback"},
	}
	confClient := &store.OAuthClient{
		ID:           "web-app",
		IsPublic:     false,
		RedirectURIs: []string{"http://127.0.0.1/oauth/callback"},
	}

	if !IsRedirectURIAllowed(pubClient, "http://127.0.0.1:53812/oauth/callback") {
		t.Fatal("expected dynamic port on 127.0.0.1 for public client to be allowed")
	}
	if !IsRedirectURIAllowed(pubClient, "http://[::1]:49152/oauth/callback") {
		t.Fatal("expected dynamic port on [::1] for public client to be allowed")
	}
	if IsRedirectURIAllowed(pubClient, "http://127.0.0.1:53812/evil/path") {
		t.Fatal("expected path mismatch on loopback to be rejected")
	}
	if IsRedirectURIAllowed(confClient, "http://127.0.0.1:53812/oauth/callback") {
		t.Fatal("expected confidential client to require exact port match")
	}
}
