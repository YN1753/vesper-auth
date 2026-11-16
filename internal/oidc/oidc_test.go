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

	// Reopen database and verify exact same RSA keypair is loaded.
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

	// Reconstruct RSA public key purely from JWKS JSON representation (like a relying party).
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
