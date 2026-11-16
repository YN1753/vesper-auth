package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/YN1753/vesper-auth/internal/store"
)

// IDTokenClaims defines standard OIDC ID Token claims plus Vesper role.
type IDTokenClaims struct {
	Nonce             string `json:"nonce,omitempty"`
	AtHash            string `json:"at_hash,omitempty"`
	AuthTime          int64  `json:"auth_time,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Role              string `json:"role,omitempty"`
	jwt.RegisteredClaims
}

// AccessTokenClaims defines RS256 access token claims.
type AccessTokenClaims struct {
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id"`
	Role     string `json:"role"`
	TokenUse string `json:"token_use"`
	jwt.RegisteredClaims
}

// SignAccessToken signs an RS256 JWT access token.
func SignAccessToken(ks *KeySet, issuer, clientID, jti, scope string, user *store.AdminUser, ttl time.Duration) (string, int64, error) {
	key := ks.Active()
	now := time.Now()
	exp := now.Add(ttl)

	claims := AccessTokenClaims{
		Scope:    scope,
		ClientID: clientID,
		Role:     "admin",
		TokenUse: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   user.ID,
			Audience:  jwt.ClaimStrings{clientID, issuer},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = key.KID
	signed, err := tok.SignedString(key.PrivateKey)
	if err != nil {
		return "", 0, err
	}
	return signed, exp.Unix(), nil
}

// SignIDToken signs an RS256 OIDC ID Token including standard profile/email/role claims and at_hash.
func SignIDToken(ks *KeySet, issuer, clientID, nonce, accessToken string, authTime int64, user *store.AdminUser, ttl time.Duration) (string, error) {
	key := ks.Active()
	now := time.Now()
	exp := now.Add(ttl)

	displayName := user.DisplayName
	if displayName == "" {
		displayName = user.Username
	}

	claims := IDTokenClaims{
		Nonce:             nonce,
		AtHash:            computeAtHash(accessToken),
		AuthTime:          authTime,
		Name:              displayName,
		PreferredUsername: user.Username,
		Email:             user.Email,
		EmailVerified:     true,
		Role:              "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   user.ID,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = key.KID
	return tok.SignedString(key.PrivateKey)
}

// VerifyAccessToken validates signature, issuer, expiration, and token_use of an RS256 access token.
func VerifyAccessToken(ks *KeySet, issuer, rawToken string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	tok, err := jwt.ParseWithClaims(rawToken, claims, keyFuncFor(ks),
		jwt.WithIssuer(issuer),
		jwt.WithValidMethods([]string{"RS256"}),
	)
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}
	if claims.TokenUse != "access" {
		return nil, errors.New("unexpected token_use")
	}
	return claims, nil
}

// VerifyIDToken validates signature and issuer of an RS256 ID Token.
func VerifyIDToken(ks *KeySet, issuer, rawToken string, ignoreExpiry bool) (*IDTokenClaims, error) {
	claims := &IDTokenClaims{}
	opts := []jwt.ParserOption{
		jwt.WithIssuer(issuer),
		jwt.WithValidMethods([]string{"RS256"}),
	}
	if ignoreExpiry {
		opts = append(opts, jwt.WithoutClaimsValidation())
	}
	tok, err := jwt.ParseWithClaims(rawToken, claims, keyFuncFor(ks), opts...)
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("invalid id token: %w", err)
	}
	if claims.Issuer != issuer {
		return nil, errors.New("issuer mismatch")
	}
	return claims, nil
}

func keyFuncFor(ks *KeySet) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return ks.Active().PublicKey, nil
		}
		k, ok := ks.Lookup(kid)
		if !ok {
			return nil, fmt.Errorf("unknown signing key %q", kid)
		}
		return k.PublicKey, nil
	}
}

// computeAtHash implements OIDC Core 3.1.3.6 for RS256 (left half of SHA-256 of access_token).
func computeAtHash(accessToken string) string {
	if accessToken == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}
