package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// IsValidCodeVerifier validates RFC 7636 §4.1 syntax (43-128 unreserved URI characters).
func IsValidCodeVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for i := 0; i < len(verifier); i++ {
		c := verifier[i]
		isAlpha := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		isDigit := c >= '0' && c <= '9'
		isUnreserved := c == '-' || c == '.' || c == '_' || c == '~'
		if !isAlpha && !isDigit && !isUnreserved {
			return false
		}
	}
	return true
}

// ComputeS256Challenge computes BASE64URL-ENCODE(SHA256(ASCII(code_verifier))).
func ComputeS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyPKCE validates code_verifier against the stored S256 code_challenge.
func VerifyPKCE(codeChallenge, method, codeVerifier string) bool {
	if codeChallenge == "" {
		return true
	}
	if method != "S256" {
		return false
	}
	if !IsValidCodeVerifier(codeVerifier) {
		return false
	}
	computed := ComputeS256Challenge(codeVerifier)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) == 1
}
