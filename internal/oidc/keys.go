package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/YN1753/vesper-auth/internal/store"
)

// RSAKey holds an RSA signing keypair and its JWK identifier.
type RSAKey struct {
	KID        string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Active     bool
}

// JWK represents an RFC 7517 RSA public key entry.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// KeySet manages RSA signing keys persisted in SQLite.
type KeySet struct {
	active *RSAKey
	keys   []*RSAKey
	byKID  map[string]*RSAKey
}

// LoadOrCreateKeySet loads persisted RSA keys from st or generates a new 2048-bit key on first boot.
func LoadOrCreateKeySet(st *store.Store) (*KeySet, error) {
	stored, err := st.ListSigningKeys()
	if err != nil {
		return nil, fmt.Errorf("list signing keys: %w", err)
	}

	ks := &KeySet{
		byKID: make(map[string]*RSAKey),
	}

	if len(stored) == 0 {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate 2048-bit RSA key: %w", err)
		}
		kid, err := computeKID(&priv.PublicKey)
		if err != nil {
			return nil, err
		}
		pemBytes, err := encodePKCS8PrivatePEM(priv)
		if err != nil {
			return nil, err
		}
		rec := &store.SigningKey{
			KID:        kid,
			Algorithm:  "RS256",
			PrivatePEM: string(pemBytes),
			Active:     true,
			CreatedAt:  time.Now().Unix(),
		}
		if err := st.SaveSigningKey(rec); err != nil {
			return nil, fmt.Errorf("persist signing key: %w", err)
		}
		rk := &RSAKey{
			KID:        kid,
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
			Active:     true,
		}
		ks.active = rk
		ks.keys = []*RSAKey{rk}
		ks.byKID[kid] = rk
		return ks, nil
	}

	for _, rec := range stored {
		priv, err := parsePrivatePEM([]byte(rec.PrivatePEM))
		if err != nil {
			return nil, fmt.Errorf("parse signing key %s: %w", rec.KID, err)
		}
		rk := &RSAKey{
			KID:        rec.KID,
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
			Active:     rec.Active,
		}
		ks.keys = append(ks.keys, rk)
		ks.byKID[rk.KID] = rk
		if rk.Active && ks.active == nil {
			ks.active = rk
		}
	}
	if ks.active == nil && len(ks.keys) > 0 {
		ks.active = ks.keys[0]
	}
	if ks.active == nil {
		return nil, errors.New("no signing keys available")
	}
	return ks, nil
}

// Active returns the currently active RSA signing key.
func (ks *KeySet) Active() *RSAKey {
	return ks.active
}

// Lookup finds a signing key by its kid header value.
func (ks *KeySet) Lookup(kid string) (*RSAKey, bool) {
	k, ok := ks.byKID[kid]
	return k, ok
}

// JWKS returns the public JWK Set structure for /.well-known/jwks.json.
func (ks *KeySet) JWKS() map[string][]JWK {
	jwks := make([]JWK, 0, len(ks.keys))
	for _, k := range ks.keys {
		jwks = append(jwks, JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: k.KID,
			N:   base64.RawURLEncoding.EncodeToString(k.PublicKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.PublicKey.E)).Bytes()),
		})
	}
	return map[string][]JWK{"keys": jwks}
}

func computeKID(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:16]), nil
}

func encodePKCS8PrivatePEM(priv *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

func parsePrivatePEM(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
		return rsaKey, nil
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
