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
	"sync"
	"time"

	"github.com/YN1753/vesper-auth/internal/store"
)

// RSAKey holds an RSA signing keypair and its JWK metadata.
type RSAKey struct {
	KID        string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Active     bool
	CreatedAt  int64
}

// KeyMeta exposes public metadata of a persisted signing key for admin inspection.
type KeyMeta struct {
	KID       string `json:"kid"`
	Algorithm string `json:"algorithm"`
	Active    bool   `json:"active"`
	CreatedAt int64  `json:"created_at"`
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

// KeySet manages RSA signing keys persisted in SQLite with thread-safe rotation support.
type KeySet struct {
	mu     sync.RWMutex
	active *RSAKey
	keys   []*RSAKey
	byKID  map[string]*RSAKey
}

// LoadOrCreateKeySet loads persisted RSA keys from st or generates a new 2048-bit key on first boot.
func LoadOrCreateKeySet(st *store.Store) (*KeySet, error) {
	ks := &KeySet{}
	if err := ks.reload(st); err != nil {
		return nil, err
	}
	return ks, nil
}

func (ks *KeySet) reload(st *store.Store) error {
	stored, err := st.ListSigningKeys()
	if err != nil {
		return fmt.Errorf("list signing keys: %w", err)
	}

	if len(stored) == 0 {
		rk, rec, err := generateNewRSAKey()
		if err != nil {
			return err
		}
		if err := st.SaveSigningKey(rec); err != nil {
			return fmt.Errorf("persist signing key: %w", err)
		}
		ks.mu.Lock()
		ks.active = rk
		ks.keys = []*RSAKey{rk}
		ks.byKID = map[string]*RSAKey{rk.KID: rk}
		ks.mu.Unlock()
		return nil
	}

	var active *RSAKey
	keys := make([]*RSAKey, 0, len(stored))
	byKID := make(map[string]*RSAKey, len(stored))

	for _, rec := range stored {
		priv, err := parsePrivatePEM([]byte(rec.PrivatePEM))
		if err != nil {
			return fmt.Errorf("parse signing key %s: %w", rec.KID, err)
		}
		rk := &RSAKey{
			KID:        rec.KID,
			PrivateKey: priv,
			PublicKey:  &priv.PublicKey,
			Active:     rec.Active,
			CreatedAt:  rec.CreatedAt,
		}
		keys = append(keys, rk)
		byKID[rk.KID] = rk
		if rk.Active && active == nil {
			active = rk
		}
	}
	if active == nil && len(keys) > 0 {
		active = keys[0]
	}
	if active == nil {
		return errors.New("no signing keys available")
	}

	ks.mu.Lock()
	ks.active = active
	ks.keys = keys
	ks.byKID = byKID
	ks.mu.Unlock()
	return nil
}

// Rotate generates a new 2048-bit RSA signing key, marks it active, and retains up to retainCount keys in JWKS.
func (ks *KeySet) Rotate(st *store.Store, retainCount int) (*RSAKey, error) {
	rk, rec, err := generateNewRSAKey()
	if err != nil {
		return nil, err
	}
	if err := st.RotateSigningKey(rec, retainCount); err != nil {
		return nil, fmt.Errorf("rotate signing key: %w", err)
	}
	if err := ks.reload(st); err != nil {
		return nil, err
	}
	return rk, nil
}

func generateNewRSAKey() (*RSAKey, *store.SigningKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate 2048-bit RSA key: %w", err)
	}
	kid, err := computeKID(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pemBytes, err := encodePKCS8PrivatePEM(priv)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().Unix()
	rec := &store.SigningKey{
		KID:        kid,
		Algorithm:  "RS256",
		PrivatePEM: string(pemBytes),
		Active:     true,
		CreatedAt:  now,
	}
	rk := &RSAKey{
		KID:        kid,
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		Active:     true,
		CreatedAt:  now,
	}
	return rk, rec, nil
}

// Active returns the currently active RSA signing key.
func (ks *KeySet) Active() *RSAKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.active
}

// Lookup finds a signing key by its kid header value.
func (ks *KeySet) Lookup(kid string) (*RSAKey, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	k, ok := ks.byKID[kid]
	return k, ok
}

// Metadata returns non-sensitive metadata for all currently retained keys.
func (ks *KeySet) Metadata() []KeyMeta {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	out := make([]KeyMeta, 0, len(ks.keys))
	for _, k := range ks.keys {
		out = append(out, KeyMeta{
			KID:       k.KID,
			Algorithm: "RS256",
			Active:    k.Active,
			CreatedAt: k.CreatedAt,
		})
	}
	return out
}

// JWKS returns the public JWK Set structure for /.well-known/jwks.json.
func (ks *KeySet) JWKS() map[string][]JWK {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
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
