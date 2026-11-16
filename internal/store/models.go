package store

import "time"

// AdminUser represents the sole administrator account.
type AdminUser struct {
	ID             string `json:"id"`
	Username       string `json:"username"`
	Email          string `json:"email"`
	DisplayName    string `json:"display_name"`
	PasswordHash   string `json:"-"`
	WebAuthnUserID []byte `json:"-"`
	CreatedAt      int64  `json:"created_at"`
	UpdatedAt      int64  `json:"updated_at"`
}

// PasskeyRecord represents a registered WebAuthn credential bound to the admin.
type PasskeyRecord struct {
	ID             string `json:"id"`
	UserID         string `json:"user_id"`
	CredentialID   []byte `json:"-"`
	CredentialHex  string `json:"credential_id"`
	Name           string `json:"name"`
	CredentialJSON string `json:"-"`
	AAGUID         string `json:"aaguid"`
	SignCount      uint32 `json:"sign_count"`
	CreatedAt      int64  `json:"created_at"`
	LastUsedAt     int64  `json:"last_used_at"`
}

// Session represents an active browser login session.
type Session struct {
	ID         string `json:"id"`
	TokenHash  string `json:"-"`
	UserID     string `json:"user_id"`
	IP         string `json:"ip"`
	UserAgent  string `json:"user_agent"`
	AuthMethod string `json:"auth_method"`
	CreatedAt  int64  `json:"created_at"`
	LastSeenAt int64  `json:"last_seen_at"`
	ExpiresAt  int64  `json:"expires_at"`
	Current    bool   `json:"current,omitempty"`
}

// SigningKey stores a persisted RSA signing keypair for RS256 OIDC tokens.
type SigningKey struct {
	KID        string `json:"kid"`
	Algorithm  string `json:"algorithm"`
	PrivatePEM string `json:"-"`
	Active     bool   `json:"active"`
	CreatedAt  int64  `json:"created_at"`
}

// OAuthClient represents a registered OAuth 2.0 / OIDC relying party.
type OAuthClient struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	SecretHash   string   `json:"-"`
	HasSecret    bool     `json:"has_secret"`
	RedirectURIs []string `json:"redirect_uris"`
	Trusted      bool     `json:"trusted"`
	PKCERequired bool     `json:"pkce_required"`
	IsPublic     bool     `json:"is_public"`
	CreatedAt    int64    `json:"created_at"`
	UpdatedAt    int64    `json:"updated_at"`
}

// AuthRequest stores a pending OAuth2 authorization request across login redirects.
type AuthRequest struct {
	ID                  string
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           int64
	CreatedAt           int64
}

// AuthCode represents a short-lived single-use OAuth2 authorization code.
type AuthCode struct {
	CodeHash            string
	ClientID            string
	UserID              string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthTime            int64
	Used                bool
	ExpiresAt           int64
	CreatedAt           int64
}

// AccessTokenRecord tracks issued access tokens for revocation checks.
type AccessTokenRecord struct {
	JTI       string
	ClientID  string
	UserID    string
	Scope     string
	Revoked   bool
	ExpiresAt int64
	CreatedAt int64
}

// RefreshTokenRecord tracks issued refresh tokens and rotation state.
type RefreshTokenRecord struct {
	TokenHash string
	FamilyID  string
	ClientID  string
	UserID    string
	Scope     string
	AuthTime  int64
	Rotated   bool
	Revoked   bool
	ExpiresAt int64
	CreatedAt int64
}

// AuditLog represents an immutable security or OAuth event record.
type AuditLog struct {
	ID        int64  `json:"id"`
	EventType string `json:"event_type"`
	Actor     string `json:"actor"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	Target    string `json:"target"`
	Detail    string `json:"detail"`
	Status    string `json:"status"`
	CreatedAt int64  `json:"created_at"`
}

func nowUnix() int64 {
	return time.Now().Unix()
}
