package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// ListSigningKeys returns all persisted RSA signing keys ordered newest first.
func (s *Store) ListSigningKeys() ([]SigningKey, error) {
	rows, err := s.db.Query(`SELECT kid, algorithm, private_pem, active, created_at FROM signing_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []SigningKey
	for rows.Next() {
		var k SigningKey
		var active int
		if err := rows.Scan(&k.KID, &k.Algorithm, &k.PrivatePEM, &active, &k.CreatedAt); err != nil {
			return nil, err
		}
		k.Active = active != 0
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// SaveSigningKey stores a signing keypair in SQLite.
func (s *Store) SaveSigningKey(k *SigningKey) error {
	activeInt := 0
	if k.Active {
		activeInt = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO signing_keys (kid, algorithm, private_pem, active, created_at) VALUES (?, ?, ?, ?, ?)`,
		k.KID, k.Algorithm, k.PrivatePEM, activeInt, k.CreatedAt,
	)
	return err
}

// ListOAuthClients returns all registered OAuth2/OIDC clients.
func (s *Store) ListOAuthClients() ([]OAuthClient, error) {
	rows, err := s.db.Query(
		`SELECT id, name, description, secret_hash, redirect_uris, trusted, pkce_required, is_public, created_at, updated_at
		 FROM oauth_clients ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []OAuthClient
	for rows.Next() {
		c, err := scanOAuthClientRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// GetOAuthClient returns an OAuth2 client by client_id.
func (s *Store) GetOAuthClient(clientID string) (*OAuthClient, error) {
	row := s.db.QueryRow(
		`SELECT id, name, description, secret_hash, redirect_uris, trusted, pkce_required, is_public, created_at, updated_at
		 FROM oauth_clients WHERE id = ?`,
		clientID,
	)
	c := &OAuthClient{}
	var urisJSON string
	var trusted, pkceReq, isPub int
	err := row.Scan(&c.ID, &c.Name, &c.Description, &c.SecretHash, &urisJSON, &trusted, &pkceReq, &isPub, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(urisJSON), &c.RedirectURIs); err != nil {
		return nil, err
	}
	c.HasSecret = c.SecretHash != ""
	c.Trusted = trusted != 0
	c.PKCERequired = pkceReq != 0
	c.IsPublic = isPub != 0
	return c, nil
}

func scanOAuthClientRow(rows *sql.Rows) (*OAuthClient, error) {
	c := &OAuthClient{}
	var urisJSON string
	var trusted, pkceReq, isPub int
	if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.SecretHash, &urisJSON, &trusted, &pkceReq, &isPub, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(urisJSON), &c.RedirectURIs); err != nil {
		return nil, err
	}
	c.HasSecret = c.SecretHash != ""
	c.Trusted = trusted != 0
	c.PKCERequired = pkceReq != 0
	c.IsPublic = isPub != 0
	return c, nil
}

// CreateOAuthClient persists a new OAuth2 client. If clientID is empty, a random va_ ID is generated.
func (s *Store) CreateOAuthClient(clientID, name, description, secretHash string, redirectURIs []string, trusted, pkceRequired, isPublic bool) (*OAuthClient, error) {
	id := strings.TrimSpace(clientID)
	if id == "" {
		rnd, err := RandomHex(12)
		if err != nil {
			return nil, err
		}
		id = "va_" + rnd
	}
	if isPublic {
		secretHash = ""
		pkceRequired = true
	}
	urisJSON, err := json.Marshal(redirectURIs)
	if err != nil {
		return nil, err
	}
	now := nowUnix()
	c := &OAuthClient{
		ID:           id,
		Name:         strings.TrimSpace(name),
		Description:  strings.TrimSpace(description),
		SecretHash:   secretHash,
		HasSecret:    secretHash != "",
		RedirectURIs: redirectURIs,
		Trusted:      trusted,
		PKCERequired: pkceRequired,
		IsPublic:     isPublic,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	_, err = s.db.Exec(
		`INSERT INTO oauth_clients (id, name, description, secret_hash, redirect_uris, trusted, pkce_required, is_public, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, c.Description, c.SecretHash, string(urisJSON), boolToInt(c.Trusted), boolToInt(c.PKCERequired), boolToInt(c.IsPublic), c.CreatedAt, c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// UpdateOAuthClient updates an existing OAuth2 client configuration.
func (s *Store) UpdateOAuthClient(clientID, name, description string, redirectURIs []string, trusted, pkceRequired, isPublic bool) (*OAuthClient, error) {
	existing, err := s.GetOAuthClient(clientID)
	if err != nil {
		return nil, err
	}
	if isPublic {
		pkceRequired = true
	}
	urisJSON, err := json.Marshal(redirectURIs)
	if err != nil {
		return nil, err
	}
	secretHash := existing.SecretHash
	if isPublic {
		secretHash = ""
	}
	now := nowUnix()
	_, err = s.db.Exec(
		`UPDATE oauth_clients
		 SET name = ?, description = ?, secret_hash = ?, redirect_uris = ?, trusted = ?, pkce_required = ?, is_public = ?, updated_at = ?
		 WHERE id = ?`,
		strings.TrimSpace(name), strings.TrimSpace(description), secretHash, string(urisJSON),
		boolToInt(trusted), boolToInt(pkceRequired), boolToInt(isPublic), now, clientID,
	)
	if err != nil {
		return nil, err
	}
	return s.GetOAuthClient(clientID)
}

// UpdateOAuthClientSecret updates the stored secret hash for a confidential client.
func (s *Store) UpdateOAuthClientSecret(clientID, secretHash string) error {
	res, err := s.db.Exec(
		`UPDATE oauth_clients SET secret_hash = ?, is_public = 0, updated_at = ? WHERE id = ?`,
		secretHash, nowUnix(), clientID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteOAuthClient deletes an OAuth2 client and cascades its codes/tokens.
func (s *Store) DeleteOAuthClient(clientID string) (string, error) {
	var name string
	err := s.db.QueryRow(`SELECT name FROM oauth_clients WHERE id = ?`, clientID).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec(`DELETE FROM oauth_clients WHERE id = ?`, clientID); err != nil {
		return "", err
	}
	return name, nil
}

// CreateAuthRequest persists a pending authorization request while the user logs in.
func (s *Store) CreateAuthRequest(req *AuthRequest) error {
	now := nowUnix()
	if req.CreatedAt == 0 {
		req.CreatedAt = now
	}
	_, err := s.db.Exec(
		`INSERT INTO auth_requests (id, client_id, redirect_uri, response_type, scope, state, nonce, code_challenge, code_challenge_method, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.ID, req.ClientID, req.RedirectURI, req.ResponseType, req.Scope, req.State, req.Nonce, req.CodeChallenge, req.CodeChallengeMethod, req.ExpiresAt, req.CreatedAt,
	)
	if err != nil {
		return err
	}
	_, _ = s.db.Exec(`DELETE FROM auth_requests WHERE expires_at <= ?`, now)
	return nil
}

// GetAuthRequest retrieves an unexpired pending authorization request.
func (s *Store) GetAuthRequest(id string) (*AuthRequest, error) {
	row := s.db.QueryRow(
		`SELECT id, client_id, redirect_uri, response_type, scope, state, nonce, code_challenge, code_challenge_method, expires_at, created_at
		 FROM auth_requests WHERE id = ? AND expires_at > ?`,
		id, nowUnix(),
	)
	r := &AuthRequest{}
	err := row.Scan(&r.ID, &r.ClientID, &r.RedirectURI, &r.ResponseType, &r.Scope, &r.State, &r.Nonce, &r.CodeChallenge, &r.CodeChallengeMethod, &r.ExpiresAt, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// DeleteAuthRequest removes a pending authorization request.
func (s *Store) DeleteAuthRequest(id string) error {
	_, err := s.db.Exec(`DELETE FROM auth_requests WHERE id = ?`, id)
	return err
}

// CreateAuthCode stores a hashed authorization code.
func (s *Store) CreateAuthCode(code *AuthCode) error {
	now := nowUnix()
	if code.CreatedAt == 0 {
		code.CreatedAt = now
	}
	_, err := s.db.Exec(
		`INSERT INTO auth_codes (code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, auth_time, used, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		code.CodeHash, code.ClientID, code.UserID, code.RedirectURI, code.Scope, code.Nonce, code.CodeChallenge, code.CodeChallengeMethod, code.AuthTime, code.ExpiresAt, code.CreatedAt,
	)
	if err != nil {
		return err
	}
	_, _ = s.db.Exec(`DELETE FROM auth_codes WHERE expires_at <= ?`, now-3600)
	return nil
}

// ConsumeAuthCode atomically validates and marks an authorization code as used.
func (s *Store) ConsumeAuthCode(rawCode string) (*AuthCode, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	hash := HashToken(rawCode)
	now := nowUnix()
	row := tx.QueryRow(
		`SELECT code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge, code_challenge_method, auth_time, used, expires_at, created_at
		 FROM auth_codes WHERE code_hash = ?`,
		hash,
	)
	ac := &AuthCode{}
	var used int
	err = row.Scan(&ac.CodeHash, &ac.ClientID, &ac.UserID, &ac.RedirectURI, &ac.Scope, &ac.Nonce, &ac.CodeChallenge, &ac.CodeChallengeMethod, &ac.AuthTime, &used, &ac.ExpiresAt, &ac.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if used != 0 {
		return nil, ErrCodeAlreadyUsed
	}
	if ac.ExpiresAt <= now {
		return nil, ErrNotFound
	}

	res, err := tx.Exec(`UPDATE auth_codes SET used = 1 WHERE code_hash = ? AND used = 0`, hash)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, ErrCodeAlreadyUsed
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	ac.Used = true
	return ac, nil
}

// CreateAccessToken persists a tracking record for an issued JWT access token.
func (s *Store) CreateAccessToken(rec *AccessTokenRecord) error {
	now := nowUnix()
	if rec.CreatedAt == 0 {
		rec.CreatedAt = now
	}
	_, err := s.db.Exec(
		`INSERT INTO access_tokens (jti, client_id, user_id, scope, revoked, expires_at, created_at)
		 VALUES (?, ?, ?, ?, 0, ?, ?)`,
		rec.JTI, rec.ClientID, rec.UserID, rec.Scope, rec.ExpiresAt, rec.CreatedAt,
	)
	if err != nil {
		return err
	}
	_, _ = s.db.Exec(`DELETE FROM access_tokens WHERE expires_at <= ?`, now-86400)
	return nil
}

// IsAccessTokenActive reports whether jti exists, is not revoked, and has not expired.
func (s *Store) IsAccessTokenActive(jti string) (bool, error) {
	var revoked int
	var expiresAt int64
	err := s.db.QueryRow(`SELECT revoked, expires_at FROM access_tokens WHERE jti = ?`, jti).Scan(&revoked, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return revoked == 0 && expiresAt > nowUnix(), nil
}

// RevokeAccessToken marks an access token as revoked.
func (s *Store) RevokeAccessToken(jti string) error {
	_, err := s.db.Exec(`UPDATE access_tokens SET revoked = 1 WHERE jti = ?`, jti)
	return err
}

// CreateRefreshToken stores a newly issued refresh token.
func (s *Store) CreateRefreshToken(rec *RefreshTokenRecord) error {
	now := nowUnix()
	if rec.CreatedAt == 0 {
		rec.CreatedAt = now
	}
	_, err := s.db.Exec(
		`INSERT INTO refresh_tokens (token_hash, family_id, client_id, user_id, scope, auth_time, rotated, revoked, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, ?)`,
		rec.TokenHash, rec.FamilyID, rec.ClientID, rec.UserID, rec.Scope, rec.AuthTime, rec.ExpiresAt, rec.CreatedAt,
	)
	return err
}

// RotateRefreshToken atomically validates oldRawToken, detects reuse, marks it rotated, and persists nextRec.
func (s *Store) RotateRefreshToken(oldRawToken, clientID string, nextRec *RefreshTokenRecord) (*RefreshTokenRecord, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	oldHash := HashToken(oldRawToken)
	now := nowUnix()
	row := tx.QueryRow(
		`SELECT token_hash, family_id, client_id, user_id, scope, auth_time, rotated, revoked, expires_at, created_at
		 FROM refresh_tokens WHERE token_hash = ?`,
		oldHash,
	)
	old := &RefreshTokenRecord{}
	var rotated, revoked int
	err = row.Scan(&old.TokenHash, &old.FamilyID, &old.ClientID, &old.UserID, &old.Scope, &old.AuthTime, &rotated, &revoked, &old.ExpiresAt, &old.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if old.ClientID != clientID {
		return nil, ErrNotFound
	}
	if rotated != 0 {
		// Refresh token replay detected: revoke the entire family.
		if _, err := tx.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?`, old.FamilyID); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, ErrTokenReused
	}
	if revoked != 0 || old.ExpiresAt <= now {
		return nil, ErrNotFound
	}

	res, err := tx.Exec(`UPDATE refresh_tokens SET rotated = 1 WHERE token_hash = ? AND rotated = 0 AND revoked = 0`, oldHash)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, ErrTokenReused
	}

	nextRec.FamilyID = old.FamilyID
	nextRec.ClientID = old.ClientID
	nextRec.UserID = old.UserID
	nextRec.Scope = old.Scope
	nextRec.AuthTime = old.AuthTime
	if nextRec.CreatedAt == 0 {
		nextRec.CreatedAt = now
	}

	if _, err := tx.Exec(
		`INSERT INTO refresh_tokens (token_hash, family_id, client_id, user_id, scope, auth_time, rotated, revoked, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, ?)`,
		nextRec.TokenHash, nextRec.FamilyID, nextRec.ClientID, nextRec.UserID, nextRec.Scope, nextRec.AuthTime, nextRec.ExpiresAt, nextRec.CreatedAt,
	); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return old, nil
}

// RevokeRefreshToken revokes a refresh token and its family if found.
func (s *Store) RevokeRefreshToken(rawToken, clientID string) (bool, error) {
	hash := HashToken(rawToken)
	var familyID, ownerClient string
	err := s.db.QueryRow(`SELECT family_id, client_id FROM refresh_tokens WHERE token_hash = ?`, hash).Scan(&familyID, &ownerClient)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if clientID != "" && ownerClient != clientID {
		return false, nil
	}
	if _, err := s.db.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?`, familyID); err != nil {
		return false, err
	}
	return true, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
