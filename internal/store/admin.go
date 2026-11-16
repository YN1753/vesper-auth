package store

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// HasAdmin reports whether an administrator account has already been initialized.
func (s *Store) HasAdmin() (bool, error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM admin_users`).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// CreateAdmin inserts the sole administrator account.
func (s *Store) CreateAdmin(username, email, displayName, passwordHash string) (*AdminUser, error) {
	has, err := s.HasAdmin()
	if err != nil {
		return nil, err
	}
	if has {
		return nil, errors.New("administrator already exists")
	}

	idHex, err := RandomHex(16)
	if err != nil {
		return nil, err
	}
	waID, err := RandomBytes(32)
	if err != nil {
		return nil, err
	}

	now := nowUnix()
	if strings.TrimSpace(displayName) == "" {
		displayName = username
	}
	user := &AdminUser{
		ID:             "usr_" + idHex,
		Username:       strings.TrimSpace(username),
		Email:          strings.TrimSpace(email),
		DisplayName:    strings.TrimSpace(displayName),
		PasswordHash:   passwordHash,
		WebAuthnUserID: waID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	_, err = s.db.Exec(
		`INSERT INTO admin_users (id, username, email, display_name, password_hash, webauthn_user_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Username, user.Email, user.DisplayName, user.PasswordHash, user.WebAuthnUserID, user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetAdmin returns the sole administrator account.
func (s *Store) GetAdmin() (*AdminUser, error) {
	row := s.db.QueryRow(
		`SELECT id, username, email, display_name, password_hash, webauthn_user_id, created_at, updated_at
		 FROM admin_users LIMIT 1`,
	)
	return scanAdmin(row)
}

// GetAdminByID returns the administrator by ID.
func (s *Store) GetAdminByID(id string) (*AdminUser, error) {
	row := s.db.QueryRow(
		`SELECT id, username, email, display_name, password_hash, webauthn_user_id, created_at, updated_at
		 FROM admin_users WHERE id = ?`, id,
	)
	return scanAdmin(row)
}

// GetAdminByUsernameOrEmail looks up the admin by username or email.
func (s *Store) GetAdminByUsernameOrEmail(identifier string) (*AdminUser, error) {
	ident := strings.TrimSpace(identifier)
	row := s.db.QueryRow(
		`SELECT id, username, email, display_name, password_hash, webauthn_user_id, created_at, updated_at
		 FROM admin_users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?) LIMIT 1`,
		ident, ident,
	)
	return scanAdmin(row)
}

// GetAdminByWebAuthnID looks up the admin by WebAuthn user handle.
func (s *Store) GetAdminByWebAuthnID(waID []byte) (*AdminUser, error) {
	row := s.db.QueryRow(
		`SELECT id, username, email, display_name, password_hash, webauthn_user_id, created_at, updated_at
		 FROM admin_users WHERE webauthn_user_id = ? LIMIT 1`,
		waID,
	)
	return scanAdmin(row)
}

func scanAdmin(row *sql.Row) (*AdminUser, error) {
	u := &AdminUser{}
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash, &u.WebAuthnUserID, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// UpdateAdminPassword replaces the administrator's password hash.
func (s *Store) UpdateAdminPassword(userID, passwordHash string) error {
	res, err := s.db.Exec(
		`UPDATE admin_users SET password_hash = ?, updated_at = ? WHERE id = ?`,
		passwordHash, nowUnix(), userID,
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

// UpdateAdminProfile updates email and display name for the administrator.
func (s *Store) UpdateAdminProfile(userID, email, displayName string) error {
	res, err := s.db.Exec(
		`UPDATE admin_users SET email = ?, display_name = ?, updated_at = ? WHERE id = ?`,
		strings.TrimSpace(email), strings.TrimSpace(displayName), nowUnix(), userID,
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

// ListPasskeys returns all Passkey records belonging to userID ordered newest first.
func (s *Store) ListPasskeys(userID string) ([]PasskeyRecord, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, credential_id, name, credential_json, aaguid, sign_count, created_at, last_used_at
		 FROM passkeys WHERE user_id = ? ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PasskeyRecord
	for rows.Next() {
		var p PasskeyRecord
		if err := rows.Scan(&p.ID, &p.UserID, &p.CredentialID, &p.Name, &p.CredentialJSON, &p.AAGUID, &p.SignCount, &p.CreatedAt, &p.LastUsedAt); err != nil {
			return nil, err
		}
		p.CredentialHex = hex.EncodeToString(p.CredentialID)
		out = append(out, p)
	}
	return out, rows.Err()
}

// CreatePasskey persists a newly registered WebAuthn credential.
func (s *Store) CreatePasskey(userID, name string, credID []byte, credJSON, aaguid string, signCount uint32) (*PasskeyRecord, error) {
	idHex, err := RandomHex(12)
	if err != nil {
		return nil, err
	}
	now := nowUnix()
	rec := &PasskeyRecord{
		ID:             "pk_" + idHex,
		UserID:         userID,
		CredentialID:   credID,
		CredentialHex:  hex.EncodeToString(credID),
		Name:           strings.TrimSpace(name),
		CredentialJSON: credJSON,
		AAGUID:         aaguid,
		SignCount:      signCount,
		CreatedAt:      now,
		LastUsedAt:     now,
	}
	if rec.Name == "" {
		rec.Name = "Passkey"
	}

	_, err = s.db.Exec(
		`INSERT INTO passkeys (id, user_id, credential_id, name, credential_json, aaguid, sign_count, created_at, last_used_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.UserID, rec.CredentialID, rec.Name, rec.CredentialJSON, rec.AAGUID, rec.SignCount, rec.CreatedAt, rec.LastUsedAt,
	)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// UpdatePasskeyCredential updates the serialized credential (sign count, flags) and last_used_at after login.
func (s *Store) UpdatePasskeyCredential(credID []byte, credJSON string, signCount uint32) error {
	_, err := s.db.Exec(
		`UPDATE passkeys SET credential_json = ?, sign_count = ?, last_used_at = ? WHERE credential_id = ?`,
		credJSON, signCount, nowUnix(), credID,
	)
	return err
}

// RenamePasskey updates the display name of a registered passkey.
func (s *Store) RenamePasskey(userID, passkeyID, newName string) error {
	name := strings.TrimSpace(newName)
	if name == "" {
		return fmt.Errorf("passkey name cannot be empty")
	}
	res, err := s.db.Exec(
		`UPDATE passkeys SET name = ? WHERE id = ? AND user_id = ?`,
		name, passkeyID, userID,
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

// DeletePasskey removes a passkey by ID for userID.
func (s *Store) DeletePasskey(userID, passkeyID string) (string, error) {
	var name string
	err := s.db.QueryRow(`SELECT name FROM passkeys WHERE id = ? AND user_id = ?`, passkeyID, userID).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec(`DELETE FROM passkeys WHERE id = ? AND user_id = ?`, passkeyID, userID); err != nil {
		return "", err
	}
	return name, nil
}

// CreateSession creates a new login session and returns the raw session token plus the stored record.
func (s *Store) CreateSession(userID, ip, userAgent, authMethod string, ttlSeconds int64) (string, *Session, error) {
	rawToken, err := RandomHex(32)
	if err != nil {
		return "", nil, err
	}
	idHex, err := RandomHex(12)
	if err != nil {
		return "", nil, err
	}
	now := nowUnix()
	ses := &Session{
		ID:         "ses_" + idHex,
		TokenHash:  HashToken(rawToken),
		UserID:     userID,
		IP:         ip,
		UserAgent:  userAgent,
		AuthMethod: authMethod,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now + ttlSeconds,
	}

	_, err = s.db.Exec(
		`INSERT INTO sessions (id, token_hash, user_id, ip, user_agent, auth_method, created_at, last_seen_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ses.ID, ses.TokenHash, ses.UserID, ses.IP, ses.UserAgent, ses.AuthMethod, ses.CreatedAt, ses.LastSeenAt, ses.ExpiresAt,
	)
	if err != nil {
		return "", nil, err
	}
	// Opportunistically clean up expired sessions.
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, now)
	return rawToken, ses, nil
}

// GetSessionByToken returns an active, unexpired session matching the raw token.
func (s *Store) GetSessionByToken(rawToken string) (*Session, error) {
	if rawToken == "" {
		return nil, ErrNotFound
	}
	hash := HashToken(rawToken)
	now := nowUnix()
	row := s.db.QueryRow(
		`SELECT id, token_hash, user_id, ip, user_agent, auth_method, created_at, last_seen_at, expires_at
		 FROM sessions WHERE token_hash = ? AND expires_at > ?`,
		hash, now,
	)
	ses := &Session{}
	err := row.Scan(&ses.ID, &ses.TokenHash, &ses.UserID, &ses.IP, &ses.UserAgent, &ses.AuthMethod, &ses.CreatedAt, &ses.LastSeenAt, &ses.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return ses, nil
}

// TouchSession updates last_seen_at and IP on an active session.
func (s *Store) TouchSession(sessionID, ip string) error {
	_, err := s.db.Exec(`UPDATE sessions SET last_seen_at = ?, ip = ? WHERE id = ?`, nowUnix(), ip, sessionID)
	return err
}

// ListActiveSessions lists all non-expired sessions for userID, marking currentSessionID.
func (s *Store) ListActiveSessions(userID, currentSessionID string) ([]Session, error) {
	now := nowUnix()
	rows, err := s.db.Query(
		`SELECT id, user_id, ip, user_agent, auth_method, created_at, last_seen_at, expires_at
		 FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY last_seen_at DESC`,
		userID, now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		var ses Session
		if err := rows.Scan(&ses.ID, &ses.UserID, &ses.IP, &ses.UserAgent, &ses.AuthMethod, &ses.CreatedAt, &ses.LastSeenAt, &ses.ExpiresAt); err != nil {
			return nil, err
		}
		ses.Current = ses.ID == currentSessionID
		out = append(out, ses)
	}
	return out, rows.Err()
}

// DeleteSessionByID revokes a specific session belonging to userID.
func (s *Store) DeleteSessionByID(userID, sessionID string) error {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE id = ? AND user_id = ?`, sessionID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSessionByToken revokes the session associated with rawToken.
func (s *Store) DeleteSessionByToken(rawToken string) error {
	if rawToken == "" {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, HashToken(rawToken))
	return err
}

// DeleteOtherSessions revokes all sessions for userID except keepSessionID.
func (s *Store) DeleteOtherSessions(userID, keepSessionID string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ? AND id != ?`, userID, keepSessionID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
