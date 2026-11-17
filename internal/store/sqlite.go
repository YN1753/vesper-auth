package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	// ErrNotFound is returned when a requested record does not exist.
	ErrNotFound = errors.New("record not found")
	// ErrCodeAlreadyUsed indicates an authorization code was already consumed.
	ErrCodeAlreadyUsed = errors.New("authorization code already used")
	// ErrTokenReused indicates refresh token reuse detection triggered.
	ErrTokenReused = errors.New("refresh token reuse detected")
)

// Store wraps SQLite persistence with separated write (single-conn) and read (multi-conn WAL) pools.
type Store struct {
	db  *sql.DB // single-connection writer
	rdb *sql.DB // concurrent WAL reader pool (shares db for :memory:)
}

// Open initializes the SQLite database at dbPath, enables WAL mode, applies schema migrations,
// and configures separated writer/reader pools for file-backed databases.
func Open(dbPath string) (*Store, error) {
	isMemory := dbPath == ":memory:" || strings.HasPrefix(dbPath, "file::memory:")
	if !isMemory && !strings.HasPrefix(dbPath, "file:") {
		dir := filepath.Dir(dbPath)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return nil, fmt.Errorf("create db directory: %w", err)
			}
		}
	}

	writeDSN := buildSQLiteDSN(dbPath, false)
	db, err := sql.Open("sqlite", writeDSN)
	if err != nil {
		return nil, fmt.Errorf("open sqlite writer: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	pragmas := []string{
		"PRAGMA journal_mode = WAL;",
		"PRAGMA synchronous = NORMAL;",
		"PRAGMA foreign_keys = ON;",
		"PRAGMA busy_timeout = 5000;",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("apply pragma %q: %w", p, err)
		}
	}

	s := &Store{db: db, rdb: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}

	if !isMemory {
		readDSN := buildSQLiteDSN(dbPath, true)
		rdb, err := sql.Open("sqlite", readDSN)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("open sqlite reader pool: %w", err)
		}
		rdb.SetMaxOpenConns(4)
		rdb.SetMaxIdleConns(4)
		if err := rdb.Ping(); err != nil {
			_ = rdb.Close()
			_ = db.Close()
			return nil, fmt.Errorf("ping sqlite reader pool: %w", err)
		}
		s.rdb = rdb
	}

	return s, nil
}

func buildSQLiteDSN(dbPath string, readOnly bool) string {
	if dbPath == ":memory:" || strings.HasPrefix(dbPath, "file:") {
		return dbPath
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	if readOnly {
		q.Add("_pragma", "query_only(1)")
	} else {
		q.Add("_pragma", "journal_mode(WAL)")
		q.Add("_pragma", "synchronous(NORMAL)")
	}
	u := url.URL{
		Scheme:   "file",
		Opaque:   filepath.ToSlash(dbPath),
		RawQuery: q.Encode(),
	}
	return u.String()
}

// Close closes both reader and writer SQLite pools.
func (s *Store) Close() error {
	var firstErr error
	if s.rdb != nil && s.rdb != s.db {
		if err := s.rdb.Close(); err != nil {
			firstErr = err
		}
	}
	if s.db != nil {
		if err := s.db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// DB exposes the writer sql.DB for diagnostics or tests.
func (s *Store) DB() *sql.DB {
	return s.db
}

// Ping verifies both writer and reader database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	var one int
	if err := s.db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		return err
	}
	if s.rdb != s.db {
		if err := s.rdb.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS system_settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_users (
	id TEXT PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	email TEXT NOT NULL,
	display_name TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	webauthn_user_id BLOB NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS passkeys (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
	credential_id BLOB NOT NULL UNIQUE,
	name TEXT NOT NULL,
	credential_json TEXT NOT NULL,
	aaguid TEXT NOT NULL DEFAULT '',
	sign_count INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	last_used_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	token_hash TEXT NOT NULL UNIQUE,
	user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
	ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	auth_method TEXT NOT NULL DEFAULT 'password',
	created_at INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	elevated_at INTEGER NOT NULL DEFAULT 0,
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS signing_keys (
	kid TEXT PRIMARY KEY,
	algorithm TEXT NOT NULL,
	private_pem TEXT NOT NULL,
	active INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_clients (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	secret_hash TEXT NOT NULL DEFAULT '',
	redirect_uris TEXT NOT NULL,
	trusted INTEGER NOT NULL DEFAULT 0,
	pkce_required INTEGER NOT NULL DEFAULT 0,
	is_public INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_requests (
	id TEXT PRIMARY KEY,
	client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
	redirect_uri TEXT NOT NULL,
	response_type TEXT NOT NULL,
	scope TEXT NOT NULL,
	state TEXT NOT NULL DEFAULT '',
	nonce TEXT NOT NULL DEFAULT '',
	code_challenge TEXT NOT NULL DEFAULT '',
	code_challenge_method TEXT NOT NULL DEFAULT '',
	prompt TEXT NOT NULL DEFAULT '',
	max_age INTEGER NOT NULL DEFAULT -1,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_requests_expires_at ON auth_requests(expires_at);

CREATE TABLE IF NOT EXISTS auth_codes (
	code_hash TEXT PRIMARY KEY,
	client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
	user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
	redirect_uri TEXT NOT NULL,
	scope TEXT NOT NULL,
	nonce TEXT NOT NULL DEFAULT '',
	code_challenge TEXT NOT NULL DEFAULT '',
	code_challenge_method TEXT NOT NULL DEFAULT '',
	auth_time INTEGER NOT NULL,
	used INTEGER NOT NULL DEFAULT 0,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires_at ON auth_codes(expires_at);

CREATE TABLE IF NOT EXISTS access_tokens (
	jti TEXT PRIMARY KEY,
	client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
	user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
	scope TEXT NOT NULL,
	revoked INTEGER NOT NULL DEFAULT 0,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at);

CREATE TABLE IF NOT EXISTS refresh_tokens (
	token_hash TEXT PRIMARY KEY,
	family_id TEXT NOT NULL,
	client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
	user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
	scope TEXT NOT NULL,
	auth_time INTEGER NOT NULL,
	rotated INTEGER NOT NULL DEFAULT 0,
	revoked INTEGER NOT NULL DEFAULT 0,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

CREATE TABLE IF NOT EXISTS audit_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	event_type TEXT NOT NULL,
	actor TEXT NOT NULL,
	ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	target TEXT NOT NULL DEFAULT '',
	detail TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status, created_at DESC);
`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	// Incremental column migrations for existing production databases.
	migrations := []struct {
		table  string
		column string
		ddl    string
	}{
		{"sessions", "elevated_at", "INTEGER NOT NULL DEFAULT 0"},
		{"auth_requests", "prompt", "TEXT NOT NULL DEFAULT ''"},
		{"auth_requests", "max_age", "INTEGER NOT NULL DEFAULT -1"},
	}
	for _, m := range migrations {
		if err := s.ensureColumn(m.table, m.column, m.ddl); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureColumn(table, column, ddl string) error {
	rows, err := s.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid, notNull, pk int
		var name, colType string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			return err
		}
		if strings.EqualFold(name, column) {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	_, err = s.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, ddl))
	return err
}

// GetOrCreateSetting atomically retrieves a persistent setting or initializes it via gen.
func (s *Store) GetOrCreateSetting(key string, gen func() (string, error)) (string, error) {
	var val string
	err := s.rdb.QueryRow(`SELECT value FROM system_settings WHERE key = ?`, key).Scan(&val)
	if err == nil {
		return val, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	err = tx.QueryRow(`SELECT value FROM system_settings WHERE key = ?`, key).Scan(&val)
	if err == nil {
		return val, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	val, err = gen()
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(
		`INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)`,
		key, val, nowUnix(),
	); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return val, nil
}

// GetOrCreateCSRFSecret returns a 32-byte persistent HMAC secret stored in SQLite.
func (s *Store) GetOrCreateCSRFSecret() ([]byte, error) {
	hexVal, err := s.GetOrCreateSetting("csrf_secret", func() (string, error) {
		return RandomHex(32)
	})
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(hexVal)
}

// CleanupExpired purges expired sessions/tokens/codes, trims old audit logs, and optimizes SQLite.
func (s *Store) CleanupExpired(auditRetentionDays int) (int64, error) {
	now := nowUnix()
	var total int64

	queries := []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM sessions WHERE expires_at <= ?`, []any{now}},
		{`DELETE FROM auth_requests WHERE expires_at <= ?`, []any{now}},
		{`DELETE FROM auth_codes WHERE expires_at <= ?`, []any{now - 3600}},
		{`DELETE FROM access_tokens WHERE expires_at <= ?`, []any{now - 86400}},
		{`DELETE FROM refresh_tokens WHERE expires_at <= ?`, []any{now - 86400}},
	}
	if auditRetentionDays > 0 {
		cutoff := now - int64(auditRetentionDays)*86400
		queries = append(queries, struct {
			sql  string
			args []any
		}{`DELETE FROM audit_logs WHERE created_at < ?`, []any{cutoff}})
	}

	for _, q := range queries {
		res, err := s.db.Exec(q.sql, q.args...)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}

	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(PASSIVE);`)
	_, _ = s.db.Exec(`PRAGMA optimize;`)
	return total, nil
}

// StartMaintenanceLoop periodically invokes CleanupExpired until ctx is cancelled.
func (s *Store) StartMaintenanceLoop(ctx context.Context, interval time.Duration, auditRetentionDays int) {
	if interval <= 0 {
		interval = time.Hour
	}
	go func() {
		// Run an initial sweep shortly after startup, then every interval.
		initialTimer := time.NewTimer(10 * time.Second)
		defer initialTimer.Stop()

		select {
		case <-ctx.Done():
			return
		case <-initialTimer.C:
			if n, err := s.CleanupExpired(auditRetentionDays); err != nil {
				slog.Warn("sqlite maintenance cleanup error", "err", err)
			} else if n > 0 {
				slog.Info("sqlite maintenance cleanup finished", "purged_rows", n)
			}
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := s.CleanupExpired(auditRetentionDays); err != nil {
					slog.Warn("sqlite maintenance cleanup error", "err", err)
				} else if n > 0 {
					slog.Info("sqlite maintenance cleanup finished", "purged_rows", n)
				}
			}
		}
	}()
}

// BackupTo creates an online, consistent single-file snapshot at destPath using VACUUM INTO
// and verifies its integrity before returning.
func (s *Store) BackupTo(ctx context.Context, destPath string) error {
	destPath = strings.TrimSpace(destPath)
	if destPath == "" {
		return errors.New("backup destination path cannot be empty")
	}
	absPath, err := filepath.Abs(destPath)
	if err != nil {
		return fmt.Errorf("resolve backup path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o750); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}

	// Write to a temporary sibling path first so existing backups aren't clobbered on failure.
	tmpPath := fmt.Sprintf("%s.tmp.%d", absPath, time.Now().UnixNano())
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, tmpPath); err != nil {
		return fmt.Errorf("vacuum into %s: %w", tmpPath, err)
	}

	checkDB, err := sql.Open("sqlite", buildSQLiteDSN(tmpPath, true))
	if err != nil {
		return fmt.Errorf("open backup for verification: %w", err)
	}
	var status string
	err = checkDB.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&status)
	_ = checkDB.Close()
	if err != nil {
		return fmt.Errorf("verify backup integrity: %w", err)
	}
	if !strings.EqualFold(status, "ok") {
		return fmt.Errorf("backup integrity check failed: %s", status)
	}

	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("chmod backup: %w", err)
	}
	if err := os.Rename(tmpPath, absPath); err != nil {
		return fmt.Errorf("finalize backup file: %w", err)
	}
	return nil
}

// RandomHex returns a cryptographically random hex string of nBytes bytes.
func RandomHex(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// HashToken returns the lowercase hex SHA-256 digest of a token or secret.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
