package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YN1753/vesper-auth/internal/auth"
	"github.com/YN1753/vesper-auth/internal/store"
)

func TestCLICommandsEndToEnd(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cli.db")
	t.Setenv("AUTH_DB_PATH", dbPath)
	t.Setenv("AUTH_ISSUER", "https://auth.starryheavens.uk")
	t.Setenv("AUTH_ADMIN_USER", "starry")
	t.Setenv("AUTH_ADMIN_EMAIL", "starry@starryheavens.uk")

	var out, errBuf bytes.Buffer
	info := BuildInfo{Version: "v1.2.0", Commit: "abc1234", BuildTime: "2026-11-17"}

	// 1. version command
	handled, err := Run([]string{"version"}, info, nil, &out, &errBuf)
	if !handled || err != nil || !strings.Contains(out.String(), "v1.2.0") {
		t.Fatalf("version failed: handled=%v err=%v out=%q", handled, err, out.String())
	}

	// 2. admin reset-password initializes sole admin when none exists
	out.Reset()
	handled, err = Run([]string{"admin", "reset-password", "--password", "InitialStrongPass123!"}, info, nil, &out, &errBuf)
	if !handled || err != nil {
		t.Fatalf("initial reset-password failed: %v (%s)", err, errBuf.String())
	}

	// Seed a session and a dummy passkey, then reset password and verify sessions are revoked.
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	u, err := st.GetAdmin()
	if err != nil {
		t.Fatalf("GetAdmin: %v", err)
	}
	rawSes, _, _ := st.CreateSession(u.ID, "127.0.0.1", "test", "password", 3600)
	_, err = st.CreatePasskey(u.ID, "MacBook Pro", []byte("cred-1"), `{}`, "0000", 1)
	if err != nil {
		t.Fatalf("CreatePasskey: %v", err)
	}
	_ = st.Close()

	// 3. list-passkeys
	out.Reset()
	_, err = Run([]string{"admin", "list-passkeys"}, info, nil, &out, &errBuf)
	if err != nil || !strings.Contains(out.String(), "MacBook Pro") {
		t.Fatalf("list-passkeys failed: err=%v out=%q", err, out.String())
	}

	// 4. delete-passkey --all
	out.Reset()
	_, err = Run([]string{"admin", "delete-passkey", "--all"}, info, nil, &out, &errBuf)
	if err != nil || !strings.Contains(out.String(), "deleted 1 passkey(s)") {
		t.Fatalf("delete-passkey --all failed: err=%v out=%q", err, out.String())
	}

	// 5. reset-password updates password and revokes active sessions
	out.Reset()
	_, err = Run([]string{"admin", "reset-password", "--password", "UpdatedStrongPass999!"}, info, nil, &out, &errBuf)
	if err != nil {
		t.Fatalf("second reset-password failed: %v", err)
	}

	// 6. rotate-key
	out.Reset()
	_, err = Run([]string{"admin", "rotate-key"}, info, nil, &out, &errBuf)
	if err != nil || !strings.Contains(out.String(), "new active kid=") {
		t.Fatalf("rotate-key failed: err=%v out=%q", err, out.String())
	}

	// 7. backup
	backupPath := filepath.Join(dir, "snap", "backup.db")
	out.Reset()
	_, err = Run([]string{"backup", backupPath}, info, nil, &out, &errBuf)
	if err != nil {
		t.Fatalf("backup failed: %v", err)
	}
	if _, statErr := os.Stat(backupPath); statErr != nil {
		t.Fatalf("backup file missing: %v", statErr)
	}

	// Verify session was revoked and new password verifies against backup!
	stCheck, err := store.Open(backupPath)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer stCheck.Close()
	if _, err := stCheck.GetSessionByToken(rawSes); err == nil {
		t.Fatal("expected session to be revoked by CLI reset-password")
	}
	uCheck, _ := stCheck.GetAdmin()
	if ok, _ := auth.VerifyPassword("UpdatedStrongPass999!", uCheck.PasswordHash); !ok {
		t.Fatal("expected updated password hash in backup")
	}
}
