package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestReadWritePoolConcurrencyCleanupAndBackup(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "live.db")
	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	if err := st.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	user, err := st.CreateAdmin("starry", "starry@starryheavens.uk", "Starry", "$argon2id$dummy")
	if err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	_, err = st.CreateOAuthClient("nezha", "哪吒监控", "", "hash", []string{"https://dash.starryheavens.uk/oauth2/callback"}, true, false, false)
	if err != nil {
		t.Fatalf("CreateOAuthClient: %v", err)
	}

	// Concurrent reads across reader pool while writing audit logs on writer pool.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := st.GetAdminByID(user.ID); err != nil {
					t.Errorf("GetAdminByID failed: %v", err)
				}
				if !st.IsClientOriginAllowed("https://dash.starryheavens.uk") {
					t.Error("expected IsClientOriginAllowed true")
				}
			}
		}()
	}
	for i := 0; i < 15; i++ {
		if err := st.RecordAudit("auth.login_password", "starry", "203.0.113.9", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/605.1", "session", "ok", "success"); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	}
	wg.Wait()

	// Insert an expired session and an old audit log (120 days old), then verify CleanupExpired purges both.
	_, _, err = st.CreateSession(user.ID, "127.0.0.1", "Mozilla/5.0 (Android 14; Mobile) Chrome/120.0", "passkey", -10)
	if err != nil {
		t.Fatalf("CreateSession expired: %v", err)
	}
	oldTs := time.Now().Add(-120 * 24 * time.Hour).Unix()
	if _, err := st.DB().Exec(`INSERT INTO audit_logs (event_type, actor, ip, user_agent, target, detail, status, created_at) VALUES ('auth.old', 'starry', '1.1.1.1', '', '', 'legacy', 'failure', ?)`, oldTs); err != nil {
		t.Fatalf("insert old audit: %v", err)
	}

	purged, err := st.CleanupExpired(90)
	if err != nil {
		t.Fatalf("CleanupExpired: %v", err)
	}
	if purged < 2 {
		t.Fatalf("expected at least 2 purged rows (expired session + old audit), got %d", purged)
	}

	// Verify filtered audit log queries.
	_ = st.RecordAudit("oauth.refresh_reuse", "nezha", "198.51.100.8", "Go-http-client/1.1", "nezha", "replay", "failure")
	failLogs, failTotal, err := st.ListAuditLogsFiltered(AuditFilter{Status: "failure", Category: "oauth.", Query: "198.51.100.8", Limit: 10})
	if err != nil {
		t.Fatalf("ListAuditLogsFiltered: %v", err)
	}
	if failTotal != 1 || len(failLogs) != 1 || failLogs[0].EventType != "oauth.refresh_reuse" {
		t.Fatalf("unexpected filtered logs: total=%d logs=%+v", failTotal, failLogs)
	}

	// Verify online atomic backup via VACUUM INTO while database remains open.
	backupPath := filepath.Join(dir, "backups", "snapshot.db")
	if err := st.BackupTo(context.Background(), backupPath); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}

	restored, err := Open(backupPath)
	if err != nil {
		t.Fatalf("open backup snapshot: %v", err)
	}
	defer restored.Close()

	u2, err := restored.GetAdmin()
	if err != nil || u2.Username != "starry" {
		t.Fatalf("backup missing admin user: err=%v user=%+v", err, u2)
	}
	c2, err := restored.GetOAuthClient("nezha")
	if err != nil || c2.Name != "哪吒监控" {
		t.Fatalf("backup missing client: err=%v client=%+v", err, c2)
	}
}

func TestParseUserAgentLabel(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15": "macOS / Safari",
		"Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36": "Android / Chrome",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0":             "Windows / Edge",
		"curl/8.7.1": "curl CLI",
	}
	for ua, want := range cases {
		if got := ParseUserAgentLabel(ua); got != want {
			t.Fatalf("ParseUserAgentLabel(%q) = %q, want %q", ua, got, want)
		}
	}
}
