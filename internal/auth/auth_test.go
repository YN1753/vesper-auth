package auth

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/YN1753/vesper-auth/internal/store"
)

func TestPasswordHashAndVerify(t *testing.T) {
	hash, err := HashPassword("Vesper-Strong-Pass-2026!")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	ok, err := VerifyPassword("Vesper-Strong-Pass-2026!", hash)
	if err != nil || !ok {
		t.Fatalf("VerifyPassword expected true, got ok=%v err=%v", ok, err)
	}

	ok, err = VerifyPassword("wrong-password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword unexpected err: %v", err)
	}
	if ok {
		t.Fatal("VerifyPassword should reject wrong password")
	}

	hash2, err := HashPassword("Vesper-Strong-Pass-2026!")
	if err != nil {
		t.Fatalf("HashPassword second call failed: %v", err)
	}
	if hash == hash2 {
		t.Fatal("expected unique salts per HashPassword call")
	}

	if _, err := VerifyPassword("abc", "not-a-phc-hash"); err == nil {
		t.Fatal("expected error for malformed hash")
	}
}

func TestRateLimiterCooldownAndReset(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	rl := NewRateLimiter(3, 5*time.Minute, 10*time.Minute)
	rl.SetClock(func() time.Time { return now })

	ipKey := "login:ip:192.0.2.10"
	acctKey := "login:acct:admin"

	if ok, _ := rl.Check(ipKey, acctKey); !ok {
		t.Fatal("expected initial request to be allowed")
	}

	for i := 0; i < 2; i++ {
		locked, _ := rl.RecordFailure(ipKey, acctKey)
		if locked {
			t.Fatalf("unexpected lockout at failure %d", i+1)
		}
	}

	locked, wait := rl.RecordFailure(ipKey, acctKey)
	if !locked || wait != 10*time.Minute {
		t.Fatalf("expected 10m lockout, got locked=%v wait=%v", locked, wait)
	}

	if ok, rem := rl.Check(ipKey); ok || rem <= 0 {
		t.Fatalf("expected IP key locked, got ok=%v rem=%v", ok, rem)
	}
	if ok, rem := rl.Check("login:ip:198.51.100.2", acctKey); ok || rem <= 0 {
		t.Fatalf("expected account key locked across IPs, got ok=%v rem=%v", ok, rem)
	}

	now = now.Add(5 * time.Minute)
	if ok, rem := rl.Check(ipKey); ok || rem != 5*time.Minute {
		t.Fatalf("expected 5m remaining, got ok=%v rem=%v", ok, rem)
	}

	now = now.Add(5*time.Minute + time.Second)
	if ok, _ := rl.Check(ipKey, acctKey); !ok {
		t.Fatal("expected lockout to expire")
	}

	rl.RecordFailure(ipKey)
	rl.RecordFailure(ipKey)
	rl.RecordFailure(ipKey)
	if ok, _ := rl.Check(ipKey); ok {
		t.Fatal("expected locked before reset")
	}
	rl.Reset(ipKey)
	if ok, _ := rl.Check(ipKey); !ok {
		t.Fatal("expected unlocked after reset")
	}
}

func TestRateLimiterMaxBucketsEviction(t *testing.T) {
	now := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	rl := NewRateLimiter(2, 10*time.Minute, 15*time.Minute)
	rl.SetMaxBuckets(5)
	rl.SetClock(func() time.Time { return now })

	// Lock one specific IP (2 failures -> locked).
	rl.RecordFailure("locked-ip")
	rl.RecordFailure("locked-ip")

	// Flood 50 distinct single-failure keys; locked-ip must stay protected and map size <= 5.
	for i := 0; i < 50; i++ {
		now = now.Add(time.Second)
		rl.RecordFailure(fmt.Sprintf("scan-ip-%d", i))
		if rl.Len() > 5 {
			t.Fatalf("bucket count exceeded maxBuckets=5: got %d", rl.Len())
		}
	}

	if ok, _ := rl.Check("locked-ip"); ok {
		t.Fatal("locked-ip should not be evicted by single-hit random IP flood")
	}
}

func TestPersistentCSRFSecretAcrossRestarts(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "csrf.db")

	st1, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open st1: %v", err)
	}
	sm1, err := NewSessionManager(st1, time.Hour, true)
	if err != nil {
		t.Fatalf("NewSessionManager 1: %v", err)
	}
	tok1 := sm1.CSRFToken("ses_abc123")
	_ = st1.Close()

	st2, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open st2: %v", err)
	}
	defer st2.Close()

	sm2, err := NewSessionManager(st2, time.Hour, true)
	if err != nil {
		t.Fatalf("NewSessionManager 2: %v", err)
	}
	if !sm2.VerifyCSRF("ses_abc123", tok1) {
		t.Fatal("expected CSRF token generated before restart to remain valid after restart")
	}
}

func TestCloneWarningDetection(t *testing.T) {
	normal := &webauthn.Credential{}
	if err := CheckCloneWarning(normal); err != nil {
		t.Fatalf("unexpected error for normal credential: %v", err)
	}

	cloned := &webauthn.Credential{
		Authenticator: webauthn.Authenticator{CloneWarning: true},
	}
	if err := CheckCloneWarning(cloned); !errors.Is(err, ErrCloneWarning) {
		t.Fatalf("expected ErrCloneWarning, got %v", err)
	}
}
