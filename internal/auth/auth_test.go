package auth

import (
	"testing"
	"time"
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

	// Ensure distinct salts produce distinct hashes.
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

	// 2 failures should not lock yet.
	for i := 0; i < 2; i++ {
		locked, _ := rl.RecordFailure(ipKey, acctKey)
		if locked {
			t.Fatalf("unexpected lockout at failure %d", i+1)
		}
	}

	// 3rd failure triggers lockout.
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

	// Advance 5 minutes -> still locked.
	now = now.Add(5 * time.Minute)
	if ok, rem := rl.Check(ipKey); ok || rem != 5*time.Minute {
		t.Fatalf("expected 5m remaining, got ok=%v rem=%v", ok, rem)
	}

	// Advance past lockout -> unlocked.
	now = now.Add(5*time.Minute + time.Second)
	if ok, _ := rl.Check(ipKey, acctKey); !ok {
		t.Fatal("expected lockout to expire")
	}

	// Reset clears active lockout immediately.
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
