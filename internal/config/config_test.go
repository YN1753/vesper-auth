package config

import "testing"

func TestTrustedProxiesAndLoadFromEnv(t *testing.T) {
	t.Setenv("AUTH_ISSUER", "https://auth.starryheavens.uk/")
	t.Setenv("AUTH_TRUSTED_PROXIES", "127.0.0.1/8, ::1/128, 10.0.0.5")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if cfg.Issuer != "https://auth.starryheavens.uk" {
		t.Fatalf("expected trimmed issuer, got %q", cfg.Issuer)
	}
	if !cfg.CookieSecure {
		t.Fatal("expected CookieSecure=true for https issuer")
	}
	if !cfg.IsTrustedProxy("127.0.0.1:45678") || !cfg.IsTrustedProxy("[::1]:8080") || !cfg.IsTrustedProxy("10.0.0.5:9000") {
		t.Fatal("expected configured proxy addresses to be trusted")
	}
	if cfg.IsTrustedProxy("198.51.100.22:12345") {
		t.Fatal("expected external IP to not be trusted")
	}
}
