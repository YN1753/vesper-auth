package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds runtime configuration for Vesper Auth.
type Config struct {
	Issuer               string
	ListenAddr           string
	DBPath               string
	AdminUsername        string
	AdminEmail           string
	AdminPassword        string
	RPID                 string
	RPDisplayName        string
	RPOrigins            []string
	SessionTTL           time.Duration
	AccessTokenTTL       time.Duration
	IDTokenTTL           time.Duration
	RefreshTokenTTL      time.Duration
	AuthCodeTTL          time.Duration
	CookieSecure         bool
	TrustProxy           bool
	RateLimitMaxAttempts int
	RateLimitWindow      time.Duration
	RateLimitLockout     time.Duration
}

// LoadFromEnv loads configuration from environment variables with sensible defaults.
func LoadFromEnv() (*Config, error) {
	issuer := strings.TrimRight(getEnv("AUTH_ISSUER", "http://127.0.0.1:8090"), "/")
	parsedIssuer, err := url.Parse(issuer)
	if err != nil || parsedIssuer.Scheme == "" || parsedIssuer.Host == "" {
		return nil, fmt.Errorf("invalid AUTH_ISSUER %q", issuer)
	}

	rpid := getEnv("AUTH_RP_ID", parsedIssuer.Hostname())
	if rpid == "" {
		return nil, fmt.Errorf("cannot determine WebAuthn RP ID from AUTH_ISSUER %q", issuer)
	}

	var origins []string
	if raw := strings.TrimSpace(os.Getenv("AUTH_RP_ORIGINS")); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			p := strings.TrimRight(strings.TrimSpace(part), "/")
			if p != "" {
				origins = append(origins, p)
			}
		}
	} else {
		origins = []string{issuer}
	}

	cookieSecure := strings.EqualFold(parsedIssuer.Scheme, "https")
	if v, ok := getEnvBool("AUTH_COOKIE_SECURE"); ok {
		cookieSecure = v
	}

	trustProxy := true
	if v, ok := getEnvBool("AUTH_TRUST_PROXY"); ok {
		trustProxy = v
	}

	cfg := &Config{
		Issuer:               issuer,
		ListenAddr:           getEnv("AUTH_LISTEN", "127.0.0.1:8090"),
		DBPath:               getEnv("AUTH_DB_PATH", "./data/auth.db"),
		AdminUsername:        getEnv("AUTH_ADMIN_USER", "admin"),
		AdminEmail:           getEnv("AUTH_ADMIN_EMAIL", "admin@starryheavens.uk"),
		AdminPassword:        os.Getenv("AUTH_ADMIN_PASSWORD"),
		RPID:                 rpid,
		RPDisplayName:        getEnv("AUTH_RP_DISPLAY_NAME", "Vesper Auth"),
		RPOrigins:            origins,
		SessionTTL:           getEnvDuration("AUTH_SESSION_TTL", 7*24*time.Hour),
		AccessTokenTTL:       getEnvDuration("AUTH_ACCESS_TOKEN_TTL", time.Hour),
		IDTokenTTL:           getEnvDuration("AUTH_ID_TOKEN_TTL", time.Hour),
		RefreshTokenTTL:      getEnvDuration("AUTH_REFRESH_TOKEN_TTL", 30*24*time.Hour),
		AuthCodeTTL:          getEnvDuration("AUTH_CODE_TTL", 5*time.Minute),
		CookieSecure:         cookieSecure,
		TrustProxy:           trustProxy,
		RateLimitMaxAttempts: getEnvInt("AUTH_RATE_LIMIT_MAX", 5),
		RateLimitWindow:      getEnvDuration("AUTH_RATE_LIMIT_WINDOW", 10*time.Minute),
		RateLimitLockout:     getEnvDuration("AUTH_RATE_LIMIT_LOCKOUT", 15*time.Minute),
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func getEnvBool(key string) (bool, bool) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return false, false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, false
	}
	return b, true
}

func getEnvInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}
