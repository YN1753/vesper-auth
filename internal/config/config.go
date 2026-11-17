package config

import (
	"fmt"
	"net"
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
	SudoTTL              time.Duration
	AccessTokenTTL       time.Duration
	IDTokenTTL           time.Duration
	RefreshTokenTTL      time.Duration
	AuthCodeTTL          time.Duration
	CookieSecure         bool
	TrustProxy           bool
	TrustedProxies       []*net.IPNet
	RateLimitMaxAttempts int
	RateLimitWindow      time.Duration
	RateLimitLockout     time.Duration
	RateLimitMaxBuckets  int
	AuditRetentionDays   int
	KeyRetainCount       int
	AlertWebhookURL      string
	AlertWebhookSecret   string
}

var defaultLoopbackNets = mustParseCIDRs("127.0.0.1/8,::1/128")

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

	trustedProxies, err := ParseTrustedProxies(getEnv("AUTH_TRUSTED_PROXIES", "127.0.0.1/8,::1/128"))
	if err != nil {
		return nil, err
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
		SudoTTL:              getEnvDuration("AUTH_SUDO_TTL", 15*time.Minute),
		AccessTokenTTL:       getEnvDuration("AUTH_ACCESS_TOKEN_TTL", time.Hour),
		IDTokenTTL:           getEnvDuration("AUTH_ID_TOKEN_TTL", time.Hour),
		RefreshTokenTTL:      getEnvDuration("AUTH_REFRESH_TOKEN_TTL", 30*24*time.Hour),
		AuthCodeTTL:          getEnvDuration("AUTH_CODE_TTL", 5*time.Minute),
		CookieSecure:         cookieSecure,
		TrustProxy:           trustProxy,
		TrustedProxies:       trustedProxies,
		RateLimitMaxAttempts: getEnvInt("AUTH_RATE_LIMIT_MAX", 5),
		RateLimitWindow:      getEnvDuration("AUTH_RATE_LIMIT_WINDOW", 10*time.Minute),
		RateLimitLockout:     getEnvDuration("AUTH_RATE_LIMIT_LOCKOUT", 15*time.Minute),
		RateLimitMaxBuckets:  getEnvInt("AUTH_RATE_LIMIT_MAX_BUCKETS", 10000),
		AuditRetentionDays:   getEnvInt("AUTH_AUDIT_RETENTION_DAYS", 90),
		KeyRetainCount:       getEnvInt("AUTH_KEY_RETAIN_COUNT", 3),
		AlertWebhookURL:      strings.TrimSpace(os.Getenv("AUTH_ALERT_WEBHOOK_URL")),
		AlertWebhookSecret:   strings.TrimSpace(os.Getenv("AUTH_ALERT_WEBHOOK_SECRET")),
	}

	return cfg, nil
}

// IsTrustedProxy reports whether remoteAddr belongs to a configured trusted reverse proxy.
func (c *Config) IsTrustedProxy(remoteAddr string) bool {
	if c == nil || !c.TrustProxy {
		return false
	}
	host := strings.TrimSpace(remoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	nets := c.TrustedProxies
	if len(nets) == 0 {
		nets = defaultLoopbackNets
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseTrustedProxies parses a comma-separated list of CIDRs or IP addresses.
func ParseTrustedProxies(raw string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, item := range strings.Split(raw, ",") {
		s := strings.TrimSpace(item)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted proxy IP %q", s)
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			s = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, cidr, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", s, err)
		}
		nets = append(nets, cidr)
	}
	return nets, nil
}

func mustParseCIDRs(raw string) []*net.IPNet {
	nets, err := ParseTrustedProxies(raw)
	if err != nil {
		panic(err)
	}
	return nets
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
