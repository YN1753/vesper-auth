package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/YN1753/vesper-auth/internal/store"
)

const SessionCookieName = "vesper_session"

// SessionManager manages browser authentication cookies and per-session CSRF tokens.
type SessionManager struct {
	store        *store.Store
	ttl          time.Duration
	cookieSecure bool
	csrfSecret   []byte
}

// NewSessionManager creates a SessionManager with an ephemeral HMAC key for CSRF derivation.
func NewSessionManager(st *store.Store, ttl time.Duration, cookieSecure bool) (*SessionManager, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return &SessionManager{
		store:        st,
		ttl:          ttl,
		cookieSecure: cookieSecure,
		csrfSecret:   secret,
	}, nil
}

// Issue creates a persistent session and sets the HttpOnly session cookie on w.
func (m *SessionManager) Issue(w http.ResponseWriter, r *http.Request, userID, ip, ua, authMethod string) (*store.Session, error) {
	rawToken, ses, err := m.store.CreateSession(userID, ip, ua, authMethod, int64(m.ttl.Seconds()))
	if err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    rawToken,
		Path:     "/",
		MaxAge:   int(m.ttl.Seconds()),
		HttpOnly: true,
		Secure:   m.isSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
	return ses, nil
}

// Authenticate reads the session cookie from r and validates it against the store.
func (m *SessionManager) Authenticate(r *http.Request) (*store.Session, *store.AdminUser, error) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return nil, nil, store.ErrNotFound
	}
	ses, err := m.store.GetSessionByToken(c.Value)
	if err != nil {
		return nil, nil, err
	}
	user, err := m.store.GetAdminByID(ses.UserID)
	if err != nil {
		return nil, nil, err
	}
	return ses, user, nil
}

// Clear deletes the session from the store and expires the browser cookie.
func (m *SessionManager) Clear(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		_ = m.store.DeleteSessionByToken(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   m.isSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// CSRFToken computes a deterministic CSRF token bound to sessionID.
func (m *SessionManager) CSRFToken(sessionID string) string {
	mac := hmac.New(sha256.New, m.csrfSecret)
	mac.Write([]byte(sessionID))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyCSRF checks whether token matches the expected CSRF token for sessionID.
func (m *SessionManager) VerifyCSRF(sessionID, token string) bool {
	if sessionID == "" || token == "" {
		return false
	}
	expected := m.CSRFToken(sessionID)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(token)) == 1
}

func (m *SessionManager) isSecure(r *http.Request) bool {
	if m.cookieSecure {
		return true
	}
	if r != nil {
		if r.TLS != nil {
			return true
		}
		if xfp := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); xfp != "" {
			first := strings.TrimSpace(strings.Split(xfp, ",")[0])
			if strings.EqualFold(first, "https") {
				return true
			}
		}
	}
	return false
}
