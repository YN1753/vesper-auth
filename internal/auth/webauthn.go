package auth

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/YN1753/vesper-auth/internal/store"
)

// ErrCloneWarning indicates a WebAuthn authenticator reported an anomalous signature counter rollback.
var ErrCloneWarning = errors.New("authenticator clone warning detected")

// WebAuthnUser adapts store.AdminUser and its registered Passkey credentials to webauthn.User.
type WebAuthnUser struct {
	User        *store.AdminUser
	Credentials []webauthn.Credential
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.User.WebAuthnUserID
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.User.Username
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	if u.User.DisplayName != "" {
		return u.User.DisplayName
	}
	return u.User.Username
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

type ceremonyState struct {
	session    *webauthn.SessionData
	userID     string
	deviceName string
	expiresAt  time.Time
}

// PasskeyManager wraps go-webauthn ceremonies and SQLite credential persistence.
type PasskeyManager struct {
	wa         *webauthn.WebAuthn
	store      *store.Store
	mu         sync.Mutex
	ceremonies map[string]*ceremonyState
}

// NewPasskeyManager initializes a WebAuthn Relying Party using the given RP ID, display name, and allowed origins.
func NewPasskeyManager(st *store.Store, rpID, rpDisplayName string, rpOrigins []string) (*PasskeyManager, error) {
	reqResident := true
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     rpOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: &reqResident,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   protocol.VerificationPreferred,
		},
		AttestationPreference: protocol.PreferNoAttestation,
	})
	if err != nil {
		return nil, fmt.Errorf("init webauthn: %w", err)
	}
	return &PasskeyManager{
		wa:         wa,
		store:      st,
		ceremonies: make(map[string]*ceremonyState),
	}, nil
}

// LoadWebAuthnUser builds a WebAuthnUser populated with all credentials for user.
func (pm *PasskeyManager) LoadWebAuthnUser(user *store.AdminUser) (*WebAuthnUser, error) {
	recs, err := pm.store.ListPasskeys(user.ID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(recs))
	for _, rec := range recs {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(rec.CredentialJSON), &c); err != nil {
			return nil, fmt.Errorf("decode stored passkey %s: %w", rec.ID, err)
		}
		creds = append(creds, c)
	}
	return &WebAuthnUser{User: user, Credentials: creds}, nil
}

// BeginRegistration starts a Passkey registration ceremony for the authenticated admin.
func (pm *PasskeyManager) BeginRegistration(user *store.AdminUser, deviceName string) (string, *protocol.CredentialCreation, error) {
	waUser, err := pm.LoadWebAuthnUser(user)
	if err != nil {
		return "", nil, err
	}

	exclusions := make([]protocol.CredentialDescriptor, 0, len(waUser.Credentials))
	for _, cred := range waUser.Credentials {
		exclusions = append(exclusions, cred.Descriptor())
	}

	opts := []webauthn.RegistrationOption{
		webauthn.WithExclusions(exclusions),
	}
	creation, session, err := pm.wa.BeginRegistration(waUser, opts...)
	if err != nil {
		return "", nil, err
	}

	cid, err := store.RandomHex(16)
	if err != nil {
		return "", nil, err
	}
	pm.putCeremony(cid, &ceremonyState{
		session:    session,
		userID:     user.ID,
		deviceName: deviceName,
		expiresAt:  time.Now().Add(5 * time.Minute),
	})
	return cid, creation, nil
}

// FinishRegistration completes a Passkey registration ceremony and stores the credential.
func (pm *PasskeyManager) FinishRegistration(user *store.AdminUser, ceremonyID string, r *http.Request) (*store.PasskeyRecord, error) {
	st, ok := pm.popCeremony(ceremonyID)
	if !ok || st.userID != user.ID {
		return nil, errors.New("registration session expired or invalid")
	}

	waUser, err := pm.LoadWebAuthnUser(user)
	if err != nil {
		return nil, err
	}

	cred, err := pm.wa.FinishRegistration(waUser, *st.session, r)
	if err != nil {
		return nil, err
	}

	credJSON, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	aaguid := ""
	if len(cred.Authenticator.AAGUID) > 0 {
		aaguid = hex.EncodeToString(cred.Authenticator.AAGUID)
	}

	return pm.store.CreatePasskey(user.ID, st.deviceName, cred.ID, string(credJSON), aaguid, cred.Authenticator.SignCount)
}

// BeginLogin starts a modal discoverable (passwordless) Passkey authentication ceremony.
func (pm *PasskeyManager) BeginLogin() (string, *protocol.CredentialAssertion, error) {
	assertion, session, err := pm.wa.BeginDiscoverableLogin()
	if err != nil {
		return "", nil, err
	}
	cid, err := store.RandomHex(16)
	if err != nil {
		return "", nil, err
	}
	pm.putCeremony(cid, &ceremonyState{
		session:   session,
		expiresAt: time.Now().Add(5 * time.Minute),
	})
	return cid, assertion, nil
}

// BeginConditionalLogin starts a WebAuthn Conditional UI ceremony for input autofill mediation.
func (pm *PasskeyManager) BeginConditionalLogin() (string, *protocol.CredentialAssertion, error) {
	assertion, session, err := pm.wa.BeginDiscoverableMediatedLogin(protocol.MediationConditional)
	if err != nil {
		return "", nil, err
	}
	cid, err := store.RandomHex(16)
	if err != nil {
		return "", nil, err
	}
	pm.putCeremony(cid, &ceremonyState{
		session:   session,
		expiresAt: time.Now().Add(10 * time.Minute),
	})
	return cid, assertion, nil
}

// FinishLogin verifies a Passkey assertion, rejects cloned authenticators, and updates sign count.
func (pm *PasskeyManager) FinishLogin(ceremonyID string, r *http.Request) (*store.AdminUser, *webauthn.Credential, error) {
	st, ok := pm.popCeremony(ceremonyID)
	if !ok {
		return nil, nil, errors.New("login ceremony expired or invalid")
	}

	var matchedUser *store.AdminUser
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		var user *store.AdminUser
		var err error
		if len(userHandle) > 0 {
			user, err = pm.store.GetAdminByWebAuthnID(userHandle)
		} else {
			user, err = pm.store.GetAdmin()
		}
		if err != nil {
			return nil, err
		}
		matchedUser = user
		return pm.LoadWebAuthnUser(user)
	}

	_, cred, err := pm.wa.FinishPasskeyLogin(handler, *st.session, r)
	if err != nil {
		return nil, nil, err
	}
	if matchedUser == nil {
		return nil, nil, errors.New("matched user missing")
	}

	if err := CheckCloneWarning(cred); err != nil {
		return matchedUser, cred, err
	}

	if cred != nil {
		if credJSON, mErr := json.Marshal(cred); mErr == nil {
			_ = pm.store.UpdatePasskeyCredential(cred.ID, string(credJSON), cred.Authenticator.SignCount)
		}
	}
	return matchedUser, cred, nil
}

// BeginSudoAssertion starts a re-authentication ceremony restricted to user's bound Passkeys.
func (pm *PasskeyManager) BeginSudoAssertion(user *store.AdminUser) (string, *protocol.CredentialAssertion, error) {
	waUser, err := pm.LoadWebAuthnUser(user)
	if err != nil {
		return "", nil, err
	}
	if len(waUser.Credentials) == 0 {
		return "", nil, errors.New("当前账号尚未绑定 Passkey，请使用主密码完成验证")
	}
	assertion, session, err := pm.wa.BeginLogin(waUser)
	if err != nil {
		return "", nil, err
	}
	cid, err := store.RandomHex(16)
	if err != nil {
		return "", nil, err
	}
	pm.putCeremony(cid, &ceremonyState{
		session:   session,
		userID:    user.ID,
		expiresAt: time.Now().Add(5 * time.Minute),
	})
	return cid, assertion, nil
}

// FinishSudoAssertion completes Passkey re-authentication for Sudo Mode elevation.
func (pm *PasskeyManager) FinishSudoAssertion(user *store.AdminUser, ceremonyID string, r *http.Request) error {
	st, ok := pm.popCeremony(ceremonyID)
	if !ok || st.userID != user.ID {
		return errors.New("验证挑战已过期，请重试")
	}
	waUser, err := pm.LoadWebAuthnUser(user)
	if err != nil {
		return err
	}
	cred, err := pm.wa.FinishLogin(waUser, *st.session, r)
	if err != nil {
		return err
	}
	if err := CheckCloneWarning(cred); err != nil {
		return err
	}
	if cred != nil {
		if credJSON, mErr := json.Marshal(cred); mErr == nil {
			_ = pm.store.UpdatePasskeyCredential(cred.ID, string(credJSON), cred.Authenticator.SignCount)
		}
	}
	return nil
}

// CheckCloneWarning returns ErrCloneWarning if the authenticator reported a cloned signature counter.
func CheckCloneWarning(cred *webauthn.Credential) error {
	if cred != nil && cred.Authenticator.CloneWarning {
		return ErrCloneWarning
	}
	return nil
}

func (pm *PasskeyManager) putCeremony(id string, st *ceremonyState) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	now := time.Now()
	for k, v := range pm.ceremonies {
		if now.After(v.expiresAt) {
			delete(pm.ceremonies, k)
		}
	}
	pm.ceremonies[id] = st
}

func (pm *PasskeyManager) popCeremony(id string) (*ceremonyState, bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	st, ok := pm.ceremonies[id]
	if !ok {
		return nil, false
	}
	delete(pm.ceremonies, id)
	if time.Now().After(st.expiresAt) {
		return nil, false
	}
	return st, true
}
