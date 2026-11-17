package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/YN1753/vesper-auth/internal/auth"
	"github.com/YN1753/vesper-auth/internal/store"
)

func (s *Server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	has, err := s.store.HasAdmin()
	if err != nil {
		s.renderer.RenderError(w, http.StatusInternalServerError, "系统错误", "无法检查管理员初始化状态。")
		return
	}
	if has {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.renderer.RenderSetup(w, SetupViewData{
		IssuerHost:   s.issuer.Host,
		DefaultUser:  s.cfg.AdminUsername,
		DefaultEmail: s.cfg.AdminEmail,
	})
}

func (s *Server) handleSetupAPI(w http.ResponseWriter, r *http.Request) {
	has, err := s.store.HasAdmin()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "无法检查系统状态")
		return
	}
	if has {
		writeAPIError(w, http.StatusForbidden, "系统已完成初始化，禁止公开注册")
		return
	}

	var req struct {
		Username    string `json:"username"`
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "请求参数格式错误")
		return
	}

	username := strings.TrimSpace(req.Username)
	email := strings.TrimSpace(req.Email)
	displayName := strings.TrimSpace(req.DisplayName)
	if username == "" || email == "" || len(req.Password) < 10 {
		writeAPIError(w, http.StatusBadRequest, "用户名、邮箱不能为空且主密码至少 10 位")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "密码加密失败")
		return
	}

	user, err := s.store.CreateAdmin(username, email, displayName, hash)
	if err != nil {
		writeAPIError(w, http.StatusConflict, "管理员账号已存在")
		return
	}

	ip := s.clientIP(r)
	if _, err := s.sessions.Issue(w, r, user.ID, ip, r.UserAgent(), "password"); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "创建登录会话失败")
		return
	}
	_ = s.store.RecordAudit("auth.setup", user.Username, ip, r.UserAgent(), user.ID, "initial admin account created", "success")
	writeJSON(w, http.StatusCreated, map[string]string{"redirect": "/"})
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	has, err := s.store.HasAdmin()
	if err != nil {
		s.renderer.RenderError(w, http.StatusInternalServerError, "系统错误", "无法读取系统状态。")
		return
	}
	if !has {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	reqID := strings.TrimSpace(r.URL.Query().Get("req"))
	nextURL := sanitizeNextURL(r.URL.Query().Get("next"))
	reauth := r.URL.Query().Get("reauth") == "1"

	if !reauth {
		if _, _, err := s.sessions.Authenticate(r); err == nil {
			if reqID != "" {
				http.Redirect(w, r, "/oauth2/authorize?req="+url.QueryEscape(reqID), http.StatusFound)
				return
			}
			if nextURL != "" {
				http.Redirect(w, r, nextURL, http.StatusFound)
				return
			}
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	var pendingClient string
	if reqID != "" {
		if ar, err := s.store.GetAuthRequest(reqID); err == nil {
			if c, err := s.store.GetOAuthClient(ar.ClientID); err == nil {
				pendingClient = c.Name
			}
		} else {
			reqID = ""
		}
	}

	s.renderer.RenderLogin(w, LoginViewData{
		IssuerHost:    s.issuer.Host,
		PendingClient: pendingClient,
		LoggedOut:     r.URL.Query().Get("logged_out") == "1",
		Reauth:        reauth,
		ReqID:         reqID,
		NextURL:       nextURL,
	})
}

func (s *Server) handlePasswordLogin(w http.ResponseWriter, r *http.Request) {
	has, err := s.store.HasAdmin()
	if err != nil || !has {
		writeAPIError(w, http.StatusServiceUnavailable, "系统尚未初始化管理员账号")
		return
	}

	var req struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
		ReqID      string `json:"req"`
		Next       string `json:"next"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "请求参数格式错误")
		return
	}

	ident := strings.TrimSpace(req.Identifier)
	ip := s.clientIP(r)
	rlKeys := []string{"login:ip:" + ip}
	if ident != "" {
		rlKeys = append(rlKeys, "login:acct:"+strings.ToLower(ident))
	}

	if ok, wait := s.limiter.Check(rlKeys...); !ok {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())+1))
		_ = s.store.RecordAudit("auth.login_rate_limited", ident, ip, r.UserAgent(), "password", "rate limit active", "failure")
		writeAPIError(w, http.StatusTooManyRequests, fmt.Sprintf("失败次数过多，请在 %d 秒后重试", int(wait.Seconds())+1))
		return
	}

	if ident == "" || req.Password == "" {
		s.limiter.RecordFailure(rlKeys...)
		writeAPIError(w, http.StatusUnauthorized, "用户名或主密码错误")
		return
	}

	user, err := s.store.GetAdminByUsernameOrEmail(ident)
	if err != nil {
		locked, wait := s.limiter.RecordFailure(rlKeys...)
		_ = s.store.RecordAudit("auth.login_password", ident, ip, r.UserAgent(), "password", "unknown account", "failure")
		if locked {
			if s.notifier != nil {
				s.notifier.Notify("auth.login_rate_limited", "warning", ident, ip, "password", "login brute-force lockout triggered")
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())+1))
			writeAPIError(w, http.StatusTooManyRequests, "登录失败次数过多，已触发临时冷却保护")
			return
		}
		writeAPIError(w, http.StatusUnauthorized, "用户名或主密码错误")
		return
	}

	valid, err := auth.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !valid {
		locked, wait := s.limiter.RecordFailure(rlKeys...)
		_ = s.store.RecordAudit("auth.login_password", user.Username, ip, r.UserAgent(), "password", "invalid password", "failure")
		if locked {
			if s.notifier != nil {
				s.notifier.Notify("auth.login_rate_limited", "warning", user.Username, ip, "password", "master password brute-force lockout triggered")
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())+1))
			writeAPIError(w, http.StatusTooManyRequests, "登录失败次数过多，已触发临时冷却保护")
			return
		}
		writeAPIError(w, http.StatusUnauthorized, "用户名或主密码错误")
		return
	}

	s.limiter.Reset(rlKeys...)
	s.replaceBrowserSession(w, r)
	if _, err := s.sessions.Issue(w, r, user.ID, ip, r.UserAgent(), "password"); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "创建会话失败")
		return
	}
	s.satisfyAuthRequestReauth(req.ReqID)
	_ = s.store.RecordAudit("auth.login_password", user.Username, ip, r.UserAgent(), "session", "master password login", "success")

	writeJSON(w, http.StatusOK, map[string]string{
		"redirect": resolveLoginRedirect(req.ReqID, req.Next),
	})
}

func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if ok, wait := s.limiter.Check("login:ip:" + ip); !ok {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())+1))
		writeAPIError(w, http.StatusTooManyRequests, fmt.Sprintf("请求过于频繁，请在 %d 秒后重试", int(wait.Seconds())+1))
		return
	}

	has, err := s.store.HasAdmin()
	if err != nil || !has {
		writeAPIError(w, http.StatusBadRequest, "系统尚未初始化")
		return
	}

	cid, assertion, err := s.passkeys.BeginLogin()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "无法发起 Passkey 登录")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ceremony_id": cid,
		"options":     assertion,
	})
}

func (s *Server) handlePasskeyConditionalBegin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if ok, wait := s.limiter.Check("login:ip:" + ip); !ok {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())+1))
		writeAPIError(w, http.StatusTooManyRequests, "请求过于频繁")
		return
	}

	has, err := s.store.HasAdmin()
	if err != nil || !has {
		writeAPIError(w, http.StatusBadRequest, "系统尚未初始化")
		return
	}

	cid, assertion, err := s.passkeys.BeginConditionalLogin()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "无法发起条件式 Passkey 请求")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ceremony_id": cid,
		"options":     assertion,
	})
}

func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	rlKey := "login:ip:" + ip
	if ok, wait := s.limiter.Check(rlKey); !ok {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())+1))
		writeAPIError(w, http.StatusTooManyRequests, fmt.Sprintf("请求过于频繁，请在 %d 秒后重试", int(wait.Seconds())+1))
		return
	}

	ceremonyID := strings.TrimSpace(r.Header.Get("X-Ceremony-ID"))
	if ceremonyID == "" {
		ceremonyID = strings.TrimSpace(r.URL.Query().Get("ceremony_id"))
	}
	if ceremonyID == "" {
		writeAPIError(w, http.StatusBadRequest, "缺少 ceremony_id")
		return
	}

	user, _, err := s.passkeys.FinishLogin(ceremonyID, r)
	if err != nil {
		if errors.Is(err, auth.ErrCloneWarning) {
			actor := "unknown"
			if user != nil {
				actor = user.Username
			}
			_ = s.store.RecordAudit("passkey.clone_detected", actor, ip, r.UserAgent(), "passkey", "authenticator signature counter rollback detected", "failure")
			if s.notifier != nil {
				s.notifier.Notify("passkey.clone_detected", "critical", actor, ip, "passkey", "authenticator clone warning detected; login blocked")
			}
			writeAPIError(w, http.StatusForbidden, "检测到硬件密钥计数器异常回退（疑似克隆风险），本次登录已拦截")
			return
		}
		if locked, _ := s.limiter.RecordFailure(rlKey); locked && s.notifier != nil {
			s.notifier.Notify("auth.login_rate_limited", "warning", "passkey", ip, "passkey", "repeated failed passkey assertions")
		}
		_ = s.store.RecordAudit("auth.login_passkey", "unknown", ip, r.UserAgent(), "passkey", err.Error(), "failure")
		writeAPIError(w, http.StatusUnauthorized, "Passkey 验证失败或凭证未绑定")
		return
	}

	s.limiter.Reset(rlKey)
	s.replaceBrowserSession(w, r)
	if _, err := s.sessions.Issue(w, r, user.ID, ip, r.UserAgent(), "passkey"); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "创建会话失败")
		return
	}

	reqID := strings.TrimSpace(r.URL.Query().Get("req"))
	s.satisfyAuthRequestReauth(reqID)
	_ = s.store.RecordAudit("auth.login_passkey", user.Username, ip, r.UserAgent(), "session", "WebAuthn passkey login", "success")

	writeJSON(w, http.StatusOK, map[string]string{
		"redirect": resolveLoginRedirect(reqID, ""),
	})
}

func (s *Server) handleLogoutAPI(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	s.sessions.Clear(w, r)
	_ = s.store.RecordAudit("auth.logout", user.Username, s.clientIP(r), r.UserAgent(), "session", "manual logout", "success")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) replaceBrowserSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.SessionCookieName); err == nil && c.Value != "" {
		_ = s.store.DeleteSessionByToken(c.Value)
	}
}

func (s *Server) satisfyAuthRequestReauth(reqID string) {
	reqID = strings.TrimSpace(reqID)
	if reqID == "" {
		return
	}
	ar, err := s.store.GetAuthRequest(reqID)
	if err != nil {
		return
	}
	var kept []string
	for _, p := range strings.Fields(ar.Prompt) {
		if p != "login" {
			kept = append(kept, p)
		}
	}
	nextPrompt := strings.Join(kept, " ")
	if nextPrompt != ar.Prompt || ar.MaxAge >= 0 {
		_ = s.store.ClearAuthRequestReauth(reqID, nextPrompt)
	}
}

func resolveLoginRedirect(reqID, next string) string {
	if strings.TrimSpace(reqID) != "" {
		return "/oauth2/authorize?req=" + url.QueryEscape(strings.TrimSpace(reqID))
	}
	if safe := sanitizeNextURL(next); safe != "" {
		return safe
	}
	return "/"
}

func sanitizeNextURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return ""
	}
	return raw
}
