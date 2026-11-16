package server

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/YN1753/vesper-auth/internal/auth"
	"github.com/YN1753/vesper-auth/internal/store"
)

type adminHandler func(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser)

func (s *Server) withAdmin(requireCSRF bool, fn adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ses, user, err := s.sessions.Authenticate(r)
		if err != nil {
			writeAPIError(w, http.StatusUnauthorized, "未登录或会话已过期")
			return
		}
		if requireCSRF {
			token := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
			if !s.sessions.VerifyCSRF(ses.ID, token) {
				writeAPIError(w, http.StatusForbidden, "CSRF 校验失败，请刷新页面")
				return
			}
		}
		_ = s.store.TouchSession(ses.ID, s.clientIP(r))
		fn(w, r, ses, user)
	}
}

func (s *Server) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	has, err := s.store.HasAdmin()
	if err != nil {
		s.renderer.RenderError(w, http.StatusInternalServerError, "系统错误", "无法检查系统状态。")
		return
	}
	if !has {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	ses, user, err := s.sessions.Authenticate(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	_ = s.store.TouchSession(ses.ID, s.clientIP(r))

	displayName := user.DisplayName
	if displayName == "" {
		displayName = user.Username
	}
	s.renderer.RenderAdmin(w, AdminViewData{
		Issuer:        s.cfg.Issuer,
		Username:      user.Username,
		Email:         user.Email,
		DisplayName:   displayName,
		IssuerJSON:    toJSString(s.cfg.Issuer),
		CSRFTokenJSON: toJSString(s.sessions.CSRFToken(ses.ID)),
	})
}

func (s *Server) handleAdminOverview(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	clients, err := s.store.ListOAuthClients()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "读取应用列表失败")
		return
	}
	passkeys, err := s.store.ListPasskeys(user.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "读取 Passkey 列表失败")
		return
	}
	sessions, err := s.store.ListActiveSessions(user.ID, ses.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "读取会话列表失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":     user,
		"clients":  clients,
		"passkeys": passkeys,
		"sessions": sessions,
	})
}

func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	var req struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "请求参数格式错误")
		return
	}
	email := strings.TrimSpace(req.Email)
	displayName := strings.TrimSpace(req.DisplayName)
	if email == "" || displayName == "" {
		writeAPIError(w, http.StatusBadRequest, "邮箱和显示名称不能为空")
		return
	}
	if err := s.store.UpdateAdminProfile(user.ID, email, displayName); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "更新资料失败")
		return
	}
	updated, err := s.store.GetAdminByID(user.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "读取更新结果失败")
		return
	}
	_ = s.store.RecordAudit("admin.profile_update", user.Username, s.clientIP(r), r.UserAgent(), user.ID, "email="+email, "success")
	writeJSON(w, http.StatusOK, map[string]any{"user": updated})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "请求参数格式错误")
		return
	}
	if len(req.NewPassword) < 10 {
		writeAPIError(w, http.StatusBadRequest, "新主密码长度至少为 10 位")
		return
	}

	ok, err := auth.VerifyPassword(req.CurrentPassword, user.PasswordHash)
	if err != nil || !ok {
		_ = s.store.RecordAudit("admin.password_change", user.Username, s.clientIP(r), r.UserAgent(), user.ID, "current password mismatch", "failure")
		writeAPIError(w, http.StatusUnauthorized, "当前主密码不正确")
		return
	}

	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "密码哈希生成失败")
		return
	}
	if err := s.store.UpdateAdminPassword(user.ID, newHash); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "密码更新失败")
		return
	}
	_ = s.store.RecordAudit("admin.password_change", user.Username, s.clientIP(r), r.UserAgent(), user.ID, "master password updated", "success")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListPasskeys(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	list, err := s.store.ListPasskeys(user.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "读取 Passkey 失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": list})
}

func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "请求参数格式错误")
		return
	}
	deviceName := strings.TrimSpace(req.Name)
	if deviceName == "" {
		deviceName = "Passkey"
	}

	cid, creation, err := s.passkeys.BeginRegistration(user, deviceName)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "无法创建 Passkey 注册挑战")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ceremony_id": cid,
		"options":     creation,
	})
}

func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	ceremonyID := strings.TrimSpace(r.Header.Get("X-Ceremony-ID"))
	if ceremonyID == "" {
		ceremonyID = strings.TrimSpace(r.URL.Query().Get("ceremony_id"))
	}
	if ceremonyID == "" {
		writeAPIError(w, http.StatusBadRequest, "缺少 ceremony_id")
		return
	}

	rec, err := s.passkeys.FinishRegistration(user, ceremonyID, r)
	if err != nil {
		_ = s.store.RecordAudit("passkey.add", user.Username, s.clientIP(r), r.UserAgent(), "passkey", err.Error(), "failure")
		writeAPIError(w, http.StatusBadRequest, "Passkey 注册验证失败: "+err.Error())
		return
	}
	_ = s.store.RecordAudit("passkey.add", user.Username, s.clientIP(r), r.UserAgent(), rec.Name, "id="+rec.ID, "success")
	writeJSON(w, http.StatusCreated, map[string]any{"passkey": rec})
}

func (s *Server) handleRenamePasskey(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	id := r.PathValue("id")
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "请求参数格式错误")
		return
	}
	if err := s.store.RenamePasskey(user.ID, id, req.Name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "Passkey 不存在")
			return
		}
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.store.RecordAudit("passkey.rename", user.Username, s.clientIP(r), r.UserAgent(), id, "name="+strings.TrimSpace(req.Name), "success")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDeletePasskey(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	id := r.PathValue("id")
	name, err := s.store.DeletePasskey(user.ID, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "Passkey 不存在")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "删除 Passkey 失败")
		return
	}
	_ = s.store.RecordAudit("passkey.delete", user.Username, s.clientIP(r), r.UserAgent(), name, "id="+id, "success")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	list, err := s.store.ListActiveSessions(user.ID, ses.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "读取会话失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": list})
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	id := r.PathValue("id")
	if id == ses.ID {
		writeAPIError(w, http.StatusBadRequest, "不能踢下线当前正在使用的会话，请使用退出登录")
		return
	}
	if err := s.store.DeleteSessionByID(user.ID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "会话不存在")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "操作失败")
		return
	}
	_ = s.store.RecordAudit("session.revoke", user.Username, s.clientIP(r), r.UserAgent(), id, "revoked remote session", "success")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	count, err := s.store.DeleteOtherSessions(user.ID, ses.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "清理会话失败")
		return
	}
	_ = s.store.RecordAudit("session.revoke_others", user.Username, s.clientIP(r), r.UserAgent(), user.ID, "revoked_count="+strconv.FormatInt(count, 10), "success")
	writeJSON(w, http.StatusOK, map[string]any{"revoked": count})
}

type clientPayload struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	RedirectURIs []string `json:"redirect_uris"`
	Trusted      bool     `json:"trusted"`
	PKCERequired bool     `json:"pkce_required"`
	IsPublic     bool     `json:"is_public"`
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	clients, err := s.store.ListOAuthClients()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "读取应用失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	var req clientPayload
	if err := decodeJSON(r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "请求参数格式错误")
		return
	}
	uris, err := validateClientInput(req.Name, req.RedirectURIs)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	var plainSecret, secretHash string
	if !req.IsPublic {
		plainSecret, secretHash, err = generateClientSecret()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "生成客户端密钥失败")
			return
		}
	}

	client, err := s.store.CreateOAuthClient("", req.Name, req.Description, secretHash, uris, req.Trusted, req.PKCERequired, req.IsPublic)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "保存应用失败")
		return
	}
	_ = s.store.RecordAudit("client.create", user.Username, s.clientIP(r), r.UserAgent(), client.Name, "client_id="+client.ID, "success")
	writeJSON(w, http.StatusCreated, map[string]any{
		"client":        client,
		"client_secret": plainSecret,
	})
}

func (s *Server) handleUpdateClient(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	id := r.PathValue("id")
	var req clientPayload
	if err := decodeJSON(r, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "请求参数格式错误")
		return
	}
	uris, err := validateClientInput(req.Name, req.RedirectURIs)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	existing, err := s.store.GetOAuthClient(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "应用不存在")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "读取应用失败")
		return
	}

	updated, err := s.store.UpdateOAuthClient(id, req.Name, req.Description, uris, req.Trusted, req.PKCERequired, req.IsPublic)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "更新应用失败")
		return
	}

	// If switching from Public -> Confidential, generate a fresh secret automatically.
	var newSecret string
	if existing.IsPublic && !req.IsPublic && updated.SecretHash == "" {
		plain, hash, gErr := generateClientSecret()
		if gErr == nil && s.store.UpdateOAuthClientSecret(id, hash) == nil {
			newSecret = plain
			updated, _ = s.store.GetOAuthClient(id)
		}
	}

	_ = s.store.RecordAudit("client.update", user.Username, s.clientIP(r), r.UserAgent(), updated.Name, "client_id="+id, "success")
	writeJSON(w, http.StatusOK, map[string]any{
		"client":        updated,
		"client_secret": newSecret,
	})
}

func (s *Server) handleRotateClientSecret(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	id := r.PathValue("id")
	client, err := s.store.GetOAuthClient(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "应用不存在")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "读取应用失败")
		return
	}
	if client.IsPublic {
		writeAPIError(w, http.StatusBadRequest, "Public 客户端不使用 Client Secret")
		return
	}

	plain, hash, err := generateClientSecret()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "生成新密钥失败")
		return
	}
	if err := s.store.UpdateOAuthClientSecret(id, hash); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "更新密钥失败")
		return
	}
	_ = s.store.RecordAudit("client.secret_rotate", user.Username, s.clientIP(r), r.UserAgent(), client.Name, "client_id="+id, "success")
	writeJSON(w, http.StatusOK, map[string]string{
		"client_id":     id,
		"client_secret": plain,
	})
}

func (s *Server) handleDeleteClient(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	id := r.PathValue("id")
	name, err := s.store.DeleteOAuthClient(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "应用不存在")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "删除应用失败")
		return
	}
	_ = s.store.RecordAudit("client.delete", user.Username, s.clientIP(r), r.UserAgent(), name, "client_id="+id, "success")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request, ses *store.Session, user *store.AdminUser) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 {
		limit = 20
	}
	logs, total, err := s.store.ListAuditLogs(limit, offset)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "读取审计日志失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"logs":  logs,
		"total": total,
	})
}

func validateClientInput(name string, rawURIs []string) ([]string, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("应用名称不能为空")
	}
	seen := make(map[string]struct{}, len(rawURIs))
	uris := make([]string, 0, len(rawURIs))
	for _, raw := range rawURIs {
		uStr := strings.TrimSpace(raw)
		if uStr == "" {
			continue
		}
		u, err := url.Parse(uStr)
		if err != nil || u.Scheme == "" || u.Fragment != "" {
			return nil, errors.New("存在无效的回调地址: " + uStr)
		}
		if (u.Scheme == "http" || u.Scheme == "https") && u.Host == "" {
			return nil, errors.New("HTTP/HTTPS 回调地址缺少域名: " + uStr)
		}
		if _, ok := seen[uStr]; !ok {
			seen[uStr] = struct{}{}
			uris = append(uris, uStr)
		}
	}
	if len(uris) == 0 {
		return nil, errors.New("请至少配置一条有效的 redirect_uri")
	}
	return uris, nil
}

func generateClientSecret() (plain, hash string, err error) {
	rnd, err := store.RandomHex(24)
	if err != nil {
		return "", "", err
	}
	plain = "vs_" + rnd
	return plain, store.HashToken(plain), nil
}
