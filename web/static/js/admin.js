(function () {
  "use strict";

  const bodyDataset = (document.body && document.body.dataset) || {};
  const CFG = {
    issuer: bodyDataset.issuer || window.location.origin,
    csrfToken: bodyDataset.csrfToken || "",
  };

  const state = {
    clients: [],
    passkeys: [],
    sessions: [],
    keys: [],
    lastSecrets: {},
    auditPage: 0,
    auditLimit: 20,
    auditTotal: 0,
    auditStatus: "",
    auditCategory: "",
    auditQuery: "",
  };

  const PRESETS = {
    nezha: {
      client_id: "nezha",
      name: "哪吒监控",
      description: "dash.starryheavens.uk 运维监控面板",
      redirect_uris: ["https://dash.starryheavens.uk/oauth2/callback"],
      trusted: true,
      pkce_required: false,
      is_public: false,
    },
    alist: {
      client_id: "alist",
      name: "Alist 网盘",
      description: "pan.starryheavens.uk 个人网盘",
      redirect_uris: ["https://pan.starryheavens.uk/api/auth/sso_callback"],
      trusted: true,
      pkce_required: false,
      is_public: false,
    },
    bothub_web: {
      client_id: "bothub-web",
      name: "BotHub 2.0 Web",
      description: "bot.starryheavens.uk Web 控制台",
      redirect_uris: ["https://bot.starryheavens.uk/auth/callback"],
      trusted: true,
      pkce_required: true,
      is_public: false,
    },
    bothub_android: {
      client_id: "bothub-android",
      name: "BotHub 2.0 Android",
      description: "BotHub Android 原生客户端 (PKCE)",
      redirect_uris: [
        "uk.starryheavens.bothub://oauth/callback",
        "http://127.0.0.1/oauth/callback",
      ],
      trusted: true,
      pkce_required: true,
      is_public: true,
    },
  };

  function esc(str) {
    return String(str == null ? "" : str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function fmtTime(unixSec) {
    if (!unixSec) return "-";
    const d = new Date(unixSec * 1000);
    return d.toLocaleString("zh-CN", { hour12: false });
  }

  function suggestDeviceName() {
    const ua = (navigator.userAgent || "").toLowerCase();
    let os = "Device";
    if (ua.includes("iphone") || ua.includes("ipad")) os = "iOS";
    else if (ua.includes("android")) os = "Android";
    else if (ua.includes("macintosh") || ua.includes("mac os x")) os = "Mac";
    else if (ua.includes("windows")) os = "Windows";
    else if (ua.includes("linux")) os = "Linux";

    let browser = "";
    if (ua.includes("edg/")) browser = "Edge";
    else if (ua.includes("firefox/")) browser = "Firefox";
    else if (ua.includes("chrome/") || ua.includes("crios/")) browser = "Chrome";
    else if (ua.includes("safari/")) browser = "Safari";

    return browser ? os + " (" + browser + ")" : os;
  }

  let toastTimer = null;
  function showToast(msg) {
    const el = document.getElementById("toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      el.classList.add("hidden");
    }, 2800);
  }

  async function copyText(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      showToast("已复制: " + (label || text));
    } catch (_) {
      showToast("复制失败，请手动选中复制");
    }
  }

  // Sudo Mode modal promise orchestration
  let pendingSudoResolve = null;
  let pendingSudoReject = null;
  const sudoModal = document.getElementById("sudo-modal");
  const sudoAlert = document.getElementById("sudo-alert");

  function requestSudoElevation() {
    return new Promise(function (resolve, reject) {
      pendingSudoResolve = resolve;
      pendingSudoReject = reject;
      if (sudoAlert) sudoAlert.classList.add("hidden");
      const pwdInput = document.getElementById("sudo-password");
      if (pwdInput) pwdInput.value = "";
      sudoModal.classList.remove("hidden");
    });
  }

  function closeSudoModal(cancelled) {
    sudoModal.classList.add("hidden");
    if (cancelled && pendingSudoReject) {
      const rej = pendingSudoReject;
      pendingSudoResolve = null;
      pendingSudoReject = null;
      rej(new Error("已取消安全验证"));
    }
  }

  async function api(url, opts, retried) {
    const rawOpts = opts || {};
    const headers = Object.assign({}, rawOpts.headers || {});
    headers["X-CSRF-Token"] = CFG.csrfToken;

    let bodyPayload = rawOpts.body;
    if (bodyPayload && typeof bodyPayload === "object") {
      headers["Content-Type"] = "application/json";
      bodyPayload = JSON.stringify(bodyPayload);
    }

    const resp = await fetch(url, {
      method: rawOpts.method || "GET",
      headers: headers,
      body: bodyPayload,
    });
    const data = await resp.json().catch(function () {
      return {};
    });

    if (resp.status === 403 && data.code === "sudo_required" && !retried) {
      await requestSudoElevation();
      return api(url, opts, true);
    }

    if (!resp.ok) {
      const err = new Error(data.error || "请求失败 (" + resp.status + ")");
      err.code = data.code;
      throw err;
    }
    return data;
  }

  function showSecretBanner(clientName, secret) {
    const banner = document.getElementById("global-secret-banner");
    document.getElementById("secret-banner-title").textContent =
      clientName + " 的 Client Secret（仅此次展示，请立即保存）";
    document.getElementById("secret-banner-value").textContent = secret;
    banner.classList.remove("hidden");
  }

  // Tab navigation
  document.querySelectorAll(".nav-tab").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const target = btn.getAttribute("data-tab");
      document.querySelectorAll(".nav-tab").forEach(function (b) {
        b.classList.toggle("active", b === btn);
      });
      ["clients", "security", "sessions", "audit"].forEach(function (name) {
        document.getElementById("tab-" + name).classList.toggle("hidden", name !== target);
      });
      if (target === "audit") {
        loadAudit();
      } else if (target === "sessions") {
        loadSessions();
      } else if (target === "security") {
        loadPasskeys();
        loadKeys();
      }
    });
  });

  async function loadOverview() {
    const data = await api("/api/admin/overview");
    state.clients = data.clients || [];
    state.passkeys = data.passkeys || [];
    state.sessions = data.sessions || [];
    state.keys = data.keys || [];
    renderClients();
    renderPasskeys();
    renderSessions();
    renderKeys();
  }

  async function loadPasskeys() {
    const data = await api("/api/admin/passkeys");
    state.passkeys = data.passkeys || [];
    renderPasskeys();
  }

  async function loadKeys() {
    const data = await api("/api/admin/keys");
    state.keys = data.keys || [];
    renderKeys();
  }

  async function loadSessions() {
    const data = await api("/api/admin/sessions");
    state.sessions = data.sessions || [];
    renderSessions();
  }

  async function loadAudit() {
    const offset = state.auditPage * state.auditLimit;
    const params = new URLSearchParams({
      limit: String(state.auditLimit),
      offset: String(offset),
    });
    if (state.auditStatus) params.set("status", state.auditStatus);
    if (state.auditCategory) params.set("category", state.auditCategory);
    if (state.auditQuery) params.set("q", state.auditQuery);

    const data = await api("/api/admin/audit?" + params.toString());
    state.auditTotal = data.total || 0;
    renderAudit(data.logs || []);
  }

  function renderClients() {
    const root = document.getElementById("clients-list");
    if (!state.clients.length) {
      root.innerHTML =
        '<div class="item-card"><div class="item-main"><div class="item-title">尚未注册任何 OAuth2 应用</div><div class="field-hint">点击上方「新增应用」或使用快速预设即可立即接入哪吒监控、Alist 或 BotHub。</div></div></div>';
      return;
    }

    root.innerHTML = state.clients
      .map(function (c) {
        const trustBadge = c.trusted
          ? '<span class="badge badge-success">静默信任</span>'
          : '<span class="badge">需确认授权</span>';
        const typeBadge = c.is_public
          ? '<span class="badge badge-gold">Public (无密钥)</span>'
          : '<span class="badge">Confidential</span>';
        const pkceBadge = c.pkce_required
          ? '<span class="badge badge-gold">PKCE 强制</span>'
          : "";
        const urisHtml = (c.redirect_uris || [])
          .map(function (u) {
            return '<div class="mono-secondary">' + esc(u) + "</div>";
          })
          .join("");

        return (
          '<div class="item-card" data-client-id="' + esc(c.id) + '">' +
          '  <div class="item-main">' +
          '    <div class="item-title-row">' +
          '      <span class="item-title">' + esc(c.name) + "</span>" +
          trustBadge +
          typeBadge +
          pkceBadge +
          "    </div>" +
          (c.description
            ? '<div class="text-secondary-sm mb-sm">' + esc(c.description) + "</div>"
            : "") +
          '    <div class="mono-accent">client_id: ' + esc(c.id) + "</div>" +
          urisHtml +
          "  </div>" +
          '  <div class="item-actions">' +
          '    <button class="btn btn-primary btn-sm act-guide" type="button">接入配置</button>' +
          '    <button class="btn btn-secondary btn-sm act-edit" type="button">编辑</button>' +
          (c.is_public
            ? ""
            : '<button class="btn btn-secondary btn-sm act-rotate" type="button">重置密钥</button>') +
          '    <button class="btn btn-danger btn-sm act-delete" type="button">删除</button>' +
          "  </div>" +
          "</div>"
        );
      })
      .join("");

    root.querySelectorAll(".item-card").forEach(function (card) {
      const id = card.getAttribute("data-client-id");
      const client = state.clients.find(function (x) {
        return x.id === id;
      });
      if (!client) return;

      card.querySelector(".act-guide").addEventListener("click", function () {
        openGuideModal(client);
      });
      card.querySelector(".act-edit").addEventListener("click", function () {
        openClientModal(client, null);
      });
      const rotateBtn = card.querySelector(".act-rotate");
      if (rotateBtn) {
        rotateBtn.addEventListener("click", async function () {
          if (!confirm("重置密钥后，原 Client Secret 将立即失效，确定继续？")) return;
          try {
            const res = await api("/api/admin/clients/" + encodeURIComponent(id) + "/rotate", {
              method: "POST",
            });
            state.lastSecrets[id] = res.client_secret;
            showSecretBanner(client.name, res.client_secret);
            showToast("密钥已重置");
          } catch (err) {
            showToast(err.message);
          }
        });
      }
      card.querySelector(".act-delete").addEventListener("click", async function () {
        if (!confirm("确定删除应用「" + client.name + "」及其关联授权令牌？")) return;
        try {
          await api("/api/admin/clients/" + encodeURIComponent(id), { method: "DELETE" });
          showToast("应用已删除");
          await loadOverview();
        } catch (err) {
          showToast(err.message);
        }
      });
    });
  }

  function renderPasskeys() {
    const root = document.getElementById("passkeys-list");
    if (!state.passkeys.length) {
      root.innerHTML =
        '<div class="item-card"><div class="item-main"><div class="item-title">尚未绑定 Passkey</div><div class="field-hint">建议立即为当前 Mac 或手机绑定 Passkey，实现指纹/面容无密码登录。</div></div></div>';
      return;
    }

    root.innerHTML = state.passkeys
      .map(function (p) {
        const shortCred = (p.credential_id || "").slice(0, 20) + "...";
        return (
          '<div class="item-card" data-pk-id="' + esc(p.id) + '">' +
          '  <div class="item-main">' +
          '    <div class="item-title-row">' +
          '      <span class="item-title">' + esc(p.name) + "</span>" +
          '      <span class="badge badge-gold">SignCount: ' + esc(p.sign_count) + "</span>" +
          "    </div>" +
          '    <div class="mono-muted">Credential: ' + esc(shortCred) + "</div>" +
          '    <div class="item-meta"><span>绑定时间: ' + esc(fmtTime(p.created_at)) + "</span><span>最近使用: " + esc(fmtTime(p.last_used_at)) + "</span></div>" +
          "  </div>" +
          '  <div class="item-actions">' +
          '    <button class="btn btn-secondary btn-sm act-pk-rename" type="button">重命名</button>' +
          '    <button class="btn btn-danger btn-sm act-pk-del" type="button">解绑</button>' +
          "  </div>" +
          "</div>"
        );
      })
      .join("");

    root.querySelectorAll(".item-card").forEach(function (card) {
      const id = card.getAttribute("data-pk-id");
      const pk = state.passkeys.find(function (x) {
        return x.id === id;
      });
      if (!pk) return;

      card.querySelector(".act-pk-rename").addEventListener("click", async function () {
        const nextName = prompt("请输入新的设备名称", pk.name);
        if (!nextName || !nextName.trim()) return;
        try {
          await api("/api/admin/passkeys/" + encodeURIComponent(id), {
            method: "PATCH",
            body: { name: nextName.trim() },
          });
          showToast("设备名称已更新");
          await loadPasskeys();
        } catch (err) {
          showToast(err.message);
        }
      });

      card.querySelector(".act-pk-del").addEventListener("click", async function () {
        if (!confirm("确定解绑 Passkey「" + pk.name + "」？")) return;
        try {
          await api("/api/admin/passkeys/" + encodeURIComponent(id), { method: "DELETE" });
          showToast("已解绑 Passkey");
          await loadPasskeys();
        } catch (err) {
          showToast(err.message);
        }
      });
    });
  }

  function renderKeys() {
    const root = document.getElementById("keys-list");
    if (!root) return;
    if (!state.keys.length) {
      root.innerHTML = '<div class="item-card"><div class="item-main">暂无密钥记录</div></div>';
      return;
    }

    root.innerHTML = state.keys
      .map(function (k) {
        const statusBadge = k.active
          ? '<span class="badge badge-success">当前签发密钥 (Active)</span>'
          : '<span class="badge">验签宽限保留</span>';
        return (
          '<div class="item-card">' +
          '  <div class="item-main">' +
          '    <div class="item-title-row">' +
          '      <span class="mono-accent mb-0">kid: ' + esc(k.kid) + "</span>" +
          statusBadge +
          '      <span class="badge">' + esc(k.algorithm) + "</span>" +
          "    </div>" +
          '    <div class="item-meta"><span>创建时间: ' + esc(fmtTime(k.created_at)) + "</span></div>" +
          "  </div>" +
          "</div>"
        );
      })
      .join("");
  }

  function renderSessions() {
    const root = document.getElementById("sessions-list");
    if (!state.sessions.length) {
      root.innerHTML = '<div class="item-card"><div class="item-main">暂无活跃会话</div></div>';
      return;
    }

    root.innerHTML = state.sessions
      .map(function (s) {
        const currentBadge = s.current
          ? '<span class="badge badge-success">当前会话</span>'
          : "";
        const methodBadge =
          s.auth_method === "passkey"
            ? '<span class="badge badge-gold">Passkey</span>'
            : '<span class="badge">主密码</span>';
        const deviceTitle = s.device_label || "Browser";

        return (
          '<div class="item-card" data-ses-id="' + esc(s.id) + '">' +
          '  <div class="item-main">' +
          '    <div class="item-title-row">' +
          '      <span class="item-title">' + esc(deviceTitle) + "</span>" +
          '      <span class="badge mono-xs">' + esc(s.ip || "unknown") + "</span>" +
          currentBadge +
          methodBadge +
          "    </div>" +
          '    <div class="text-secondary-sm">' + esc(s.user_agent || "-") + "</div>" +
          '    <div class="item-meta"><span>登录时间: ' + esc(fmtTime(s.created_at)) + "</span><span>最近活跃: " + esc(fmtTime(s.last_seen_at)) + "</span></div>" +
          "  </div>" +
          '  <div class="item-actions">' +
          (s.current
            ? ""
            : '<button class="btn btn-danger btn-sm act-ses-revoke" type="button">踢下线</button>') +
          "  </div>" +
          "</div>"
        );
      })
      .join("");

    root.querySelectorAll(".act-ses-revoke").forEach(function (btn) {
      const card = btn.closest(".item-card");
      const id = card.getAttribute("data-ses-id");
      btn.addEventListener("click", async function () {
        try {
          await api("/api/admin/sessions/" + encodeURIComponent(id), { method: "DELETE" });
          showToast("会话已踢下线");
          await loadSessions();
        } catch (err) {
          showToast(err.message);
        }
      });
    });
  }

  function renderAudit(logs) {
    const tbody = document.getElementById("audit-tbody");
    if (!logs.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-muted-cell">暂无匹配的审计记录</td></tr>';
    } else {
      tbody.innerHTML = logs
        .map(function (l) {
          const stBadge =
            l.status === "success"
              ? '<span class="badge badge-success">成功</span>'
              : '<span class="badge badge-danger">失败</span>';
          return (
            "<tr>" +
            '<td class="mono-xs nowrap">' + esc(fmtTime(l.created_at)) + "</td>" +
            "<td>" + stBadge + "</td>" +
            '<td class="mono-xs">' + esc(l.event_type) + "</td>" +
            "<td>" + esc(l.actor) + "</td>" +
            '<td class="mono-xs">' + esc(l.ip || "-") + "</td>" +
            "<td><div>" + esc(l.target || "-") + '</div><div class="field-hint-tight">' + esc(l.detail) + "</div></td>" +
            "</tr>"
          );
        })
        .join("");
    }

    const start = state.auditTotal === 0 ? 0 : state.auditPage * state.auditLimit + 1;
    const end = Math.min((state.auditPage + 1) * state.auditLimit, state.auditTotal);
    document.getElementById("audit-summary").textContent =
      "显示第 " + start + " - " + end + " 条，共 " + state.auditTotal + " 条";
    document.getElementById("audit-prev-btn").disabled = state.auditPage === 0;
    document.getElementById("audit-next-btn").disabled = end >= state.auditTotal;
  }

  // Client Modal
  const clientModal = document.getElementById("client-modal");
  function openClientModal(client, preset) {
    const isEdit = !!client;
    document.getElementById("client-edit-id").value = isEdit ? client.id : "";
    document.getElementById("client-modal-title").textContent = isEdit
      ? "编辑应用: " + client.name
      : "新增 OAuth2 应用";

    const idFieldWrap = document.getElementById("client-custom-id-field");
    const idInput = document.getElementById("client-custom-id");
    if (isEdit) {
      idFieldWrap.classList.add("hidden");
      idInput.value = "";
    } else {
      idFieldWrap.classList.remove("hidden");
      idInput.value = (preset && preset.client_id) || "";
    }

    const src = client || preset || {};
    document.getElementById("client-name").value = src.name || "";
    document.getElementById("client-desc").value = src.description || "";
    document.getElementById("client-uris").value = (src.redirect_uris || []).join("\n");
    document.getElementById("client-trusted").checked =
      src.trusted !== undefined ? !!src.trusted : true;
    document.getElementById("client-public").checked = !!src.is_public;
    document.getElementById("client-pkce").checked = !!src.pkce_required || !!src.is_public;
    clientModal.classList.remove("hidden");
  }

  function closeClientModal() {
    clientModal.classList.add("hidden");
  }

  document.getElementById("client-public").addEventListener("change", function (e) {
    if (e.target.checked) {
      document.getElementById("client-pkce").checked = true;
    }
  });

  document.getElementById("new-client-btn").addEventListener("click", function () {
    openClientModal(null, null);
  });

  document.querySelectorAll(".preset-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const key = btn.getAttribute("data-preset");
      openClientModal(null, PRESETS[key]);
    });
  });

  document.getElementById("client-modal-close").addEventListener("click", closeClientModal);
  document.getElementById("client-modal-cancel").addEventListener("click", closeClientModal);

  document.getElementById("client-form").addEventListener("submit", async function (e) {
    e.preventDefault();
    const editId = document.getElementById("client-edit-id").value.trim();
    const uris = document
      .getElementById("client-uris")
      .value.split(/\r?\n/)
      .map(function (s) {
        return s.trim();
      })
      .filter(Boolean);

    const body = {
      name: document.getElementById("client-name").value.trim(),
      description: document.getElementById("client-desc").value.trim(),
      redirect_uris: uris,
      trusted: document.getElementById("client-trusted").checked,
      is_public: document.getElementById("client-public").checked,
      pkce_required: document.getElementById("client-pkce").checked,
    };
    if (!editId) {
      body.client_id = document.getElementById("client-custom-id").value.trim();
    }

    try {
      if (editId) {
        const res = await api("/api/admin/clients/" + encodeURIComponent(editId), {
          method: "PUT",
          body: body,
        });
        if (res.client_secret && res.client) {
          state.lastSecrets[res.client.id] = res.client_secret;
          showSecretBanner(res.client.name, res.client_secret);
        }
        showToast("应用配置已更新");
      } else {
        const res = await api("/api/admin/clients", {
          method: "POST",
          body: body,
        });
        if (res.client_secret && res.client) {
          state.lastSecrets[res.client.id] = res.client_secret;
          showSecretBanner(res.client.name, res.client_secret);
        }
        showToast("应用已创建");
      }
      closeClientModal();
      await loadOverview();
    } catch (err) {
      showToast(err.message);
    }
  });

  // Integration Guide Modal
  const guideModal = document.getElementById("guide-modal");
  function kvRow(label, value, copyable) {
    const valStr = String(value || "");
    const btn = copyable
      ? '<button class="btn btn-secondary btn-sm copy-kv" data-val="' + esc(valStr) + '" data-label="' + esc(label) + '" type="button">复制</button>'
      : "";
    return (
      '<div class="kv-row">' +
      '  <div class="kv-cell">' +
      '    <div class="kv-key">' + esc(label) + "</div>" +
      '    <div class="kv-val">' + esc(valStr) + "</div>" +
      "  </div>" +
      btn +
      "</div>"
    );
  }

  function openGuideModal(client) {
    const iss = CFG.issuer;
    const secretVal = client.is_public
      ? "无 (Public PKCE 客户端不需要 Client Secret)"
      : state.lastSecrets[client.id] || "已加盐哈希存储（如需查看明文，请点击列表中的「重置密钥」）";
    const hasPlainSecret = !!state.lastSecrets[client.id] && !client.is_public;
    const discovery = iss + "/.well-known/openid-configuration";

    document.getElementById("guide-modal-title").textContent = client.name + " - OIDC 接入参数";
    document.getElementById("guide-modal-sub").textContent =
      "直接复制以下标准参数填入第三方应用后台即可完成对接";

    const fullBundle = JSON.stringify(
      {
        issuer: iss,
        discovery_url: discovery,
        authorization_endpoint: iss + "/oauth2/authorize",
        token_endpoint: iss + "/oauth2/token",
        userinfo_endpoint: iss + "/oauth2/userinfo",
        introspection_endpoint: iss + "/oauth2/introspect",
        jwks_uri: iss + "/.well-known/jwks.json",
        end_session_endpoint: iss + "/oauth2/logout",
        client_id: client.id,
        client_secret: hasPlainSecret
          ? state.lastSecrets[client.id]
          : client.is_public
          ? null
          : "<reset_to_reveal>",
        redirect_uris: client.redirect_uris,
        scopes: client.is_public ? "openid profile email offline_access" : "openid profile email",
      },
      null,
      2
    );

    const html =
      '<div class="mb-md"><button id="copy-all-bundle" class="btn btn-primary btn-block" type="button">一键复制完整 JSON 接入配置</button></div>' +
      '<div class="kv-table">' +
      kvRow("OIDC Discovery URL (推荐)", discovery, true) +
      kvRow("Client ID", client.id, true) +
      kvRow("Client Secret", secretVal, hasPlainSecret) +
      kvRow("Authorization Endpoint", iss + "/oauth2/authorize", true) +
      kvRow("Token Endpoint", iss + "/oauth2/token", true) +
      kvRow("UserInfo Endpoint", iss + "/oauth2/userinfo", true) +
      kvRow("Introspection Endpoint", iss + "/oauth2/introspect", true) +
      kvRow("JWKS URI", iss + "/.well-known/jwks.json", true) +
      kvRow("End Session (Logout) Endpoint", iss + "/oauth2/logout", true) +
      kvRow("回调地址 (Redirect URI)", (client.redirect_uris || []).join(" , "), true) +
      kvRow(
        "哪吒监控 (Nezha) 字段映射",
        "OAuth2 Type: OIDC / Endpoint: " + discovery + " / Scopes: openid profile email",
        false
      ) +
      kvRow(
        "Alist 网盘字段映射",
        "SSO Client ID & Secret + OIDC Endpoint: " +
          discovery +
          " / Callback: https://pan.starryheavens.uk/api/auth/sso_callback",
        false
      ) +
      "</div>";

    const bodyEl = document.getElementById("guide-body");
    bodyEl.innerHTML = html;
    bodyEl.querySelectorAll(".copy-kv").forEach(function (btn) {
      btn.addEventListener("click", function () {
        copyText(btn.getAttribute("data-val"), btn.getAttribute("data-label"));
      });
    });
    document.getElementById("copy-all-bundle").addEventListener("click", function () {
      copyText(fullBundle, "完整 OIDC 配置");
    });

    guideModal.classList.remove("hidden");
  }

  document.getElementById("guide-modal-close").addEventListener("click", function () {
    guideModal.classList.add("hidden");
  });

  // Backdrop click & Escape key dismissal for all modals
  [clientModal, guideModal, sudoModal].forEach(function (backdrop) {
    if (!backdrop) return;
    backdrop.addEventListener("click", function (e) {
      if (e.target === backdrop) {
        if (backdrop === sudoModal) {
          closeSudoModal(true);
        } else {
          backdrop.classList.add("hidden");
        }
      }
    });
  });

  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    if (sudoModal && !sudoModal.classList.contains("hidden")) {
      closeSudoModal(true);
      return;
    }
    if (!guideModal.classList.contains("hidden")) {
      guideModal.classList.add("hidden");
      return;
    }
    if (!clientModal.classList.contains("hidden")) {
      closeClientModal();
    }
  });

  // Sudo Modal buttons
  document.getElementById("sudo-modal-close").addEventListener("click", function () {
    closeSudoModal(true);
  });

  document.getElementById("sudo-passkey-btn").addEventListener("click", async function () {
    const btn = document.getElementById("sudo-passkey-btn");
    sudoAlert.classList.add("hidden");
    btn.disabled = true;
    try {
      await window.VesperWebAuthn.sudo(CFG.csrfToken);
      const res = pendingSudoResolve;
      pendingSudoResolve = null;
      pendingSudoReject = null;
      sudoModal.classList.add("hidden");
      if (res) res();
    } catch (err) {
      sudoAlert.textContent = err.message || "Passkey 验证失败";
      sudoAlert.classList.remove("hidden");
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById("sudo-password-form").addEventListener("submit", async function (e) {
    e.preventDefault();
    sudoAlert.classList.add("hidden");
    const pwd = document.getElementById("sudo-password").value;
    try {
      const resp = await fetch("/api/admin/sudo/password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": CFG.csrfToken,
        },
        body: JSON.stringify({ password: pwd }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || "主密码验证失败");
      }
      const res = pendingSudoResolve;
      pendingSudoResolve = null;
      pendingSudoReject = null;
      sudoModal.classList.add("hidden");
      if (res) res();
    } catch (err) {
      sudoAlert.textContent = err.message;
      sudoAlert.classList.remove("hidden");
    }
  });

  // Secret banner
  document.getElementById("copy-banner-secret").addEventListener("click", function () {
    copyText(document.getElementById("secret-banner-value").textContent, "Client Secret");
  });
  document.getElementById("close-banner-secret").addEventListener("click", function () {
    document.getElementById("global-secret-banner").classList.add("hidden");
  });

  // Passkey registration with auto-suggested device name
  const passkeyDeviceInput = document.getElementById("passkey-device-name");
  if (passkeyDeviceInput && !passkeyDeviceInput.value) {
    passkeyDeviceInput.value = suggestDeviceName();
  }

  document.getElementById("register-passkey-form").addEventListener("submit", async function (e) {
    e.preventDefault();
    const btn = document.getElementById("register-passkey-btn");
    const deviceName = passkeyDeviceInput.value.trim();
    if (!deviceName) return;

    btn.disabled = true;
    btn.textContent = "请在设备上完成生物识别验证...";
    try {
      await window.VesperWebAuthn.register(deviceName, CFG.csrfToken);
      passkeyDeviceInput.value = suggestDeviceName();
      showToast("Passkey 绑定成功");
      await loadPasskeys();
    } catch (err) {
      showToast(err.message || "Passkey 绑定失败");
    } finally {
      btn.disabled = false;
      btn.textContent = "绑定当前设备 Passkey";
    }
  });

  // Rotate RSA Signing Key
  document.getElementById("rotate-key-btn").addEventListener("click", async function () {
    if (
      !confirm(
        "轮换 RSA 签名密钥将生成新活跃密钥用于后续签发，旧公钥将继续保留在 JWKS 中供存量令牌平滑验签。确认执行？"
      )
    ) {
      return;
    }
    try {
      const res = await api("/api/admin/keys/rotate", { method: "POST" });
      showToast("签名密钥已轮换 (kid: " + res.kid + ")");
      await loadKeys();
    } catch (err) {
      showToast(err.message);
    }
  });

  // Profile & password forms
  document.getElementById("profile-form").addEventListener("submit", async function (e) {
    e.preventDefault();
    try {
      const res = await api("/api/admin/profile", {
        method: "POST",
        body: {
          email: document.getElementById("profile-email").value.trim(),
          display_name: document.getElementById("profile-display").value.trim(),
        },
      });
      document.getElementById("admin-badge").textContent =
        res.user.username + " (" + res.user.email + ")";
      showToast("管理员资料已保存");
    } catch (err) {
      showToast(err.message);
    }
  });

  document.getElementById("password-change-form").addEventListener("submit", async function (e) {
    e.preventDefault();
    const cur = document.getElementById("current-password").value;
    const nw = document.getElementById("new-password").value;
    const cf = document.getElementById("confirm-new-password").value;
    const revokeTokens = document.getElementById("revoke-all-tokens").checked;
    if (nw !== cf) {
      showToast("两次输入的新密码不一致");
      return;
    }
    try {
      await api("/api/admin/password", {
        method: "POST",
        body: {
          current_password: cur,
          new_password: nw,
          revoke_tokens: revokeTokens,
        },
      });
      e.target.reset();
      showToast("主密码已更新，其他会话已自动清理");
    } catch (err) {
      showToast(err.message);
    }
  });

  // Sessions & Audit controls
  document.getElementById("revoke-others-btn").addEventListener("click", async function () {
    if (!confirm("确定踢下线除当前浏览器之外的所有登录会话？")) return;
    try {
      await api("/api/admin/sessions/others", { method: "DELETE" });
      showToast("已清理其他会话");
      await loadSessions();
    } catch (err) {
      showToast(err.message);
    }
  });

  function applyAuditFilter() {
    state.auditStatus = document.getElementById("audit-filter-status").value;
    state.auditCategory = document.getElementById("audit-filter-category").value;
    state.auditQuery = document.getElementById("audit-filter-query").value.trim();
    state.auditPage = 0;
    loadAudit();
  }

  document.getElementById("audit-filter-status").addEventListener("change", applyAuditFilter);
  document.getElementById("audit-filter-category").addEventListener("change", applyAuditFilter);
  document.getElementById("audit-filter-form").addEventListener("submit", function (e) {
    e.preventDefault();
    applyAuditFilter();
  });

  document.getElementById("refresh-audit-btn").addEventListener("click", loadAudit);
  document.getElementById("audit-prev-btn").addEventListener("click", function () {
    if (state.auditPage > 0) {
      state.auditPage--;
      loadAudit();
    }
  });
  document.getElementById("audit-next-btn").addEventListener("click", function () {
    if ((state.auditPage + 1) * state.auditLimit < state.auditTotal) {
      state.auditPage++;
      loadAudit();
    }
  });

  document.getElementById("logout-btn").addEventListener("click", async function () {
    await api("/api/auth/logout", { method: "POST" }).catch(function () {});
    window.location.href = "/login?logged_out=1";
  });

  loadOverview().catch(function (err) {
    showToast(err.message);
  });
})();
