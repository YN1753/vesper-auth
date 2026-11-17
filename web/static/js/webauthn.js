(function (global) {
  "use strict";

  function base64urlToBytes(str) {
    const pad = "=".repeat((4 - (str.length % 4)) % 4);
    const base64 = (str + pad).replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(base64);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) {
      bytes[i] = raw.charCodeAt(i);
    }
    return bytes;
  }

  function bytesToBase64url(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let bin = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function ensureSupported() {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      throw new Error("当前浏览器环境不支持 WebAuthn Passkey，请使用 HTTPS 或更换现代浏览器");
    }
  }

  function prepareRequestOptions(pk) {
    pk.challenge = base64urlToBytes(pk.challenge);
    if (Array.isArray(pk.allowCredentials)) {
      pk.allowCredentials = pk.allowCredentials.map(function (item) {
        return Object.assign({}, item, { id: base64urlToBytes(item.id) });
      });
    }
    return pk;
  }

  function serializeAssertion(cred) {
    return {
      id: cred.id,
      rawId: bytesToBase64url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      response: {
        authenticatorData: bytesToBase64url(cred.response.authenticatorData),
        clientDataJSON: bytesToBase64url(cred.response.clientDataJSON),
        signature: bytesToBase64url(cred.response.signature),
        userHandle: cred.response.userHandle
          ? bytesToBase64url(cred.response.userHandle)
          : undefined,
      },
    };
  }

  async function passkeyLogin(reqId) {
    ensureSupported();
    const beginResp = await fetch("/api/auth/passkey/login/begin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ req: reqId || "" }),
    });
    const beginData = await beginResp.json();
    if (!beginResp.ok) {
      throw new Error(beginData.error || "无法发起 Passkey 登录请求");
    }

    const pk = prepareRequestOptions(beginData.options.publicKey);
    const cred = await navigator.credentials.get({ publicKey: pk });
    if (!cred) {
      throw new Error("未获取到 Passkey 凭证");
    }

    const finishUrl =
      "/api/auth/passkey/login/finish?ceremony_id=" +
      encodeURIComponent(beginData.ceremony_id) +
      (reqId ? "&req=" + encodeURIComponent(reqId) : "");

    const finishResp = await fetch(finishUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Ceremony-ID": beginData.ceremony_id,
      },
      body: JSON.stringify(serializeAssertion(cred)),
    });
    const finishData = await finishResp.json();
    if (!finishResp.ok) {
      throw new Error(finishData.error || "Passkey 验证失败");
    }
    return finishData;
  }

  async function passkeyConditionalLogin(reqId, abortSignal) {
    if (
      !window.PublicKeyCredential ||
      typeof window.PublicKeyCredential.isConditionalMediationAvailable !== "function"
    ) {
      return null;
    }
    const available = await window.PublicKeyCredential.isConditionalMediationAvailable();
    if (!available) {
      return null;
    }

    const beginResp = await fetch("/api/auth/passkey/login/conditional", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ req: reqId || "" }),
    });
    if (!beginResp.ok) {
      return null;
    }
    const beginData = await beginResp.json();
    const pk = prepareRequestOptions(beginData.options.publicKey);

    const cred = await navigator.credentials.get({
      publicKey: pk,
      mediation: "conditional",
      signal: abortSignal,
    });
    if (!cred) {
      return null;
    }

    const finishUrl =
      "/api/auth/passkey/login/finish?ceremony_id=" +
      encodeURIComponent(beginData.ceremony_id) +
      (reqId ? "&req=" + encodeURIComponent(reqId) : "");

    const finishResp = await fetch(finishUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Ceremony-ID": beginData.ceremony_id,
      },
      body: JSON.stringify(serializeAssertion(cred)),
    });
    const finishData = await finishResp.json();
    if (!finishResp.ok) {
      throw new Error(finishData.error || "Passkey 验证失败");
    }
    return finishData;
  }

  async function passkeyRegister(deviceName, csrfToken) {
    ensureSupported();
    const beginHeaders = { "Content-Type": "application/json" };
    if (csrfToken) beginHeaders["X-CSRF-Token"] = csrfToken;

    const beginResp = await fetch("/api/admin/passkeys/register/begin", {
      method: "POST",
      headers: beginHeaders,
      body: JSON.stringify({ name: deviceName }),
    });
    const beginData = await beginResp.json();
    if (!beginResp.ok) {
      const err = new Error(beginData.error || "无法发起 Passkey 绑定");
      err.code = beginData.code;
      throw err;
    }

    const pk = beginData.options.publicKey;
    pk.challenge = base64urlToBytes(pk.challenge);
    pk.user.id = base64urlToBytes(pk.user.id);
    if (Array.isArray(pk.excludeCredentials)) {
      pk.excludeCredentials = pk.excludeCredentials.map(function (item) {
        return Object.assign({}, item, { id: base64urlToBytes(item.id) });
      });
    }

    const cred = await navigator.credentials.create({ publicKey: pk });
    if (!cred) {
      throw new Error("Passkey 创建已取消");
    }

    const transports =
      typeof cred.response.getTransports === "function"
        ? cred.response.getTransports()
        : undefined;

    const payload = {
      id: cred.id,
      rawId: bytesToBase64url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      response: {
        attestationObject: bytesToBase64url(cred.response.attestationObject),
        clientDataJSON: bytesToBase64url(cred.response.clientDataJSON),
        transports: transports,
      },
    };

    const finishHeaders = {
      "Content-Type": "application/json",
      "X-Ceremony-ID": beginData.ceremony_id,
    };
    if (csrfToken) finishHeaders["X-CSRF-Token"] = csrfToken;

    const finishResp = await fetch(
      "/api/admin/passkeys/register/finish?ceremony_id=" +
        encodeURIComponent(beginData.ceremony_id),
      {
        method: "POST",
        headers: finishHeaders,
        body: JSON.stringify(payload),
      }
    );
    const finishData = await finishResp.json();
    if (!finishResp.ok) {
      throw new Error(finishData.error || "Passkey 绑定验证失败");
    }
    return finishData;
  }

  async function passkeySudo(csrfToken) {
    ensureSupported();
    const headers = { "Content-Type": "application/json" };
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;

    const beginResp = await fetch("/api/admin/sudo/passkey/begin", {
      method: "POST",
      headers: headers,
      body: "{}",
    });
    const beginData = await beginResp.json();
    if (!beginResp.ok) {
      throw new Error(beginData.error || "无法发起 Passkey 二次验证");
    }

    const pk = prepareRequestOptions(beginData.options.publicKey);
    const cred = await navigator.credentials.get({ publicKey: pk });
    if (!cred) {
      throw new Error("未获取到 Passkey 凭证");
    }

    const finishHeaders = {
      "Content-Type": "application/json",
      "X-Ceremony-ID": beginData.ceremony_id,
    };
    if (csrfToken) finishHeaders["X-CSRF-Token"] = csrfToken;

    const finishResp = await fetch(
      "/api/admin/sudo/passkey/finish?ceremony_id=" +
        encodeURIComponent(beginData.ceremony_id),
      {
        method: "POST",
        headers: finishHeaders,
        body: JSON.stringify(serializeAssertion(cred)),
      }
    );
    const finishData = await finishResp.json();
    if (!finishResp.ok) {
      throw new Error(finishData.error || "Passkey 二次验证失败");
    }
    return finishData;
  }

  global.VesperWebAuthn = {
    login: passkeyLogin,
    conditionalLogin: passkeyConditionalLogin,
    register: passkeyRegister,
    sudo: passkeySudo,
  };
})(window);
