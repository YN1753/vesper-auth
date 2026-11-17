(function () {
  "use strict";

  const body = document.body;
  const reqId = (body && body.dataset.reqId) || "";
  const nextUrl = (body && body.dataset.nextUrl) || "";
  const alertBox = document.getElementById("login-alert");
  const passkeyBtn = document.getElementById("passkey-btn");
  const toggleBtn = document.getElementById("toggle-password-btn");
  const pwdForm = document.getElementById("password-form");
  const pwdSubmit = document.getElementById("password-submit");

  let conditionalAbort = null;

  function showError(msg) {
    alertBox.textContent = msg;
    alertBox.classList.remove("hidden");
  }

  function redirectAfterLogin(data) {
    if (data && data.redirect) {
      window.location.href = data.redirect;
      return;
    }
    if (reqId) {
      window.location.href = "/oauth2/authorize?req=" + encodeURIComponent(reqId);
      return;
    }
    window.location.href = nextUrl || "/";
  }

  function startConditionalMediation() {
    if (!window.VesperWebAuthn || typeof AbortController === "undefined") {
      return;
    }
    conditionalAbort = new AbortController();
    window.VesperWebAuthn.conditionalLogin(reqId, conditionalAbort.signal)
      .then(function (data) {
        if (data) {
          redirectAfterLogin(data);
        }
      })
      .catch(function (err) {
        if (err && err.name === "AbortError") {
          return;
        }
      });
  }

  if (toggleBtn && pwdForm) {
    toggleBtn.addEventListener("click", function () {
      const isHidden = pwdForm.classList.toggle("hidden");
      toggleBtn.setAttribute("aria-expanded", String(!isHidden));
      if (!isHidden) {
        const input = document.getElementById("identifier");
        if (input) input.focus();
      }
    });
  }

  if (passkeyBtn) {
    passkeyBtn.addEventListener("click", async function () {
      alertBox.classList.add("hidden");
      if (conditionalAbort) {
        conditionalAbort.abort();
        conditionalAbort = null;
      }
      passkeyBtn.disabled = true;
      try {
        const data = await window.VesperWebAuthn.login(reqId);
        redirectAfterLogin(data);
      } catch (err) {
        showError(err.message || "Passkey 登录失败");
        passkeyBtn.disabled = false;
        startConditionalMediation();
      }
    });
  }

  if (pwdForm) {
    pwdForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      alertBox.classList.add("hidden");
      if (conditionalAbort) {
        conditionalAbort.abort();
        conditionalAbort = null;
      }
      pwdSubmit.disabled = true;
      pwdSubmit.textContent = "正在验证...";
      try {
        const resp = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            identifier: document.getElementById("identifier").value.trim(),
            password: document.getElementById("password").value,
            req: reqId,
            next: nextUrl,
          }),
        });
        const data = await resp.json();
        if (!resp.ok) {
          throw new Error(data.error || "登录失败");
        }
        redirectAfterLogin(data);
      } catch (err) {
        showError(err.message);
        pwdSubmit.disabled = false;
        pwdSubmit.textContent = "验证主密码并登录";
      }
    });
  }

  startConditionalMediation();
})();
