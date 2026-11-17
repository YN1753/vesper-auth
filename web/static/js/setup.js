(function () {
  "use strict";

  const form = document.getElementById("setup-form");
  const alertBox = document.getElementById("setup-alert");
  const submitBtn = document.getElementById("setup-submit");
  if (!form) return;

  function showError(msg) {
    alertBox.textContent = msg;
    alertBox.classList.remove("hidden");
  }

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    alertBox.classList.add("hidden");

    const password = document.getElementById("password").value;
    const confirm = document.getElementById("password_confirm").value;
    if (password !== confirm) {
      showError("两次输入的主密码不一致");
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = "正在初始化...";
    try {
      const resp = await fetch("/api/auth/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: document.getElementById("username").value.trim(),
          email: document.getElementById("email").value.trim(),
          display_name: document.getElementById("display_name").value.trim(),
          password: password,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || "初始化失败");
      }
      window.location.href = data.redirect || "/";
    } catch (err) {
      showError(err.message);
      submitBtn.disabled = false;
      submitBtn.textContent = "创建管理员并进入控制台";
    }
  });
})();
