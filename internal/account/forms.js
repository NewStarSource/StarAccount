"use strict";
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-account-form]").forEach(form => {
    let pending = false;
    const status = form.querySelector("[data-account-status]");
    form.addEventListener("input", () => { status.hidden = true; });
    form.addEventListener("submit", async event => {
      event.preventDefault();
      if (pending) return;
      const data = new URLSearchParams(new FormData(form)), button = form.querySelector("button");
      pending = true; button.disabled = true; form.setAttribute("aria-busy", "true"); status.hidden = true;
      try {
        const response = await fetch(form.action, {method:"POST", body:data, headers:{Accept:"application/json"}});
        const result = await response.json();
        if (!response.ok) throw new Error(result.message || "操作未完成，请稍后重试。");
        window.location.assign("/");
      } catch (error) { status.textContent = error.name === "TypeError" ? "连接中断，请稍后重试。" : error.name === "SyntaxError" ? "服务响应异常，请稍后重试。" : error.message; status.hidden = false; }
      finally { pending = false; button.disabled = false; form.removeAttribute("aria-busy"); }
    });
  });
});
