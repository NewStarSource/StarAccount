document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector("[data-profile-form]");
  if (!form) return;
  const bio = form.elements.bio;
  const preview = form.querySelector("[data-bio-preview]");
  const status = form.querySelector("[data-profile-status]");
  const modes = form.querySelectorAll("[data-bio-mode]");
  const saveButton = form.querySelector('[type="submit"]');
  let request, previewRevision = 0, revision = 0, saving = false;

  const fieldErrors = new Map();
  ["display_name", "bio", "location", "website"].forEach(name => {
    const input = form.elements[name], error = document.createElement("p");
    error.id = "error-" + name; error.className = "field-error"; error.hidden = true;
    input.insertAdjacentElement("afterend", error); fieldErrors.set(name, error);
    input.setAttribute("aria-describedby", error.id);
    input.addEventListener("input", () => { error.hidden = true; input.removeAttribute("aria-invalid"); });
  });
  const clearErrors = () => fieldErrors.forEach((error, name) => {
    error.hidden = true; form.elements[name].removeAttribute("aria-invalid");
  });
  const showError = (name, message) => {
    const error = fieldErrors.get(name); if (!error) return;
    error.textContent = message; error.hidden = false;
    const input = form.elements[name]; input.setAttribute("aria-invalid", "true");
    if (name === "bio" && input.hidden) modes[0].click();
    input.focus();
  };

  form.addEventListener("input", () => { revision++; status.textContent = "未保存"; delete status.dataset.feedback; });
  modes.forEach(button => button.addEventListener("click", async () => {
    const showingPreview = button.dataset.bioMode === "preview";
    bio.hidden = showingPreview;
    preview.hidden = !showingPreview;
    modes.forEach(mode => mode.setAttribute("aria-pressed", String(mode === button)));
    request?.abort();
    const current = ++previewRevision;
    preview.removeAttribute("aria-busy");
    if (!showingPreview) return;
    request = new AbortController();
    preview.setAttribute("aria-busy", "true");
    try {
      const data = new URLSearchParams({bio: bio.value, "gorilla.csrf.Token": form.elements["gorilla.csrf.Token"].value});
      const response = await fetch("/api/v1/profile/preview", {method: "POST", body: data, headers: {Accept: "text/html"}, signal: request.signal});
      if (!response.ok) throw new Error(response.status === 401 ? "请重新登录" : "预览失败，请重试");
      const html = await response.text();
      if (current === previewRevision) preview.innerHTML = html || '<p class="muted">暂无简介</p>';
    } catch (error) {
      if (error.name !== "AbortError" && current === previewRevision) status.textContent = error.message;
    } finally {
      if (current === previewRevision) preview.removeAttribute("aria-busy");
    }
  }));

  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (saving) return;
    clearErrors(); delete status.dataset.feedback;
    const savedRevision = revision;
    saving = true; saveButton.disabled = true; status.textContent = "保存中…";
    try {
      const response = await fetch(form.action, {method: "POST", body: new URLSearchParams(new FormData(form)), headers: {Accept: "application/json"}});
      const result = await response.json();
      if (!response.ok) { showError(result.field, result.message); throw new Error(result.message || "保存失败，请重试"); }
      status.textContent = revision === savedRevision ? "已保存" : "有修改未保存";
    } catch (error) { status.dataset.feedback = "error"; status.textContent = error.name === "TypeError" ? "连接中断，修改尚未保存。" : error.name === "SyntaxError" ? "保存结果未确认，请刷新后检查。" : error.message; }
    finally { saving = false; saveButton.disabled = false; }
  });
});
