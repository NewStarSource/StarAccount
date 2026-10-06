document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector("[data-profile-form]");
  if (!form) return;
  const bio = form.elements.bio;
  const preview = form.querySelector("[data-bio-preview]");
  const status = form.querySelector("[data-profile-status]");
  const modes = form.querySelectorAll("[data-bio-mode]");
  const saveButton = form.querySelector('[type="submit"]');
  let request, previewRevision = 0, revision = 0, saving = false;

  form.addEventListener("input", () => { revision++; status.textContent = "未保存"; });
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
    const savedRevision = revision;
    saving = true; saveButton.disabled = true; status.textContent = "保存中…";
    try {
      const response = await fetch(form.action, {method: "POST", body: new URLSearchParams(new FormData(form)), headers: {Accept: "application/json"}});
      const result = await response.json();
      if (!response.ok) throw new Error(result.message || "保存失败，请重试");
      status.textContent = revision === savedRevision ? "已保存" : "有修改未保存";
    } catch (error) { status.textContent = error.message; }
    finally { saving = false; saveButton.disabled = false; }
  });
});
