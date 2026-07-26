(() => {
  "use strict";
  const status = document.querySelector("#collaboration-status");
  const csrfToken = document.querySelector("meta[name='csrf-token']")?.content;
  let selectedCase = "";
  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
  const render = (name, items) => {
    const target = document.querySelector(`[data-list="${name}"]`);
    if (!target) return;
    if (!items.length) {
      target.innerHTML = '<p class="collaboration-empty">No recorded items.</p>';
      return;
    }
    target.innerHTML = items.map((item) => {
      const title = item.title || item.author || "Investigation activity";
      const body = item.body || item.description || item.status || "";
      const meta = item.case_id ? `Case ${item.case_id}` : (item.updated_at || item.created_at || "");
      return `<article class="collaboration-item"><h4>${escapeHtml(title)}</h4><p>${escapeHtml(body)}</p><span class="collaboration-meta">${escapeHtml(meta)}</span></article>`;
    }).join("");
  };
  const load = async () => {
    status.textContent = "Loading collaboration data…";
    try {
      const response = await fetch("/api/v1/collaboration", {headers: {"Accept": "application/json"}});
      if (!response.ok) throw new Error(`Request failed (${response.status})`);
      const data = await response.json();
      ["assigned_tasks", "investigation_updates", "comments", "mentions"].forEach((name) => render(name, data[name] || []));
      status.textContent = "Collaboration data is current.";
    } catch (error) {
      status.textContent = `Collaboration data is unavailable. ${error.message}`;
    }
  };
  const api = async (path, options = {}) => {
    const headers = {"Accept": "application/json", "Content-Type": "application/json", ...(options.headers || {})};
    if (csrfToken && !["GET", "HEAD", "OPTIONS"].includes((options.method || "GET").toUpperCase())) headers["X-CSRF-Token"] = csrfToken;
    const response = await fetch(path, {...options, headers});
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
    return body;
  };
  const record = (title, detail, meta = "") => `<article class="collaboration-item"><h4>${escapeHtml(title)}</h4><p>${escapeHtml(detail || "")}</p><span class="collaboration-meta">${escapeHtml(meta)}</span></article>`;
  const populateCases = async () => {
    const [cases, organization] = await Promise.all([api("/api/v1/cases"), api("/api/v1/organizations/current")]);
    const caseSelect = document.querySelector("#collaboration-case");
    caseSelect.innerHTML = '<option value="">Select an investigation</option>' + cases.items.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.case_number)} · ${escapeHtml(item.title)}</option>`).join("");
    document.querySelector("#task-assignee").innerHTML = '<option value="">Unassigned</option>' + organization.members.map((member) => `<option value="${escapeHtml(member.user_id)}">${escapeHtml(member.username || member.email || member.user_id)}</option>`).join("");
  };
  const renderCase = async () => {
    if (!selectedCase) return;
    const data = await api(`/api/v1/cases/${selectedCase}/collaboration`);
    const set = (id, html) => { document.querySelector(id).innerHTML = html || '<p class="collaboration-empty">No recorded items.</p>'; };
    set("#case-team", data.team.map((item) => record(item.username, item.team_role, item.status)).join(""));
    set("#case-tasks", data.tasks.map((item) => record(item.title, item.assignee || "Unassigned", `${item.priority} · ${item.status}`)).join(""));
    set("#case-discussions", data.threads.map((item) => record(item.title, `${item.comments.length} visible comments`, item.status)).join(""));
    set("#case-reviews", data.reviews.map((item) => record(item.reviewer, item.status, item.decision_note || item.request_note || "")).join(""));
  };
  document.querySelector("#collaboration-refresh")?.addEventListener("click", load);
  document.querySelector("#collaboration-case")?.addEventListener("change", async (event) => { selectedCase = event.target.value; await renderCase(); });
  document.querySelector("#task-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!selectedCase) { status.textContent = "Select an investigation before assigning a task."; return; }
    await api(`/api/v1/cases/${selectedCase}/tasks`, {method: "POST", body: JSON.stringify({title: document.querySelector("#task-title").value, assignee_user_id: document.querySelector("#task-assignee").value || null, priority: document.querySelector("#task-priority").value})});
    event.target.reset(); await Promise.all([renderCase(), load()]);
  });
  document.querySelector("#discussion-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!selectedCase) { status.textContent = "Select an investigation before starting a discussion."; return; }
    await api(`/api/v1/cases/${selectedCase}/discussions`, {method: "POST", body: JSON.stringify({title: document.querySelector("#discussion-title").value})});
    event.target.reset(); await renderCase();
  });
  Promise.all([load(), populateCases()]).catch((error) => { status.textContent = `Collaboration data is unavailable. ${error.message}`; });
})();
