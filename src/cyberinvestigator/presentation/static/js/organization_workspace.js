(() => {
  const esc = (value) => String(value ?? "unavailable").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const metric = (key, value) => `<div class="organization-metric"><span>${esc(key)}</span><strong>${esc(value)}</strong></div>`;
  const record = (title, detail) => `<article class="organization-record"><strong>${esc(title)}</strong><span>${esc(detail)}</span></article>`;
  async function api(path, options = {}) { const response = await fetch(path, { headers: { "Content-Type": "application/json", Accept: "application/json" }, ...options }); const body = await response.json(); if (!response.ok) throw new Error(body.error || `Request failed (${response.status}).`); return body; }
  async function load() {
    const [organizations, data] = await Promise.all([api("/api/v1/organizations"), api("/api/v1/organizations/current")]);
    const select = document.querySelector("#organization-switch");
    select.innerHTML = organizations.items.map((item) => `<option value="${esc(item.id)}" ${item.id === organizations.active_organization_id ? "selected" : ""}>${esc(item.name)} · ${esc(item.organization_role)}</option>`).join("");
    document.querySelector("#organization-collected").textContent = `Organization evidence collected ${new Date(data.collected_at).toLocaleString()}.`;
    document.querySelector("#organization-summary").innerHTML = Object.entries(data.organization_overview).map(([k,v]) => metric(k.replaceAll("_"," "), v)).join("");
    document.querySelector("#organization-usage-metrics").innerHTML = Object.entries(data.usage).filter(([k]) => k !== "source").map(([k,v]) => metric(k, v)).join("");
    document.querySelector("#organization-quotas").innerHTML = data.quotas.length ? data.quotas.map((x) => record(x.resource, `limit ${x.limit} · usage ${x.usage ?? "unavailable"} · ${x.enabled ? "enabled" : "disabled"}`)).join("") : "<p>No organization quotas are configured.</p>";
    document.querySelector("#organization-member-list").innerHTML = data.members.length ? data.members.map((x) => record(x.username || x.user_id, `${x.email || "email unavailable"} · ${x.organization_role} · ${x.status}`)).join("") : "<p>No organization members are recorded.</p>";
    document.querySelector("#organization-invitation-list").innerHTML = data.invitations.length ? data.invitations.map((x) => record(x.email, `${x.organization_role} · ${x.status} · delivery ${x.delivery_status}`)).join("") : "<p>No invitations are recorded.</p>";
  }
  document.querySelector("#organization-refresh")?.addEventListener("click", () => load().catch(alert));
  document.querySelector("#organization-switch")?.addEventListener("change", async (event) => { await api(`/api/v1/organizations/${event.target.value}/switch`, { method: "POST", body: "{}" }); window.location.reload(); });
  document.querySelector("#organization-invite-form")?.addEventListener("submit", async (event) => { event.preventDefault(); await api("/api/v1/organizations/current/invitations", { method: "POST", body: JSON.stringify({ email: document.querySelector("#organization-invite-email").value, organization_role: document.querySelector("#organization-invite-role").value, reason: document.querySelector("#organization-invite-reason").value }) }); event.target.reset(); await load(); });
  load().catch((error) => { document.querySelector("#organization-collected").textContent = error.message; });
})();
