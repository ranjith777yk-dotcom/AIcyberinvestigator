(() => {
  const esc = (value) => String(value ?? "unavailable").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const empty = (message) => `<p class="text-muted">${esc(message)}</p>`;
  const records = (items, render, message) => items?.length ? items.map(render).join("") : empty(message);
  const record = (title, detail) => `<article class="governance-record"><strong>${esc(title)}</strong><span>${esc(detail)}</span></article>`;
  async function api(path, options = {}) {
    const response = await fetch(path, { headers: { "Content-Type": "application/json", Accept: "application/json" }, ...options });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status}).`);
    return body;
  }
  async function load() {
    const data = await api("/api/v1/admin/governance");
    document.querySelector("#governance-collected").textContent = `Governance evidence collected ${new Date(data.collected_at).toLocaleString()}.`;
    document.querySelector("#governance-risks").innerHTML = records(data.critical_risks, (x) => record(`${x.level}: ${x.title}`, x.message), "No persisted critical governance risks are open.");
    document.querySelector("#governance-policy-status").innerHTML = [["configured", data.policy_status.configured], ["valid", data.policy_status.valid], ["version", data.policy_status.effective_policy.version], ["classified cases", data.classification.classified_cases], ["unclassified cases", data.classification.unclassified_cases], ["data errors", data.policy_status.data_errors.length]].map(([k,v]) => `<div class="governance-metric"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join("");
    document.querySelector("#governance-holds").innerHTML = records(data.legal_holds, (x) => record(x.case_number || x.case_id, x.reason), "No active legal holds are recorded.");
    document.querySelector("#governance-retention").innerHTML = records(data.retention_alerts, (x) => record(`${x.case_number} · ${x.status}`, `${x.classification} · review due ${x.review_due_at}`), "No cases meet a configured retention review date.");
    document.querySelector("#governance-classifications").innerHTML = records(data.classification.assignments, (x) => `<article class="governance-record"><strong>${esc(x.case_number)} · ${esc(x.classification)}</strong><span>${esc(x.title)} · ${x.explicit ? "explicit" : "policy default"}</span><button class="btn btn-sm btn-outline-secondary mt-2" data-classify="${esc(x.case_id)}" type="button">Change classification</button></article>`, "No active investigations are available.");
    document.querySelector("#governance-privacy").innerHTML = records(data.privacy_requests, (x) => record(`${x.request_type} · ${x.status}`, x.subject_reference), "No privacy requests are recorded.");
    document.querySelector("#governance-activity").innerHTML = records(data.governance_activity, (x) => record(x.action, `${x.username} · ${x.result} · ${x.created_at}`), "No governance activity is recorded.");
    const policy = data.policy_status.effective_policy;
    document.querySelector("#policy-default").value = policy.default_classification;
    document.querySelector("#policy-classification-required").checked = Boolean(policy.classification_required);
    document.querySelector("#policy-export-reason").checked = Boolean(policy.export_reason_required);
    document.querySelector("#policy-retention-internal").value = policy.retention_days.internal || "";
    document.querySelector("#policy-retention-confidential").value = policy.retention_days.confidential || "";
    document.querySelector("#policy-retention-restricted").value = policy.retention_days.restricted || "";
  }
  document.querySelector("#governance-refresh")?.addEventListener("click", () => load().catch(alert));
  document.querySelector("#governance-classifications")?.addEventListener("click", async (event) => { const button = event.target.closest("[data-classify]"); if (!button) return; const level = prompt("Classification: public, internal, confidential, or restricted"); const reason = prompt("Reason (minimum 10 characters):"); if (level && reason) { await api(`/api/v1/admin/governance/classifications/${button.dataset.classify}`, { method: "PUT", body: JSON.stringify({ level, reason }) }); await load(); } });
  document.querySelector("#privacy-request-form")?.addEventListener("submit", async (event) => { event.preventDefault(); await api("/api/v1/admin/governance/privacy-requests", { method: "POST", body: JSON.stringify({ request_type: document.querySelector("#privacy-type").value, subject_reference: document.querySelector("#privacy-subject").value, reason: document.querySelector("#privacy-reason").value }) }); event.target.reset(); await load(); });
  document.querySelector("#governance-policy-form")?.addEventListener("submit", async (event) => { event.preventDefault(); const formats = { public: ["json","html","md","markdown","csv","xlsx","excel","docx","pdf","zip"], internal: ["json","html","md","markdown","csv","xlsx","excel","docx","pdf","zip"], confidential: ["json","pdf","zip"], restricted: ["pdf","zip"] }; await api("/api/v1/admin/governance/policy", { method: "PUT", body: JSON.stringify({ default_classification: document.querySelector("#policy-default").value, classification_required: document.querySelector("#policy-classification-required").checked, export_reason_required: document.querySelector("#policy-export-reason").checked, disposition_approval_required: true, retention_days: { public: null, internal: Number(document.querySelector("#policy-retention-internal").value) || null, confidential: Number(document.querySelector("#policy-retention-confidential").value) || null, restricted: Number(document.querySelector("#policy-retention-restricted").value) || null }, allowed_export_formats: formats, reason: document.querySelector("#policy-reason").value }) }); await load(); });
  load().catch((error) => { document.querySelector("#governance-collected").textContent = error.message; });
})();
