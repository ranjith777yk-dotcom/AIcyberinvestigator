(() => {
  "use strict";
  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
  const record = (title, detail, meta) => `<article class="evidence-lab-record"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(detail)}</span><span>${escapeHtml(meta)}</span></article>`;
  const render = (name, items) => {
    const target = document.querySelector(`[data-lab-list="${name}"]`);
    if (!target) return;
    if (!items.length) { target.innerHTML = '<p class="evidence-lab-empty">No recorded items.</p>'; return; }
    target.innerHTML = items.map((item) => {
      if (name === "evidence_status") return record(item.evidence_number, item.filename, `${item.storage_state} · ${item.analysis_status}`);
      if (name === "analysis_results") return record(item.analyzer, item.status, item.integrity_verified ? "SHA-256 verified" : "Integrity not verified");
      if (name === "queue") return record(item.step || "Queued", item.status, `${item.progress ?? 0}%`);
      return record(item.name, item.artifact_type, item.content_hash || "Hash unavailable");
    }).join("");
  };
  fetch("/api/v1/evidence-lab", {headers: {"Accept": "application/json"}})
    .then(async (response) => {
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
      return body;
    })
    .then((data) => {
      ["evidence_status", "analysis_results", "queue", "artifacts"].forEach((name) => render(name, data[name] || []));
      const sandbox = data.sandbox || {};
      document.querySelector("#evidence-lab-provider").textContent = sandbox.configured
        ? `Sandbox adapter: ${sandbox.provider} · ${sandbox.status}`
        : `Sandbox unavailable: ${sandbox.reason || "No isolated provider is configured."}`;
    })
    .catch((error) => { document.querySelector("#evidence-lab-provider").textContent = `Evidence Lab data is unavailable. ${error.message}`; });
})();
