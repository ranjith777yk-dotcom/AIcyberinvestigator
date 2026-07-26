(() => {
  "use strict";
  const status = document.querySelector("#hunt-status");
  const csrf = document.querySelector("meta[name='csrf-token']")?.content;
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[character]));
  const api = async (path, options = {}) => {
    const headers = {"Accept":"application/json","Content-Type":"application/json",...(options.headers || {})};
    if (csrf && !["GET","HEAD","OPTIONS"].includes((options.method || "GET").toUpperCase())) headers["X-CSRF-Token"] = csrf;
    const response = await fetch(path, {...options, headers});
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
    return body;
  };
  const card = (title, detail, meta) => `<article class="hunting-record"><strong>${esc(title)}</strong><span>${esc(detail)}</span><span>${esc(meta)}</span></article>`;
  const render = (name, items) => {
    const target = document.querySelector(`[data-hunt-list="${name}"]`);
    if (!target) return;
    if (!items.length) { target.innerHTML = '<p class="hunting-empty">No recorded items.</p>'; return; }
    target.innerHTML = items.map((item) => {
      if (name === "active_hunts") return card(item.name, item.hypothesis, `${item.case_number || item.case_id} · ${item.status}`);
      if (name === "ioc_searches") return card(`${item.indicator_type}: ${item.indicator_value}`, `${item.evidence_matches} evidence matches`, item.provider_status);
      if (name === "detection_alerts") return card(item.indicator_type, item.indicator_value, `${item.source} · ${item.status}`);
      return card(item, "Recorded rule ATT&CK tag", "Authored coverage; not a confirmed detection");
    }).join("");
  };
  const populateHunts = (hunts) => {
    const options = '<option value="">Select hunt</option>' + hunts.map((hunt) => `<option value="${esc(hunt.id)}">${esc(hunt.name)}</option>`).join("");
    document.querySelector("#ioc-hunt").innerHTML = options;
    document.querySelector("#ai-hunt").innerHTML = options;
  };
  const load = async () => {
    const data = await api("/api/v1/threat-hunting");
    ["active_hunts","ioc_searches","detection_alerts","attack_coverage"].forEach((name) => render(name, data[name] || []));
    populateHunts(data.hunt_history || []);
    document.querySelector("#hunt-provider-note").textContent = data.provider_status.available
      ? `Configured threat intelligence providers: ${data.provider_status.providers.join(", ")}`
      : "Threat intelligence providers are unavailable; evidence-only correlation remains available.";
    status.textContent = "Threat Hunting Center is current.";
  };
  const loadCases = async () => {
    const data = await api("/api/v1/cases");
    document.querySelector("#hunt-case").innerHTML = '<option value="">Select investigation</option>' + data.items.map((item) => `<option value="${esc(item.id)}">${esc(item.case_number)} · ${esc(item.title)}</option>`).join("");
  };
  document.querySelector("#hunt-refresh")?.addEventListener("click", () => load().catch((error) => { status.textContent = error.message; }));
  document.querySelector("#hunt-form")?.addEventListener("submit", async (event) => {
    event.preventDefault(); await api("/api/v1/threat-hunting/hunts", {method:"POST", body:JSON.stringify({case_id:document.querySelector("#hunt-case").value,name:document.querySelector("#hunt-name").value,hypothesis:document.querySelector("#hunt-hypothesis").value,scope:document.querySelector("#hunt-scope").value})}); event.target.reset(); await load();
  });
  document.querySelector("#ioc-form")?.addEventListener("submit", async (event) => {
    event.preventDefault(); await api(`/api/v1/threat-hunting/hunts/${document.querySelector("#ioc-hunt").value}/ioc-searches`, {method:"POST", body:JSON.stringify({indicator_type:document.querySelector("#ioc-type").value,indicator_value:document.querySelector("#ioc-value").value,enrich:document.querySelector("#ioc-enrich").checked})}); event.target.reset(); await load();
  });
  document.querySelector("#rule-form")?.addEventListener("submit", async (event) => {
    event.preventDefault(); await api("/api/v1/detection-rules", {method:"POST",body:JSON.stringify({rule_key:document.querySelector("#rule-key").value,definition:JSON.parse(document.querySelector("#rule-definition").value),enabled:document.querySelector("#rule-enabled").checked})}); event.target.reset(); await load();
  });
  document.querySelector("#hunt-ai")?.addEventListener("click", async () => {
    const hunt = document.querySelector("#ai-hunt").value;
    if (!hunt) { status.textContent = "Select a hunt before requesting suggestions."; return; }
    const data = await api(`/api/v1/threat-hunting/hunts/${hunt}/ai-recommendations`, {method:"POST",body:"{}"});
    document.querySelector("#hunt-ai-output").textContent = JSON.stringify(data, null, 2);
  });
  Promise.all([load(), loadCases()]).catch((error) => { status.textContent = `Threat hunting data is unavailable. ${error.message}`; });
})();
