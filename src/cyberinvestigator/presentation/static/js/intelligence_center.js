(() => {
  "use strict";
  const status = document.querySelector("#intelligence-status");
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
  const record = (title, detail, meta) => `<article class="intelligence-record"><strong>${esc(title)}</strong><span>${esc(detail)}</span><span>${esc(meta)}</span></article>`;
  const renderList = (name, items) => {
    const target = document.querySelector(`[data-intelligence-list="${name}"]`);
    if (!target) return;
    if (!items.length) { target.innerHTML = '<p class="intelligence-empty">No sourced records.</p>'; return; }
    target.innerHTML = items.map((item) => {
      if (name === "intelligence_feed" && item.kind === "indicator") return record(`${item.indicator_type}: ${item.value}`, item.lifecycle_status, `${item.source} · ${item.reputation}`);
      return record(item.name || item.external_id, item.object_type || item.source, `${item.source} · ${item.verified ? "verified" : "unverified assertion"}`);
    }).join("");
  };
  const renderGraph = (graph) => {
    const svg = document.querySelector("#intelligence-graph");
    const list = document.querySelector("#intelligence-graph-list");
    const nodes = (graph.nodes || []).slice(0, 80);
    const positions = new Map(nodes.map((node, index) => {
      const angle = (index / Math.max(nodes.length, 1)) * Math.PI * 2;
      const radius = 70 + (index % 4) * 38;
      return [node.id, {x: 450 + Math.cos(angle) * radius, y: 210 + Math.sin(angle) * radius}];
    }));
    const edges = (graph.edges || []).filter((edge) => positions.has(edge.source) && positions.has(edge.target)).slice(0, 160);
    const lines = edges.map((edge) => { const a=positions.get(edge.source), b=positions.get(edge.target); return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"><title>${esc(edge.relationship_type)} · ${esc(edge.provenance)}</title></line>`; }).join("");
    const circles = nodes.map((node) => { const point=positions.get(node.id); return `<g><circle cx="${point.x}" cy="${point.y}" r="8"><title>${esc(node.kind)}: ${esc(node.label)}</title></circle><text x="${point.x + 11}" y="${point.y + 4}">${esc(String(node.label).slice(0, 28))}</text></g>`; }).join("");
    svg.innerHTML = `<title id="graph-title">Intelligence relationship graph</title><desc id="graph-description">${nodes.length} nodes and ${edges.length} visible sourced relationships.</desc>${lines}${circles}`;
    list.innerHTML = edges.length ? edges.map((edge) => `<li>${esc(edge.source)} — ${esc(edge.relationship_type)} → ${esc(edge.target)} <small>${esc(edge.provenance)}</small></li>`).join("") : "<li>No sourced relationships.</li>";
  };
  const load = async () => {
    const data = await api("/api/v1/intelligence-center");
    ["intelligence_feed","threat_actors","campaigns"].forEach((name) => renderList(name, data[name] || []));
    renderGraph(data.graph || {nodes:[],edges:[]});
    document.querySelector("#intelligence-adapters").textContent = `${data.providers.available ? `Providers: ${data.providers.configured.join(", ")}` : "Threat intelligence providers unavailable"} · Sharing: ${data.sharing.status}`;
    status.textContent = "Threat Intelligence Center is current.";
  };
  document.querySelector("#intelligence-refresh")?.addEventListener("click", () => load().catch((error) => { status.textContent = error.message; }));
  document.querySelector("#intelligence-search-form")?.addEventListener("submit", async (event) => {
    event.preventDefault(); const data=await api("/api/v1/intelligence-center/iocs/search",{method:"POST",body:JSON.stringify({indicator_type:document.querySelector("#intelligence-ioc-type").value,indicator_value:document.querySelector("#intelligence-ioc-value").value,enrich:document.querySelector("#intelligence-enrich").checked})}); document.querySelector("#intelligence-search-result").innerHTML=record(`${data.indicator.indicator_type}: ${data.indicator.value}`,`${data.evidence_matches.length} evidence matches`,data.provider_status); await load();
  });
  document.querySelector("#intelligence-import-form")?.addEventListener("submit", async (event) => {
    event.preventDefault(); await api("/api/v1/intelligence-center/objects",{method:"POST",body:JSON.stringify({object_type:document.querySelector("#intelligence-object-type").value,name:document.querySelector("#intelligence-object-name").value,external_id:document.querySelector("#intelligence-external-id").value,source:document.querySelector("#intelligence-source").value,reference:document.querySelector("#intelligence-reference").value,verified:document.querySelector("#intelligence-verified").checked})}); event.target.reset(); await load();
  });
  document.querySelector("#intelligence-ai")?.addEventListener("click", async () => { const data=await api("/api/v1/intelligence-center/ai-summary",{method:"POST",body:"{}"}); document.querySelector("#intelligence-ai-output").textContent=JSON.stringify(data,null,2); });
  load().catch((error) => { status.textContent = `Threat intelligence data is unavailable. ${error.message}`; });
})();
