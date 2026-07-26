(() => {
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  let searchable = [];
  let operations = [];
  const operationCard = (item) => `<details class="api-operation"><summary><span class="api-method">${esc(item.method)}</span><span class="api-path">${esc(item.path)}</span><strong>${esc(item.summary)}</strong></summary><div class="api-details"><p>Operation ID: <code>${esc(item.operationId)}</code></p><p>Visibility: ${esc(item.visibility)} · Permissions: ${esc(item.permissions.join(", ") || "public")}</p><p>Responses: ${esc(item.responses.join(", "))}</p>${item.parameters.length ? `<p>Path parameters: ${esc(item.parameters.join(", "))}</p>` : ""}${item.mutating ? "<p>Session-authenticated browser requests require the CSRF header.</p>" : ""}</div></details>`;
  function renderOperations(tag = "") {
    const filtered = operations.filter((item) => !tag || item.tag === tag);
    document.querySelector("#api-operation-list").innerHTML = filtered.map(operationCard).join("") || "<p>No operation matches this resource.</p>";
  }
  async function load() {
    const [specResponse, catalogResponse] = await Promise.all([fetch("/api/v1/openapi.json"), fetch("/api/v1/developer/catalog")]);
    if (!specResponse.ok || !catalogResponse.ok) throw new Error("Developer documentation is unavailable for this session.");
    const spec = await specResponse.json();
    const catalog = await catalogResponse.json();
    for (const [path, methods] of Object.entries(spec.paths)) for (const [method, operation] of Object.entries(methods)) {
      if (!["get","post","put","patch","delete"].includes(method)) continue;
      operations.push({ method, path: `/api/v1${path}`, summary: operation.summary, operationId: operation.operationId, tag: operation.tags?.[0] || "Other", visibility: operation["x-visibility"], permissions: operation["x-required-permissions"] || [], responses: Object.keys(operation.responses || {}), parameters: (operation.parameters || []).map((item) => item.name), mutating: method !== "get" });
    }
    const tags = [...new Set(operations.map((item) => item.tag))].sort();
    document.querySelector("#api-tag").insertAdjacentHTML("beforeend", tags.map((tag) => `<option>${esc(tag)}</option>`).join(""));
    document.querySelector("#developer-version").textContent = `${catalog.api.version} · OpenAPI ${catalog.api.openapi} · ${catalog.api.operation_count} visible operations`;
    document.querySelector("#developer-guide-list").innerHTML = catalog.guides.map((guide) => `<article class="developer-doc-card"><strong>${esc(guide.title)}</strong><p>${esc(guide.audience)} · <code>${esc(guide.path)}</code></p></article>`).join("");
    document.querySelector("#developer-sdk-list").innerHTML = Object.entries(catalog.sdks).filter(([key]) => key !== "generation_source").map(([name, sdk]) => `<article class="developer-doc-card"><strong>${esc(name)}</strong><p><span class="developer-status">${esc(sdk.status)}</span> · <code>${esc(sdk.path)}</code></p></article>`).join("");
    document.querySelector("#developer-webhooks").innerHTML = `<p><span class="developer-status">${esc(catalog.webhooks.status)}</span></p><p>Subscriptions: ${esc(catalog.webhooks.subscription_api)}<br>Delivery worker: ${esc(catalog.webhooks.delivery_worker)}</p>`;
    document.querySelector("#developer-release-notes").textContent = catalog.release_notes.content || "Release notes are unavailable.";
    searchable = [...operations.map((item) => ({ title: `${item.method.toUpperCase()} ${item.path}`, detail: item.summary, anchor: "#api-reference" })), ...catalog.guides.map((item) => ({ title: item.title, detail: `${item.audience} ${item.path}`, anchor: "#developer-guides" }))];
    document.querySelector("#developer-search-status").textContent = `${searchable.length} API operations and guides are searchable.`;
    renderOperations();
  }
  document.querySelector("#api-tag")?.addEventListener("change", (event) => renderOperations(event.target.value));
  document.querySelector("#developer-search")?.addEventListener("input", (event) => {
    const query = event.target.value.trim().toLowerCase();
    const matches = query ? searchable.filter((item) => `${item.title} ${item.detail}`.toLowerCase().includes(query)).slice(0, 25) : [];
    document.querySelector("#developer-search-results").innerHTML = matches.map((item) => `<a class="developer-doc-card" href="${item.anchor}"><strong>${esc(item.title)}</strong><span>${esc(item.detail)}</span></a>`).join("");
    document.querySelector("#developer-search-status").textContent = query ? `${matches.length} matching entries.` : `${searchable.length} API operations and guides are searchable.`;
  });
  load().catch((error) => { document.querySelector("#developer-search-status").textContent = error.message; });
})();
