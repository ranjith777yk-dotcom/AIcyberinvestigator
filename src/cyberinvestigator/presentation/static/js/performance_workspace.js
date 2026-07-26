(() => {
  const escapeHtml = (value) => String(value ?? "unavailable").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const items = (data) => Object.entries(data || {}).map(([key, value]) => `<div class="performance-item"><span>${escapeHtml(key.replaceAll("_", " "))}</span><strong>${escapeHtml(typeof value === "object" ? JSON.stringify(value) : value)}</strong></div>`).join("");
  const list = (data) => Object.entries(data || {}).map(([key, value]) => `<div class="performance-item"><strong>${escapeHtml(key.replaceAll("_", " "))}</strong><span>${escapeHtml(typeof value === "object" ? JSON.stringify(value) : value)}</span></div>`).join("");
  async function api(path, options = {}) {
    const response = await fetch(path, { headers: { "Content-Type": "application/json", Accept: "application/json" }, ...options });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status}).`);
    return body;
  }
  async function load() {
    const data = await api("/api/v1/admin/performance");
    document.querySelector("#performance-collected").textContent = `Current-process evidence collected ${new Date(data.collected_at).toLocaleString()}.`;
    document.querySelector("#performance-health").innerHTML = items({ process_uptime_seconds: data.platform_health.process_uptime_seconds, process_id: data.platform_health.process_id, requests_total: data.platform_health.request_telemetry.requests_total, p95_ms: data.platform_health.request_telemetry.latency_ms.p95, error_rate: data.platform_health.request_telemetry.server_error_rate });
    document.querySelector("#performance-capacity").innerHTML = list(data.capacity);
    document.querySelector("#performance-queue").innerHTML = items(data.queue_status);
    document.querySelector("#performance-cache").innerHTML = items(data.cache);
    document.querySelector("#performance-bottlenecks").innerHTML = data.bottlenecks.length ? data.bottlenecks.map((item) => `<div class="performance-item"><strong>${escapeHtml(item.component)}</strong><span>${escapeHtml(item.status)}</span></div>`).join("") : "<p>No bottleneck is present in the currently observed process metrics.</p>";
    document.querySelector("#performance-ha").innerHTML = list(data.high_availability);
  }
  document.querySelector("#performance-refresh")?.addEventListener("click", () => load().catch(alert));
  document.querySelector("#performance-cache-clear")?.addEventListener("click", async () => { const reason = prompt("Reason for cache invalidation (minimum 10 characters):"); if (reason) { await api("/api/v1/admin/performance/cache/invalidate", { method: "POST", body: JSON.stringify({ reason }) }); await load(); } });
  document.querySelector("#capacity-plan-form")?.addEventListener("submit", async (event) => { event.preventDefault(); await api("/api/v1/admin/performance/capacity-plan", { method: "PATCH", body: JSON.stringify({ target_p95_ms: document.querySelector("#capacity-p95").value, maximum_queue_depth: document.querySelector("#capacity-queue").value, minimum_free_storage_percent: document.querySelector("#capacity-storage").value, reason: document.querySelector("#capacity-reason").value }) }); await load(); });
  load().catch((error) => { document.querySelector("#performance-collected").textContent = error.message; });
})();
