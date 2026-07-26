(() => {
  const text = (value) => String(value ?? "");
  const escapeHtml = (value) => text(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  const unavailable = (report) => `<p class="quality-unavailable">${escapeHtml(report?.detail || "Evidence unavailable.")}</p>`;
  const reportView = (report) => report?.status === "available"
    ? `<pre class="small mb-0">${escapeHtml(JSON.stringify(report.data, null, 2))}</pre>` : unavailable(report);
  const metrics = (status) => status.status === "unavailable" ? unavailable(status) :
    ["status","tests","failures","errors","skipped","duration_seconds"].map((key) => `<div class="quality-metric"><span>${escapeHtml(key.replace("_"," "))}</span><strong class="quality-status-${escapeHtml(status.status)}">${escapeHtml(status[key])}</strong></div>`).join("");
  async function load() {
    const response = await fetch("/api/v1/admin/quality", { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`Quality evidence request failed (${response.status}).`);
    const data = await response.json();
    document.querySelector("#quality-collected").textContent = `Evidence collected ${new Date(data.collected_at).toLocaleString()}.`;
    document.querySelector("#quality-test-status").innerHTML = metrics(data.test_status);
    document.querySelector("#quality-failed-runs").innerHTML = data.failed_runs.length ? data.failed_runs.map((run) => `<div class="quality-item"><strong>${escapeHtml(run.suite)}</strong><div>${run.failures} failures · ${run.errors} errors</div></div>`).join("") : "<p>No failed runs are present in the available JUnit evidence.</p>";
    document.querySelector("#quality-security").innerHTML = `<div class="quality-item"><h4>SAST</h4>${reportView(data.security_findings.sast)}</div><div class="quality-item"><h4>Dependencies</h4>${reportView(data.security_findings.dependencies)}</div>`;
    document.querySelector("#quality-coverage").innerHTML = reportView(data.coverage_summary);
    document.querySelector("#quality-accessibility").innerHTML = reportView(data.accessibility);
    document.querySelector("#quality-performance").innerHTML = reportView(data.performance);
    document.querySelector("#quality-suites").innerHTML = data.suites.length ? data.suites.map((suite) => `<div class="quality-item"><strong>${escapeHtml(suite.name)}</strong><div>${suite.tests} tests · ${suite.duration_seconds}s · ${escapeHtml(suite.status)}</div></div>`).join("") : "<p class=\"quality-unavailable\">No suite evidence is available.</p>";
  }
  const refresh = () => load().catch((error) => { document.querySelector("#quality-collected").textContent = error.message; });
  document.querySelector("#quality-refresh")?.addEventListener("click", refresh);
  refresh();
})();
