"use strict";

const pageState = { cases: 1 };
let selectedInvestigationCase = null;
const evidenceInventory = new Map();
let selectedEvidence = null;

function el(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  Object.entries(options).forEach(([key, value]) => {
    if (key === "className") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "dataset") Object.entries(value).forEach(([name, item]) => { node.dataset[name] = item; });
    else if (key === "type") node.type = value;
    else if (key === "value") node.value = value;
    else node.setAttribute(key, value);
  });
  children.forEach((child) => node.append(child));
  return node;
}

function setState(node, icon, title, text, variant = "") {
  if (!node) return;
  node.classList.remove("d-none");
  node.classList.toggle("text-danger", variant === "danger");
  node.replaceChildren(
    el("i", { className: `bi ${icon}` }),
    el("h3", { text: title }),
    el("p", { text }),
  );
}

function hide(node) {
  node?.classList.add("d-none");
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "-";
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length);
  return `${(bytes / (1024 ** exponent)).toFixed(exponent > 1 ? 1 : 0)} ${units[exponent - 1]}`;
}

function clamp(value, min = 0, max = 100) {
  return Math.min(max, Math.max(min, Number(value) || 0));
}

function emptyInline(icon, title, text) {
  return el("div", { className: "empty-state compact" }, [
    el("i", { className: `bi ${icon}` }),
    el("h3", { text: title }),
    el("p", { text }),
  ]);
}

function renderKeyValueGrid(target, items) {
  if (!target) return;
  target.replaceChildren(...items.map((item) => el("div", { className: "health-item" }, [
    el("small", { text: item.label }),
    el("strong", { text: String(item.value) }),
  ])));
}

function query(params) {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "" && value !== "all") search.set(key, value);
  });
  const text = search.toString();
  return text ? `?${text}` : "";
}

function requestedCaseId() {
  return new URLSearchParams(window.location.search).get("case_id") || "";
}

function applyRequestedCase(targets) {
  const caseId = requestedCaseId();
  if (!caseId) return;
  targets.forEach((target) => {
    if (target?.querySelector(`option[value="${CSS.escape(caseId)}"]`)) target.value = caseId;
  });
}

async function fetchCases(params = {}) {
  return api(`/api/v1/cases${query(params)}`);
}

async function caseOptions(targets, includeAll = false) {
  const data = await fetchCases({ per_page: 100, sort: "case_number", direction: "asc" });
  targets.forEach((target) => {
    if (!target) return;
    const options = [];
    options.push(el("option", { value: includeAll ? "all" : "", text: includeAll ? "All cases" : "Select case" }));
    data.items.forEach((item) => options.push(el("option", { value: item.id, text: `${item.case_number} - ${item.title}` })));
    target.replaceChildren(...options);
  });
  return data.items;
}

function initialiseDashboardCards() {
  if (!document.querySelector("[data-dashboard-root]")) return;
  const root = document.querySelector("[data-dashboard-root]");
  const setText = (selector, value) => {
    document.querySelectorAll(selector).forEach((node) => { node.textContent = value; });
  };
  const setNote = (name, value) => {
    const node = document.querySelector(`[data-metric-note='${name}']`);
    if (node) node.textContent = value;
  };
  const clearSkeletons = () => root.querySelectorAll(".skeleton").forEach((node) => node.classList.remove("skeleton"));
  document.querySelectorAll("[data-metric]").forEach((node) => { node.textContent = "-"; });
  api("/api/v1/dashboard")
    .then((data) => {
      const criticalAlerts = (data.recent_notifications || []).filter((item) => ["critical", "high"].includes(item.priority || "")).length;
      const networkStatus = data.threat_score >= 65 ? "Elevated" : data.timeline_count ? "Monitored" : "Quiet";
      clearSkeletons();
      setText("[data-metric='threat-score']", data.threat_score === null ? "-" : String(data.threat_score));
      setText("[data-metric='threat-alert-count']", String(criticalAlerts));
      setText("[data-metric='progress']", data.progress === null ? "-" : `${data.progress}%`);
      setText("[data-metric='cases-count']", String(data.cases_count));
      setText("[data-metric='evidence-count']", String(data.evidence_count));
      setText("[data-metric='timeline-count']", String(data.timeline_count));
      setText("[data-metric='reports-count']", String(data.reports_count || 0));
      setText("[data-metric='critical-alerts']", String(criticalAlerts));
      setText("[data-metric='network-status']", networkStatus);
      setText("[data-metric='plugin-status']", data.plugin_status === "enabled" ? "Enabled" : "Disabled");
      setText("[data-metric='ai-status']", data.provider?.available ? "Available" : "Offline mode");
      setText("[data-metric='system-health']", data.plugin_health.failures ? "Degraded" : "Healthy");
      setText("[data-current-case-number]", data.selected_case?.case_number || "No active case");
      setText("[data-current-case-title]", data.selected_case?.title || "Create an investigation to begin correlation.");
      setText("[data-dashboard-notification-count]", String((data.recent_notifications || []).filter((item) => !item.read).length));
      setText("[data-dashboard-notification-label]", criticalAlerts ? `${criticalAlerts} high priority alert(s)` : "No critical notifications");
      setNote("cases", `${data.active_cases_count || 0} active`);
      setNote("evidence", data.selected_case ? `Latest case ${data.selected_case.case_number}` : "No active case");
      setNote("timeline", `${data.timeline_count} events in focus`);
      setNote("plugins", `${data.plugin_health.configured} discovered, ${data.plugin_health.failures} failures`);
      setNote("reports", `${data.reports_count || 0} generated`);
      setNote("ai", "Ready for investigation support");
      setNote("threat", criticalAlerts ? `${criticalAlerts} recorded alert(s) need review` : "No priority alerts recorded");
      setNote("alerts", criticalAlerts ? "Needs review" : "Clear");
      setNote("network", `${data.timeline_count || 0} correlated events`);
      setNote("health", data.plugin_health.failures ? `${data.plugin_health.failures} service issue(s)` : "All monitored services ready");
      setTrend("cases", `${data.active_cases_count || 0} active`);
      setTrend("alerts", criticalAlerts ? "Review" : "Stable");
      setTrend("ai", data.provider?.provider || "local");
      setTrend("evidence", `${data.evidence_count || 0} items`);
      setTrend("network", networkStatus);
      setTrend("plugins", data.plugin_health.status || data.plugin_status);
      setTrend("timeline", `${data.timeline_count || 0} events`);
      setTrend("reports", `${data.reports_count || 0} ready`);
      setTrend("health", data.plugin_health.failures ? "Review" : "Operational");
      renderDashboardBanner(data, criticalAlerts);
      renderSocCharts(data);
      renderSocFeeds(data);
      renderEvidenceSummary(document.querySelector("[data-list='recent-evidence']"), data.recent_evidence || []);
      renderReportsSummary(document.querySelector("[data-list='latest-reports']"), data.latest_reports || []);
      renderAiRecommendation(data);
      renderCustodyStatus(data);
      renderKeyValueGrid(document.querySelector("[data-plugin-health]"), [
        { label: "Network", value: networkStatus },
        { label: "AI", value: data.provider?.available ? "available" : "offline" },
        { label: "Configured", value: data.plugin_health.configured },
        { label: "Enabled", value: data.plugin_health.enabled },
        { label: "Plugin health", value: data.plugin_health.failures ? "degraded" : data.plugin_health.status },
      ]);
      renderProgress(
        Number(data.lifecycle_progress?.completed || 0) * 25,
        data.lifecycle_progress || {},
      );
      initialiseDashboardCaseTable(data.active_cases || []);
    })
    .catch((error) => {
      clearSkeletons();
      document.querySelectorAll("[data-metric]").forEach((node) => { node.textContent = "-"; });
      document.querySelectorAll("[data-list], [data-chart], [data-plugin-health]").forEach((node) => {
        node.replaceChildren(emptyInline("bi-exclamation-triangle", "Dashboard unavailable", error.message));
      });
      const headline = document.querySelector("[data-dashboard-headline]");
      const subtitle = document.querySelector("[data-dashboard-subtitle]");
      if (headline) headline.textContent = "Briefing unavailable";
      if (subtitle) subtitle.textContent = "Workspace data could not be loaded. Retry after checking your connection.";
      document.querySelector("[data-dashboard-recommendation]")?.replaceChildren(
        emptyInline("bi-exclamation-triangle", "AI findings unavailable", "The dashboard snapshot could not be loaded."),
      );
      showToast(error.message, "danger");
    });
}

function setTrend(name, value) {
  const node = document.querySelector(`[data-trend='${name}']`);
  if (node) node.textContent = value;
}

function renderDashboardBanner(data, criticalAlerts) {
  const headline = document.querySelector("[data-dashboard-headline]");
  const subtitle = document.querySelector("[data-dashboard-subtitle]");
  if (headline) {
    if (!data.selected_case) headline.textContent = "No active investigation is in focus";
    else if (criticalAlerts) headline.textContent = `${criticalAlerts} priority alert(s) require review`;
    else if ((data.ai_insights || []).length) headline.textContent = "New AI-assisted findings are available";
    else headline.textContent = "Review the latest investigation activity";
  }
  if (subtitle) {
    subtitle.textContent = `${data.active_cases_count || 0} active investigation(s), ${criticalAlerts} critical alert(s), ${data.evidence_count || 0} evidence item(s), and ${data.timeline_count || 0} timeline event(s) are currently correlated.`;
  }
}

function renderSocCharts(data) {
  renderBarChart(
    document.querySelector("[data-chart='threat-activity']"),
    Object.entries(data.event_type_counts || {}).map(([label, value]) => ({
      label: label.replaceAll("_", " ").split(".")[0],
      value,
    })),
    "Recorded timeline activity",
  );
  renderLineChart(document.querySelector("[data-chart='score-trend']"), buildScoreTrend(data), { label: "Score", color: "#3b6df6", fill: true });
  renderBarChart(document.querySelector("[data-chart='timeline-activity']"), data.timeline_preview?.map((item, index) => ({ label: item.group || `T${index + 1}`, value: item.threat_weight || 8 })) || [], "Timeline events");
  renderDonutChart(document.querySelector("[data-chart='attack-distribution']"), attackDistribution(data));
  renderHorizontalBars(document.querySelector("[data-chart='case-status']"), caseStatusDistribution(data));
  renderHorizontalBars(document.querySelector("[data-chart='ioc-categories']"), iocCategories(data));
  renderHorizontalBars(document.querySelector("[data-chart='mitre-techniques']"), mitreTechniqueData(data));
  renderBarChart(document.querySelector("[data-chart='investigation-trend']"), data.case_graph || [], "Investigation activity");
  renderLineChart(document.querySelector("[data-chart='evidence-growth']"), buildEvidenceGrowth(data), { label: "Evidence", color: "#149f6d", fill: true });
  const routes = {
    threat: "/timeline", "score-trend": "/timeline", "timeline-activity": "/timeline",
    "attack-distribution": "/timeline", "case-status": "/cases", "investigation-trend": "/cases",
    "evidence-growth": "/evidence", "ioc-categories": "/evidence", "mitre-techniques": "/reports",
  };
  document.querySelectorAll("[data-chart]").forEach((chart) => {
    const panel = chart.closest(".soc-panel");
    const route = routes[chart.dataset.chart];
    if (!panel || !route || panel.dataset.navigationReady) return;
    panel.dataset.navigationReady = "true";
    panel.classList.add("soc-clickable-panel");
    panel.tabIndex = 0;
    panel.setAttribute("role", "link");
    panel.addEventListener("click", (event) => { if (!event.target.closest("a,button")) window.location.href = route; });
    panel.addEventListener("keydown", (event) => { if (event.key === "Enter") window.location.href = route; });
  });
}

function buildEvidenceGrowth(data) {
  const items = [...(data.recent_evidence || [])].reverse();
  if (!items.length) return [{ label: "Start", value: 0 }, { label: "Current", value: Number(data.evidence_count || 0) }];
  return items.map((item, index) => ({ label: item.evidence_number || `E${index + 1}`, value: index + 1 }));
}

function buildScoreTrend(data) {
  const base = Number(data.threat_score || 0);
  const points = data.threat_graph?.length ? data.threat_graph : [{ label: "Start", value: Math.max(0, base - 18) }, { label: "Current", value: base }];
  return points.map((point, index) => ({ label: point.label || `P${index + 1}`, value: clamp(point.value || base) }));
}

function attackDistribution(data) {
  const counts = data.event_type_counts || {};
  const rows = Object.entries(counts).map(([label, value]) => ({ label: label.split(".")[0] || label, value }));
  if (rows.length) return rows.slice(0, 5);
  return [
    { label: "Evidence", value: data.evidence_count || 1 },
    { label: "Timeline", value: data.timeline_count || 1 },
    { label: "Reports", value: data.reports_count || 1 },
  ];
}

function caseStatusDistribution(data) {
  return [
    { label: "Active", value: data.active_cases_count || 0, color: "#149f6d" },
    { label: "Queued", value: Math.max(0, (data.cases_count || 0) - (data.active_cases_count || 0)), color: "#3b6df6" },
    { label: "High Priority", value: (data.case_graph || []).filter((item) => ["critical", "high"].includes(item.severity)).length, color: "#d9534f" },
  ];
}

function iocCategories(data) {
  return [
    { label: "Evidence", value: data.evidence_count || 0, color: "#149f6d" },
    { label: "Reports", value: data.reports_count || 0, color: "#775cf4" },
    { label: "Alerts", value: (data.recent_notifications || []).length, color: "#e98c1a" },
    { label: "Activity", value: data.timeline_count || 0, color: "#3b6df6" },
  ];
}

function mitreTechniqueData(data) {
  const counts = data.event_type_counts || {};
  const mapped = Object.entries(counts).slice(0, 5).map(([label, value], index) => ({
    label: ["Initial Access", "Execution", "Persistence", "Discovery", "Impact"][index] || label,
    value,
    color: ["#3b6df6", "#775cf4", "#e98c1a", "#149f6d", "#d9534f"][index % 5],
  }));
  return mapped.length ? mapped : [{ label: "No mapping", value: 1, color: "#8893a5" }];
}

function renderLineChart(target, points, options = {}) {
  if (!target) return;
  const data = points.length ? points : [{ label: "No signal", value: 0 }];
  const width = 640;
  const height = target.classList.contains("soc-chart-large") ? 260 : 190;
  const pad = 26;
  const max = Math.max(...data.map((item) => Number(item.value) || 0), 1);
  const step = data.length > 1 ? (width - pad * 2) / (data.length - 1) : 0;
  const coords = data.map((item, index) => {
    const x = pad + index * step;
    const y = height - pad - ((Number(item.value) || 0) / max) * (height - pad * 2);
    return { x, y, item };
  });
  const path = coords.map((point, index) => `${index ? "L" : "M"}${point.x},${point.y}`).join(" ");
  const area = `${path} L${coords.at(-1).x},${height - pad} L${coords[0].x},${height - pad} Z`;
  target.replaceChildren(el("div", { className: "soc-svg-chart", title: `${options.label || "Signal"} max ${max}` }, [
    svg("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": `${options.label || "Signal"} chart` }, [
      svg("path", { d: area, class: "soc-chart-area", style: `--chart-color:${options.color || "#3b6df6"}` }),
      svg("path", { d: path, class: "soc-chart-line", style: `--chart-color:${options.color || "#3b6df6"}` }),
      ...coords.map((point) => svg("circle", { cx: point.x, cy: point.y, r: "5", class: "soc-chart-point" }, [
        svg("title", {}, [`${point.item.label}: ${point.item.value}`]),
      ])),
    ]),
  ]));
}

function renderBarChart(target, rows, label) {
  if (!target) return;
  const data = rows.length ? rows : [{ label: "None", value: 0 }];
  const max = Math.max(...data.map((item) => Number(item.value) || 0), 1);
  target.replaceChildren(el("div", { className: "soc-column-chart", title: label }, data.map((item, index) => el("div", { className: "soc-column", title: `${item.label}: ${item.value}`, style: `--h:${Math.max(8, ((Number(item.value) || 0) / max) * 100)}%;--delay:${index * 45}ms` }, [
    el("span", { text: String(item.value) }),
    el("small", { text: item.label }),
  ]))));
}

function renderHorizontalBars(target, rows) {
  if (!target) return;
  const data = rows.length ? rows : [{ label: "No data", value: 0, color: "#8893a5" }];
  const max = Math.max(...data.map((item) => Number(item.value) || 0), 1);
  target.replaceChildren(el("div", { className: "soc-horizontal-bars" }, data.map((item) => el("div", { className: "soc-hbar", title: `${item.label}: ${item.value}` }, [
    el("span", { text: item.label }),
    el("div", { className: "soc-hbar-track" }, [el("div", { className: "soc-hbar-fill", style: `width:${Math.max(5, ((Number(item.value) || 0) / max) * 100)}%;--bar-color:${item.color || "#3b6df6"}` })]),
    el("strong", { text: String(item.value) }),
  ]))));
}

function renderDonutChart(target, rows) {
  if (!target) return;
  const colors = ["#3b6df6", "#775cf4", "#149f6d", "#e98c1a", "#d9534f"];
  const total = rows.reduce((sum, item) => sum + (Number(item.value) || 0), 0) || 1;
  let cumulative = 0;
  const gradient = rows.map((item, index) => {
    const start = (cumulative / total) * 360;
    cumulative += Number(item.value) || 0;
    const end = (cumulative / total) * 360;
    return `${colors[index % colors.length]} ${start}deg ${end}deg`;
  }).join(",");
  target.replaceChildren(el("div", { className: "soc-donut-card" }, [
    el("div", { className: "soc-donut", style: `background:conic-gradient(${gradient})` }, [el("strong", { text: String(total) }), el("small", { text: "events" })]),
    el("div", { className: "soc-donut-legend" }, rows.map((item, index) => el("span", { title: `${item.label}: ${item.value}` }, [
      el("i", { style: `background:${colors[index % colors.length]}` }),
      document.createTextNode(`${item.label} ${item.value}`),
    ]))),
  ]));
}

function svg(tag, attrs = {}, children = []) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value));
  children.forEach((child) => node.append(typeof child === "string" ? document.createTextNode(child) : child));
  return node;
}

function renderSocFeeds(data) {
  const feedItems = [
    ...(data.recent_notifications || []).map((item) => ({ title: item.title, text: item.message, type: item.category || "Alert", icon: notificationIcon(item.category), severity: item.priority || "info", time: item.created_at })),
    ...(data.recent_activity || []).map((item) => ({ title: item.summary, text: item.event_type, type: "Timeline", icon: "bi bi-clock-history", severity: item.threat_level || "medium", time: item.occurred_at })),
    ...(data.recent_evidence || []).map((item) => ({ title: "Evidence Uploaded", text: item.original_filename, type: "Evidence", icon: "bi bi-folder2-open", severity: item.analysis_status === "completed" ? "low" : "medium", time: item.acquired_at })),
    ...(data.latest_reports || []).map((item) => ({ title: "Report Generated", text: item.title, type: "Report", icon: "bi bi-file-earmark-text", severity: "info", time: item.generated_at })),
  ].sort((a, b) => new Date(b.time || 0) - new Date(a.time || 0));
  renderThreatFeed(document.querySelector("[data-list='live-threat-feed']"), feedItems.slice(0, 8));
  renderThreatFeed(document.querySelector("[data-list='recent-alerts']"), feedItems.filter((item) => ["critical", "high", "medium"].includes(item.severity)).slice(0, 5), true);
  renderThreatFeed(document.querySelector("[data-list='login-attempts']"), loginAttemptFeed(data), true);
}

function loginAttemptFeed(data) {
  const notifications = (data.recent_notifications || []).filter((item) => `${item.title} ${item.message}`.toLowerCase().includes("login"));
  if (notifications.length) {
    return notifications.map((item) => ({ title: item.title, text: item.message, type: "Auth", icon: "bi bi-person-lock", severity: item.priority || "info", time: item.created_at }));
  }
  return [
    { title: "Session Active", text: "Current workspace session is authenticated.", type: "Auth", icon: "bi bi-person-check", severity: "low", time: new Date().toISOString() },
    { title: "No Failed Login Burst", text: "No recent login alerts in dashboard scope.", type: "Auth", icon: "bi bi-shield-check", severity: "info", time: new Date().toISOString() },
  ];
}

function renderThreatFeed(target, items, compact = false) {
  if (!target) return;
  if (!items.length) {
    target.replaceChildren(emptyInline("bi-broadcast", "No live events", "New alerts, reports, evidence, and timeline events will appear here."));
    return;
  }
  target.replaceChildren(...items.map((item) => el("a", { className: `soc-feed-card severity-${item.severity} ${compact ? "compact" : ""}`.trim(), href: feedHref(item.type), title: item.text }, [
    el("i", { className: item.icon || "bi bi-broadcast" }),
    el("div", {}, [
      el("strong", { text: item.title || item.type }),
      el("span", { text: item.text || "Event recorded" }),
      el("small", { text: `${item.type || "Signal"} - ${formatDate(item.time)}` }),
    ]),
  ])));
}

function feedHref(type) {
  const lower = String(type || "").toLowerCase();
  if (lower.includes("evidence")) return "/evidence";
  if (lower.includes("report")) return "/reports";
  if (lower.includes("timeline")) return "/timeline";
  if (lower.includes("auth")) return "/profile#activity";
  return "/profile#notifications";
}

function renderAiRecommendation(data) {
  const target = document.querySelector("[data-dashboard-recommendation]");
  if (!target) return;
  const insight = (data.ai_insights || [])[0];
  if (!insight) {
    target.replaceChildren(
      emptyInline(
        "bi-stars",
        "No AI findings recorded",
        data.selected_case
          ? "Run an AI-assisted analysis or open investigation chat to create a case-linked finding."
          : "Create an investigation before requesting case-linked AI analysis.",
      ),
    );
    return;
  }
  target.replaceChildren(el("div", { className: "soc-ai-card" }, [
    el("div", { className: "soc-ai-fields" }, [
      aiField("Recorded finding", insight.title || "AI-assisted analysis"),
      aiField("Summary", insight.body),
      aiField("Recorded", insight.created_at ? formatDate(insight.created_at) : "Timestamp unavailable"),
    ]),
    el("a", { className: "btn btn-sm btn-primary", href: "/ai-chat" }, [el("i", { className: "bi bi-stars" }), document.createTextNode("Continue with AI")]),
  ]));
}

function aiField(label, value) {
  return el("p", {}, [el("small", { text: label }), el("span", { text: value })]);
}

function renderCustodyStatus(data) {
  const target = document.querySelector("[data-dashboard-custody]");
  if (!target) return;
  const evidence = data.recent_evidence || [];
  const completed = evidence.filter((item) => item.analysis_status === "completed").length;
  const total = evidence.length || data.evidence_count || 0;
  const percent = total ? Math.round((completed / total) * 100) : 100;
  target.replaceChildren(el("div", { className: "soc-custody-card" }, [
    el("div", { className: "progress", role: "progressbar", "aria-valuenow": String(percent), "aria-valuemin": "0", "aria-valuemax": "100" }, [
      el("div", { className: "progress-bar", style: `width:${percent}%`, text: `${percent}%` }),
    ]),
    el("div", { className: "soc-mini-kv mt-3" }, [
      el("span", { text: "Verified" }), el("strong", { text: String(completed) }),
      el("span", { text: "Recent Items" }), el("strong", { text: String(total) }),
      el("span", { text: "Status" }), el("strong", { text: percent >= 80 ? "Strong" : "Needs Review" }),
    ]),
  ]));
}

const dashboardCaseState = { items: [], page: 1, perPage: 6, loaded: false };

function initialiseDashboardCaseTable(items) {
  if (dashboardCaseState.loaded || !document.querySelector("[data-dashboard-cases]")) return;
  dashboardCaseState.loaded = true;
  dashboardCaseState.items = items;
  bindDashboardCaseControls();
  renderDashboardCaseTable();
}

function bindDashboardCaseControls() {
  document.querySelector("#dashboard-case-search")?.addEventListener("input", debounce(() => { dashboardCaseState.page = 1; renderDashboardCaseTable(); }));
  document.querySelector("#dashboard-case-filter")?.addEventListener("change", () => { dashboardCaseState.page = 1; renderDashboardCaseTable(); });
  document.querySelector("#dashboard-case-sort")?.addEventListener("change", () => { dashboardCaseState.page = 1; renderDashboardCaseTable(); });
  document.querySelector("[data-dashboard-page='prev']")?.addEventListener("click", () => { dashboardCaseState.page = Math.max(1, dashboardCaseState.page - 1); renderDashboardCaseTable(); });
  document.querySelector("[data-dashboard-page='next']")?.addEventListener("click", () => { dashboardCaseState.page += 1; renderDashboardCaseTable(); });
}

function renderDashboardCaseTable() {
  const target = document.querySelector("[data-dashboard-cases]");
  if (!target) return;
  const term = (document.querySelector("#dashboard-case-search")?.value || "").toLowerCase();
  const filter = document.querySelector("#dashboard-case-filter")?.value || "all";
  const sort = document.querySelector("#dashboard-case-sort")?.value || "created-desc";
  let items = dashboardCaseState.items.filter((item) => {
    const text = `${item.case_number} ${item.title} ${item.owner || ""} ${item.status} ${item.priority}`.toLowerCase();
    return (!term || text.includes(term)) && (filter === "all" || item.status === filter);
  });
  items = sortDashboardCases(items, sort);
  const pages = Math.max(1, Math.ceil(items.length / dashboardCaseState.perPage));
  dashboardCaseState.page = Math.min(dashboardCaseState.page, pages);
  const start = (dashboardCaseState.page - 1) * dashboardCaseState.perPage;
  const visible = items.slice(start, start + dashboardCaseState.perPage);
  if (!visible.length) {
    const filtered = Boolean(term || filter !== "all");
    target.replaceChildren(el("tr", {}, [el("td", { colspan: "8" }, [
      filtered
        ? emptyInline("bi-search", "No investigations match", "Adjust search, sorting, or filtering.")
        : emptyInline("bi-briefcase", "No active investigations", "Create a case to begin an investigation workflow."),
    ])]));
  } else {
    target.replaceChildren(...visible.map((item) => el("tr", { title: `${item.case_number} - ${item.title}` }, [
      el("td", {}, [el("code", { text: item.case_number })]),
      el("td", {}, [el("strong", { text: item.title }), el("small", { className: "text-muted d-block", text: (item.description || "No description").slice(0, 88) })]),
      el("td", {}, [el("span", { className: `priority-pill priority-${item.priority}`, text: item.priority })]),
      el("td", {}, [el("div", { className: "owner-cell" }, [
        el("span", { className: "avatar", text: (item.owner || "?").slice(0, 2).toUpperCase() }),
        el("span", { text: item.owner || "Unassigned" }),
      ])]),
      el("td", {}, [el("span", { className: "badge text-bg-light", text: item.status })]),
      el("td", { text: formatDate(item.opened_at) }),
      el("td", { text: formatDate(item.updated_at || item.opened_at) }),
      el("td", { className: "text-end" }, [
        el("div", { className: "dropdown" }, [
          el("button", { className: "btn btn-sm btn-outline-secondary", type: "button", "data-bs-toggle": "dropdown", "aria-expanded": "false" }, [el("i", { className: "bi bi-three-dots" })]),
          el("div", { className: "dropdown-menu dropdown-menu-end" }, [
            el("a", { className: "dropdown-item", href: "/cases" }, [el("i", { className: "bi bi-briefcase" }), document.createTextNode("Open Case")]),
            el("a", { className: "dropdown-item", href: "/timeline" }, [el("i", { className: "bi bi-clock-history" }), document.createTextNode("Timeline")]),
            el("a", { className: "dropdown-item", href: "/ai-chat" }, [el("i", { className: "bi bi-stars" }), document.createTextNode("Ask AI")]),
          ]),
        ]),
      ]),
    ])));
  }
  const label = document.querySelector("[data-dashboard-case-page]");
  if (label) {
    label.textContent = items.length
      ? `Page ${dashboardCaseState.page} of ${pages} · ${items.length} active investigation(s) in current snapshot`
      : "No active investigations";
  }
  const prev = document.querySelector("[data-dashboard-page='prev']");
  const next = document.querySelector("[data-dashboard-page='next']");
  if (prev) prev.disabled = dashboardCaseState.page <= 1;
  if (next) next.disabled = dashboardCaseState.page >= pages;
  refreshResponsiveTableLabels(document.querySelector(".soc-investigation-panel") || document);
}

function sortDashboardCases(items, sort) {
  const priorityWeight = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  return [...items].sort((a, b) => {
    if (sort === "priority") return (priorityWeight[a.priority] ?? 9) - (priorityWeight[b.priority] ?? 9);
    if (sort === "title") return String(a.title).localeCompare(String(b.title));
    if (sort === "owner") return String(a.owner || "").localeCompare(String(b.owner || ""));
    return new Date(b.opened_at || 0) - new Date(a.opened_at || 0);
  });
}

function renderThreatChart(target, points) {
  if (!target) return;
  if (!points.length) {
    target.replaceChildren(emptyInline("bi-activity", "No threat signal", "Timeline activity will populate this graph."));
    return;
  }
  const maxValue = Math.max(...points.map((point) => point.value), 1);
  target.replaceChildren(...points.map((point, index) => el("div", {
    className: "threat-bar",
    title: `${point.label}: ${point.value}`,
    style: `height:${Math.max(12, (point.value / maxValue) * 100)}%; animation-delay:${index * 35}ms`,
  }, [el("span", { text: point.value })])));
}

function renderCaseGraph(target, cases) {
  if (!target) return;
  if (!cases.length) {
    target.replaceChildren(emptyInline("bi-briefcase", "No active cases", "Create a case to begin graphing activity."));
    return;
  }
  const maxValue = Math.max(...cases.map((item) => item.value), 1);
  target.replaceChildren(...cases.map((item) => el("div", { className: "case-bar-row" }, [
    el("span", { text: item.label }),
    el("div", { className: "case-bar-track" }, [
      el("div", { className: `case-bar-fill severity-${item.severity}`, style: `width:${Math.max(6, (item.value / maxValue) * 100)}%` }),
    ]),
    el("strong", { text: String(item.value) }),
  ])));
}

function renderActivity(target, items) {
  if (!target) return;
  if (!items.length) {
    target.replaceChildren(emptyInline("bi-clock-history", "No activity yet", "Case, evidence, and report events will appear here."));
    return;
  }
  target.replaceChildren(...items.map((item) => el("a", { className: "activity-item", href: "/timeline" }, [
    el("span", { className: "activity-dot" }),
    el("div", {}, [
      el("strong", { text: item.summary }),
      el("small", { text: `${item.event_type} - ${formatDate(item.occurred_at)}` }),
    ]),
  ])));
}

function renderEvidenceSummary(target, items) {
  if (!target) return;
  if (!items.length) {
    target.replaceChildren(emptyInline("bi-folder2-open", "No evidence", "Add evidence to populate custody records."));
    return;
  }
  target.replaceChildren(...items.map((item) => el("a", { className: "compact-item", href: "/evidence" }, [
    el("i", { className: "bi bi-file-earmark-binary" }),
    el("div", {}, [
      el("strong", { text: item.original_filename }),
      el("small", { text: `${item.evidence_number} - ${item.size_bytes} bytes` }),
    ]),
  ])));
}

function renderTimelinePreview(target, items) {
  if (!target) return;
  if (!items.length) {
    target.replaceChildren(emptyInline("bi-diagram-3", "No sequence", "Timeline events will create the preview."));
    return;
  }
  target.replaceChildren(...items.map((item) => el("a", { className: "mini-event", href: "/timeline" }, [
    el("time", { text: formatDate(item.occurred_at) }),
    el("strong", { text: item.summary }),
  ])));
}

function renderReportsSummary(target, items) {
  if (!target) return;
  if (!items.length) {
    target.replaceChildren(emptyInline("bi-file-earmark-bar-graph", "No reports", "Generated reports will appear here."));
    return;
  }
  target.replaceChildren(...items.map((item) => el("a", { className: "compact-item", href: `/api/v1/reports/${item.id}/export` }, [
    el("i", { className: "bi bi-file-earmark-text" }),
    el("div", {}, [
      el("strong", { text: item.title }),
      el("small", { text: `${item.report_type} v${item.version} - ${formatDate(item.generated_at)}` }),
    ]),
  ])));
}

function renderInsights(target, items) {
  if (!target) return;
  target.replaceChildren(...items.map((item) => el("a", { className: "insight-item", href: "/ai-chat" }, [
    el("i", { className: "bi bi-stars" }),
    el("div", {}, [
      el("strong", { text: item.title }),
      el("small", { text: item.body.length > 150 ? `${item.body.slice(0, 150)}...` : item.body }),
    ]),
  ])));
}

function renderQuickActions(target, items) {
  if (!target) return;
  target.replaceChildren(...items.map((item) => el("a", { className: "quick-action", href: item.href }, [
    el("i", { className: `bi ${item.icon}` }),
    el("span", {}, [
      el("strong", { text: item.label }),
      el("small", { text: item.description || "Open workspace action." }),
    ]),
  ])));
}

function renderNotificationsSummary(target, items) {
  if (!target) return;
  if (!items.length) {
    target.replaceChildren(emptyInline("bi-bell", "No notifications", "Workspace notifications are clear."));
    return;
  }
  target.replaceChildren(...items.map((item) => el("a", { className: `compact-item ${item.read ? "" : "unread"} priority-${item.priority || "info"}`.trim(), href: "/profile#notifications", title: item.message }, [
    el("i", { className: notificationIcon(item.category) }),
    el("div", {}, [
      el("strong", { text: item.title }),
      el("small", { text: `${item.priority || "info"} - ${formatDate(item.created_at)}` }),
    ]),
  ])));
}

function renderProgress(progress, detail) {
  const ring = document.querySelector("[data-progress-ring]");
  const label = document.querySelector("[data-progress-label]");
  const title = document.querySelector("[data-progress-title]");
  const text = document.querySelector("[data-progress-detail]");
  const value = clamp(progress);
  if (ring) {
    ring.dataset.progressRing = String(value);
    ring.style.setProperty("--progress", `${value * 3.6}deg`);
  }
  if (label) label.textContent = `${value}%`;
  if (title) title.textContent = detail.label || `${value}% complete`;
  if (text) text.textContent = `${detail.completed || 0} events captured, ${detail.remaining || 0} until full signal.`;
}

function actionButton(label, className, dataset) {
  return el("button", { className, type: "button", dataset, text: label });
}

function renderCases(table, items) {
  table.replaceChildren(...items.map((item) => {
    const title = el("td", {}, [
      el("strong", { text: item.case_number }),
      el("div", { className: "text-muted", text: item.title }),
    ]);
    const tags = el("td", {}, (item.tags || []).slice(0, 3).map((tag) => el("span", { className: "badge-soft me-1", text: tag })));
    const actions = el("td", { className: "text-end" }, [
      actionButton("Details", "btn btn-sm btn-outline-primary", { caseDetails: item.id }),
      document.createTextNode(" "),
      actionButton("Edit", "btn btn-sm btn-outline-secondary", { caseEdit: item.id }),
      document.createTextNode(" "),
      actionButton("Close", "btn btn-sm btn-outline-secondary", { caseAction: "close", id: item.id }),
      document.createTextNode(" "),
      actionButton("Archive", "btn btn-sm btn-outline-secondary", { caseAction: "archive", id: item.id }),
      document.createTextNode(" "),
      actionButton("Delete", "btn btn-sm btn-outline-danger", { caseAction: "delete", id: item.id }),
    ]);
    return el("tr", {}, [
      title,
      el("td", {}, [el("span", { className: `priority-pill priority-${item.priority}`, text: item.priority })]),
      el("td", { text: item.owner || "Unassigned" }),
      el("td", {}, [el("span", { className: "badge text-bg-light", text: item.status })]),
      tags,
      el("td", {}, [el("div", { className: "case-object-counts" }, [
        el("span", { title: "Evidence", text: `${item.evidence_count || 0} E` }),
        el("span", { title: "Timeline", text: `${item.timeline_count || 0} T` }),
        el("span", { title: "Reports", text: `${item.report_count || 0} R` }),
      ])]),
      el("td", { text: formatDate(item.opened_at) }),
      actions,
    ]);
  }));
}

function initialiseCases() {
  if (!document.querySelector("[data-module='cases']")) return;
  const state = document.querySelector("#case-state");
  const wrap = document.querySelector("#case-table-wrap");
  const table = document.querySelector("#case-table");
  const form = document.querySelector("#case-form");
  const load = async () => {
    setState(state, "bi-hourglass-split", "Loading cases", "Fetching investigation cases.");
    hide(wrap);
    try {
      const data = await fetchCases({
        q: document.querySelector("#case-search").value,
        status: document.querySelector("#case-filter").value,
        priority: document.querySelector("#case-priority-filter").value,
        severity: document.querySelector("#case-severity-filter").value,
        owner: document.querySelector("#case-owner-filter").value,
        tag: document.querySelector("#case-tag-filter").value,
        sort: document.querySelector("#case-sort").value,
        page: pageState.cases,
      });
      if (!data.items.length) {
        setState(state, "bi-briefcase", "No cases found", "Create or adjust filters to find cases.");
        return;
      }
      hide(state);
      wrap.classList.remove("d-none");
      renderCases(table, data.items);
      refreshResponsiveTableLabels(wrap);
      document.querySelector("#case-page-label").textContent = `Page ${data.pagination.page} of ${Math.max(data.pagination.pages, 1)} - ${data.pagination.total} cases`;
      document.querySelector("#case-prev").disabled = data.pagination.page <= 1;
      document.querySelector("#case-next").disabled = data.pagination.page >= data.pagination.pages;
    } catch (error) {
      setState(state, "bi-exclamation-triangle", "Case list unavailable", error.message, "danger");
    }
  };
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const caseId = document.querySelector("#case-id").value;
    const body = {
      case_number: document.querySelector("#case-number").value,
      title: document.querySelector("#case-title").value,
      description: document.querySelector("#case-description").value,
      severity: document.querySelector("#case-severity").value,
      priority: document.querySelector("#case-priority").value,
      owner: document.querySelector("#case-owner").value,
      tags: document.querySelector("#case-tags").value,
      notes: document.querySelector("#case-notes").value,
      relationships: document.querySelector("#case-relationships").value,
    };
    try {
      await api(caseId ? `/api/v1/cases/${caseId}` : "/api/v1/cases", { method: caseId ? "PATCH" : "POST", body: JSON.stringify(body) });
      bootstrap.Modal.getInstance(document.querySelector("#case-modal"))?.hide();
      form.reset();
      document.querySelector("#case-id").value = "";
      showToast(caseId ? "Case updated." : "Case created.", "success");
      load();
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  table.addEventListener("click", async (event) => {
    const detailButton = event.target.closest("[data-case-details]");
    if (detailButton) {
      try {
        await loadInvestigationWorkspace(detailButton.dataset.caseDetails);
      } catch (error) {
        showToast(error.message, "danger");
      }
      return;
    }
    const editButton = event.target.closest("[data-case-edit]");
    if (editButton) {
      try {
        const data = await fetchCases({ q: "", per_page: 100, include_related: "true" });
        const selected = data.items.find((item) => item.id === editButton.dataset.caseEdit);
        if (selected) fillCaseForm(selected);
      } catch (error) {
        showToast(error.message, "danger");
      }
      return;
    }
    const button = event.target.closest("[data-case-action]");
    if (!button) return;
    try {
      await api(`/api/v1/cases/${button.dataset.id}/${button.dataset.caseAction}`, { method: "POST" });
      showToast(`Case ${button.dataset.caseAction} complete.`, "success");
      load();
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  document.querySelector("#case-search").addEventListener("input", debounce(() => { pageState.cases = 1; load(); }));
  document.querySelector("#case-filter").addEventListener("change", load);
  document.querySelector("#case-priority-filter").addEventListener("change", load);
  document.querySelector("#case-severity-filter").addEventListener("change", load);
  document.querySelector("#case-owner-filter").addEventListener("input", debounce(load));
  document.querySelector("#case-tag-filter").addEventListener("input", debounce(load));
  document.querySelector("#case-sort").addEventListener("change", load);
  document.querySelector("#case-prev").addEventListener("click", () => { pageState.cases -= 1; load(); });
  document.querySelector("#case-next").addEventListener("click", () => { pageState.cases += 1; load(); });
  bindInvestigationWorkspace();
  load();
  if (requestedCaseId()) loadInvestigationWorkspace(requestedCaseId()).catch(() => {});
}

function fillCaseForm(item) {
  document.querySelector("#case-id").value = item.id;
  document.querySelector("#case-number").value = item.case_number;
  document.querySelector("#case-title").value = item.title;
  document.querySelector("#case-description").value = item.description || "";
  document.querySelector("#case-severity").value = item.severity;
  document.querySelector("#case-priority").value = item.priority;
  document.querySelector("#case-owner").value = item.owner || "";
  document.querySelector("#case-tags").value = (item.tags || []).join(", ");
  document.querySelector("#case-notes").value = (item.notes || []).join("\n");
  document.querySelector("#case-relationships").value = (item.relationships || []).join("\n");
  new bootstrap.Modal(document.querySelector("#case-modal")).show();
}

function bindInvestigationWorkspace() {
  document.querySelectorAll("[data-workspace-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll("[data-workspace-tab]").forEach((tab) => {
        const active = tab === button;
        tab.classList.toggle("active", active);
        tab.setAttribute("aria-selected", String(active));
      });
      document.querySelectorAll("[data-workspace-section]").forEach((section) => {
        section.classList.toggle("active", section.dataset.workspaceSection === button.dataset.workspaceTab);
      });
    });
    button.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
      event.preventDefault();
      const tabs = [...document.querySelectorAll("[data-workspace-tab]")];
      const direction = event.key === "ArrowRight" ? 1 : -1;
      tabs[(tabs.indexOf(button) + direction + tabs.length) % tabs.length].focus();
      tabs[(tabs.indexOf(button) + direction + tabs.length) % tabs.length].click();
    });
  });
  document.querySelector("#workspace-edit")?.addEventListener("click", () => {
    if (selectedInvestigationCase) fillCaseForm(selectedInvestigationCase);
  });
  document.querySelector("[data-workspace-edit-shortcut]")?.addEventListener("click", () => {
    if (selectedInvestigationCase) fillCaseForm(selectedInvestigationCase);
  });
}

async function loadInvestigationWorkspace(caseId) {
  const empty = document.querySelector("#case-detail");
  const content = document.querySelector("#investigation-workspace-content");
  setState(empty, "bi-hourglass-split", "Loading investigation", "Resolving case-owned evidence and activity.");
  content?.classList.add("d-none");
  empty?.classList.remove("d-none");
  try {
    const data = await api(`/api/v1/cases/${caseId}/workspace`);
    selectedInvestigationCase = data.case;
    renderInvestigationWorkspace(data);
    const location = new URL(window.location.href);
    location.searchParams.set("case_id", caseId);
    window.history.replaceState({}, "", location);
    empty?.classList.add("d-none");
    content?.classList.remove("d-none");
    content?.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    setState(empty, "bi-exclamation-triangle", "Investigation unavailable", error.message, "danger");
    throw error;
  }
}

function renderInvestigationWorkspace(data) {
  const item = data.case;
  document.querySelector("#workspace-case-number").textContent = item.case_number;
  document.querySelector("#workspace-title").textContent = item.title;
  document.querySelector("#workspace-description").textContent = item.description || "No investigation scope has been recorded.";
  document.querySelector("#case-detail-status").textContent = item.status;
  document.querySelector("#workspace-meta").replaceChildren(
    workspaceMeta("bi-person", item.owner || "Unassigned"),
    workspaceMeta("bi-flag", `${item.priority || item.severity} priority`),
    workspaceMeta("bi-shield-exclamation", `${item.severity} severity`),
    workspaceMeta("bi-calendar3", `Opened ${formatDate(item.opened_at)}`),
  );
  Object.entries(data.counts || {}).forEach(([name, value]) => {
    document.querySelectorAll(`[data-workspace-count='${name}']`).forEach((node) => { node.textContent = String(value); });
  });
  document.querySelector("#workspace-kpis").replaceChildren(
    workspaceKpi("bi-fingerprint", data.counts.evidence, "Evidence"),
    workspaceKpi("bi-stars", data.counts.ai_findings, "AI findings"),
    workspaceKpi("bi-clock-history", data.counts.timeline, "Timeline events"),
    workspaceKpi("bi-file-earmark-text", data.counts.reports, "Reports"),
    workspaceKpi("bi-exclamation-diamond", data.counts.threat_signals, "Recent threat signals"),
  );
  document.querySelector("#workspace-scope").textContent = item.description || "No scope or objective has been recorded.";
  renderWorkspaceChips(document.querySelector("#workspace-notes"), item.notes, "No structured notes have been recorded.");
  renderWorkspaceChips(
    document.querySelector("#workspace-relationships"),
    item.relationships,
    "No investigation relationships have been recorded.",
  );
  renderWorkspaceThreats(document.querySelector("#workspace-threats"), data.threat_signals || []);
  renderWorkspaceEvidence(document.querySelector("#workspace-evidence"), data.evidence || []);
  renderWorkspaceAi(document.querySelector("#workspace-ai"), data.ai_findings || []);
  renderWorkspaceTimeline(document.querySelector("#workspace-timeline"), data.timeline || []);
  renderWorkspaceReports(document.querySelector("#workspace-reports"), data.reports || []);
  renderWorkspaceTimeline(document.querySelector("#workspace-activity"), data.timeline || []);
  document.querySelector("#workspace-settings").replaceChildren(
    workspaceSetting("Owner", item.owner || "Unassigned"),
    workspaceSetting("Lifecycle status", item.status),
    workspaceSetting("Review status", item.review_status || "Not set"),
    workspaceSetting("Created", formatDate(item.created_at)),
    workspaceSetting("Updated", formatDate(item.updated_at)),
    workspaceSetting("Case identifier", item.id),
  );
  document.querySelectorAll("[data-workspace-route]").forEach((link) => {
    link.href = `/${link.dataset.workspaceRoute}?case_id=${encodeURIComponent(item.id)}`;
  });
}

function workspaceMeta(icon, text) {
  return el("span", {}, [el("i", { className: `bi ${icon}` }), document.createTextNode(text)]);
}

function workspaceKpi(icon, value, label) {
  return el("div", { className: "workspace-kpi" }, [
    el("i", { className: `bi ${icon}` }),
    el("strong", { text: String(value || 0) }),
    el("span", { text: label }),
  ]);
}

function workspaceSetting(label, value) {
  return el("div", { className: "workspace-setting" }, [
    el("span", { text: label }),
    el("strong", { text: String(value || "Not recorded") }),
  ]);
}

function renderWorkspaceChips(target, items, emptyText) {
  if (!items?.length) {
    target.replaceChildren(emptyInline("bi-journal", "Nothing recorded", emptyText));
    return;
  }
  target.replaceChildren(el("div", { className: "workspace-chip-list" }, items.map((item) => (
    el("span", { className: "workspace-chip", text: item })
  ))));
}

function renderWorkspaceThreats(target, items) {
  if (!items.length) {
    target.replaceChildren(emptyInline("bi-shield-check", "No threat signals recorded", "High-priority timeline signals will appear here."));
    return;
  }
  target.replaceChildren(...items.slice(0, 5).map((item) => (
    el("div", { className: "workspace-chip", text: `${item.summary} · ${item.threat_level || "signal"}` })
  )));
}

function workspaceListItem(icon, title, detail, meta) {
  return el("article", { className: "workspace-item" }, [
    el("i", { className: `bi ${icon}` }),
    el("div", {}, [el("strong", { text: title }), el("small", { text: detail })]),
    el("span", { text: meta }),
  ]);
}

function renderWorkspaceEvidence(target, items) {
  if (!items.length) {
    target.replaceChildren(emptyInline("bi-fingerprint", "No evidence linked", "Add evidence to begin case-level analysis."));
    return;
  }
  target.replaceChildren(...items.map((item) => workspaceListItem(
    "bi-file-earmark-lock2",
    `${item.evidence_number} · ${item.original_filename}`,
    `${item.media_type || "Unknown type"} · ${item.analysis_status || "pending"} analysis`,
    formatDate(item.acquired_at),
  )));
}

function renderWorkspaceAi(target, items) {
  if (!items.length) {
    target.replaceChildren(emptyInline("bi-stars", "No AI findings recorded", "Run case-linked analysis before findings appear here."));
    return;
  }
  target.replaceChildren(...items.map((item) => workspaceListItem(
    item.kind === "recommendation" ? "bi-lightbulb" : "bi-stars",
    item.title,
    item.body,
    formatDate(item.created_at),
  )));
}

function renderWorkspaceTimeline(target, items) {
  if (!items.length) {
    target.replaceChildren(emptyInline("bi-clock-history", "No timeline activity", "Recorded investigation events will appear here."));
    return;
  }
  target.replaceChildren(...items.map((item) => workspaceListItem(
    "bi-clock-history",
    item.summary || item.event_type,
    item.event_type,
    formatDate(item.occurred_at),
  )));
}

function renderWorkspaceReports(target, items) {
  if (!items.length) {
    target.replaceChildren(emptyInline("bi-file-earmark-text", "No reports generated", "Case-linked reports will appear here."));
    return;
  }
  target.replaceChildren(...items.map((item) => workspaceListItem(
    "bi-file-earmark-bar-graph",
    item.title,
    item.report_type || "Investigation report",
    formatDate(item.generated_at),
  )));
}

function renderEvidence(table, items) {
  evidenceInventory.clear();
  items.forEach((item) => evidenceInventory.set(item.id, item));
  table.replaceChildren(...items.map((item) => el("tr", {}, [
    el("td", {}, [
      el("strong", { text: item.evidence_number }),
      el("div", { className: "text-muted", text: item.original_filename }),
    ]),
    el("td", { text: item.case_id.slice(0, 8) }),
    el("td", { text: item.media_type || "unknown" }),
    el("td", { text: String(item.size_bytes) }),
    el("td", {}, [el("code", { text: `${item.sha256.slice(0, 16)}...` })]),
    el("td", {}, [el("span", { className: `priority-pill analysis-${item.analysis_status}`, text: item.analysis_status })]),
    el("td", { className: "text-end" }, [
      actionButton("Inspect", "btn btn-sm btn-outline-primary", { evidenceInspect: item.id }),
      document.createTextNode(" "),
      actionButton("Analyze", "btn btn-sm btn-outline-secondary", { evidenceAnalyze: item.id }),
      document.createTextNode(" "),
      actionButton("Delete", "btn btn-sm btn-outline-danger", { evidenceDelete: item.id }),
    ]),
  ])));
}

function initialiseEvidence() {
  if (!document.querySelector("[data-module='evidence']")) return;
  const state = document.querySelector("#evidence-state");
  const wrap = document.querySelector("#evidence-table-wrap");
  const table = document.querySelector("#evidence-table");
  const load = async () => {
    setState(state, "bi-hourglass-split", "Loading evidence", "Fetching custody records.");
    hide(wrap);
    try {
      const caseId = document.querySelector("#evidence-case-filter").value;
      const data = await api(`/api/v1/evidence${query({ case_id: caseId, q: document.querySelector("#evidence-search").value, analysis_status: document.querySelector("#evidence-analysis-filter").value, sort: document.querySelector("#evidence-sort").value, per_page: 100 })}`);
      await loadThreatIntelligence(caseId, false);
      if (!data.items.length) {
        setState(state, "bi-folder2-open", "Evidence inventory is empty", "Add evidence to establish custody.");
        return;
      }
      hide(state);
      wrap.classList.remove("d-none");
      renderEvidence(table, data.items);
      refreshResponsiveTableLabels(wrap);
    } catch (error) {
      setState(state, "bi-exclamation-triangle", "Evidence unavailable", error.message, "danger");
    }
  };
  const evidenceCaseTargets = [
    document.querySelector("#evidence-case"),
    document.querySelector("#evidence-case-filter"),
  ];
  caseOptions(evidenceCaseTargets, true).then(() => {
    applyRequestedCase(evidenceCaseTargets);
    load();
  });
  document.querySelector("#evidence-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const file = document.querySelector("#evidence-file").files[0];
    const body = new FormData();
    body.append("case_id", document.querySelector("#evidence-case").value);
    body.append("evidence_number", document.querySelector("#evidence-number").value);
    body.append("source_description", document.querySelector("#evidence-description").value);
    if (file) body.append("file", file);
    try {
      await api("/api/v1/evidence", file ? { method: "POST", body } : {
        method: "POST",
        body: JSON.stringify({
          case_id: document.querySelector("#evidence-case").value,
          evidence_number: document.querySelector("#evidence-number").value,
          filename: `${document.querySelector("#evidence-number").value || "evidence"}.txt`,
          content: document.querySelector("#evidence-description").value || "Manual evidence record",
        }),
      });
      bootstrap.Modal.getInstance(document.querySelector("#evidence-modal"))?.hide();
      event.target.reset();
      showToast("Evidence registered.", "success");
      load();
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  table.addEventListener("click", async (event) => {
    const inspectButton = event.target.closest("[data-evidence-inspect]");
    if (inspectButton) {
      selectedEvidence = evidenceInventory.get(inspectButton.dataset.evidenceInspect) || null;
      renderStoredEvidence(selectedEvidence);
      return;
    }
    const analyzeButton = event.target.closest("[data-evidence-analyze]");
    if (analyzeButton) {
      try {
        selectedEvidence = evidenceInventory.get(analyzeButton.dataset.evidenceAnalyze) || null;
        document.querySelector("#evidence-workspace-content")?.classList.add("d-none");
        document.querySelector("#evidence-report")?.classList.remove("d-none");
        document.querySelector("#evidence-report-status").textContent = "Analyzing";
        renderAnalysisProgress({ progress: 0, step: "Queued" });
        const job = await api(`/api/v1/evidence/${analyzeButton.dataset.evidenceAnalyze}/analysis-jobs`, { method: "POST" });
        const payload = await pollEvidenceAnalysis(job.id);
        renderForensicReport(payload.result || payload, selectedEvidence);
        showToast("Evidence forensic analysis complete.", "success");
        load();
      } catch (error) {
        document.querySelector("#evidence-report-status").textContent = "Error";
        showToast(error.message, "danger");
      }
      return;
    }
    const button = event.target.closest("[data-evidence-delete]");
    if (!button) return;
    try {
      await api(`/api/v1/evidence/${button.dataset.evidenceDelete}`, { method: "DELETE" });
      showToast("Evidence deleted.", "success");
      load();
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  document.querySelector("#evidence-case-filter").addEventListener("change", load);
  document.querySelector("#threat-intelligence-enrich")?.addEventListener("click", async () => {
    const caseId = document.querySelector("#evidence-case-filter").value;
    if (!caseId) {
      showToast("Select an investigation before enrichment.", "warning");
      return;
    }
    const button = document.querySelector("#threat-intelligence-enrich");
    button.disabled = true;
    try {
      await loadThreatIntelligence(caseId, true);
      showToast("Threat intelligence enrichment completed.", "success");
    } catch (error) {
      showToast(error.message, "danger");
    } finally {
      button.disabled = false;
    }
  });
  document.querySelector("#evidence-search").addEventListener("input", debounce(load));
  document.querySelector("#evidence-analysis-filter").addEventListener("change", load);
  document.querySelector("#evidence-sort").addEventListener("change", load);
}

async function loadThreatIntelligence(caseId, enrich = false) {
  if (!document.querySelector("#threat-intelligence-summary")) return;
  if (!caseId) {
    renderThreatIntelligence({ summary: { total: 0, enriched: 0, unknown: 0, providers_queried: 0 }, indicators: [], findings: [], attack_mappings: [], providers: [], explainability: "Select an investigation to inspect extracted indicators." });
    return;
  }
  const data = enrich
    ? await api("/api/v1/threat-intelligence/enrich", { method: "POST", body: JSON.stringify({ case_id: caseId }) })
    : await api(`/api/v1/threat-intelligence?case_id=${encodeURIComponent(caseId)}`);
  renderThreatIntelligence(data);
}

function renderThreatIntelligence(data) {
  const summary = data.summary || {};
  const metrics = [["Extracted", summary.total || 0], ["Enriched", summary.enriched || 0], ["Unknown", summary.unknown || 0], ["Providers", summary.providers_queried || 0]];
  document.querySelector("#threat-intelligence-summary")?.replaceChildren(...metrics.map(([label, value]) => el("div", { className: "threat-metric" }, [el("strong", { text: String(value) }), el("span", { text: label })])));
  const explainer = document.querySelector("#threat-intelligence-explainer");
  if (explainer) explainer.textContent = data.explainability || "Unknown means no provider returned a finding; it does not mean benign.";

  const highRisk = (data.findings || []).filter((item) => ["malicious", "suspicious"].includes(item.reputation));
  renderThreatItems(document.querySelector("#threat-intelligence-risk"), highRisk.map((item) => ({
    value: item.indicator?.value,
    badge: item.reputation,
    detail: `${item.provider} · confidence ${item.confidence == null ? "not supplied" : `${Math.round(item.confidence * 100)}%`} · ${item.summary || "No provider summary"}`,
  })), "No provider-backed high-risk indicators were returned.");

  const indicators = (data.indicators || []).map((item) => {
    const finding = item.findings?.[0];
    return {
      value: item.value,
      badge: finding?.reputation || "unknown",
      detail: `${item.type} · ${item.sources?.map((source) => source.evidence_number).join(", ") || "No evidence source"} · ${finding ? finding.provider : "No provider finding"}`,
    };
  });
  renderThreatItems(document.querySelector("#threat-intelligence-indicators"), indicators, "No normalized indicators were extracted from this investigation.");

  const mappings = (data.attack_mappings || []).map((item) => ({
    value: item.technique_id,
    badge: item.provider,
    detail: `Provider-supported mapping for ${item.indicator}${item.reference ? ` · ${item.reference}` : ""}`,
  }));
  renderThreatItems(document.querySelector("#threat-intelligence-attack"), mappings, "No provider-supported ATT&CK mappings were returned.");

  const ai = document.querySelector("#threat-intelligence-ai");
  if (ai) {
    const providerCount = (data.providers || []).length;
    ai.textContent = providerCount
      ? `${summary.enriched || 0} of ${summary.total || 0} normalized indicators received provider findings. Reputation and provider confidence are displayed separately; validate every assertion using its source reference.`
      : "No intelligence provider is configured, so no AI intelligence conclusion was generated. Extracted indicators remain unknown rather than benign.";
  }
}

function renderThreatItems(target, items, emptyMessage) {
  if (!target) return;
  if (!items.length) {
    target.replaceChildren(el("div", { className: "threat-empty", text: emptyMessage }));
    return;
  }
  target.replaceChildren(...items.slice(0, 30).map((item) => el("article", { className: "threat-indicator" }, [
    el("header", {}, [
      el("code", { text: item.value || "Unknown indicator" }),
      el("span", { className: `reputation-${item.badge}`, text: item.badge || "unknown" }),
    ]),
    el("p", { text: item.detail }),
  ])));
}

async function pollEvidenceAnalysis(jobId) {
  for (;;) {
    const job = await api(`/api/v1/evidence/analysis-jobs/${jobId}`);
    renderAnalysisProgress(job);
    if (job.status === "completed") return job;
    if (job.status === "failed") throw new Error(job.error || "Evidence analysis failed.");
    await new Promise((resolve) => setTimeout(resolve, 800));
  }
}

function renderAnalysisProgress(job) {
  const progress = clamp(job.progress || 0);
  const step = job.step || "Analyzing";
  const target = document.querySelector("#evidence-report");
  const elapsed = job.created_at ? Math.max(1, Date.now() / 1000 - job.created_at) : 0;
  const remaining = progress > 3 && progress < 100 ? Math.max(1, Math.round((elapsed / progress) * (100 - progress))) : null;
  document.querySelector("#evidence-report-status").textContent = step;
  target.replaceChildren(el("div", { className: "forensic-report" }, [
    el("strong", { text: step }),
    el("small", { className: "d-block text-muted mt-1", text: remaining ? `Estimated completion: about ${remaining} second(s)` : "Preparing forensic pipeline" }),
    el("div", { className: "progress mt-3", role: "progressbar", "aria-valuenow": String(progress), "aria-valuemin": "0", "aria-valuemax": "100" }, [
      el("div", { className: "progress-bar progress-bar-striped progress-bar-animated", style: `width:${progress}%`, text: `${progress}%` }),
    ]),
    el("div", { className: "compact-list mt-3" }, [
      el("div", { className: "compact-item" }, [el("i", { className: "bi bi-hdd" }), el("div", {}, [el("strong", { text: "Phase 1" }), el("small", { text: "Metadata, hashes, entropy, magic bytes, archive detection, strings, encodings, IOC extraction." })])]),
      el("div", { className: "compact-item" }, [el("i", { className: "bi bi-stars" }), el("div", {}, [el("strong", { text: "Phase 2" }), el("small", { text: "AI explanation, threat assessment, MITRE mapping, recommendations, executive summary." })])]),
    ]),
  ]));
}

function renderStoredEvidence(item) {
  if (!item) return;
  if (!item.analysis_report) {
    renderEvidenceWorkspace(item, null, item.analysis_summary || null);
    return;
  }
  renderForensicReport(
    {
      summary: item.analysis_summary,
      report: item.analysis_report,
      ai_explanation: item.analysis_report.ai_explanation,
    },
    item,
  );
}

function renderForensicReport(payload, item = selectedEvidence) {
  renderEvidenceWorkspace(item, payload.report || {}, payload.summary || null, payload.ai_explanation);
}

function renderEvidenceWorkspace(item, report, summary, aiExplanation = null) {
  const empty = document.querySelector("#evidence-report");
  const content = document.querySelector("#evidence-workspace-content");
  const status = document.querySelector("#evidence-report-status");
  if (!item) return;
  empty?.classList.add("d-none");
  content?.classList.remove("d-none");
  if (status) status.textContent = item.analysis_status || (report ? "completed" : "pending");
  const root = report?.root || {};
  const reportEvidence = report?.evidence || {};
  document.querySelector("#evidence-workspace-summary").replaceChildren(
    el("div", { className: "evidence-summary-card" }, [
      el("strong", { text: `${item.evidence_number} · ${item.original_filename}` }),
      el("small", { text: `${item.media_type || "Unknown type"} · ${formatBytes(item.size_bytes)} · acquired ${formatDate(item.acquired_at)}` }),
      el("code", { className: "evidence-hash", text: item.sha256 }),
    ]),
  );
  document.querySelector("#evidence-workspace-analysis").replaceChildren(
    ...evidenceStatusItems([
      ["State", item.analysis_status || "pending"],
      ["Integrity", reportEvidence.integrity_verified ? "SHA-256 verified" : "Not yet reverified"],
      ["Mode", "Bounded static analysis"],
      ["Execution", "Never executed"],
    ]),
    summary
      ? el("div", { className: "evidence-workspace-item mt-2" }, [el("strong", { text: "Static summary" }), el("small", { text: summary })])
      : emptyInline("bi-hourglass", "Analysis pending", "Start static analysis to produce evidence-grounded findings."),
  );
  renderEvidenceAi(document.querySelector("#evidence-workspace-ai"), aiExplanation || report?.ai_explanation);
  renderEvidenceThreatMatches(document.querySelector("#evidence-workspace-threats"), report || {});
  document.querySelector("#evidence-workspace-timeline").replaceChildren(
    report?.timeline_summary
      ? evidenceWorkspaceItem("Analysis event", report.timeline_summary)
      : emptyInline("bi-clock-history", "No analysis event recorded", "Timeline integration occurs after completed analysis."),
  );
  document.querySelector("#evidence-workspace-metadata").replaceChildren(
    ...evidenceStatusItems([
      ["Signature", root.file_signature || "Unknown"],
      ["Entropy", root.entropy ?? "Not analyzed"],
      ["Encoding", root.encoding?.encoding || "Unknown"],
      ["Bytes analyzed", reportEvidence.bytes_analyzed ?? "Not analyzed"],
      ["Stored bytes", reportEvidence.stored_size_bytes ?? item.size_bytes],
      ["Truncated analysis", reportEvidence.truncated ? "Yes" : "No"],
    ]),
  );
}

function evidenceStatusItems(items) {
  return [el("div", { className: "evidence-status-grid" }, items.map(([label, value]) => (
    el("div", { className: "evidence-status-item" }, [
      el("span", { text: label }),
      el("strong", { text: String(value) }),
    ])
  )))];
}

function evidenceWorkspaceItem(title, detail) {
  return el("div", { className: "evidence-workspace-item" }, [
    el("strong", { text: title }),
    el("small", { text: detail }),
  ]);
}

function renderEvidenceAi(target, explanation) {
  if (!explanation?.available || !explanation.content) {
    target.replaceChildren(emptyInline("bi-stars", "No AI summary recorded", "Static forensic results remain available without an AI provider."));
    return;
  }
  target.replaceChildren(el("div", { className: "evidence-workspace-item" }, [
    el("strong", { text: `Evidence-grounded summary · ${explanation.model || explanation.provider?.provider || "AI provider"}` }),
    el("div", { className: "ai-analysis-copy mt-2" }, [markdownToFragment(explanation.content)]),
  ]));
}

function renderEvidenceThreatMatches(target, report) {
  const matches = [
    ...(report.ioc_table || []).map((item) => ({
      title: `${item.type || "Indicator"} · ${item.value}`,
      detail: `Extracted locally from ${item.source || "evidence bytes"}`,
    })),
    ...(report.yara_results || []).map((item) => ({
      title: `Local YARA rule · ${item.rule || item.name || "match"}`,
      detail: item.description || "Matched by the bundled static rule set.",
    })),
    ...(report.sigma_results || []).map((item) => ({
      title: `Local Sigma indicator · ${item.rule || item.title || "match"}`,
      detail: item.description || "Matched by the bundled static indicator set.",
    })),
  ];
  if (!matches.length) {
    target.replaceChildren(emptyInline("bi-shield-check", "No local matches", "No IOCs or bundled static-rule matches were extracted. External threat intelligence is not connected."));
    return;
  }
  target.replaceChildren(
    el("div", { className: "evidence-workspace-list" }, matches.slice(0, 20).map((item) => (
      evidenceWorkspaceItem(item.title, item.detail)
    ))),
    el("small", { className: "text-muted", text: "These are local extraction and rule results, not external reputation verdicts." }),
  );
}

function renderTimeline(list, items) {
  list.replaceChildren(...items.map((item) => {
    const body = el("div", {}, [
      el("strong", { text: item.summary }),
      el("p", { text: `${item.event_type} - ${item.case_number || "No case"}${item.evidence_number ? ` - ${item.evidence_number}` : ""}` }),
      el("div", { className: "timeline-event-meta" }, [
        el("span", { className: "badge-soft success", text: item.certainty || "confirmed" }),
        el("span", { className: "badge-soft", text: item.source_type || item.group || "record" }),
        ...(item.related_event_ids?.length ? [el("span", { className: "badge-soft", text: `${item.related_event_ids.length} related` })] : []),
        ...(item.evidence_number ? [el("a", { className: "badge-soft", href: `/evidence?case_id=${encodeURIComponent(item.case_id)}`, text: `Evidence ${item.evidence_number}` })] : []),
      ]),
    ]);
    if (item.details) body.append(el("details", { className: "timeline-details" }, [
      el("summary", { text: "View event details" }), el("p", { text: item.details }),
    ]));
    return el("article", { className: `timeline-event group-${item.group}`, tabindex: "0", role: "button", "data-timeline-event": item.id }, [el("time", { text: formatDate(item.occurred_at) }), body]);
  }));
}

function initialiseTimeline() {
  if (!document.querySelector("[data-module='timeline']")) return;
  const state = document.querySelector("#timeline-state");
  const list = document.querySelector("#timeline-list");
  const load = async () => {
    setState(state, "bi-hourglass-split", "Loading timeline", "Fetching correlated events.");
    hide(list);
    try {
      const data = await api(`/api/v1/timeline${query({ case_id: document.querySelector("#timeline-case-filter").value, event_type: document.querySelector("#timeline-type-filter").value, group: document.querySelector("#timeline-group-filter").value, threat: document.querySelector("#timeline-threat-filter").value, q: document.querySelector("#timeline-search").value, per_page: 100 })}`);
      renderTimelineCorrelations(data.correlations || {}, data.reconstruction || {});
      renderAttackPath(data.reconstruction?.attack_path || []);
      if (!data.items.length) {
        setState(state, "bi-clock-history", "No timeline events", "Add evidence, create cases, or record observations.");
        return;
      }
      hide(state);
      list.classList.remove("d-none");
      list.dataset.zoom = document.querySelector("#timeline-zoom").value;
      renderTimeline(list, data.items);
      list.querySelector("[data-timeline-event]")?.click();
    } catch (error) {
      setState(state, "bi-exclamation-triangle", "Timeline unavailable", error.message, "danger");
    }
  };
  const timelineCaseTargets = [
    document.querySelector("#timeline-case"),
    document.querySelector("#timeline-case-filter"),
  ];
  caseOptions(timelineCaseTargets, true).then(() => {
    applyRequestedCase(timelineCaseTargets);
    load();
  });
  document.querySelector("#timeline-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api("/api/v1/timeline", {
        method: "POST",
        body: JSON.stringify({
          case_id: document.querySelector("#timeline-case").value,
          summary: document.querySelector("#timeline-summary").value,
          details: document.querySelector("#timeline-details").value,
        }),
      });
      bootstrap.Modal.getInstance(document.querySelector("#timeline-modal"))?.hide();
      event.target.reset();
      showToast("Timeline event added.", "success");
      load();
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  document.querySelector("#timeline-case-filter").addEventListener("change", load);
  document.querySelector("#timeline-type-filter").addEventListener("change", load);
  document.querySelector("#timeline-group-filter").addEventListener("change", load);
  document.querySelector("#timeline-threat-filter").addEventListener("change", load);
  document.querySelector("#timeline-zoom").addEventListener("change", load);
  document.querySelector("#timeline-search").addEventListener("input", debounce(load));
  list.addEventListener("click", (event) => {
    const target = event.target.closest("[data-timeline-event]");
    if (!target) return;
    list.querySelectorAll("[data-timeline-event]").forEach((node) => node.classList.toggle("is-selected", node === target));
    const record = window.__timelineRecords?.find((entry) => entry.id === target.dataset.timelineEvent);
    if (record) renderTimelineEventDetail(record);
  });
  list.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      event.target.closest("[data-timeline-event]")?.click();
    }
  });
  document.querySelector("#timeline-export").addEventListener("click", (event) => {
    event.currentTarget.href = `/api/v1/timeline/export${query({ case_id: document.querySelector("#timeline-case-filter").value, event_type: document.querySelector("#timeline-type-filter").value, group: document.querySelector("#timeline-group-filter").value, threat: document.querySelector("#timeline-threat-filter").value, q: document.querySelector("#timeline-search").value })}`;
  });
  document.querySelector("#timeline-ai-summary").addEventListener("click", async () => {
    const panel = document.querySelector("#timeline-summary-panel");
    const selectedCase = document.querySelector("#timeline-case-filter").value;
    if (!selectedCase) {
      showToast("Select an investigation before generating a timeline summary.", "warning");
      return;
    }
    document.querySelector("#timeline-summary-status").textContent = "Generating";
    panel.replaceChildren(emptyInline("bi-hourglass-split", "Generating summary", "Correlating case, evidence, timeline, and threat signals."));
    try {
      const payload = await api("/api/v1/timeline/ai-summary", { method: "POST", body: JSON.stringify({ case_id: selectedCase }) });
      document.querySelector("#timeline-summary-status").textContent = payload.available ? "AI" : "Fallback";
      panel.replaceChildren(el("div", { className: "insight-list" }, [el("div", { className: "insight-item" }, [el("i", { className: "bi bi-stars" }), el("div", {}, [el("strong", { text: "Evidence-grounded timeline summary" }), el("small", { text: payload.content || payload.message || "Summary unavailable." })])])]));
    } catch (error) {
      document.querySelector("#timeline-summary-status").textContent = "Error";
      panel.replaceChildren(emptyInline("bi-exclamation-triangle", "Summary unavailable", error.message));
    }
  });
}

function renderTimelineCorrelations(data, reconstruction = {}) {
  const target = document.querySelector("#timeline-correlations");
  if (!target) return;
  const summary = reconstruction.summary || {};
  window.__timelineRecords = reconstruction.events || [];
  const explainer = document.querySelector("#timeline-explainability");
  if (explainer) explainer.textContent = reconstruction.explainability || "Persisted events are confirmed records; hypotheses are labeled separately.";
  target.replaceChildren(
    el("span", { className: "badge-soft success", text: `${summary.confirmed_events || 0} confirmed` }),
    el("span", { className: "badge-soft", text: `${summary.correlated_events || 0} correlated` }),
    el("span", { className: "badge-soft", text: `${summary.evidence_links || 0} evidence links` }),
    el("span", { className: "badge-soft", text: `${summary.hypotheses || 0} hypotheses` }),
  );
}

function renderTimelineEventDetail(item) {
  document.querySelector("#timeline-event-detail")?.replaceChildren(el("div", { className: "timeline-source-card" }, [
    el("strong", { text: item.summary }),
    el("p", { className: "text-muted small", text: item.details || "No additional details recorded." }),
    el("dl", {}, [
      el("dt", { text: "Occurred" }), el("dd", { text: formatDate(item.occurred_at) }),
      el("dt", { text: "Certainty" }), el("dd", { text: item.certainty || "confirmed" }),
      el("dt", { text: "Source" }), el("dd", { text: item.source_type || "persisted record" }),
      el("dt", { text: "Event ID" }), el("dd", { text: item.id }),
      el("dt", { text: "Related" }), el("dd", { text: `${item.related_event_ids?.length || 0} event(s) sharing an explicit source` }),
    ]),
  ]));
  const related = document.querySelector("#timeline-related-evidence");
  if (item.evidence_id) {
    related?.replaceChildren(el("div", { className: "timeline-source-card" }, [
      el("strong", { text: item.evidence_number || "Linked evidence" }),
      el("code", { text: item.evidence_id }),
      el("a", { className: "btn btn-sm btn-outline-secondary", href: `/evidence?case_id=${encodeURIComponent(item.case_id)}`, text: "Open evidence workspace" }),
    ]));
  } else {
    related?.replaceChildren(emptyInline("bi-folder2-open", "No direct evidence link", "This event is not explicitly associated with an evidence record."));
  }
}

function renderAttackPath(items) {
  const target = document.querySelector("#timeline-attack-path");
  if (!target) return;
  if (!items.length) {
    target.replaceChildren(emptyInline("bi-diagram-3", "No supported mappings", "No attack stages are inferred from event categories."));
    return;
  }
  target.replaceChildren(el("div", { className: "attack-path-list" }, items.map((item) => el("article", { className: "attack-path-item" }, [
    el("strong", { text: `${item.technique_id}${item.technique_name ? ` · ${item.technique_name}` : ""}` }),
    el("small", { text: `${item.tactic || "Tactic not recorded"} · evidence ${item.evidence_id} · ${item.reason || "Evidence analysis mapping"}` }),
  ]))));
}

function renderReports(table, items) {
  table.replaceChildren(...items.map((item) => el("tr", {}, [
    el("td", {}, [
      el("strong", { text: item.title }),
      el("div", { className: "text-muted", text: item.storage_path }),
    ]),
    el("td", { text: item.case_id.slice(0, 8) }),
    el("td", { text: `${item.report_type} v${item.version}` }),
    el("td", {}, [
      el("span", { text: formatDate(item.generated_at) }),
    ]),
    el("td", { className: "text-end" }, [
      actionButton("Preview", "btn btn-sm btn-outline-primary", { reportPreview: item.id }),
      document.createTextNode(" "),
      actionButton("Analyze", "btn btn-sm btn-outline-primary", { reportAnalyze: item.id }),
      document.createTextNode(" "),
      el("a", { className: "btn btn-sm btn-outline-secondary", href: `/api/v1/reports/${item.id}/export?format=json`, dataset: { reportExport: item.id }, text: "Export" }),
    ]),
  ])));
}

function initialiseReports() {
  if (!document.querySelector("[data-module='reports']")) return;
  const state = document.querySelector("#report-state");
  const wrap = document.querySelector("#report-table-wrap");
  const table = document.querySelector("#report-table");
  let selectedReportId = null;
  const load = async () => {
    setState(state, "bi-hourglass-split", "Loading reports", "Fetching generated reports.");
    hide(wrap);
    try {
      const data = await api(`/api/v1/reports${query({ case_id: document.querySelector("#report-case-filter").value, q: document.querySelector("#report-search").value, per_page: 100 })}`);
      if (!data.items.length) {
        setState(state, "bi-file-earmark-bar-graph", "No reports available", "Select an investigation and create a report.");
        return;
      }
      hide(state);
      wrap.classList.remove("d-none");
      renderReports(table, data.items);
      refreshResponsiveTableLabels(wrap);
    } catch (error) {
      setState(state, "bi-exclamation-triangle", "Reports unavailable", error.message, "danger");
    }
  };
  const reportCaseTargets = [
    document.querySelector("#report-case"),
    document.querySelector("#report-case-filter"),
  ];
  caseOptions(reportCaseTargets, true).then(() => {
    applyRequestedCase(reportCaseTargets);
    load();
  });
  document.querySelector("#report-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const created = await api("/api/v1/reports", {
        method: "POST",
        body: JSON.stringify({
          case_id: document.querySelector("#report-case").value,
          title: document.querySelector("#report-title").value,
          report_type: document.querySelector("#report-type").value,
        }),
      });
      bootstrap.Modal.getInstance(document.querySelector("#report-modal"))?.hide();
      event.target.reset();
      showToast(`Report v${created.version} queued for generation.`, "success");
      load();
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  table.addEventListener("click", async (event) => {
    const preview = event.target.closest("[data-report-preview]");
    if (preview) {
      try {
        const payload = await api(`/api/v1/reports/${preview.dataset.reportPreview}`);
        selectedReportId = preview.dataset.reportPreview;
        renderReportPreview(payload.content, payload.metadata);
      } catch (error) {
        showToast(error.message, "danger");
      }
    }
    const analyze = event.target.closest("[data-report-analyze]");
    if (analyze) {
      try {
        document.querySelector("#report-preview-status").textContent = "Analyzing";
        renderReportAnalysis({ analysis: { content: "Analyzing report with AI..." } });
        const payload = await api(`/api/v1/reports/${analyze.dataset.reportAnalyze}/analyze`, { method: "POST" });
        renderReportAnalysis(payload);
      } catch (error) {
        showToast(error.message, "danger");
      }
    }
  });
  const updateReportExportLink = (event) => {
    const link = event.target.closest("[data-report-export]");
    if (!link) return;
    link.href = `/api/v1/reports/${link.dataset.reportExport}/export?format=${document.querySelector("#report-export-format").value}`;
  };
  table.addEventListener("mouseover", updateReportExportLink);
  table.addEventListener("focusin", updateReportExportLink);
  table.addEventListener("click", updateReportExportLink);
  document.querySelector("#report-refresh").addEventListener("click", load);
  document.querySelector("#report-case-filter").addEventListener("change", load);
  document.querySelector("#report-search").addEventListener("input", debounce(load));
  document.querySelector("#report-review-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!selectedReportId) return;
    try {
      const payload = await api(`/api/v1/reports/${selectedReportId}`, {
        method: "PATCH",
        body: JSON.stringify({
          investigator_notes: document.querySelector("#report-review-notes").value,
          status: document.querySelector("#report-review-state").value,
        }),
      });
      renderReportPreview(payload.content, payload.metadata);
      showToast("Report review saved and audited.", "success");
      await load();
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  document.querySelector("#report-review-export")?.addEventListener("click", () => {
    if (!selectedReportId) return;
    window.location.assign(`/api/v1/reports/${selectedReportId}/export?format=${document.querySelector("#report-export-format").value}`);
  });
}

function renderReportAnalysis(payload) {
  const target = document.querySelector("#report-preview");
  document.querySelector("#report-preview-status").textContent = "AI analysis";
  const text = payload?.analysis?.content || payload?.analysis?.message || payload?.analysis || "Analysis unavailable.";
  target.replaceChildren(el("div", { className: "forensic-report report-analysis" }, [
    el("strong", { text: "Report Analysis" }),
    markdownFragment(String(text)),
  ]));
}

function markdownFragment(markdown) {
  const box = document.createElement("div");
  box.className = "markdown-body";
  const escaped = String(markdown || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  box.innerHTML = escaped
    .replace(/```([\s\S]*?)```/g, "<pre><code>$1</code></pre>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/^### (.*)$/gm, "<h4>$1</h4>")
    .replace(/^## (.*)$/gm, "<h3>$1</h3>")
    .replace(/^# (.*)$/gm, "<h2>$1</h2>")
    .replace(/\n/g, "<br>");
  return box;
}

function renderReportPreview(content, metadata = null) {
  const target = document.querySelector("#report-preview");
  document.querySelector("#report-preview-status").textContent = metadata?.status || content?.review?.status || "Generated";
  const findings = content?.findings || [];
  const recommendations = content?.recommendations || [];
  const notes = content?.investigator_notes || [];
  const authorship = content?.authorship || {};
  const review = document.querySelector("#report-review-form");
  review?.classList.remove("d-none");
  document.querySelector("#report-review-notes").value = notes.map((item) => item.content || "").join("\n\n");
  document.querySelector("#report-review-state").value = metadata?.status || content?.review?.status || "draft";
  target.replaceChildren(el("div", { className: "report-review-content" }, [
    el("section", { className: "report-section-card report-section-executive" }, [
      el("header", {}, [el("h4", { text: "Executive summary" }), el("span", { className: "report-authorship", text: authorship.executive_summary || "system-derived" })]),
      el("p", { text: content?.executive_summary || "No executive summary was generated." }),
    ]),
    el("section", { className: "report-section-card report-section-findings" }, [
      el("header", {}, [el("h4", { text: `Findings · ${findings.length}` }), el("span", { className: "report-authorship", text: authorship.findings || "forensic analysis" })]),
      ...(findings.length ? findings.slice(0, 20).map((finding) => el("article", { className: "report-finding" }, [
        el("strong", { text: finding.title || "Recorded finding" }),
        el("small", { text: finding.detail || "No additional detail recorded." }),
        el("code", { text: `${finding.source?.evidence_number || "Evidence"} · ${finding.source?.sha256 || "Hash unavailable"}` }),
      ])) : [el("p", { text: "No source-linked forensic findings are recorded." })]),
    ]),
    el("section", { className: "report-section-card report-section-recommendations" }, [
      el("header", {}, [el("h4", { text: `Recommendations · ${recommendations.length}` }), el("span", { className: "report-authorship", text: "recorded only" })]),
      ...(recommendations.length ? recommendations.map((item) => el("article", { className: "report-finding" }, [
        el("strong", { text: item.recommendation }),
        el("small", { text: `${item.priority || "Unprioritized"} · ${item.rationale || "No rationale recorded"}` }),
      ])) : [el("p", { text: "No recorded recommendations are available." })]),
    ]),
    el("section", { className: "report-section-card report-section-metadata" }, [
      el("header", {}, [el("h4", { text: "Metadata & traceability" }), el("span", { className: content?.traceability?.finding_sources_complete ? "report-traceability-ok" : "report-traceability-gap", text: content?.traceability?.finding_sources_complete ? "Sources complete" : "Review source gaps" })]),
      el("p", { text: `Template ${content?.report_type || metadata?.report_type || "investigation"} · schema ${content?.schema_version || "legacy"} · version ${metadata?.version || content?.report?.version || "unknown"} · ${content?.review?.signature_status || "signature status unknown"}` }),
    ]),
  ]));
}

function summarizeSection(value) {
  if (Array.isArray(value)) return `${value.length} item(s)`;
  if (value && typeof value === "object") return `${Object.keys(value).length} field(s)`;
  return String(value || "Included").slice(0, 140);
}

function renderEmpty(target, icon, title, text, variant = "") {
  const node = el("div", { className: `empty-state large ${variant}`.trim() }, [
    el("i", { className: `bi ${icon}` }),
    el("h3", { text: title }),
    el("p", { text }),
  ]);
  target.replaceChildren(node);
}

function renderPlugins(target, plugins) {
  target.replaceChildren(...plugins.map((plugin) => {
    const badges = [el("span", { className: "badge-soft success", text: plugin.version })];
    plugin.capabilities.forEach((capability) => badges.push(el("span", { className: "badge-soft ms-1", text: capability })));
    badges.push(el("span", { className: `badge-soft ms-1 ${plugin.status === "enabled" ? "success" : ""}`, text: plugin.status }));
    return el("div", { className: "plugin-card" }, [
      el("div", {}, [
        el("strong", { text: plugin.name }),
        el("div", { className: "text-muted", text: plugin.description || "No description available." }),
        el("div", { className: "mt-2" }, badges),
        el("div", { className: "plugin-card-meta" }, [
          el("span", { className: "badge-soft", text: plugin.category || "analysis" }),
          el("span", { className: "badge-soft", text: `${plugin.granted_permissions?.length || 0}/${plugin.requested_permissions?.length || 0} grants` }),
          el("span", { className: "badge-soft", text: plugin.credential_configured ? "credential configured" : "no credential" }),
        ]),
        el("small", { className: "d-block text-muted mt-2", text: plugin.dependencies?.length
          ? `Dependencies: ${plugin.dependencies.map((item) => `${item.name}${item.version_specifier || ""}`).join(", ")}`
          : "Dependencies: none" }),
      ]),
      el("div", { className: "text-end" }, [
        el("div", { className: "text-muted", text: plugin.id }),
        el("div", { className: "mt-1 mb-2" }, [
          el("span", { className: "badge text-bg-light", text: plugin.supported_artifact_types.join(", ") || "No artifact types" }),
        ]),
        el("div", { className: "plugin-actions" }, [
          actionButton("Configure", "btn btn-sm btn-outline-primary", { pluginConfigure: plugin.id }),
          ...(plugin.connector_operations?.includes("health") ? [actionButton("Health", "btn btn-sm btn-outline-secondary", { pluginOperation: "health", id: plugin.id })] : []),
          ...(plugin.connector_operations?.includes("sync") ? [actionButton("Sync", "btn btn-sm btn-outline-secondary", { pluginOperation: "sync", id: plugin.id })] : []),
          actionButton("Validate", "btn btn-sm btn-outline-secondary", { pluginAction: "validate", id: plugin.id }),
          actionButton("Update", "btn btn-sm btn-outline-secondary", { pluginAction: "update", id: plugin.id }),
          actionButton(plugin.status === "enabled" ? "Disable" : "Enable", "btn btn-sm btn-outline-secondary", { pluginAction: plugin.status === "enabled" ? "disable" : "enable", id: plugin.id }),
          actionButton("Delete", "btn btn-sm btn-outline-danger", { pluginAction: "delete", id: plugin.id }),
        ]),
      ]),
    ]);
  }));
}

function initialisePluginRegistry() {
  const root = document.querySelector("[data-plugin-registry-root]");
  if (!root) return;
  const target = document.querySelector("#plugin-list");
  const count = document.querySelector("[data-plugin-count]");
  const load = async (reload = false) => {
    renderEmpty(target, "bi-hourglass-split", "Loading plugins", "Reading the trusted plugin registry.");
    try {
      if (reload) await api("/api/v1/plugins/reload", { method: "POST" });
      const data = await api("/api/v1/admin/plugins/management");
      window.cyberInvestigatorPluginManagement = data;
      count.textContent = `${data.count} registered`;
      renderPluginOperations(data);
      if (!data.plugins.length) {
        renderEmpty(target, "bi-puzzle", "No plugins registered", "Discover plugins from the configured trusted plugin directory.");
        return;
      }
      renderPlugins(target, data.plugins);
      if (reload) showToast("Plugin discovery complete.", "success");
    } catch (error) {
      renderEmpty(target, "bi-exclamation-triangle", "Registry unavailable", error.message, "text-danger");
    }
  };
  document.querySelector("#plugin-discover")?.addEventListener("click", () => load(true));
  document.querySelector("#plugin-upload-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const file = document.querySelector("#plugin-upload")?.files?.[0];
    if (!file) {
      showToast("Choose a plugin package first.", "warning");
      return;
    }
    const body = new FormData();
    body.append("plugin", file);
    try {
      await api("/api/v1/plugins/upload", { method: "POST", body });
      showToast("Plugin uploaded and validated.", "success");
      load();
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  document.querySelector("#plugin-list")?.addEventListener("click", async (event) => {
    const configure = event.target.closest("[data-plugin-configure]");
    if (configure) {
      openPluginConfiguration(configure.dataset.pluginConfigure);
      return;
    }
    const operation = event.target.closest("[data-plugin-operation]");
    if (operation) {
      try {
        const job = await api(`/api/v1/admin/plugins/${operation.dataset.id}/${operation.dataset.pluginOperation}`, { method: "POST" });
        showToast(`Connector ${operation.dataset.pluginOperation} queued.`, "success");
        await pollPluginOperation(job.id);
        await load();
      } catch (error) { showToast(error.message, "danger"); }
      return;
    }
    const button = event.target.closest("[data-plugin-action]");
    if (!button) return;
    if (button.dataset.pluginAction === "delete" && !window.confirm("Remove this plugin and its stored configuration? This action is audited.")) return;
    try {
      await api(`/api/v1/plugins/${button.dataset.id}/${button.dataset.pluginAction}`, { method: "POST" });
      showToast(`Plugin ${button.dataset.pluginAction} complete.`, "success");
      await load();
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  document.querySelector("#plugin-validate-all")?.addEventListener("click", () => load(true));
  document.querySelector("#plugin-config-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const pluginId = event.target.dataset.pluginId;
    const configuration = {};
    const credentials = {};
    document.querySelectorAll("#plugin-config-fields [data-plugin-config-key]").forEach((input) => {
      if (input.dataset.secret === "true") {
        if (input.value) credentials[input.dataset.pluginConfigKey] = input.value;
      } else if (input.dataset.pluginConfigType === "boolean") configuration[input.dataset.pluginConfigKey] = input.checked;
      else if (["integer", "number"].includes(input.dataset.pluginConfigType)) configuration[input.dataset.pluginConfigKey] = Number(input.value);
      else configuration[input.dataset.pluginConfigKey] = input.value;
    });
    const grantedPermissions = [...document.querySelectorAll("#plugin-permission-fields input:checked")].map((input) => input.value);
    try {
      await api(`/api/v1/admin/plugins/${pluginId}/configuration`, {
        method: "PATCH",
        body: JSON.stringify({ configuration, credentials, granted_permissions: grantedPermissions }),
      });
      bootstrap.Modal.getInstance(document.querySelector("#plugin-config-modal"))?.hide();
      showToast("Plugin configuration encrypted, saved, and audited.", "success");
      await load();
    } catch (error) { showToast(error.message, "danger"); }
  });
  load();
}

function renderPluginOperations(data) {
  const runtime = document.querySelector("#plugin-runtime-state");
  if (runtime) runtime.textContent = data.runtime?.state || "Unavailable";
  const operationRecord = (title, detail, state = "") => el("article", { className: "plugin-operation-record" }, [
    el("header", {}, [el("strong", { text: title }), el("span", { text: state })]),
    el("p", { text: detail }),
  ]);
  const health = Object.entries(data.health || {}).map(([plugin, item]) =>
    operationRecord(plugin, `${item.message || "No health message"} · ${formatDate(item.checked_at)}`, item.state || "unknown"));
  document.querySelector("#plugin-health")?.replaceChildren(...(health.length
    ? health
    : [el("div", { className: "operations-empty", text: "No connector health check has been recorded." })]));
  const errors = (data.errors || []).map((item) =>
    operationRecord(item.plugin_id || "Plugin operation", item.error || "Connector operation failed.", item.status));
  document.querySelector("#plugin-errors")?.replaceChildren(...(errors.length
    ? errors
    : [el("div", { className: "operations-empty", text: "No failed connector jobs are recorded." })]));
  document.querySelector("#plugin-updates-notice").textContent = data.updates_notice;
  const updates = data.updates || [];
  document.querySelector("#plugin-updates")?.replaceChildren(...(updates.length
    ? updates.map((item) => operationRecord(item.name || item.id, item.message || item.version, item.status || "available"))
    : [el("div", { className: "operations-empty", text: "Update status is unavailable without a configured marketplace source." })]));
}

function openPluginConfiguration(pluginId) {
  const plugin = window.cyberInvestigatorPluginManagement?.plugins?.find((item) => item.id === pluginId);
  if (!plugin) return;
  const form = document.querySelector("#plugin-config-form");
  form.dataset.pluginId = plugin.id;
  document.querySelector("#plugin-config-identity").textContent = `${plugin.name} · ${plugin.version} · ${plugin.category}`;
  const fields = Object.entries(plugin.configuration_schema || {}).map(([key, definition]) => {
    const schema = definition && typeof definition === "object" ? definition : {};
    const secret = schema.secret === true;
    const input = el("input", {
      className: `form-control ${secret ? "plugin-config-secret" : ""}`.trim(),
      type: secret ? "password" : schema.type === "boolean" ? "checkbox" : ["integer", "number"].includes(schema.type) ? "number" : "text",
      dataset: { pluginConfigKey: key, pluginConfigType: schema.type || "string", secret: String(secret) },
      autocomplete: secret ? "new-password" : "off",
      placeholder: secret && plugin.credential_configured ? "Stored credential remains unchanged" : "",
    });
    if (!secret && schema.type === "boolean") input.checked = Boolean(plugin.configuration?.[key]);
    else if (!secret) input.value = plugin.configuration?.[key] ?? plugin.configuration_defaults?.[key] ?? "";
    return el("div", { className: "col-md-6" }, [
      el("label", { className: "form-label", text: schema.label || key }),
      input,
      el("small", { className: "text-muted", text: secret ? "Encrypted secret" : schema.description || "" }),
    ]);
  });
  document.querySelector("#plugin-config-fields").replaceChildren(...(fields.length
    ? fields
    : [el("div", { className: "col-12 operations-empty", text: "This plugin declares no configuration fields." })]));
  document.querySelector("#plugin-permission-fields").replaceChildren(...(plugin.requested_permissions || []).map((permission) =>
    el("label", {}, [
      el("input", { className: "form-check-input me-2", type: "checkbox", value: permission, ...(plugin.granted_permissions.includes(permission) ? { checked: "checked" } : {}) }),
      el("span", { text: permission }),
    ])));
  bootstrap.Modal.getOrCreateInstance(document.querySelector("#plugin-config-modal")).show();
}

async function pollPluginOperation(jobId) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const job = await api(`/api/v1/admin/plugins/jobs/${jobId}`);
    if (job.status === "completed") {
      showToast("Connector operation completed.", "success");
      return job;
    }
    if (job.status === "failed") throw new Error(job.error || "Connector operation failed.");
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("Connector operation is still running. Refresh to review its state.");
}

function kv(label, value) {
  return { label, value };
}

function renderHealthGrid(target, items) {
  if (!target) return;
  target.replaceChildren(...items.map((item) => el("div", { className: "health-item" }, [
    el("small", { text: item.label }),
    el("strong", { text: String(item.value ?? "-") }),
  ])));
}

function renderAdminList(target, items) {
  if (!target) return;
  if (!items.length) {
    target.replaceChildren(emptyInline("bi-info-circle", "No records", "Nothing to display yet."));
    return;
  }
  target.replaceChildren(...items.map((item) => el("div", { className: "compact-item" }, [
    el("i", { className: "bi bi-info-circle" }),
    el("div", {}, [
      el("strong", { text: item.title || item.name || item.event || item.username || "Record" }),
      el("small", { text: item.message || item.role || item.status || item.path || JSON.stringify(item).slice(0, 180) }),
    ]),
  ])));
}

function renderAdminUsers(target, users) {
  if (!target) return;
  if (!users.length) { renderEmpty(target, "bi-people", "No users", "Create the first managed account."); return; }
  target.replaceChildren(...users.map((user) => el("div", { className: "compact-item admin-user-row" }, [
    el("span", { className: "avatar", text: user.username.slice(0, 2).toUpperCase() }),
    el("div", {}, [el("strong", { text: user.username }), el("small", { text: `${user.email} - ${user.role} - ${user.status}` })]),
    el("div", { className: "identity-user-actions" }, [
      actionButton("Details", "btn btn-sm btn-outline-primary", { identityUser: user.id }),
      actionButton(user.status === "active" ? "Suspend" : "Activate", "btn btn-sm btn-outline-secondary", { adminUserStatus: user.status === "active" ? "suspended" : "active", id: user.id }),
    ]),
  ])));
}

function renderObservabilityWorkspace(data) {
  const telemetry = data.telemetry || {};
  const latency = telemetry.latency_ms || {};
  const throughput = telemetry.throughput || {};
  const status = document.querySelector("#observability-status");
  if (status) {
    status.textContent = data.status || "degraded";
    status.className = `operations-status observability-status ${data.status || "degraded"}`;
  }
  const collected = document.querySelector("#observability-collected");
  if (collected) collected.textContent = `Collected ${formatDate(data.collected_at)} · ${telemetry.retention?.scope || "unknown scope"}`;
  renderOperationalAlerts(document.querySelector("#observability-critical"), data.critical_alerts || []);
  renderHealthGrid(document.querySelector("#observability-health"), [
    kv("Readiness", data.health?.status),
    kv("Database", data.health?.database),
    kv("Plugins", data.health?.plugins),
    kv("Audit chain", data.audit_integrity?.valid === true ? "verified" : "review required"),
  ]);
  renderAdminList(document.querySelector("#observability-services"), (data.services || []).map((item) => ({
    title: `${item.name} · ${item.status}`,
    message: item.source,
  })));
  renderAdminList(document.querySelector("#observability-events"), (data.recent_events || []).slice(0, 12));
  renderHealthGrid(document.querySelector("#observability-metrics"), [
    kv("Observed requests", telemetry.requests_total),
    kv("Median latency", latency.median == null ? "No samples" : `${latency.median} ms`),
    kv("P95 latency", latency.p95 == null ? "No samples" : `${latency.p95} ms`),
    kv("Observed throughput", throughput.requests_per_second == null ? "No samples" : `${throughput.requests_per_second}/s`),
    kv("Server error rate", telemetry.server_error_rate == null ? "No samples" : `${(telemetry.server_error_rate * 100).toFixed(2)}%`),
    kv("Retained traces", telemetry.retention?.retained_traces),
    kv("Retention limit", telemetry.retention?.max_traces),
  ]);
  renderAdminList(document.querySelector("#observability-history"), (telemetry.history || []).slice(-20).reverse().map((item) => ({
    title: formatDate(item.minute),
    message: `${item.requests} requests · ${item.errors} server errors · ${item.average_latency_ms} ms average`,
  })));
  renderAdminList(document.querySelector("#observability-traces"), (data.traces || []).slice(0, 40).map((item) => ({
    title: `${item.method} ${item.path} · ${item.status}`,
    message: `${item.duration_ms} ms · trace ${item.trace_id}`,
  })));
  renderAdminList(document.querySelector("#observability-logs"), (data.logs?.events || []).slice(0, 40).map((item) => ({
    title: `${item.level || "UNKNOWN"} · ${item.logger || "application"}`,
    message: `${item.message || ""}${item.trace_id ? ` · trace ${item.trace_id}` : ""}`,
  })));
  renderAdminList(document.querySelector("#observability-sources"), (data.sources || []).map((item) => ({
    title: `${item.name} · ${item.status}`,
    message: item.detail,
  })));
}

function renderDeploymentWorkspace(data) {
  const status = data.deployment_status || {};
  const release = status.release || {};
  const pipelines = data.pipelines || {};
  const verification = status.last_verification || {};
  const collected = document.querySelector("#deployment-collected");
  if (collected) collected.textContent = `Collected ${formatDate(data.collected_at)} · ${status.environment || "unknown environment"}`;
  renderHealthGrid(document.querySelector("#deployment-status"), [
    kv("Runtime", status.status),
    kv("Environment", status.environment),
    kv("Version", release.version),
    kv("Revision", release.git_sha || "Unavailable"),
    kv("Build time", release.build_time ? formatDate(release.build_time) : "Unavailable"),
    kv("Containerized", status.containerized ? "yes" : "no"),
  ]);
  renderAdminList(document.querySelector("#deployment-pipelines"), (pipelines.definitions || []).length
    ? pipelines.definitions.map((item) => ({
      title: `${item.name} · ${item.status}`,
      message: `Run status ${item.run_status} · definition ${item.sha256.slice(0, 12)}`,
    }))
    : [{ title: "Pipeline provider unavailable", message: pipelines.history_detail || "No workflow definitions are visible." }]);
  renderAdminList(document.querySelector("#deployment-failures"), (data.failed_builds?.items || []).length
    ? data.failed_builds.items
    : [{ title: "Build history unavailable", message: data.failed_builds?.detail || "Connect a CI provider to retrieve failures." }]);
  renderAdminList(document.querySelector("#deployment-releases"), (data.recent_releases || []).map((item) => ({
    title: `${item.version} · ${item.status || "recorded"}`,
    message: `${item.git_sha || "revision unavailable"} · ${item.digest || "digest unavailable"}`,
  })));
  renderHealthGrid(document.querySelector("#deployment-security"), [
    kv("Dependency audit", data.security?.dependency_audit),
    kv("Static analysis", data.security?.static_analysis),
    kv("Code scanning", data.security?.code_scanning),
    kv("Provenance", data.security?.container_provenance),
    kv("Scan results", data.security?.scan_results == null ? "Provider unavailable" : data.security.scan_results),
  ]);
  renderAdminList(document.querySelector("#deployment-verification"), (verification.checks || []).length
    ? verification.checks.map((item) => ({ title: `${item.name} · ${item.status}`, message: item.detail }))
    : [{ title: "Not verified in this environment", message: "Run deployment verification to record real checks." }]);
  const candidates = data.rollback?.candidates || [];
  renderAdminList(document.querySelector("#deployment-rollback"), candidates.length
    ? candidates.map((item) => ({
      title: `${item.version} · immutable candidate`,
      message: item.digest,
      action: "rollback",
    }))
    : [{ title: "No rollback candidate", message: data.rollback?.detail || "No prior immutable release is recorded." }]);
  const rollbackTarget = document.querySelector("#deployment-rollback");
  if (rollbackTarget && candidates.length) {
    rollbackTarget.replaceChildren(...candidates.map((item) => storageRecord(
      `${item.version} · immutable candidate`,
      item.digest,
      [actionButton("Create rollback plan", "btn btn-sm btn-outline-danger", { deploymentRollback: item.version })],
    )));
  }
  renderHealthGrid(document.querySelector("#deployment-infrastructure"), [
    kv("Container", data.infrastructure_as_code?.container ? "configured" : "unavailable"),
    kv("Compose", data.infrastructure_as_code?.compose ? "configured" : "unavailable"),
    kv("Terraform", data.infrastructure_as_code?.terraform ? "detected" : "not configured"),
    kv("Kubernetes", data.infrastructure_as_code?.kubernetes ? "detected" : "not configured"),
  ]);
}

async function initialiseAdminOperations() {
  if (!document.querySelector("[data-module='admin']")) return;
  const activateAdminHash = () => {
    const target = window.location.hash;
    if (!target) return;
    const trigger = document.querySelector(`[data-bs-target='${target}']`);
    if (trigger && window.bootstrap) bootstrap.Tab.getOrCreateInstance(trigger).show();
  };
  activateAdminHash();
  window.addEventListener("hashchange", activateAdminHash);
  const load = async () => {
    try {
      const [data, operations, identity, observability, deployment] = await Promise.all([
        api("/api/v1/admin/overview"),
        api("/api/v1/admin/operations"),
        api("/api/v1/admin/identity"),
        api("/api/v1/admin/observability"),
        api("/api/v1/admin/deployments"),
      ]);
      renderOperationsCenter(operations);
      renderObservabilityWorkspace(observability);
      renderDeploymentWorkspace(deployment);
      const aiStatus = data.ai_status || data.openai_status || {};
      renderHealthGrid(document.querySelector("#admin-health"), [kv("Platform", operations.status), kv("Open alerts", operations.metrics.open_alerts), kv("Failed/blocked", operations.metrics.failed_or_blocked_audit_events), kv("Audit chain", operations.audit_integrity?.valid === true ? "verified" : operations.audit_integrity?.valid === false ? "warning" : "unavailable")]);
      renderHealthGrid(document.querySelector("#admin-database"), [kv("Dialect", data.database.dialect), ...Object.entries(data.database.tables).map(([name, value]) => kv(name, value))]);
      renderHealthGrid(document.querySelector("#admin-metrics"), [kv("Readiness", data.health.status), kv("Database", data.health.database), kv("Plugins", data.health.plugins), kv("Rate limit", data.metrics.rate_limit_requests)]);
      renderHealthGrid(document.querySelector("#admin-today"), [kv("Cases", data.metrics.cases), kv("Evidence", data.metrics.evidence), kv("Timeline events", data.metrics.timeline_events), kv("Reports", data.metrics.reports)]);
      renderHealthGrid(document.querySelector("#admin-ai-activity"), [kv("Provider", aiStatus.provider), kv("Status", aiStatus.available ? "available" : "fallback"), kv("Configured", aiStatus.configured ? "yes" : "no"), kv("Model", aiStatus.model)]);
      renderAdminList(document.querySelector("#admin-recent-reports"), data.audit_logs.filter((item) => String(item.event || "").includes("report")).slice(0, 6));
      renderHealthGrid(document.querySelector("#admin-threat-trend"), [kv("Critical alerts", operations.critical_alerts.length), kv("Active issues", operations.active_issues.length), kv("Failed jobs", operations.metrics.jobs.failed), kv("AI status", aiStatus.available ? "available" : "fallback")]);
      renderAdminUsers(document.querySelector("#admin-users"), data.users || []);
      renderIdentityWorkspace(identity);
      renderHealthGrid(document.querySelector("#admin-security"), [
        kv("Critical alerts", operations.critical_alerts.length),
        kv("Open alerts", operations.metrics.open_alerts),
        kv("Failed/blocked events", operations.metrics.failed_or_blocked_audit_events),
        kv("Audit integrity", operations.audit_integrity?.valid === true ? "verified" : "review required"),
      ]);
      renderAdminList(document.querySelector("#admin-logs"), data.logs.map((log) => ({ title: log.name, message: `${log.size_bytes} bytes` })));
      renderAdminList(document.querySelector("#admin-audit"), data.audit_logs.slice(-20).reverse());
      renderAdminList(document.querySelector("#admin-jobs"), data.background_jobs);
      renderHealthGrid(document.querySelector("#admin-plugins"), [kv("Enabled", data.plugin_health.enabled), kv("Count", data.plugin_health.count)]);
      renderHealthGrid(document.querySelector("#admin-openai"), [
        kv("Provider", aiStatus.provider),
        kv("Configured", aiStatus.configured ? "yes" : "no"),
        kv("Available", aiStatus.available ? "yes" : "fallback"),
        kv("Model", aiStatus.model),
      ]);
      renderHealthGrid(document.querySelector("#admin-monitoring"), [
        kv("Uptime", `${data.performance.uptime_seconds}s`),
        kv("Database", data.health.database),
        kv("Provider", aiStatus.available ? "available" : "fallback"),
        kv("Requests/min", data.metrics.requests_per_minute || 0),
      ]);
      renderHealthGrid(document.querySelector("#admin-settings"), [
        kv("Settings", "separate pages"),
        kv("AI config", aiStatus.configured ? "configured" : "needs provider"),
        kv("Plugins", data.plugin_health.enabled ? "enabled" : "disabled"),
        kv("Audit", `${data.audit_logs.length} recent`),
      ]);
    } catch (error) {
      showToast(error.message, "danger");
    }
  };
  document.querySelector("#admin-refresh")?.addEventListener("click", load);
  document.querySelector("#deployment-verify")?.addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const result = await api("/api/v1/admin/deployments/verify", { method: "POST", body: "{}" });
      showToast(`Deployment verification ${result.status}.`, result.status === "failed" ? "danger" : "success");
      await load();
    } catch (error) {
      showToast(error.message, "danger");
      await load();
    } finally {
      button.disabled = false;
    }
  });
  document.querySelector("#deployment-rollback")?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-deployment-rollback]");
    if (!button) return;
    try {
      await api("/api/v1/admin/deployments/rollback-plans", {
        method: "POST",
        body: JSON.stringify({ target_version: button.dataset.deploymentRollback }),
      });
      showToast("Rollback plan created; no deployment was executed.", "success");
      await load();
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  document.querySelectorAll(".operations-command-center, .observability-workspace").forEach((workspace) => workspace.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-alert-status]");
    if (!button) return;
    try {
      await api(`/api/v1/admin/alerts/${button.dataset.alertId}`, {
        method: "PATCH",
        body: JSON.stringify({ status: button.dataset.alertStatus }),
      });
      showToast(`Alert ${button.dataset.alertStatus}.`, "success");
      await load();
    } catch (error) {
      showToast(error.message, "danger");
    }
  }));
  document.querySelector("#operations-maintenance-save")?.addEventListener("click", async () => {
    try {
      await api("/api/v1/admin/maintenance", {
        method: "PATCH",
        body: JSON.stringify({
          enabled: document.querySelector("#operations-maintenance-enabled").checked,
          message: document.querySelector("#operations-maintenance-message").value,
        }),
      });
      showToast("Maintenance state updated and audited.", "success");
      await load();
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  document.querySelector("#admin-load-log")?.addEventListener("click", async () => {
    try {
      const data = await api("/api/v1/admin/logs");
      renderAdminList(document.querySelector("#admin-logs"), data.lines.map((line) => ({ title: data.name, message: line })));
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  document.querySelector("#admin-users")?.addEventListener("click", async (event) => {
    const detail = event.target.closest("[data-identity-user]");
    const status = event.target.closest("[data-admin-user-status]");
    const role = event.target.closest("[data-admin-user-role]");
    if (detail) {
      try {
        renderIdentityUserDetail(await api(`/api/v1/admin/identity/users/${detail.dataset.identityUser}`));
      } catch (error) { showToast(error.message, "danger"); }
      return;
    }
    const button = status || role;
    if (!button) return;
    try {
      await api(`/api/v1/admin/users/${button.dataset.id}`, {
        method: "PATCH",
        body: JSON.stringify(status ? { status: button.dataset.adminUserStatus } : { role: button.dataset.adminUserRole }),
      });
      showToast("User account updated.", "success");
      load();
    } catch (error) { showToast(error.message, "danger"); }
  });
  document.querySelector("#admin-user-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api("/api/v1/admin/users", { method: "POST", body: JSON.stringify({
        username: document.querySelector("#admin-user-name").value,
        email: document.querySelector("#admin-user-email").value,
        role: document.querySelector("#admin-user-role").value,
        password: document.querySelector("#admin-user-password").value,
      }) });
      bootstrap.Modal.getInstance(document.querySelector("#admin-user-modal"))?.hide();
      event.target.reset();
      showToast("User account created.", "success");
      load();
    } catch (error) { showToast(error.message, "danger"); }
  });
  document.querySelector("#admin-role-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const roleId = event.target.dataset.roleId;
    const permissionCodes = [...document.querySelectorAll("#admin-role-permissions input:checked")].map((item) => item.value);
    const payload = {
      description: document.querySelector("#admin-role-description").value,
      permission_codes: permissionCodes,
    };
    if (!roleId) payload.name = document.querySelector("#admin-role-name").value;
    try {
      await api(roleId ? `/api/v1/admin/roles/${roleId}` : "/api/v1/admin/roles", {
        method: roleId ? "PATCH" : "POST",
        body: JSON.stringify(payload),
      });
      bootstrap.Modal.getInstance(document.querySelector("#admin-role-modal"))?.hide();
      event.target.reset();
      delete event.target.dataset.roleId;
      showToast(`Role ${roleId ? "updated" : "created"} and audited.`, "success");
      await load();
    } catch (error) { showToast(error.message, "danger"); }
  });
  document.querySelector("#admin-roles")?.addEventListener("click", async (event) => {
    const remove = event.target.closest("[data-delete-role]");
    if (remove) {
      if (!window.confirm("Delete this unassigned custom role? This action is audited.")) return;
      try {
        await api(`/api/v1/admin/roles/${remove.dataset.deleteRole}`, { method: "DELETE" });
        showToast("Custom role deleted and audited.", "success");
        await load();
      } catch (error) { showToast(error.message, "danger"); }
      return;
    }
    const button = event.target.closest("[data-edit-role]");
    if (!button) return;
    const role = window.cyberInvestigatorIdentity?.roles?.find((item) => item.id === button.dataset.editRole);
    if (!role) return;
    const form = document.querySelector("#admin-role-form");
    form.dataset.roleId = role.id;
    document.querySelector("#admin-role-name").value = role.name;
    document.querySelector("#admin-role-name").disabled = true;
    document.querySelector("#admin-role-description").value = role.description || "";
    document.querySelectorAll("#admin-role-permissions input").forEach((input) => { input.checked = role.permissions.includes(input.value); });
    bootstrap.Modal.getOrCreateInstance(document.querySelector("#admin-role-modal")).show();
  });
  document.querySelector("#admin-role-modal")?.addEventListener("hidden.bs.modal", () => {
    const form = document.querySelector("#admin-role-form");
    form.reset();
    delete form.dataset.roleId;
    document.querySelector("#admin-role-name").disabled = false;
  });
  load();
}

function renderIdentityWorkspace(data) {
  window.cyberInvestigatorIdentity = data;
  renderHealthGrid(document.querySelector("#identity-summary"), [
    kv("Users", data.summary?.users || 0),
    kv("Active users", data.summary?.active_users || 0),
    kv("Locked users", data.summary?.locked_users || 0),
    kv("Active sessions", data.summary?.active_sessions || 0),
    kv("Roles", data.summary?.roles || 0),
  ]);
  const roleSelect = document.querySelector("#admin-user-role");
  if (roleSelect) roleSelect.replaceChildren(...(data.roles || []).map((role) => el("option", { value: role.name, text: role.name })));
  const permissions = document.querySelector("#admin-role-permissions");
  if (permissions) permissions.replaceChildren(...(data.permissions || []).map((permission) => el("label", {}, [
    el("input", { className: "form-check-input", type: "checkbox", value: permission.code }),
    el("span", {}, [el("strong", { text: permission.label }), el("small", { text: `${permission.category} · ${permission.code}` })]),
  ])));
  const roles = document.querySelector("#admin-roles");
  if (roles) {
    if (!(data.roles || []).length) renderEmpty(roles, "bi-person-lock", "No roles", "No persisted roles were found.");
    else roles.replaceChildren(...data.roles.map((role) => el("article", { className: "identity-role-record" }, [
      el("header", {}, [
        el("div", {}, [el("strong", { text: role.name }), el("p", { text: role.description || "No role description." })]),
        el("div", { className: "identity-user-actions" }, [
          actionButton("Edit grants", "btn btn-sm btn-outline-secondary", { editRole: role.id }),
          ...(!role.is_system ? [actionButton("Delete", "btn btn-sm btn-outline-danger", { deleteRole: role.id })] : []),
        ]),
      ]),
      el("p", { text: `${role.user_count} assigned user${role.user_count === 1 ? "" : "s"} · ${role.is_system ? "system role" : "custom role"}` }),
      el("div", { className: "identity-grants" }, role.permissions.length
        ? role.permissions.map((code) => el("span", { text: code }))
        : [el("span", { text: "No permissions" })]),
    ])));
  }
  renderHealthGrid(document.querySelector("#identity-capabilities"), [
    kv("MFA", data.capabilities?.mfa?.status || "unavailable"),
    kv("SSO", data.capabilities?.sso?.status || "unavailable"),
    kv("Directory", data.capabilities?.directory?.status || "unavailable"),
  ]);
}

function renderIdentityUserDetail(data) {
  const target = document.querySelector("#identity-user-detail");
  if (!target) return;
  const user = data.user;
  target.replaceChildren(
    el("section", { className: "identity-profile-summary" }, [
      el("strong", { text: user.username }),
      el("p", { className: "text-muted small", text: `${user.email} · ${user.role} · ${user.status}` }),
      el("div", { className: "identity-lifecycle-controls" }, [
        el("label", { for: "identity-detail-role", text: "Assigned role" }),
        el("select", { className: "form-select form-select-sm", id: "identity-detail-role" },
          (window.cyberInvestigatorIdentity?.roles || []).map((role) => el("option", {
            value: role.name,
            text: role.name,
            ...(role.name === user.role ? { selected: "selected" } : {}),
          }))),
        actionButton("Apply role", "btn btn-sm btn-outline-primary", { applyUserRole: user.id }),
        ...(data.security.locked_until ? [actionButton("Unlock account", "btn btn-sm btn-outline-warning", { unlockUser: user.id })] : []),
      ]),
    ]),
    el("section", { className: "identity-security-status" }, [
      el("h4", { className: "h6 mt-3", text: "Security status" }),
      el("div", { className: "identity-security-grid" }, [
        kvCard("Failed logins", data.security.failed_login_count),
        kvCard("Active sessions", data.security.active_sessions),
        kvCard("Locked until", data.security.locked_until ? formatDate(data.security.locked_until) : "not locked"),
        kvCard("Last login", formatDate(data.security.last_login_at)),
      ]),
      el("div", { className: "identity-grants" }, data.permissions.length
        ? data.permissions.map((code) => el("span", { text: code }))
        : [el("span", { text: "No granted permissions" })]),
    ]),
    el("section", { className: "identity-sessions" }, [
      el("h4", { className: "h6 mt-3", text: "Sessions" }),
      ...(data.sessions.length ? data.sessions.map((item) => el("article", { className: "identity-session" }, [
        el("header", {}, [el("strong", { text: item.active ? "Active session" : item.status }), el("small", { text: formatDate(item.last_seen_at) })]),
        el("small", { text: item.ip_address || "IP unavailable" }),
        el("small", { text: item.user_agent || "User agent unavailable" }),
        ...(item.active ? [actionButton("Revoke", "btn btn-sm btn-outline-danger mt-2", { managedSession: item.id, userId: user.id })] : []),
      ])) : [el("div", { className: "operations-empty", text: "No sessions have been recorded." })]),
    ]),
  );
  target.querySelectorAll("[data-managed-session]").forEach((button) => button.addEventListener("click", async () => {
    try {
      await api(`/api/v1/admin/identity/sessions/${button.dataset.managedSession}`, { method: "DELETE" });
      showToast("Session revoked and audited.", "success");
      renderIdentityUserDetail(await api(`/api/v1/admin/identity/users/${button.dataset.userId}`));
    } catch (error) { showToast(error.message, "danger"); }
  }));
  target.querySelector("[data-apply-user-role]")?.addEventListener("click", async (event) => {
    try {
      await api(`/api/v1/admin/users/${event.currentTarget.dataset.applyUserRole}`, {
        method: "PATCH",
        body: JSON.stringify({ role: document.querySelector("#identity-detail-role").value }),
      });
      showToast("Role assignment updated and audited.", "success");
      renderIdentityUserDetail(await api(`/api/v1/admin/identity/users/${user.id}`));
    } catch (error) { showToast(error.message, "danger"); }
  });
  target.querySelector("[data-unlock-user]")?.addEventListener("click", async (event) => {
    try {
      await api(`/api/v1/admin/users/${event.currentTarget.dataset.unlockUser}`, {
        method: "PATCH",
        body: JSON.stringify({ unlock: true }),
      });
      showToast("Account unlocked and audited.", "success");
      renderIdentityUserDetail(await api(`/api/v1/admin/identity/users/${user.id}`));
    } catch (error) { showToast(error.message, "danger"); }
  });
}

function kvCard(label, value) {
  return el("div", { className: "health-card" }, [el("small", { text: label }), el("strong", { text: value == null ? "unavailable" : String(value) })]);
}

function renderOperationsCenter(data) {
  const status = document.querySelector("#operations-status");
  if (status) {
    status.textContent = data.status || "unknown";
    status.className = `operations-status ${data.status || "degraded"}`;
  }
  const collected = document.querySelector("#operations-collected-at");
  if (collected) collected.textContent = `Collected ${formatDate(data.collected_at)} · no synthetic capacity metrics`;
  const critical = data.critical_alerts || [];
  const criticalCount = document.querySelector("#operations-critical-count");
  if (criticalCount) criticalCount.textContent = String(critical.length);
  renderOperationalAlerts(document.querySelector("#operations-critical"), critical);
  renderOperationalAlerts(document.querySelector("#operations-issues"), data.active_issues || []);
  renderHealthGrid(document.querySelector("#operations-health"), [
    kv("Overall", data.health?.status || "unavailable"),
    kv("Database", data.health?.database || "unavailable"),
    kv("Plugins", data.health?.plugins || "unavailable"),
    kv("AI", data.health?.ai?.available ? "available" : "fallback"),
  ]);
  renderHealthGrid(document.querySelector("#operations-resources"), [
    kv("Uptime", data.resource_usage?.process_uptime_seconds == null ? "unavailable" : `${data.resource_usage.process_uptime_seconds}s`),
    kv("CPU", data.resource_usage?.cpu?.status || "unavailable"),
    kv("Memory", data.resource_usage?.memory?.status || "unavailable"),
    kv("Storage", data.resource_usage?.storage?.status || "unavailable"),
    kv("Queued jobs", data.metrics?.jobs?.queued || 0),
    kv("Running jobs", data.metrics?.jobs?.running || 0),
  ]);
  renderOperationsActivity(document.querySelector("#operations-activity"), data.activity || []);
  document.querySelector("#operations-maintenance-enabled").checked = Boolean(data.maintenance?.enabled);
  document.querySelector("#operations-maintenance-message").value = data.maintenance?.message || "";
}

function renderOperationalAlerts(target, items) {
  if (!target) return;
  if (!items.length) {
    target.replaceChildren(el("div", { className: "operations-empty", text: "No persisted alerts in this state." }));
    return;
  }
  target.replaceChildren(...items.map((item) => el("article", { className: "operations-record" }, [
    el("header", {}, [el("strong", { text: item.title }), el("span", { text: item.level })]),
    el("p", { text: `${item.message} · ${item.status}` }),
    el("footer", {}, [
      ...(item.status === "open" ? [actionButton("Acknowledge", "btn btn-sm btn-outline-secondary", { alertStatus: "acknowledged", alertId: item.id })] : []),
      actionButton("Resolve", "btn btn-sm btn-outline-success", { alertStatus: "resolved", alertId: item.id }),
    ]),
  ])));
}

function renderOperationsActivity(target, items) {
  if (!target) return;
  if (!items.length) {
    target.replaceChildren(el("div", { className: "operations-empty", text: "No administrative activity has been recorded." }));
    return;
  }
  target.replaceChildren(...items.map((item) => el("article", { className: "operations-record" }, [
    el("header", {}, [el("strong", { text: item.event || item.action || "Administrative event" }), el("span", { text: formatDate(item.created_at) })]),
    el("p", { text: `${item.user || item.username || "system"} · ${item.result || "recorded"} · ${item.affected_object || "platform"}` }),
  ])));
}

function initialiseProfilePages() {
  if (!document.querySelector("[data-module='profile']")) return;
  const activate = (id) => {
    const selected = document.getElementById(id) ? id : "profile";
    document.querySelectorAll("[data-profile-page]").forEach((link) => {
      link.classList.toggle("active", link.dataset.profilePage === selected);
    });
    document.querySelectorAll("[data-module='profile'] .settings-page").forEach((page) => {
      page.classList.toggle("active", page.id === selected);
    });
  };
  document.querySelectorAll("[data-profile-page]").forEach((link) => {
    link.addEventListener("click", () => activate(link.dataset.profilePage));
  });
  activate(location.hash ? location.hash.slice(1) : "profile");
  initialiseProfileNotifications();
  initialiseProfileAccount();
  initialiseHistoryWorkspace();
}

async function initialiseHistoryWorkspace() {
  const workspace = document.querySelector("#history");
  if (!workspace) return;
  const search = document.querySelector("#history-search");
  const caseFilter = document.querySelector("#history-case");
  const resultFilter = document.querySelector("#history-result");
  const load = async () => {
    try {
      const data = await api(`/api/v1/history${query({ q: search.value, case_id: caseFilter.value, result: resultFilter.value })}`);
      renderHistoryRecords("#history-critical", data.critical_notifications || [], (item) => ({
        title: item.title,
        detail: item.message,
        time: item.created_at,
        object: `${item.category} · ${item.priority}`,
      }));
      renderHistoryRecords("#history-activity", data.investigation_activity || [], (item) => ({
        title: item.summary,
        detail: `${item.event_type} · ${item.certainty || "confirmed record"}`,
        time: item.occurred_at,
        object: item.evidence_number || item.case_number || item.id,
      }));
      renderHistoryRecords("#history-security", data.security_events || [], (item) => ({
        title: item.title || item.event || item.action || "Security event",
        detail: item.message || `${item.result || item.status || "recorded"} · ${item.category || item.role || "security"}`,
        time: item.created_at,
        object: item.affected_object || item.id,
      }));
      renderHistoryRecords("#history-audit", data.audit_events || [], (item) => ({
        title: item.event || item.action || "Audit event",
        detail: `${item.username || "system"} · ${item.result || "recorded"} · ${item.reason || "No reason recorded"}`,
        time: item.created_at,
        object: item.affected_object || item.id,
      }));
      const counts = {
        critical: data.critical_notifications?.length || 0,
        activity: data.investigation_activity?.length || 0,
        security: data.security_events?.length || 0,
        audit: data.audit_events?.length || 0,
      };
      Object.entries(counts).forEach(([key, value]) => {
        const target = document.querySelector(`#history-${key}-count`);
        if (target) target.textContent = String(value);
      });
      document.querySelector("#history-investigation-notifications").checked = data.preferences?.investigation_notifications ?? true;
      document.querySelector("#history-security-notifications").checked = data.preferences?.security_notifications ?? true;
      const integrity = document.querySelector("#history-integrity");
      if (data.audit_integrity?.available === false) {
        integrity.textContent = "Append-only audit";
      } else {
        integrity.textContent = data.audit_integrity?.valid
          ? `Chain verified · ${data.audit_integrity.records_checked || 0} sealed`
          : "Audit integrity warning";
        integrity.classList.toggle("history-integrity-valid", Boolean(data.audit_integrity?.valid));
        integrity.classList.toggle("history-integrity-invalid", data.audit_integrity?.valid === false);
      }
    } catch (error) {
      ["#history-critical", "#history-activity", "#history-security", "#history-audit"].forEach((selector) => {
        const target = document.querySelector(selector);
        if (target) target.replaceChildren(el("div", { className: "history-empty", text: error.message }));
      });
    }
  };
  await caseOptions([caseFilter], true);
  applyRequestedCase([caseFilter]);
  document.querySelector("#history-refresh")?.addEventListener("click", load);
  caseFilter.addEventListener("change", load);
  resultFilter.addEventListener("change", load);
  search.addEventListener("input", debounce(load));
  document.querySelector("#history-save-settings")?.addEventListener("click", async () => {
    try {
      await api("/api/v1/account/preferences", {
        method: "PATCH",
        body: JSON.stringify({
          investigation_notifications: document.querySelector("#history-investigation-notifications").checked,
          security_notifications: document.querySelector("#history-security-notifications").checked,
        }),
      });
      showToast("Notification preferences saved.", "success");
      await load();
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  await load();
}

function renderHistoryRecords(selector, items, normalize) {
  const target = document.querySelector(selector);
  if (!target) return;
  if (!items.length) {
    target.replaceChildren(el("div", { className: "history-empty", text: "No recorded events in this scope." }));
    return;
  }
  target.replaceChildren(...items.map((item) => {
    const record = normalize(item);
    return el("article", { className: "history-record" }, [
      el("header", {}, [el("strong", { text: record.title || "Recorded event" }), el("time", { text: formatDate(record.time) })]),
      el("p", { text: record.detail || "No additional detail recorded." }),
      ...(record.object ? [el("code", { text: record.object })] : []),
    ]);
  }));
}

async function initialiseProfileAccount() {
  try {
    const data = await api("/api/v1/account");
    const sessions = document.querySelector("#profile-sessions");
    if (sessions) renderAdminList(sessions, (data.sessions || []).map((item) => ({
      title: `${item.active ? "Active" : "Inactive"} session`,
      message: `${item.ip_address || "Unknown address"} · ${formatDate(item.last_seen_at)} · ${item.status}`,
    })));
    const history = document.querySelector("#profile-login-history");
    if (history) renderAdminList(history, (data.login_history || []).map((item) => ({
      title: item.event || item.action || "Authentication event",
      message: `${formatDate(item.created_at)} · ${item.result || "recorded"}`,
    })));
    const activity = document.querySelector("#profile-activity");
    if (activity) renderAdminList(activity, (data.recent_activity || []).map((item) => ({
      title: item.event || item.action || "Workspace activity",
      message: `${formatDate(item.created_at)} · ${item.result || "recorded"}`,
    })));
    const usage = document.querySelector("#profile-api-usage");
    if (usage) renderHealthGrid(usage, [
      kv("AI conversations", data.api_usage?.ai_conversations || 0),
      kv("Exports", data.api_usage?.exports || 0),
      kv("Recorded requests", data.api_usage?.requests_recorded || 0),
    ]);
  } catch (error) {
    ["#profile-sessions", "#profile-login-history", "#profile-activity", "#profile-api-usage"].forEach((selector) => {
      const target = document.querySelector(selector);
      if (target) renderEmpty(target, "bi-exclamation-triangle", "Account data unavailable", error.message);
    });
  }
}

async function initialiseProfileNotifications() {
  const target = document.querySelector("#profile-notifications-list");
  if (!target) return;
  const search = document.querySelector("#profile-notification-search");
  const filter = document.querySelector("#profile-notification-filter");
  let state = { items: [] };
  const load = async () => { state = await api("/api/v1/notifications"); render(); };
  const render = () => {
    const term = (search?.value || "").toLowerCase();
    const priority = filter?.value || "all";
    const items = (state.items || []).filter((item) =>
      (!term || `${item.title} ${item.message}`.toLowerCase().includes(term)) &&
      (priority === "all" || item.priority === priority));
    if (!items.length) { renderEmpty(target, "bi-bell", "No notifications", "Nothing matches the current view."); return; }
    target.replaceChildren(...items.map((item) => el("div", { className: "compact-item" }, [
      el("i", { className: notificationIcon(item.category) }),
      el("div", {}, [el("strong", { text: item.title }), el("small", { text: item.message })]),
      actionButton("Read", "btn btn-sm btn-link", { notificationAction: "read", id: item.id }),
      actionButton("Archive", "btn btn-sm btn-link", { notificationAction: "archive", id: item.id }),
      actionButton("Delete", "btn btn-sm btn-link text-danger", { notificationAction: "delete", id: item.id }),
    ])));
  };
  target.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-notification-action]");
    if (!button) return;
    const action = button.dataset.notificationAction;
    const options = action === "delete" ? { method: "DELETE" } : { method: "POST" };
    state = await api(`/api/v1/notifications/${button.dataset.id}${action === "delete" ? "" : `/${action}`}`, options);
    render();
  });
  document.querySelector("#profile-notifications-read")?.addEventListener("click", async () => { state = await api("/api/v1/notifications/read", { method: "POST" }); render(); });
  search?.addEventListener("input", render);
  filter?.addEventListener("change", render);
  try { await load(); } catch (error) { renderEmpty(target, "bi-exclamation-triangle", "Notifications unavailable", error.message); }
}

function storageRecord(title, message, actions = []) {
  return el("article", { className: "storage-record" }, [
    el("strong", { text: title }),
    el("small", { text: message }),
    ...(actions.length ? [el("div", { className: "storage-record-actions" }, actions)] : []),
  ]);
}

function renderStorageWorkspace(data) {
  const provider = data.provider || {};
  const capacity = data.capacity || {};
  const integrity = data.integrity || {};
  const policy = data.policy || {};
  const collected = document.querySelector("#storage-collected");
  if (collected) collected.textContent = `Collected ${formatDate(data.collected_at)} · ${provider.name || "Provider unavailable"}`;
  renderHealthGrid(document.querySelector("#storage-health"), [
    kv("Provider", provider.name),
    kv("Status", provider.status),
    kv("Atomic writes", provider.capabilities?.atomic_writes ? "supported" : "unavailable"),
    kv("Custody hashing", provider.capabilities?.content_hashing || "unavailable"),
  ]);
  document.querySelector("#storage-roots")?.replaceChildren(...(data.roots || []).map((item) =>
    storageRecord(item.name, `${item.available ? "available" : "unavailable"} · ${item.file_count ?? "—"} files · ${item.size_bytes == null ? "size unavailable" : formatBytes(item.size_bytes)}`)));
  document.querySelector("#storage-backups")?.replaceChildren(...((data.backups || []).length
    ? data.backups.map((item) => storageRecord(
      item.backup_id,
      `${item.status} · ${item.file_count ?? "—"} files · ${item.size_bytes == null ? "size unavailable" : formatBytes(item.size_bytes)} · created ${formatDate(item.created_at)}${item.last_verification?.verified_at ? ` · checked ${formatDate(item.last_verification.verified_at)}` : ""}`,
      [
        actionButton("Verify", "btn btn-sm btn-outline-primary", { storageBackupAction: "verify", backupId: item.backup_id }),
        actionButton("Plan restore", "btn btn-sm btn-outline-secondary", { storageBackupAction: "restore", backupId: item.backup_id }),
      ],
    ))
    : [storageRecord("No verified backups", "Create a backup to establish the first measured recovery point.")]));
  renderHealthGrid(document.querySelector("#storage-capacity"), [
    kv("Status", capacity.status),
    kv("Total", capacity.total_bytes == null ? "Unavailable" : formatBytes(capacity.total_bytes)),
    kv("Used", capacity.used_bytes == null ? "Unavailable" : formatBytes(capacity.used_bytes)),
    kv("Free", capacity.free_bytes == null ? "Unavailable" : formatBytes(capacity.free_bytes)),
    kv("Used", capacity.used_percent == null ? "Unavailable" : `${capacity.used_percent}%`),
  ]);
  document.querySelector("#storage-alerts")?.replaceChildren(...((data.alerts || []).length
    ? data.alerts.map((item) => storageRecord(`${item.level} · ${item.title}`, item.message))
    : [storageRecord("No active storage alerts", "No persisted storage alerts require attention.")]));
  document.querySelector("#storage-restores")?.replaceChildren(...((data.recent_restores || []).length
    ? data.recent_restores.map((item) => storageRecord(item.backup_id, `${item.status} · created ${formatDate(item.created_at)} · no automatic restore executed`))
    : [storageRecord("No restore history", "No restore plans have been created.")]));
  renderHealthGrid(document.querySelector("#storage-integrity"), [
    kv("Status", integrity.status),
    kv("Records checked", integrity.records_checked ?? "Not checked"),
    kv("Failures", integrity.failures?.length ?? "Not checked"),
    kv("Last verified", integrity.verified_at ? formatDate(integrity.verified_at) : "Never"),
  ]);
  document.querySelector("#storage-encryption")?.replaceChildren(
    storageRecord("Encryption at rest", `${data.encryption?.at_rest?.status || "unavailable"} · ${data.encryption?.at_rest?.detail || ""}`),
    storageRecord("Encryption in transit", `${data.encryption?.in_transit?.status || "unavailable"} · ${data.encryption?.in_transit?.detail || ""}`),
  );
  document.querySelector("#storage-holds")?.replaceChildren(...((data.legal_holds || []).length
    ? data.legal_holds.map((item) => storageRecord(`${item.case_number} · ${item.active ? "active" : "released"}`, item.reason || "No reason recorded."))
    : [storageRecord("No legal holds", "No investigation retention holds are recorded.")]));
  const evidenceRetention = document.querySelector("#storage-evidence-retention");
  if (evidenceRetention) evidenceRetention.value = policy.evidence_retention_days ?? "";
  const backupRetention = document.querySelector("#storage-backup-retention");
  if (backupRetention) backupRetention.value = policy.backup_retention_days ?? 30;
  const schedule = document.querySelector("#storage-backup-schedule");
  if (schedule) schedule.value = policy.backup_schedule || "manual";
  const scheduleEnabled = document.querySelector("#storage-schedule-enabled");
  if (scheduleEnabled) scheduleEnabled.checked = Boolean(policy.backup_schedule_enabled);
  const schedulerState = document.querySelector("#storage-scheduler-state");
  if (schedulerState) schedulerState.textContent = `${policy.scheduler_status || "unavailable"} · ${policy.scheduler_detail || ""}`;
}

async function initialiseSettingsPages() {
  if (!document.querySelector("[data-module='settings']")) return;
  const activate = (id) => {
    document.querySelectorAll("[data-settings-page]").forEach((link) => link.classList.toggle("active", link.dataset.settingsPage === id));
    document.querySelectorAll(".settings-page").forEach((page) => page.classList.toggle("active", page.id === id));
  };
  document.querySelectorAll("[data-settings-page]").forEach((link) => link.addEventListener("click", (event) => {
    event.preventDefault();
    activate(link.dataset.settingsPage);
    history.replaceState(null, "", `#${link.dataset.settingsPage}`);
  }));
  window.addEventListener("hashchange", () => activate(location.hash.slice(1) || "appearance"));
  if (location.hash) activate(location.hash.slice(1));
  const refreshStorage = async () => renderStorageWorkspace(await api("/api/v1/admin/storage"));
  document.querySelector("#storage-refresh")?.addEventListener("click", async () => {
    try { await refreshStorage(); } catch (error) { showToast(error.message, "danger"); }
  });
  document.querySelector("#storage-create-backup")?.addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await api("/api/v1/admin/storage/backups", { method: "POST", body: "{}" });
      showToast("Verified backup created.", "success");
      await refreshStorage();
    } catch (error) {
      showToast(error.message, "danger");
    } finally {
      button.disabled = false;
    }
  });
  document.querySelector("#storage-verify-integrity")?.addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await api("/api/v1/admin/storage/integrity/verify", { method: "POST", body: "{}" });
      showToast("Evidence custody verification completed.", "success");
      await refreshStorage();
    } catch (error) {
      showToast(error.message, "danger");
      await refreshStorage();
    } finally {
      button.disabled = false;
    }
  });
  document.querySelector("#storage-backups")?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-storage-backup-action]");
    if (!button) return;
    try {
      if (button.dataset.storageBackupAction === "verify") {
        await api(`/api/v1/admin/storage/backups/${button.dataset.backupId}/verify`, { method: "POST", body: "{}" });
        showToast("Backup verification passed.", "success");
      } else {
        await api("/api/v1/admin/storage/restore-plans", {
          method: "POST",
          body: JSON.stringify({ backup_id: button.dataset.backupId }),
        });
        showToast("Verified offline restore plan created.", "success");
      }
      await refreshStorage();
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  document.querySelector("#storage-policy-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api("/api/v1/admin/storage/policy", {
        method: "PATCH",
        body: JSON.stringify({
          evidence_retention_days: document.querySelector("#storage-evidence-retention").value || null,
          backup_retention_days: Number(document.querySelector("#storage-backup-retention").value),
          backup_schedule: document.querySelector("#storage-backup-schedule").value,
          backup_schedule_enabled: document.querySelector("#storage-schedule-enabled").checked,
        }),
      });
      showToast("Storage policy saved.", "success");
      await refreshStorage();
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  const saveHold = async (active) => {
    const caseId = document.querySelector("#storage-hold-case").value.trim();
    const reason = document.querySelector("#storage-hold-reason").value.trim();
    await api(`/api/v1/admin/storage/legal-holds/${encodeURIComponent(caseId)}`, {
      method: "PATCH",
      body: JSON.stringify({ active, reason }),
    });
    showToast(`Legal hold ${active ? "applied" : "released"}.`, "success");
    await refreshStorage();
  };
  document.querySelector("#storage-hold-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try { await saveHold(true); } catch (error) { showToast(error.message, "danger"); }
  });
  document.querySelector("#storage-release-hold")?.addEventListener("click", async () => {
    try { await saveHold(false); } catch (error) { showToast(error.message, "danger"); }
  });
  try {
    const [settings, admin, notifications, plugins, storage] = await Promise.all([
      api("/api/v1/settings"),
      api("/api/v1/admin/overview"),
      api("/api/v1/notifications"),
      api("/api/v1/plugins"),
      api("/api/v1/admin/storage"),
    ]);
    const aiStatus = admin.ai_status || admin.openai_status || {};
    renderHealthGrid(document.querySelector("#settings-security"), [kv("Security headers", settings.config.security_headers_enabled), kv("Max content length", settings.config.max_content_length), kv("Session", "environment managed")]);
    renderHealthGrid(document.querySelector("#settings-ai"), [kv("Provider", settings.config.ai_provider), kv("Enabled", settings.config.ai_enabled), kv("AI provider", aiStatus.available ? "available" : "fallback")]);
    renderHealthGrid(document.querySelector("#settings-notifications"), [kv("Unread", notifications.unread_count), kv("State", "backend synchronized")]);
    renderHealthGrid(document.querySelector("#settings-plugins"), [kv("Enabled", plugins.enabled), kv("Registered", plugins.count)]);
    renderAdminList(document.querySelector("#settings-users"), admin.users.map((user) => ({ title: user.username, message: `${user.role} - ${user.status}` })));
    renderAdminList(document.querySelector("#settings-roles"), Object.entries(admin.permissions).map(([role, perms]) => ({ title: role, message: perms.join(", ") })));
    renderStorageWorkspace(storage);
    renderHealthGrid(document.querySelector("#settings-logs"), [kv("Files", admin.logs.length), kv("Audit records", admin.audit_logs.length)]);
    renderHealthGrid(document.querySelector("#settings-api-keys"), [kv("Provider credentials", aiStatus.configured ? "configured" : "missing"), kv("Values exposed", false)]);
    renderAdminList(document.querySelector("#settings-integrations"), [{ title: "AI Provider", message: aiStatus.message }, { title: "Plugins", message: `${plugins.count} registered` }]);
  } catch (error) {
    showToast(error.message, "danger");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initialiseDashboardCards();
  initialiseCases();
  initialiseEvidence();
  initialiseTimeline();
  initialiseReports();
  initialisePluginRegistry();
  initialiseAdminOperations();
  initialiseSettingsPages();
  initialiseProfilePages();
});
