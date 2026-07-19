"use strict";

const pageState = { cases: 1 };

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
  const setText = (selector, value) => {
    document.querySelectorAll(selector).forEach((node) => { node.textContent = value; });
  };
  const setNote = (name, value) => {
    const node = document.querySelector(`[data-metric-note='${name}']`);
    if (node) node.textContent = value;
  };
  const clearSkeletons = () => document.querySelectorAll(".skeleton").forEach((node) => node.classList.remove("skeleton"));
  document.querySelectorAll("[data-metric]").forEach((node) => { node.textContent = "-"; });
  api("/api/v1/dashboard")
    .then((data) => {
      clearSkeletons();
      setText("[data-metric='threat-score']", data.threat_score === null ? "-" : String(data.threat_score));
      setText("[data-metric='progress']", data.progress === null ? "-" : `${data.progress}%`);
      setText("[data-metric='cases-count']", String(data.cases_count));
      setText("[data-metric='evidence-count']", String(data.evidence_count));
      setText("[data-metric='timeline-count']", String(data.timeline_count));
      setText("[data-metric='reports-count']", String(data.reports_count || 0));
      setText("[data-metric='plugin-status']", data.plugin_status === "enabled" ? "Enabled" : "Disabled");
      setText("[data-metric='ai-status']", data.provider?.available ? "Available" : "Offline mode");
      setNote("cases", `${data.active_cases_count || 0} active`);
      setNote("evidence", data.selected_case ? `Latest case ${data.selected_case.case_number}` : "No active case");
      setNote("timeline", `${data.timeline_count} events in focus`);
      setNote("plugins", `${data.plugin_health.configured} discovered, ${data.plugin_health.failures} failures`);
      setNote("reports", `${data.reports_count || 0} generated`);
      setNote("ai", "Ready for investigation support");
      setNote("threat", data.threat_score === null ? "No timeline signal" : "Derived from activity");
      renderThreatChart(document.querySelector("[data-chart='threat']"), data.threat_graph || []);
      renderCaseGraph(document.querySelector("[data-chart='cases']"), data.case_graph || []);
      renderActivity(document.querySelector("[data-list='recent-activity']"), data.recent_activity || []);
      renderEvidenceSummary(document.querySelector("[data-list='recent-evidence']"), data.recent_evidence || []);
      renderTimelinePreview(document.querySelector("[data-list='timeline-preview']"), data.timeline_preview || []);
      renderReportsSummary(document.querySelector("[data-list='latest-reports']"), data.latest_reports || []);
      renderInsights(document.querySelector("[data-list='ai-insights']"), data.ai_insights || []);
      renderQuickActions(document.querySelector("[data-list='quick-actions']"), data.quick_actions || []);
      renderNotificationsSummary(document.querySelector("[data-list='recent-notifications']"), data.recent_notifications || []);
      renderKeyValueGrid(document.querySelector("[data-plugin-health]"), [
        { label: "Registry", value: data.plugin_health.status },
        { label: "Configured", value: data.plugin_health.configured },
        { label: "Enabled", value: data.plugin_health.enabled },
        { label: "Executions", value: data.plugin_health.executions },
        { label: "Failures", value: data.plugin_health.failures },
      ]);
      renderProgress(data.progress || 0, data.investigation_progress || {});
    })
    .catch((error) => {
      clearSkeletons();
      document.querySelectorAll("[data-metric]").forEach((node) => { node.textContent = "-"; });
      document.querySelectorAll("[data-list], [data-chart], [data-plugin-health]").forEach((node) => {
        node.replaceChildren(emptyInline("bi-exclamation-triangle", "Dashboard unavailable", error.message));
      });
      showToast(error.message, "danger");
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
      el("td", { text: String((item.attachments || []).length) }),
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
        const data = await fetchCases({ q: "", per_page: 100 });
        const selected = data.items.find((item) => item.id === detailButton.dataset.caseDetails);
        if (selected) renderCaseDetail(selected);
      } catch (error) {
        showToast(error.message, "danger");
      }
      return;
    }
    const editButton = event.target.closest("[data-case-edit]");
    if (editButton) {
      try {
        const data = await fetchCases({ q: "", per_page: 100 });
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
  load();
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

function renderCaseDetail(item) {
  const target = document.querySelector("#case-detail");
  const status = document.querySelector("#case-detail-status");
  if (status) status.textContent = item.status;
  target.replaceChildren(
    el("div", { className: "case-detail-grid" }, [
      el("section", {}, [el("h4", { text: "Notes" }), ...(item.notes || []).map((note) => el("p", { text: note }))]),
      el("section", {}, [el("h4", { text: "Relationships" }), ...(item.relationships || []).map((rel) => el("p", { text: rel }))]),
      el("section", {}, [el("h4", { text: "Attachments" }), ...((item.attachments || []).map((ev) => el("p", { text: `${ev.evidence_number} - ${ev.original_filename}` })))]),
      el("section", {}, [el("h4", { text: "History" }), ...((item.history || []).map((event) => el("p", { text: `${event.event_type}: ${event.summary}` })))]),
    ]),
  );
}

function renderEvidence(table, items) {
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
  caseOptions([document.querySelector("#evidence-case"), document.querySelector("#evidence-case-filter")], true).then(load);
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
    const analyzeButton = event.target.closest("[data-evidence-analyze]");
    if (analyzeButton) {
      try {
        document.querySelector("#evidence-report-status").textContent = "Analyzing";
        document.querySelector("#evidence-report").replaceChildren(emptyInline("bi-hourglass-split", "Analyzing evidence", "Inspecting bytes, encodings, archives, metadata, strings, and flags."));
        const payload = await api(`/api/v1/evidence/${analyzeButton.dataset.evidenceAnalyze}/analysis`);
        renderForensicReport(payload);
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
  document.querySelector("#evidence-search").addEventListener("input", debounce(load));
  document.querySelector("#evidence-analysis-filter").addEventListener("change", load);
  document.querySelector("#evidence-sort").addEventListener("change", load);
}

function renderForensicReport(payload) {
  const target = document.querySelector("#evidence-report");
  const status = document.querySelector("#evidence-report-status");
  const report = payload.report || {};
  const root = report.root || {};
  const findings = report.findings || [];
  if (status) status.textContent = "Completed";
  target.replaceChildren(
    el("div", { className: "forensic-report" }, [
      el("strong", { text: payload.summary || "Analysis complete" }),
      el("div", { className: "health-grid mt-3" }, [
        el("div", { className: "health-item" }, [el("small", { text: "Signature" }), el("strong", { text: root.file_signature || "Unknown" })]),
        el("div", { className: "health-item" }, [el("small", { text: "Entropy" }), el("strong", { text: String(root.entropy ?? "-") })]),
        el("div", { className: "health-item" }, [el("small", { text: "Encoding" }), el("strong", { text: root.encoding?.encoding || "Unknown" })]),
        el("div", { className: "health-item" }, [el("small", { text: "Children" }), el("strong", { text: String((root.children || []).length) })]),
      ]),
      el("h4", { text: "Findings" }),
      findings.length ? el("div", { className: "compact-list" }, findings.slice(0, 12).map((finding) => el("div", { className: "compact-item" }, [
        el("i", { className: "bi bi-search" }),
        el("div", {}, [el("strong", { text: finding.type }), el("small", { text: `${finding.path}: ${finding.detail}` })]),
      ]))) : emptyInline("bi-check-circle", "No strong indicators", "No hidden-content or flag indicators were detected."),
      el("h4", { text: "Explanation" }),
      el("div", { className: "compact-list" }, (report.explanation || []).map((line) => el("p", { text: line }))),
    ]),
  );
}

function renderTimeline(list, items) {
  list.replaceChildren(...items.map((item) => {
    const body = el("div", {}, [
      el("strong", { text: item.summary }),
      el("p", { text: `${item.event_type} - ${item.case_number || "No case"}${item.evidence_number ? ` - ${item.evidence_number}` : ""}` }),
    ]);
    if (item.details) body.append(el("small", { text: item.details }));
    return el("article", { className: `timeline-event group-${item.group} threat-${item.threat_level}` }, [el("time", { text: formatDate(item.occurred_at) }), body]);
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
      renderTimelineCorrelations(data.correlations || {});
      if (!data.items.length) {
        setState(state, "bi-clock-history", "No timeline events", "Add evidence, create cases, or record observations.");
        return;
      }
      hide(state);
      list.classList.remove("d-none");
      list.dataset.zoom = document.querySelector("#timeline-zoom").value;
      renderTimeline(list, data.items);
    } catch (error) {
      setState(state, "bi-exclamation-triangle", "Timeline unavailable", error.message, "danger");
    }
  };
  caseOptions([document.querySelector("#timeline-case"), document.querySelector("#timeline-case-filter")], true).then(load);
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
  document.querySelector("#timeline-export").addEventListener("click", (event) => {
    event.currentTarget.href = `/api/v1/timeline/export${query({ case_id: document.querySelector("#timeline-case-filter").value, event_type: document.querySelector("#timeline-type-filter").value, group: document.querySelector("#timeline-group-filter").value, threat: document.querySelector("#timeline-threat-filter").value, q: document.querySelector("#timeline-search").value })}`;
  });
  document.querySelector("#timeline-ai-summary").addEventListener("click", async () => {
    const panel = document.querySelector("#timeline-summary-panel");
    document.querySelector("#timeline-summary-status").textContent = "Generating";
    panel.replaceChildren(emptyInline("bi-hourglass-split", "Generating summary", "Correlating case, evidence, timeline, and threat signals."));
    try {
      const payload = await api("/api/v1/timeline/ai-summary", { method: "POST", body: JSON.stringify({ case_id: document.querySelector("#timeline-case-filter").value }) });
      document.querySelector("#timeline-summary-status").textContent = payload.available ? "AI" : "Fallback";
      panel.replaceChildren(el("div", { className: "insight-list" }, [el("div", { className: "insight-item" }, [el("i", { className: "bi bi-stars" }), el("div", {}, [el("strong", { text: "Timeline summary" }), el("small", { text: payload.content || payload.message || "Summary unavailable." })])])]));
    } catch (error) {
      document.querySelector("#timeline-summary-status").textContent = "Error";
      panel.replaceChildren(emptyInline("bi-exclamation-triangle", "Summary unavailable", error.message));
    }
  });
}

function renderTimelineCorrelations(data) {
  const target = document.querySelector("#timeline-correlations");
  if (!target) return;
  target.replaceChildren(
    el("span", { className: "badge-soft", text: `Threat ${data.threat_score || 0}/100` }),
    el("span", { className: "badge-soft success", text: `${(data.cases || []).length} cases` }),
    el("span", { className: "badge-soft", text: `${(data.evidence || []).length} evidence links` }),
    ...Object.entries(data.groups || {}).map(([name, count]) => el("span", { className: "badge-soft", text: `${name}: ${count}` })),
  );
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
  caseOptions([document.querySelector("#report-case"), document.querySelector("#report-case-filter")], true).then(load);
  document.querySelector("#report-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api("/api/v1/reports", {
        method: "POST",
        body: JSON.stringify({
          case_id: document.querySelector("#report-case").value,
          title: document.querySelector("#report-title").value,
          report_type: document.querySelector("#report-type").value,
        }),
      });
      bootstrap.Modal.getInstance(document.querySelector("#report-modal"))?.hide();
      event.target.reset();
      showToast("Report generated.", "success");
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
        renderReportPreview(payload.content);
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

function renderReportPreview(content) {
  const target = document.querySelector("#report-preview");
  document.querySelector("#report-preview-status").textContent = content?.report?.report_type || "Generated";
  const sections = ["executive_summary", "evidence", "timeline", "threat_score", "iocs", "mitre_attack", "ai_explanation", "recommendations", "appendix", "charts"];
  target.replaceChildren(el("div", { className: "forensic-report" }, [
    el("strong", { text: content?.title || "Report preview" }),
    ...sections.map((section) => el("div", { className: "compact-item" }, [
      el("i", { className: "bi bi-check2-circle" }),
      el("div", {}, [el("strong", { text: section.replaceAll("_", " ") }), el("small", { text: summarizeSection(content?.[section]) })]),
    ])),
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
    return el("div", { className: "plugin-card" }, [
      el("div", {}, [
        el("strong", { text: plugin.name }),
        el("div", { className: "text-muted", text: plugin.description || "No description available." }),
        el("div", { className: "mt-2" }, badges),
      ]),
      el("div", { className: "text-end" }, [
        el("div", { className: "text-muted", text: plugin.id }),
        el("div", { className: "mt-1 mb-2" }, [
          el("span", { className: "badge text-bg-light", text: plugin.supported_artifact_types.join(", ") || "No artifact types" }),
        ]),
        el("div", { className: "plugin-actions" }, [
          actionButton("Validate", "btn btn-sm btn-outline-secondary", { pluginAction: "validate", id: plugin.id }),
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
      const data = reload ? await api("/api/v1/plugins/reload", { method: "POST" }) : await api("/api/v1/plugins");
      count.textContent = `${data.count} registered`;
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
    const button = event.target.closest("[data-plugin-action]");
    if (!button) return;
    try {
      const data = await api(`/api/v1/plugins/${button.dataset.id}/${button.dataset.pluginAction}`, { method: "POST" });
      count.textContent = `${data.count} registered`;
      renderPlugins(target, data.plugins || []);
      showToast(`Plugin ${button.dataset.pluginAction} complete.`, "success");
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  document.querySelector("#plugin-validate-all")?.addEventListener("click", () => load(true));
  load();
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
      const data = await api("/api/v1/admin/overview");
      const aiStatus = data.ai_status || data.openai_status || {};
      renderHealthGrid(document.querySelector("#admin-health"), [kv("Risk", data.security.risk_level), kv("Threat score", data.security.threat_score), kv("Failed logins", data.security.authentication.failed_logins), kv("Alerts", data.security.recent_alerts?.length || 0)]);
      renderHealthGrid(document.querySelector("#admin-database"), [kv("Dialect", data.database.dialect), ...Object.entries(data.database.tables).map(([name, value]) => kv(name, value))]);
      renderHealthGrid(document.querySelector("#admin-metrics"), [kv("Readiness", data.health.status), kv("Database", data.health.database), kv("Plugins", data.health.plugins), kv("Rate limit", data.metrics.rate_limit_requests)]);
      renderHealthGrid(document.querySelector("#admin-today"), [kv("Cases", data.metrics.cases), kv("Evidence", data.metrics.evidence), kv("Timeline events", data.metrics.timeline_events), kv("Reports", data.metrics.reports)]);
      renderHealthGrid(document.querySelector("#admin-ai-activity"), [kv("Provider", aiStatus.provider), kv("Status", aiStatus.available ? "available" : "fallback"), kv("Configured", aiStatus.configured ? "yes" : "no"), kv("Model", aiStatus.model)]);
      renderAdminList(document.querySelector("#admin-recent-reports"), data.audit_logs.filter((item) => String(item.event || "").includes("report")).slice(0, 6));
      renderHealthGrid(document.querySelector("#admin-threat-trend"), [kv("Risk level", data.security.risk_level), kv("Confidence", data.security.confidence), kv("Priority", data.security.priority), kv("AI status", aiStatus.available ? "available" : "fallback")]);
      renderAdminList(document.querySelector("#admin-users"), [
        ...data.users.map((user) => ({
          title: `${user.username} (${user.role})`,
          message: `${user.status} - last login ${formatDate(user.last_login_at)}`,
        })),
      ]);
      renderAdminList(
        document.querySelector("#admin-roles"),
        Object.entries(data.permissions).map(([role, perms]) => ({
          title: `${role} permissions`,
          message: perms.join(", "),
        })),
      );
      renderHealthGrid(document.querySelector("#admin-security"), [
        kv("Risk level", data.security.risk_level),
        kv("Threat score", data.security.threat_score),
        kv("Failed logins", data.security.authentication.failed_logins),
        kv("Locked accounts", data.security.authentication.locked_accounts),
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
  document.querySelector("#admin-load-log")?.addEventListener("click", async () => {
    try {
      const data = await api("/api/v1/admin/logs");
      renderAdminList(document.querySelector("#admin-logs"), data.lines.map((line) => ({ title: data.name, message: line })));
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  load();
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
  }));
  if (location.hash) activate(location.hash.slice(1));
  try {
    const [settings, admin, notifications, plugins] = await Promise.all([
      api("/api/v1/settings"),
      api("/api/v1/admin/overview"),
      api("/api/v1/notifications"),
      api("/api/v1/plugins"),
    ]);
    const aiStatus = admin.ai_status || admin.openai_status || {};
    renderHealthGrid(document.querySelector("#settings-security"), [kv("Security headers", settings.config.security_headers_enabled), kv("Max content length", settings.config.max_content_length), kv("Session", "environment managed")]);
    renderHealthGrid(document.querySelector("#settings-ai"), [kv("Provider", settings.config.ai_provider), kv("Enabled", settings.config.ai_enabled), kv("AI provider", aiStatus.available ? "available" : "fallback")]);
    renderHealthGrid(document.querySelector("#settings-notifications"), [kv("Unread", notifications.unread_count), kv("State", "backend synchronized")]);
    renderHealthGrid(document.querySelector("#settings-plugins"), [kv("Enabled", plugins.enabled), kv("Registered", plugins.count)]);
    renderAdminList(document.querySelector("#settings-users"), admin.users.map((user) => ({ title: user.username, message: `${user.role} - ${user.status}` })));
    renderAdminList(document.querySelector("#settings-roles"), Object.entries(admin.permissions).map(([role, perms]) => ({ title: role, message: perms.join(", ") })));
      renderHealthGrid(document.querySelector("#settings-storage"), [kv("Database", admin.database.dialect), kv("Cases", admin.metrics.cases), kv("Evidence", admin.metrics.evidence)]);
    renderHealthGrid(document.querySelector("#settings-logs"), [kv("Files", admin.logs.length), kv("Audit records", admin.audit_logs.length)]);
    renderAdminList(document.querySelector("#settings-backups"), [{ title: "Manual backup", message: "Use scripts/backup.ps1 for local backup operations." }, { title: "Recovery", message: "Use scripts/recover.ps1 for restore workflows." }]);
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
