"use strict";

function showToast(message, variant = "info") {
  let container = document.querySelector(".toast-container");
  if (!container) {
    container = document.createElement("div");
    container.className = "toast-container position-fixed bottom-0 end-0 p-3";
    container.setAttribute("aria-live", "polite");
    document.body.append(container);
  }
  const toast = document.createElement("div");
  toast.className = `toast align-items-center border-0 text-bg-${variant}`;
  toast.setAttribute("role", "status");
  const shell = document.createElement("div");
  shell.className = "d-flex";
  const body = document.createElement("div");
  body.className = "toast-body";
  body.textContent = message;
  const close = document.createElement("button");
  close.className = "btn-close btn-close-white me-2 m-auto";
  close.type = "button";
  close.setAttribute("data-bs-dismiss", "toast");
  close.setAttribute("aria-label", "Close");
  shell.append(body, close);
  toast.append(shell);
  container.append(toast);
  const instance = new bootstrap.Toast(toast, { delay: 5000 });
  toast.addEventListener("hidden.bs.toast", () => toast.remove());
  instance.show();
}

async function api(path, options = {}) {
  const csrfToken = document.querySelector("meta[name='csrf-token']")?.content;
  const headers = { Accept: "application/json", ...(options.body instanceof FormData ? {} : { "Content-Type": "application/json" }) };
  if (csrfToken && !["GET", "HEAD", "OPTIONS"].includes((options.method || "GET").toUpperCase())) headers["X-CSRF-Token"] = csrfToken;
  const response = await fetch(path, {
    headers,
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
  return payload;
}

function initialiseEnterpriseUi() {
  const sidebarToggle = document.querySelector("#sidebar-collapse-toggle");
  if (sidebarToggle) {
    const collapsed = localStorage.getItem("cyberinvestigator.sidebar") === "collapsed";
    document.body.classList.toggle("sidebar-collapsed", collapsed);
    sidebarToggle.setAttribute("aria-expanded", String(!collapsed));
    sidebarToggle.addEventListener("click", () => {
      const isCollapsed = document.body.classList.toggle("sidebar-collapsed");
      localStorage.setItem("cyberinvestigator.sidebar", isCollapsed ? "collapsed" : "expanded");
      sidebarToggle.setAttribute("aria-expanded", String(!isCollapsed));
      sidebarToggle.setAttribute("aria-label", isCollapsed ? "Expand navigation" : "Collapse navigation");
    });
  }
  document.querySelectorAll("[title], [data-bs-toggle='tooltip']").forEach((node) => {
    if (!node.getAttribute("data-bs-toggle")) node.setAttribute("data-bs-toggle", "tooltip");
    if (!node.getAttribute("data-bs-placement")) node.setAttribute("data-bs-placement", "bottom");
  });
  if (window.bootstrap?.Tooltip) {
    document.querySelectorAll("[data-bs-toggle='tooltip']").forEach((node) => {
      bootstrap.Tooltip.getOrCreateInstance(node, { trigger: "hover focus" });
    });
  }
  document.querySelectorAll("form").forEach((form) => {
    form.addEventListener("submit", () => {
      form.setAttribute("aria-busy", "true");
      window.setTimeout(() => form.removeAttribute("aria-busy"), 2400);
    });
  });
  refreshResponsiveTableLabels();
  initialiseTableContextMenus();
}

function initialiseTableContextMenus() {
  const menu = document.createElement("div");
  menu.className = "soc-context-menu d-none";
  menu.setAttribute("role", "menu");
  document.body.append(menu);
  const close = () => menu.classList.add("d-none");
  document.addEventListener("click", close);
  document.addEventListener("scroll", close, true);
  document.addEventListener("contextmenu", (event) => {
    const row = event.target.closest(".professional-table tbody tr");
    if (!row || !row.children.length) return;
    event.preventDefault();
    const label = row.children[0]?.innerText?.trim() || "Selected row";
    const actions = [...row.querySelectorAll("button, a")].filter((item) => !item.disabled);
    const heading = document.createElement("div");
    heading.className = "soc-context-heading";
    heading.textContent = label;
    const copy = document.createElement("button");
    copy.type = "button"; copy.className = "soc-context-action";
    copy.innerHTML = "<i class='bi bi-copy'></i><span>Copy row details</span>";
    copy.addEventListener("click", async () => { await navigator.clipboard.writeText(row.innerText.trim()); showToast("Row details copied.", "success"); });
    const available = actions.slice(0, 4).map((source) => {
      const action = document.createElement("button");
      action.type = "button"; action.className = "soc-context-action";
      action.innerHTML = `<i class="bi bi-lightning-charge"></i><span>${source.textContent.trim() || source.title || "Open"}</span>`;
      action.addEventListener("click", () => source.click());
      return action;
    });
    menu.replaceChildren(heading, copy, ...available);
    menu.style.left = `${Math.min(event.clientX, window.innerWidth - 230)}px`;
    menu.style.top = `${Math.min(event.clientY, window.innerHeight - 220)}px`;
    menu.classList.remove("d-none");
  });
}

function refreshResponsiveTableLabels(root = document) {
  root.querySelectorAll(".table").forEach((table) => {
    const labels = [...table.querySelectorAll("thead th")].map((cell) => cell.textContent.trim());
    table.querySelectorAll("tbody tr").forEach((row) => {
      [...row.children].forEach((cell, index) => {
        if (labels[index] && !cell.dataset.label) cell.dataset.label = labels[index];
      });
    });
  });
}

function debounce(fn, delay = 250) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

function applyTheme(theme) {
  const normalizedTheme = theme === "dark" ? "dark" : "light";
  document.documentElement.dataset.theme = normalizedTheme;
  document.documentElement.dataset.bsTheme = normalizedTheme;
  localStorage.setItem("cyberinvestigator.theme", normalizedTheme);
  const topToggleIcon = document.querySelector("#theme-toggle-top i");
  if (topToggleIcon) topToggleIcon.className = normalizedTheme === "dark" ? "bi bi-sun" : "bi bi-moon-stars";
  document.querySelectorAll("#theme-toggle").forEach((toggle) => {
    toggle.checked = normalizedTheme === "dark";
  });
}

async function initialiseNotifications() {
  const dot = document.querySelector("#notification-dot");
  const count = document.querySelector("#notification-count");
  const items = document.querySelector("#notification-items");
  const markRead = document.querySelector("#mark-notifications-read");
  const search = document.querySelector("#notification-search");
  const filter = document.querySelector("#notification-filter");
  if (!dot || !count || !items || !markRead) return;
  let notificationState = { unread_count: 0, items: [] };

  const render = (state) => {
    notificationState = state;
    const term = (search?.value || "").trim().toLowerCase();
    const severity = filter?.value || "all";
    const visibleItems = (state.items || []).filter((item) => {
      const matchesSearch = !term || `${item.title} ${item.message} ${item.category}`.toLowerCase().includes(term);
      const itemSeverity = item.priority || "info";
      const matchesSeverity = severity === "all" || itemSeverity === severity;
      return matchesSearch && matchesSeverity;
    });
    dot.classList.toggle("d-none", state.unread_count === 0);
    document.querySelectorAll(".nav-attention-dot").forEach((node) => node.classList.toggle("d-none", state.unread_count === 0));
    count.textContent = state.unread_count ? `${state.unread_count} unread` : "All caught up";
    if (!visibleItems.length) {
      const empty = document.createElement("div");
      empty.className = "notification-empty";
      empty.innerHTML = "<i class='bi bi-bell'></i><strong>No notifications</strong><span>Nothing matches the current view.</span>";
      items.replaceChildren(empty);
      return;
    }
    items.replaceChildren(...groupNotifications(visibleItems).flatMap((group) => {
      const heading = document.createElement("div");
      heading.className = "notification-group-heading";
      heading.textContent = group.label;
      return [heading, ...group.items.map((item) => {
      const row = document.createElement("div");
      row.className = `notification-item priority-${item.priority || "info"} ${item.read ? "" : "unread"}`;
      const icon = document.createElement("i");
      icon.className = notificationIcon(item.category);
      const body = document.createElement("div");
      body.className = "notification-body";
      const title = document.createElement("strong");
      title.textContent = item.title;
      const message = document.createElement("span");
      message.textContent = item.message;
      const meta = document.createElement("small");
      meta.textContent = `${item.category || "workspace"} - ${item.priority || "info"}`;
      const archive = document.createElement("button");
      archive.type = "button";
      archive.className = "btn btn-sm btn-link notification-archive";
      archive.setAttribute("aria-label", `Archive ${item.title}`);
      archive.innerHTML = "<i class='bi bi-archive'></i>";
      archive.addEventListener("click", async (event) => {
        event.preventDefault();
        event.stopPropagation();
        try {
          render(await api(`/api/v1/notifications/${item.id}/archive`, { method: "POST" }));
        } catch (error) {
          showToast(error.message, "danger");
        }
      });
      const read = document.createElement("button");
      read.type = "button";
      read.className = "btn btn-sm btn-link notification-read";
      read.setAttribute("aria-label", `Mark ${item.title} read`);
      read.innerHTML = "<i class='bi bi-check2'></i>";
      read.disabled = Boolean(item.read);
      read.addEventListener("click", async (event) => {
        event.preventDefault();
        event.stopPropagation();
        try {
          render(await api(`/api/v1/notifications/${item.id}/read`, { method: "POST" }));
        } catch (error) {
          showToast(error.message, "danger");
        }
      });
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "btn btn-sm btn-link text-danger notification-delete";
      remove.setAttribute("aria-label", `Delete ${item.title}`);
      remove.innerHTML = "<i class='bi bi-trash'></i>";
      remove.addEventListener("click", async (event) => {
        event.preventDefault();
        event.stopPropagation();
        try {
          render(await api(`/api/v1/notifications/${item.id}`, { method: "DELETE" }));
        } catch (error) {
          showToast(error.message, "danger");
        }
      });
      body.append(title, message, meta);
      row.append(icon, body, read, archive, remove);
      return row;
      })];
    }));
  };

  try {
    render(await api("/api/v1/notifications"));
  } catch (error) {
    count.textContent = "Unavailable";
  }

  markRead.addEventListener("click", async () => {
    try {
      render(await api("/api/v1/notifications/read", { method: "POST" }));
      showToast("Notifications marked as read.", "success");
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
  search?.addEventListener("input", () => render(notificationState));
  filter?.addEventListener("change", () => render(notificationState));
}

function groupNotifications(items) {
  const collapsed = [];
  const seen = new Map();
  items.forEach((item) => {
    const key = `${item.title}|${item.category}|${item.priority}`;
    if (seen.has(key)) {
      const existing = seen.get(key);
      existing.repeatCount = (existing.repeatCount || 1) + 1;
      existing.message = `${existing.repeatCount} repeated alerts. Latest: ${item.message}`;
      return;
    }
    const copy = { ...item, repeatCount: 1 };
    seen.set(key, copy);
    collapsed.push(copy);
  });
  const now = new Date();
  const startToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const startYesterday = startToday - 86400000;
  const groups = [
    { label: "Today", items: [] },
    { label: "Yesterday", items: [] },
    { label: "Earlier", items: [] },
  ];
  collapsed.forEach((item) => {
    const ts = item.created_at ? new Date(item.created_at).getTime() : startToday;
    if (ts >= startToday) groups[0].items.push(item);
    else if (ts >= startYesterday) groups[1].items.push(item);
    else groups[2].items.push(item);
  });
  return groups.filter((group) => group.items.length);
}

function notificationIcon(category) {
  const icons = {
    security: "bi bi-shield-exclamation",
    evidence: "bi bi-folder2-open",
    reports: "bi bi-file-earmark-text",
    ai: "bi bi-stars",
    plugins: "bi bi-puzzle",
    database: "bi bi-database",
  };
  return icons[category] || "bi bi-info-circle";
}

async function initialisePreferences() {
  applyTheme(localStorage.getItem("cyberinvestigator.theme") || "dark");
  document.querySelectorAll("#theme-toggle-top, #theme-toggle-profile").forEach((toggle) => toggle.addEventListener("click", () => {
    const nextTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    applyTheme(nextTheme);
    showToast(`Switched to ${nextTheme} mode.`, "success");
  }));
  document.querySelector("#theme-toggle")?.addEventListener("change", (event) => applyTheme(event.target.checked ? "dark" : "light"));

  if (document.querySelector("[data-module='settings']")) {
    try {
      const settings = await api("/api/v1/settings");
      document.querySelector("#ai-settings-state").textContent = settings.config.ai_enabled
        ? `Provider ${settings.config.ai_provider} is enabled.`
        : `Provider ${settings.config.ai_provider} is configured but disabled.`;
      initialiseAiSettingsForm(settings.config);
      await loadAiManagement();
      document.querySelector("#notification-settings-state").textContent = "Notification state is synchronized with the backend.";
    } catch (error) {
      showToast("Unable to load settings.", "danger");
    }
  }

  document.querySelector("#settings-save")?.addEventListener("click", async () => {
    const theme = document.querySelector("#theme-toggle")?.checked ? "dark" : "light";
    try {
      await api("/api/v1/settings", {
        method: "PATCH",
        body: JSON.stringify({ namespace: "workspace", settings: { theme } }),
      });
      applyTheme(theme);
      showToast("Preferences saved.", "success");
    } catch (error) {
      showToast(error.message, "danger");
    }
  });
}

function initialiseAiSettingsForm(config) {
  const form = document.querySelector("#ai-settings-form");
  if (!form) return;
  const provider = document.querySelector("#ai-provider");
  const model = document.querySelector("#ai-model");
  const temperature = document.querySelector("#ai-temperature");
  const temperatureValue = document.querySelector("#ai-temperature-value");
  const maxTokens = document.querySelector("#ai-max-tokens");
  const streaming = document.querySelector("#ai-streaming");
  const endpoint = document.querySelector("#ollama-endpoint");
  const credential = document.querySelector("#ai-provider-credential");
  const test = document.querySelector("#ai-test-connection");
  const result = document.querySelector("#ai-test-result");

  provider.value = config.ai_provider || "ollama";
  model.value = config.ai_model || "qwen3:8b";
  temperature.value = String(config.ai_temperature ?? 0.2);
  temperatureValue.textContent = temperature.value;
  maxTokens.value = String(config.ai_max_tokens || 1200);
  streaming.checked = Boolean(config.ai_streaming);
  endpoint.value = config.ollama_endpoint || "http://localhost:11434";

  temperature.addEventListener("input", () => {
    temperatureValue.textContent = temperature.value;
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api("/api/v1/settings", {
        method: "PATCH",
        body: JSON.stringify({
          namespace: "ai",
          settings: {
            provider: provider.value,
            model: model.value.trim(),
            temperature: Number(temperature.value),
            max_tokens: Number(maxTokens.value),
            streaming: streaming.checked,
            ollama_endpoint: endpoint.value.trim(),
          },
        }),
      });
      const providerUpdate = { model: model.value.trim() };
      if (provider.value === "ollama") providerUpdate.endpoint = endpoint.value.trim();
      if (credential.value) providerUpdate.credential = credential.value;
      await api(`/api/v1/admin/ai/providers/${provider.value}`, {
        method: "PATCH",
        body: JSON.stringify(providerUpdate),
      });
      credential.value = "";
      showToast("AI settings saved.", "success");
      await loadAiManagement();
    } catch (error) {
      showToast(error.message, "danger");
    }
  });

  test?.addEventListener("click", async () => {
    result.textContent = "Testing provider connection...";
    try {
      const status = await api("/api/v1/ai/test-connection", {
        method: "POST",
        body: JSON.stringify({ provider: provider.value }),
      });
      const installed = (status.installed_models || []).length ? ` Installed: ${status.installed_models.join(", ")}` : "";
      result.textContent = `${status.provider} ${status.available ? "available" : "unavailable"} - ${status.message}${installed}`;
      showToast(status.available ? "AI provider is available." : status.message, status.available ? "success" : "warning");
    } catch (error) {
      result.textContent = error.message;
      showToast(error.message, "danger");
    }
  });
}

function aiManagementRecord(title, detail, state = "") {
  const article = document.createElement("article");
  article.className = "ai-admin-record";
  const header = document.createElement("header");
  const strong = document.createElement("strong");
  strong.textContent = title;
  const badge = document.createElement("span");
  badge.className = `ai-admin-state ${state}`;
  badge.textContent = state;
  header.append(strong, badge);
  const small = document.createElement("small");
  small.textContent = detail;
  article.append(header, small);
  return article;
}

function aiProviderCard(provider, selectedProvider) {
  const state = provider.enabled && provider.available ? "available" : "unavailable";
  const card = aiManagementRecord(
    provider.provider,
    `${provider.model || "No model selected"} · ${provider.message} · ${provider.requests_recorded || 0} recorded request(s)`,
    state,
  );
  const controls = document.createElement("div");
  controls.className = "d-flex gap-2 mt-2 flex-wrap";
  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "btn btn-sm btn-outline-secondary";
  toggle.textContent = provider.enabled ? "Disable" : "Enable";
  toggle.addEventListener("click", async () => {
    await api(`/api/v1/admin/ai/providers/${provider.provider}`, { method: "PATCH", body: JSON.stringify({ enabled: !provider.enabled }) });
    await loadAiManagement();
  });
  const test = document.createElement("button");
  test.type = "button";
  test.className = "btn btn-sm btn-outline-secondary";
  test.textContent = "Test";
  test.addEventListener("click", async () => {
    const result = await api("/api/v1/ai/test-connection", { method: "POST", body: JSON.stringify({ provider: provider.provider }) });
    showToast(result.message, result.available ? "success" : "warning");
    await loadAiManagement();
  });
  const makeDefault = document.createElement("button");
  makeDefault.type = "button";
  makeDefault.className = "btn btn-sm btn-outline-primary";
  makeDefault.textContent = provider.provider === selectedProvider ? "Default" : "Make default";
  makeDefault.disabled = !provider.enabled || provider.provider === selectedProvider;
  makeDefault.addEventListener("click", async () => {
    await api("/api/v1/settings", { method: "PATCH", body: JSON.stringify({ namespace: "ai", settings: { provider: provider.provider, model: provider.model } }) });
    await loadAiManagement();
  });
  controls.append(toggle, test, makeDefault);
  card.append(controls);
  return card;
}

function renderAiManagementList(target, records, emptyMessage) {
  if (!target) return;
  if (!records.length) {
    const empty = document.createElement("div");
    empty.className = "operations-empty";
    empty.textContent = emptyMessage;
    target.replaceChildren(empty);
    return;
  }
  target.replaceChildren(...records);
}

async function loadAiManagement() {
  if (!document.querySelector("#ai-management-providers")) return;
  const data = await api("/api/v1/admin/ai/management");
  window.cyberInvestigatorAiManagement = data;
  renderAiManagementList(
    document.querySelector("#ai-management-providers"),
    data.providers.map((provider) => aiProviderCard(provider, data.selected_provider) /* provider card */ || aiManagementRecord(
      provider.provider,
      `${provider.model || "No model selected"} · ${provider.message} · credential ${provider.credential_configured ? "configured" : "not configured"}`,
      provider.available ? "available" : "unavailable",
    )),
    "No provider adapters are registered.",
  );
  renderAiManagementList(
    document.querySelector("#ai-management-workloads"),
    Object.entries(data.workloads).map(([workload, assignment]) => aiManagementRecord(
      workload,
      `${assignment.provider} · ${assignment.model}`,
      "",
    )),
    "No workload assignments are configured.",
  );
  const health = document.querySelector("#ai-management-health");
  if (health) {
    health.replaceChildren(
      ...data.providers.map((provider) => aiManagementRecord(
        provider.provider,
        provider.available ? "Adapter reported available." : provider.message,
        provider.available ? "available" : "unavailable",
      )),
    );
  }
  renderAiManagementList(
    document.querySelector("#ai-management-usage"),
    data.usage.map((usage) => aiManagementRecord(
      `${usage.provider} · ${usage.model}`,
      `${usage.requests_recorded} recorded request(s) · input ${usage.token_usage_status === "unavailable" ? "unavailable" : usage.input_tokens} · output ${usage.token_usage_status === "unavailable" ? "unavailable" : usage.output_tokens}`,
      "",
    )),
    "No provider-reported usage has been recorded.",
  );
  renderAiManagementList(
    document.querySelector("#ai-management-prompts"),
    data.prompt_versions.map((prompt) => aiManagementRecord(
      `${prompt.workload} · ${prompt.version}`,
      `${prompt.active ? "Active" : "Inactive"} · ${prompt.description || "No description"} · created by ${prompt.created_by || "unknown"}`,
      prompt.active ? "available" : "",
    )),
    "No managed prompt versions exist; built-in safety prompts remain active.",
  );
  document.querySelector("#ai-failover-enabled").checked = Boolean(data.failover.enabled);
  document.querySelector("#ai-failover-order").value = (data.failover.order || []).join(", ");
  const workloads = Object.keys(data.workloads);
  ["#ai-workload", "#ai-prompt-workload"].forEach((selector) => {
    const select = document.querySelector(selector);
    select.replaceChildren(...workloads.map((workload) => {
      const option = document.createElement("option");
      option.value = workload;
      option.textContent = workload;
      return option;
    }));
  });
  ["#ai-workload-provider"].forEach((selector) => {
    const select = document.querySelector(selector);
    select.replaceChildren(...data.providers.map((provider) => {
      const option = document.createElement("option");
      option.value = provider.provider;
      option.textContent = provider.provider;
      return option;
    }));
  });
  const selectedWorkload = document.querySelector("#ai-workload").value;
  if (selectedWorkload && data.workloads[selectedWorkload]) {
    document.querySelector("#ai-workload-provider").value = data.workloads[selectedWorkload].provider;
    document.querySelector("#ai-workload-model").value = data.workloads[selectedWorkload].model;
  }
}

document.querySelector("#ai-management-refresh")?.addEventListener("click", () => loadAiManagement().catch((error) => showToast(error.message, "danger")));
document.querySelector("#ai-workload")?.addEventListener("change", (event) => {
  const assignment = window.cyberInvestigatorAiManagement?.workloads?.[event.target.value];
  if (!assignment) return;
  document.querySelector("#ai-workload-provider").value = assignment.provider;
  document.querySelector("#ai-workload-model").value = assignment.model;
});
document.querySelector("#ai-workload-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const workload = document.querySelector("#ai-workload").value;
  try {
    await api(`/api/v1/admin/ai/workloads/${workload}`, {
      method: "PATCH",
      body: JSON.stringify({
        provider: document.querySelector("#ai-workload-provider").value,
        model: document.querySelector("#ai-workload-model").value,
      }),
    });
    showToast("Workload assignment updated and audited.", "success");
    await loadAiManagement();
  } catch (error) { showToast(error.message, "danger"); }
});
document.querySelector("#ai-prompt-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/v1/admin/ai/prompts", {
      method: "POST",
      body: JSON.stringify({
        workload: document.querySelector("#ai-prompt-workload").value,
        version: document.querySelector("#ai-prompt-version").value,
        content: document.querySelector("#ai-prompt-content").value,
        activate: document.querySelector("#ai-prompt-activate").checked,
      }),
    });
    event.target.reset();
    document.querySelector("#ai-prompt-activate").checked = true;
    showToast("Immutable prompt version created and audited.", "success");
    await loadAiManagement();
  } catch (error) { showToast(error.message, "danger"); }
});
document.querySelector("#ai-failover-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/v1/admin/ai/failover", {
      method: "PATCH",
      body: JSON.stringify({
        enabled: document.querySelector("#ai-failover-enabled").checked,
        order: document.querySelector("#ai-failover-order").value.split(",").map((item) => item.trim()).filter(Boolean),
      }),
    });
    showToast("Failover policy updated and audited.", "success");
    await loadAiManagement();
  } catch (error) { showToast(error.message, "danger"); }
});

async function initialiseAiChat() {
  const form = document.querySelector("#ai-chat-form");
  if (!form) return;
  const status = document.querySelector("#ai-provider-status");
  const messages = document.querySelector("#chat-messages");
  const caseSelect = document.querySelector("#chat-case");
  const fileInput = document.querySelector("#chat-files");
  const dropZone = document.querySelector("#chat-drop-zone");
  const uploadList = document.querySelector("#chat-upload-list");
  const conversationButton = document.querySelector("[data-ui-action='conversation']");
  const conversationList = document.querySelector("#conversation-list");
  const conversationSearch = document.querySelector("#conversation-search");
  const stopButton = document.querySelector("#stop-generation");
  const attachmentButton = document.querySelector("[data-ui-action='attachment']");
  let history = [];
  let conversationId = crypto.randomUUID();
  let generationController = null;
  let pendingFiles = [];
  const renderGrounding = (grounding = {}, caseRecord = null) => {
    const counts = grounding.counts || {};
    const confidence = grounding.confidence || {};
    const sources = grounding.sources || [];
    const setText = (selector, value) => { const node = document.querySelector(selector); if (node) node.textContent = value; };
    setText("#ai-summary-title", caseRecord ? `${caseRecord.case_number} · ${caseRecord.title}` : "No investigation selected");
    setText("#ai-summary-copy", confidence.rationale || "Select an investigation to ground responses in its recorded evidence.");
    setText("#ai-count-evidence", counts.evidence ?? "—");
    setText("#ai-count-timeline", counts.timeline ?? "—");
    setText("#ai-count-reports", counts.reports ?? "—");
    setText("#ai-confidence-level", confidence.level ? confidence.level[0].toUpperCase() + confidence.level.slice(1) : "Insufficient");
    setText("#ai-source-count", String(sources.length));
    const sourceList = document.querySelector("#ai-source-list");
    if (!sourceList) return;
    if (!sources.length) {
      const empty = document.createElement("p");
      empty.textContent = "No source records loaded.";
      sourceList.replaceChildren(empty);
      return;
    }
    sourceList.replaceChildren(...sources.slice(0, 20).map((source) => {
      const row = document.createElement("div");
      row.className = "ai-source-item";
      const title = document.createElement("strong");
      title.textContent = source.id || source.label || "Source record";
      const detail = document.createElement("small");
      detail.textContent = source.summary || source.sha256 || source.type || "Recorded investigation source";
      row.append(title, detail);
      return row;
    }));
  };
  const loadCaseContext = async () => {
    if (!caseSelect?.value) { renderGrounding(); return; }
    const workspace = await api(`/api/v1/cases/${encodeURIComponent(caseSelect.value)}/workspace`);
    const sources = [
      { id: `CASE:${workspace.case.case_number}`, type: "case", label: workspace.case.case_number, summary: workspace.case.title },
      ...(workspace.evidence || []).map((item) => ({ id: `EVIDENCE:${item.evidence_number || item.id}`, type: "evidence", summary: item.original_filename, sha256: item.sha256 })),
      ...(workspace.timeline || []).map((item) => ({ id: `TIMELINE:${item.id}`, type: "timeline", summary: item.summary || item.event_type })),
      ...(workspace.reports || []).map((item) => ({ id: `REPORT:${item.id}`, type: "report", summary: item.title || item.report_type })),
    ];
    const supportingCategories = ["evidence", "timeline", "reports"].filter((key) => Number(workspace.counts?.[key]) > 0).length;
    renderGrounding({
      counts: workspace.counts,
      sources,
      confidence: {
        level: supportingCategories >= 2 && workspace.counts?.evidence ? "moderate" : "limited",
        rationale: sources.length > 1 ? "Available records will be supplied to the assistant; analyst validation remains required." : "Only the investigation record is available; collect supporting evidence before drawing conclusions.",
      },
    }, workspace.case);
  };

  const loadConversations = async () => {
    if (!conversationList) return;
    const data = await api(`/api/v1/ai/conversations?q=${encodeURIComponent(conversationSearch?.value || "")}`);
    if (!data.items.length) {
      conversationList.innerHTML = "<div class='text-muted small'>No recent conversations.</div>";
      return;
    }
    conversationList.replaceChildren(...data.items.map((item) => {
      const row = document.createElement("div");
      row.className = "compact-item conversation-item";
      const open = document.createElement("button");
      open.type = "button";
      open.className = "btn btn-link text-start flex-grow-1";
      open.textContent = item.title;
      open.addEventListener("click", async () => {
        const detail = await api(`/api/v1/ai/conversations/${item.id}`);
        conversationId = detail.id;
        history = detail.messages || [];
        messages.replaceChildren();
        history.forEach((entry) => appendChatMessage(messages, entry.role, entry.content));
        if (detail.case_id && caseSelect) {
          caseSelect.value = detail.case_id;
          await loadCaseContext();
        }
      });
      const rename = document.createElement("button");
      rename.type = "button"; rename.className = "btn btn-sm btn-link"; rename.title = "Rename";
      rename.innerHTML = "<i class='bi bi-pencil'></i>";
      rename.addEventListener("click", async () => {
        const title = window.prompt("Rename conversation", item.title);
        if (!title?.trim()) return;
        await api(`/api/v1/ai/conversations/${item.id}`, { method: "PATCH", body: JSON.stringify({ title: title.trim() }) });
        await loadConversations();
      });
      const remove = document.createElement("button");
      remove.type = "button"; remove.className = "btn btn-sm btn-link text-danger"; remove.title = "Delete";
      remove.innerHTML = "<i class='bi bi-trash'></i>";
      remove.addEventListener("click", async () => {
        await api(`/api/v1/ai/conversations/${item.id}`, { method: "DELETE" });
        if (conversationId === item.id) conversationButton?.click();
        await loadConversations();
      });
      row.append(open, rename, remove);
      return row;
    }));
  };

  try {
    const provider = await api("/api/v1/ai/status");
    if (status) {
      status.lastChild.textContent = provider.available ? `${provider.provider} · ${provider.model || "configured"}` : "Local analysis fallback";
      status.classList.toggle("is-live", Boolean(provider.available));
    }
  } catch {
    if (status) status.lastChild.textContent = "Provider status unavailable";
  }
  try {
    const cases = await api("/api/v1/cases?per_page=100&sort=opened_at");
    const options = [new Option("Latest active case", "")];
    cases.items.forEach((item) => options.push(new Option(`${item.case_number} - ${item.title}`, item.id)));
    caseSelect?.replaceChildren(...options);
    const requestedCase = new URLSearchParams(window.location.search).get("case_id");
    if (requestedCase && caseSelect?.querySelector(`option[value="${CSS.escape(requestedCase)}"]`)) {
      caseSelect.value = requestedCase;
    }
    await loadCaseContext();
  } catch {
    showToast("Unable to load case context.", "danger");
  }
  caseSelect?.addEventListener("change", () => loadCaseContext().catch((error) => showToast(error.message, "danger")));

  conversationButton?.addEventListener("click", () => {
    history = [];
    conversationId = crypto.randomUUID();
    pendingFiles = [];
    renderChatUploads(uploadList, pendingFiles);
    renderChatState(messages, "bi bi-chat-square-text", "New conversation", "Send a message to begin.");
    showToast("New conversation started.", "success");
  });
  conversationSearch?.addEventListener("input", () => loadConversations().catch(() => {}));
  stopButton?.addEventListener("click", () => generationController?.abort());
  attachmentButton?.addEventListener("click", () => fileInput?.click());
  fileInput?.addEventListener("change", () => {
    pendingFiles = [...pendingFiles, ...Array.from(fileInput.files || [])];
    renderChatUploads(uploadList, pendingFiles);
  });
  dropZone?.addEventListener("click", () => fileInput?.click());
  ["dragenter", "dragover"].forEach((eventName) => dropZone?.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("drag-over");
  }));
  ["dragleave", "drop"].forEach((eventName) => dropZone?.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("drag-over");
  }));
  dropZone?.addEventListener("drop", (event) => {
    pendingFiles = [...pendingFiles, ...Array.from(event.dataTransfer?.files || [])];
    renderChatUploads(uploadList, pendingFiles);
  });
  document.querySelectorAll("[data-chat-prompt]").forEach((button) => button.addEventListener("click", () => {
    form.querySelector("#chat-message").value = button.dataset.chatPrompt;
    form.requestSubmit();
  }));

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = form.querySelector("#chat-message");
    const message = input.value.trim();
    if (!message) {
      showToast("Enter a message before sending.", "warning");
      return;
    }
    appendChatMessage(messages, "user", message);
    input.value = "";
    const bubble = appendChatMessage(messages, "assistant", "_..._");
    generationController = new AbortController();
    stopButton?.classList.remove("d-none");
    try {
      const result = await streamChat(message, caseSelect?.value || "", conversationId, history, pendingFiles, bubble, generationController.signal);
      conversationId = result.conversationId || conversationId;
      history.push({ role: "user", content: message }, { role: "assistant", content: result.reply });
      addChatResponseActions(bubble, result.reply, () => { input.value = message; form.requestSubmit(); });
      const caseSource = result.grounding?.sources?.find((item) => item.type === "case");
      renderGrounding(result.grounding, caseSource ? { case_number: caseSource.label, title: caseSource.summary } : null);
      pendingFiles = [];
      renderChatUploads(uploadList, pendingFiles);
      await loadConversations();
    } catch (error) {
      if (error.name === "AbortError") showToast("Generation stopped.", "warning");
      else {
        bubble.replaceChildren(markdownToFragment(`**Chat error:** ${error.message}`));
        showToast(error.message, "danger");
      }
    } finally {
      generationController = null;
      stopButton?.classList.add("d-none");
    }
  });
  await loadConversations().catch(() => {});
}

function renderChatState(container, iconClass, titleText, bodyText) {
  const orb = document.createElement("span");
  orb.className = "ai-orb";
  const icon = document.createElement("i");
  icon.className = iconClass;
  orb.append(icon);
  const title = document.createElement("h3");
  title.textContent = titleText;
  const body = document.createElement("p");
  body.textContent = bodyText;
  container.replaceChildren(orb, title, body);
}

function appendChatMessage(container, role, markdown) {
  const empty = container.querySelector(".chat-empty");
  if (empty) container.replaceChildren();
  const item = document.createElement("div");
  item.className = `chat-message ${role}`;
  const avatar = document.createElement("div");
  avatar.className = "chat-avatar";
  avatar.textContent = role === "user" ? "You" : "AI";
  const bubble = document.createElement("div");
  bubble.className = "chat-bubble";
  bubble.append(markdownToFragment(markdown));
  item.append(avatar, bubble);
  container.append(item);
  container.scrollTop = container.scrollHeight;
  return bubble;
}

async function streamChat(message, caseId, conversationId, history, files, target, signal) {
  const body = new FormData();
  body.append("message", message);
  body.append("case_id", caseId);
  body.append("conversation_id", conversationId);
  body.append("history", JSON.stringify(history));
  files.forEach((file) => body.append("files", file));
  const csrfToken = document.querySelector("meta[name='csrf-token']")?.content;
  const headers = { Accept: "text/event-stream" };
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const response = await fetch("/api/v1/ai/chat/stream", { method: "POST", headers, body, signal });
  if (!response.ok || !response.body) throw new Error(`Chat API returned HTTP ${response.status}`);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let reply = "";
  let persistedConversationId = conversationId;
  let grounding = null;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const events = buffer.split("\n\n");
    buffer = events.pop() || "";
    for (const eventText of events) {
      if (!eventText.startsWith("data: ")) continue;
      const payload = JSON.parse(eventText.slice(6));
      if (payload.type === "token") {
        reply += payload.content || "";
        target.replaceChildren(markdownToFragment(reply));
      } else if (payload.type === "error") {
        throw new Error(payload.message || "AI Chat failed.");
      } else if (payload.type === "done") {
        persistedConversationId = payload.conversation_id || persistedConversationId;
        grounding = payload.grounding || grounding;
      }
    }
  }
  return { reply, conversationId: persistedConversationId, grounding };
}

function addChatResponseActions(bubble, reply, regenerate) {
  const actions = document.createElement("div");
  actions.className = "chat-response-actions";
  const copy = document.createElement("button");
  copy.type = "button"; copy.className = "btn btn-sm btn-link"; copy.innerHTML = "<i class='bi bi-copy'></i> Copy";
  copy.addEventListener("click", async () => { await navigator.clipboard.writeText(reply); showToast("Response copied.", "success"); });
  const retry = document.createElement("button");
  retry.type = "button"; retry.className = "btn btn-sm btn-link"; retry.innerHTML = "<i class='bi bi-arrow-clockwise'></i> Regenerate";
  retry.addEventListener("click", regenerate);
  actions.append(copy, retry);
  bubble.append(actions);
}

function renderChatUploads(target, files) {
  if (!target) return;
  if (!files.length) {
    target.replaceChildren();
    return;
  }
  target.replaceChildren(...files.map((file) => {
    const row = document.createElement("div");
    row.className = "compact-item";
    row.innerHTML = `<i class="bi bi-file-earmark-binary"></i><div><strong></strong><small>${file.size} bytes queued</small></div>`;
    row.querySelector("strong").textContent = file.name;
    return row;
  }));
}

function markdownToFragment(markdown) {
  const template = document.createElement("template");
  const escaped = String(markdown || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  template.innerHTML = escaped
    .replace(/```([\s\S]*?)```/g, "<pre><code>$1</code></pre>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/^### (.*)$/gm, "<h4>$1</h4>")
    .replace(/^## (.*)$/gm, "<h3>$1</h3>")
    .replace(/^# (.*)$/gm, "<h2>$1</h2>")
    .replace(/\n\|(.+)\|\n\|[-:| ]+\|\n((?:\|.*\|\n?)+)/g, renderMarkdownTable)
    .replace(/\n/g, "<br>");
  return template.content;
}

function renderMarkdownTable(_match, header, rows) {
  const headers = header.split("|").map((cell) => cell.trim()).filter(Boolean);
  const bodyRows = rows.trim().split("\n").map((row) => row.split("|").map((cell) => cell.trim()).filter(Boolean));
  return `<table class="table table-sm"><thead><tr>${headers.map((cell) => `<th>${cell}</th>`).join("")}</tr></thead><tbody>${bodyRows.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

document.addEventListener("DOMContentLoaded", () => {
  initialiseEnterpriseUi();
  initialisePreferences();
  initialiseNotifications();
  initialiseAiChat();
});
