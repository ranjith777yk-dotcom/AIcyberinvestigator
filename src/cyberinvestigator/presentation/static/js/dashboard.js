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
      body.append(title, message, meta);
      row.append(icon, body, archive);
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
  applyTheme(localStorage.getItem("cyberinvestigator.theme") || "light");
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
      showToast("AI settings saved.", "success");
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
  const attachmentButton = document.querySelector("[data-ui-action='attachment']");
  const history = [];
  let pendingFiles = [];

  try {
    await api("/api/v1/ai/status");
    status?.remove();
  } catch {
    status?.remove();
  }
  try {
    const cases = await api("/api/v1/cases?per_page=100&sort=opened_at");
    const options = [new Option("Latest active case", "")];
    cases.items.forEach((item) => options.push(new Option(`${item.case_number} - ${item.title}`, item.id)));
    caseSelect?.replaceChildren(...options);
  } catch {
    showToast("Unable to load case context.", "danger");
  }

  conversationButton?.addEventListener("click", () => {
    history.length = 0;
    pendingFiles = [];
    renderChatUploads(uploadList, pendingFiles);
    renderChatState(messages, "bi bi-chat-square-text", "New conversation", "Send a message to begin.");
    showToast("New conversation started.", "success");
  });
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
    try {
      const reply = await streamChat(message, caseSelect?.value || "", history, pendingFiles, bubble);
      history.push({ role: "user", content: message }, { role: "assistant", content: reply });
      pendingFiles = [];
      renderChatUploads(uploadList, pendingFiles);
    } catch (error) {
      bubble.replaceChildren(markdownToFragment(`**Chat error:** ${error.message}`));
      showToast(error.message, "danger");
    }
  });
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

async function streamChat(message, caseId, history, files, target) {
  const body = new FormData();
  body.append("message", message);
  body.append("case_id", caseId);
  body.append("history", JSON.stringify(history));
  files.forEach((file) => body.append("files", file));
  const csrfToken = document.querySelector("meta[name='csrf-token']")?.content;
  const headers = { Accept: "text/event-stream" };
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const response = await fetch("/api/v1/ai/chat/stream", { method: "POST", headers, body });
  if (!response.ok || !response.body) throw new Error(`Chat API returned HTTP ${response.status}`);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let reply = "";
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
      }
    }
  }
  return reply;
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
