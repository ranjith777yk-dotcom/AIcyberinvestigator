"use strict";
(() => {
  const backdrop = document.querySelector("#command-backdrop");
  const trigger = document.querySelector("#command-trigger");
  const search = document.querySelector("#command-search");
  const results = document.querySelector("#command-results");
  const entityResults = document.querySelector("#command-entity-results");
  const progress = document.querySelector("#page-progress");
  if (!backdrop || !search || !results) return;
  const commands = () => [...results.querySelectorAll("a")].filter((item) => !item.hidden);
  let activeIndex = 0;
  let searchTimer;
  let searchController;
  const staticCommands = () => [...results.children].filter((item) => item.matches?.("a[data-command]"));
  const setActive = (index) => {
    const available = commands();
    if (!available.length) return;
    activeIndex = (index + available.length) % available.length;
    available.forEach((item, itemIndex) => item.classList.toggle("active", itemIndex === activeIndex));
    available[activeIndex].scrollIntoView({ block: "nearest" });
  };
  const open = () => {
    backdrop.hidden = false;
    document.body.classList.add("command-open");
    trigger?.setAttribute("aria-expanded", "true");
    search.value = "";
    staticCommands().forEach((item) => { item.hidden = false; });
    entityResults?.replaceChildren();
    setActive(0);
    window.setTimeout(() => search.focus(), 0);
  };
  const close = () => {
    backdrop.hidden = true;
    document.body.classList.remove("command-open");
    trigger?.setAttribute("aria-expanded", "false");
    trigger?.focus();
  };
  trigger?.addEventListener("click", open);
  backdrop.addEventListener("mousedown", (event) => { if (event.target === backdrop) close(); });
  search.addEventListener("input", () => {
    const term = search.value.trim().toLowerCase();
    staticCommands().forEach((item) => { item.hidden = Boolean(term) && !item.dataset.command.includes(term) && !item.textContent.toLowerCase().includes(term); });
    window.clearTimeout(searchTimer);
    searchController?.abort();
    entityResults?.replaceChildren();
    if (term.length >= 2) {
      renderEntitySearchState("Searching authorized workspace records…", "bi-arrow-repeat");
      searchTimer = window.setTimeout(() => searchEntities(term), 250);
    }
    setActive(0);
  });
  search.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") { event.preventDefault(); setActive(activeIndex + (event.key === "ArrowDown" ? 1 : -1)); }
    if (event.key === "Enter" && commands()[activeIndex]) { event.preventDefault(); commands()[activeIndex].click(); }
  });
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); backdrop.hidden ? open() : close(); }
    else if (event.key === "Escape" && !backdrop.hidden) close();
  });
  document.addEventListener("click", (event) => {
    const link = event.target.closest("a[href]");
    if (link && link.target !== "_blank" && link.origin === window.location.origin) progress?.classList.add("active");
  });
  window.addEventListener("pageshow", () => {
    progress?.classList.remove("active");
    progress?.classList.add("complete");
    window.setTimeout(() => progress?.classList.remove("complete"), 300);
  });

  async function searchEntities(term) {
    if (!entityResults) return;
    searchController = new AbortController();
    const definitions = [
      { key: "cases", endpoint: "/api/v1/cases", route: "/cases", icon: "bi-briefcase", type: "Case", title: (item) => `${item.case_number} · ${item.title}`, detail: (item) => `${item.priority || item.severity} · ${item.status}` },
      { key: "evidence", endpoint: "/api/v1/evidence", route: "/evidence", icon: "bi-fingerprint", type: "Evidence", title: (item) => `${item.evidence_number} · ${item.original_filename}`, detail: (item) => `${item.analysis_status} · ${item.media_type || "unknown type"}` },
      { key: "timeline", endpoint: "/api/v1/timeline", route: "/timeline", icon: "bi-clock-history", type: "Timeline", title: (item) => item.summary, detail: (item) => `${item.event_type} · ${item.case_number || "case event"}` },
      { key: "reports", endpoint: "/api/v1/reports", route: "/reports", icon: "bi-file-earmark-bar-graph", type: "Report", title: (item) => item.title, detail: (item) => `${item.report_type} · version ${item.version}` },
    ].filter((definition) => entityResults.dataset[definition.key] === "true");
    try {
      const settled = await Promise.allSettled(definitions.map(async (definition) => {
        const params = new URLSearchParams({ q: term, page: "1", per_page: "3" });
        const response = await fetch(`${definition.endpoint}?${params}`, {
          headers: { Accept: "application/json" },
          signal: searchController.signal,
        });
        if (!response.ok) throw new Error(`Search failed with ${response.status}`);
        const payload = await response.json();
        return { definition, items: (payload.items || []).slice(0, 3) };
      }));
      if (search.value.trim().toLowerCase() !== term) return;
      const groups = settled.filter((item) => item.status === "fulfilled").map((item) => item.value);
      const records = groups.flatMap(({ definition, items }) => items.map((item) => ({ definition, item }))).slice(0, 8);
      entityResults.replaceChildren();
      if (!records.length) {
        renderEntitySearchState("No authorized records match this search.", "bi-search");
        return;
      }
      const heading = document.createElement("p");
      heading.className = "command-section-label";
      heading.textContent = "Workspace results";
      entityResults.append(heading, ...records.map(({ definition, item }) => {
        const link = document.createElement("a");
        link.href = `${definition.route}?q=${encodeURIComponent(term)}`;
        link.dataset.command = `${definition.type} ${definition.title(item)} ${definition.detail(item)}`.toLowerCase();
        const icon = document.createElement("i");
        icon.className = `bi ${definition.icon}`;
        const copy = document.createElement("span");
        const title = document.createElement("strong");
        title.textContent = definition.title(item);
        const detail = document.createElement("small");
        detail.textContent = definition.detail(item);
        copy.append(title, detail);
        const type = document.createElement("span");
        type.className = "command-result-type";
        type.textContent = definition.type;
        link.append(icon, copy, type);
        return link;
      }));
      setActive(0);
    } catch (error) {
      if (error.name !== "AbortError") renderEntitySearchState("Workspace search is temporarily unavailable.", "bi-exclamation-circle");
    }
  }

  function renderEntitySearchState(message, iconName) {
    if (!entityResults) return;
    const state = document.createElement("div");
    state.className = "command-search-state";
    const icon = document.createElement("i");
    icon.className = `bi ${iconName}`;
    const text = document.createElement("span");
    text.textContent = message;
    state.append(icon, text);
    entityResults.replaceChildren(state);
  }
})();
