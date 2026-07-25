"use strict";

(() => {
  const tiers = [
    ["mobile", window.matchMedia("(max-width: 575.98px)")],
    ["tablet", window.matchMedia("(min-width: 576px) and (max-width: 991.98px)")],
    ["laptop", window.matchMedia("(min-width: 992px) and (max-width: 1399.98px)")],
    ["desktop", window.matchMedia("(min-width: 1400px)")],
  ];

  const applyTier = () => {
    const active = tiers.find(([, media]) => media.matches)?.[0] || "desktop";
    document.documentElement.dataset.viewport = active;
  };
  tiers.forEach(([, media]) => media.addEventListener?.("change", applyTier));
  applyTier();

  const navigation = document.querySelector("#navigation");
  navigation?.querySelectorAll("a.nav-link").forEach((link) => {
    link.addEventListener("click", () => {
      if (!window.matchMedia("(max-width: 991.98px)").matches || !window.bootstrap?.Offcanvas) return;
      bootstrap.Offcanvas.getInstance(navigation)?.hide();
    });
  });
})();
