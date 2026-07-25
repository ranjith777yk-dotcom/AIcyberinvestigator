# CyberInvestigator Enterprise Design System

## Scope

The design system is the stable presentation contract for all future CyberInvestigator modules. It provides:

- semantic CSS tokens in `design_system.css`;
- reusable `.ci-*` component classes;
- server-rendered Jinja primitives in `templates/components/ui.html`;
- responsive behavior for desktop, laptop, tablet, and mobile;
- dark-theme, reduced-motion, forced-colors, keyboard, and screen-reader support.

Adaptive layout, navigation, tables, forms, charts, dialogs, and report
behavior are defined in [`responsive-framework.md`](responsive-framework.md).

It does not replace Bootstrap immediately. Existing pages may migrate incrementally. New UI should prefer the design-system API and must not introduce a separate token vocabulary.

## Import

The authenticated shell and authentication experience already load the design-system stylesheet. A template can import the component macros with:

```jinja
{% import "components/ui.html" as ui %}
```

## Design Principles

1. **Operational clarity:** the primary investigation task is visually dominant.
2. **Evidence integrity:** destructive or custody-sensitive actions are explicit.
3. **Calm severity:** critical color communicates risk; it is not decoration.
4. **Progressive disclosure:** summaries lead to details instead of showing everything at once.
5. **Dense, not cramped:** security professionals need information density with consistent rhythm.
6. **Accessible by default:** keyboard, contrast, motion preference, and non-color cues are component requirements.

## Tokens

Tokens use the `--ci-*` prefix and are semantic rather than page-specific.

### Color

Use:

- `--ci-color-canvas`
- `--ci-color-surface`
- `--ci-color-surface-subtle`
- `--ci-color-surface-raised`
- `--ci-color-text`
- `--ci-color-text-secondary`
- `--ci-color-border`
- `--ci-color-primary`
- `--ci-color-info`
- `--ci-color-success`
- `--ci-color-warning`
- `--ci-color-critical`

Do not encode severity using only color. Pair it with text and, where useful, an icon.

### Typography

The type scale ranges from `--ci-text-xs` to `--ci-text-2xl`. Product UI should normally use:

- `xs`: metadata, table headers, supporting labels;
- `sm`: controls, descriptions, dense operational content;
- `md`: normal body content and panel titles;
- `lg` and above: page and section hierarchy.

Use `--ci-font-mono` only for hashes, IOCs, identifiers, timestamps requiring alignment, and technical literals.

### Spacing

Spacing follows a 4 px base grid through `--ci-space-1` to `--ci-space-12`. Components should use tokens rather than arbitrary margins.

### Shape and elevation

- Small radii: inputs, buttons, compact controls.
- Medium/large radii: cards, panels, dialogs.
- `shadow-xs/sm`: default product surfaces.
- `shadow-md`: interactive elevation and dropdowns.
- `shadow-lg`: modal or command overlays only.

Do not combine a strong border, gradient, and large shadow on the same ordinary card.

## Components

### Buttons

Variants:

- `primary`: one primary action per local region;
- `secondary`: normal visible actions;
- `ghost`: low-emphasis or toolbar action;
- `critical`: confirmed destructive or high-impact security action.

Sizes are `sm`, default, and `lg`. Icon-only controls require an accessible name and the `ci-button--icon` class.

```jinja
{{ ui.button("Register evidence", "primary", "cloud-arrow-up", type="submit") }}
{{ ui.action_link("Open timeline", url_for("web.timeline"), "secondary", "clock-history") }}
```

### Forms

Each control uses a visible label. Help text explains format or consequence; error text explains recovery.

```html
<div class="ci-field">
  <label class="ci-field__label" for="case-owner">Owner</label>
  <input class="ci-input" id="case-owner" name="owner" autocomplete="off">
  <span class="ci-field__help">Assign the investigator responsible for triage.</span>
</div>
```

Set `aria-invalid="true"` and associate error text using `aria-describedby`. Never rely on placeholders as labels.

### Panels and cards

Panels contain a titled operational region. Cards represent a concise object or metric. Interactive cards must remain keyboard-accessible links or buttons.

```jinja
{% call(slot) ui.panel("Evidence overview", "Recent custody activity", "fingerprint") %}
  {% if slot == "actions" %}{{ ui.action_link("Repository", url_for("web.evidence"), "ghost") }}{% endif %}
  {% if slot == "body" %}<div>Panel content</div>{% endif %}
{% endcall %}
```

### Status

Supported intents are `neutral`, `info`, `success`, `warning`, and `critical`.

```jinja
{{ ui.status("Analysis complete", "success") }}
```

Statuses describe state. Buttons describe actions. Do not use a status pill as a button.

### Tables

Use `.ci-table-wrap` around `.ci-table`. For mobile record layouts, add `.ci-table--responsive` and populate `data-label` on every cell. Keep row actions discoverable without requiring hover.

Tables are for comparable records. Use a list for heterogeneous events or narrative content.

### Notifications

Use `.ci-notice` for inline information and intent variants for success, warning, or critical messages. Toasts are reserved for transient confirmation; errors requiring recovery remain visible in context.

### Loading states

Use the skeleton macro for initial data loading:

```jinja
{{ ui.skeleton(4, "Loading investigation cases") }}
```

Preserve the final component geometry to minimize layout shift. Use a spinner only inside an action that the user initiated.

### Empty and error states

Empty states explain why the region is empty and provide one relevant next step. Error states identify what failed without leaking backend details and provide recovery when possible.

```jinja
{{ ui.empty_state("No evidence yet", "Add the first artifact to begin analysis.", "inbox", "Add evidence", url_for("web.evidence")) }}
{{ ui.error_state("Timeline unavailable", "Timeline events could not be loaded.", "retry-timeline") }}
```

## Icon Standard

Bootstrap Icons is the current canonical icon set.

- Use outline icons for navigation and ordinary actions.
- Use filled icons sparingly for active state or severity.
- Use consistent metaphors: briefcase for cases, fingerprint/folder for evidence, clock-history for timeline, file-earmark for reports, stars for AI, shield for security.
- Decorative icons use `aria-hidden="true"`.
- Standalone icons require an accessible name.
- Do not mix emoji, custom SVG styles, and Bootstrap Icons in product controls.

## Responsive Contracts

### Desktop — 1200 px and above

- Multi-column operational layouts are appropriate.
- Content remains within `--ci-content-max`.
- Tables can retain full comparison columns.

### Laptop — 992–1199 px

- Reduce secondary columns before compressing primary work.
- Preserve readable controls and avoid horizontal page scrolling.
- Navigation may collapse while primary actions remain visible.

### Tablet — 576–991 px

- Prefer one or two columns.
- Reflow toolbars and make controls at least 44 px high.
- Use off-canvas navigation and touch-safe spacing.

### Mobile — below 576 px

- Present one primary workflow at a time.
- Stack panel actions and filters.
- Convert responsive tables to labelled records.
- Do not hide functionality that exists on desktop.
- Avoid fixed heights for content regions.

## Accessibility Requirements

- WCAG 2.2 AA is the baseline.
- Every interaction is keyboard-operable.
- Focus remains visible and is not obscured.
- Minimum touch target is 44 px on tablet/mobile.
- Asynchronous regions use meaningful `role="status"` or `aria-live`.
- Alerts that require action remain in the document.
- Dialogs manage focus and restore it to the trigger.
- Motion respects `prefers-reduced-motion`.
- Windows High Contrast is supported through `forced-colors`.
- Charts have accessible names and nearby textual interpretation.

## Adoption Rules

For new modules:

1. Import the shared macros.
2. Use semantic tokens and `.ci-*` primitives.
3. Add feature classes only for layout or domain-specific visualization.
4. Implement loading, empty, error, forbidden, and degraded states.
5. Verify all four responsive modes.
6. Add a functional rendering test.

For existing modules:

- Migrate when the module is already being changed.
- Do not perform broad class-name rewrites without visual regression coverage.
- Preserve IDs and data attributes used by JavaScript.
- Preserve form names, actions, CSRF fields, routes, and permission checks.

## Versioning

The design system is currently version `1.x`.

- Adding a token, component, or optional macro argument is backward-compatible.
- Renaming or changing the meaning of a `.ci-*` class or token requires a deprecation period.
- Removing a component requires repository-wide usage search and migration.
- Legacy aliases may be retained until automated browser coverage confirms removal is safe.
