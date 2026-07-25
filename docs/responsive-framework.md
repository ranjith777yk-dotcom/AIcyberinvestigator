# CyberInvestigator Responsive Framework

## Purpose

The responsive framework provides one adaptive contract for current and future CyberInvestigator modules. It complements the enterprise design system and does not replace page features, routes, API behavior, or server-side rendering.

Files:

- `presentation/static/css/responsive.css`
- `presentation/static/js/responsive.js`

The framework is CSS-first. Its JavaScript only exposes the active viewport tier and closes mobile navigation after selection; it performs no network requests and creates no alternate application state.

## Standard Viewport Tiers

| Tier | Range | Product behavior |
| --- | --- | --- |
| Mobile | below 576 px | One prioritized workflow, stacked actions, labelled records, full-screen task dialogs |
| Tablet | 576–991 px | Touch-first one/two-column layouts, off-canvas navigation, reflowed toolbars |
| Laptop | 992–1399 px | Full capability with tighter gutters, reduced secondary context, compact shell |
| Desktop | 1400 px and above | Full enterprise workspace with multi-column operational context |

CSS media queries are authoritative. JavaScript publishes `data-viewport="mobile|tablet|laptop|desktop"` on `<html>` only when a component genuinely requires behavioral awareness.

Do not use user-agent detection.

## Layout Primitives

All responsive utilities use the `.ci-r-*` namespace.

### Container

```html
<div class="ci-r-container">...</div>
```

Constrains content to the design-system maximum and applies adaptive page gutters.

### Adaptive grid

```html
<div class="ci-r-grid" style="--ci-r-columns: 12">...</div>
```

The column system becomes six columns on tablet and one column on mobile.

### Auto grid

```html
<div class="ci-r-auto-grid" style="--ci-r-min: 260px">...</div>
```

Use for KPI cards or equal-value summaries. Do not use auto-fit when a primary region must remain dominant.

### Primary/secondary split

```html
<div class="ci-r-split">
  <main class="ci-r-priority">Primary investigation work</main>
  <aside class="ci-r-secondary" data-mobile-priority="low">Supporting context</aside>
</div>
```

The split becomes one column on tablet/mobile. Primary work remains first.

### Navigation/content sidebar

```html
<div class="ci-r-sidebar">
  <nav>Local navigation</nav>
  <section>Module content</section>
</div>
```

Use for settings or local module navigation, not the global application shell.

### Responsive toolbar

```html
<div class="ci-r-toolbar">
  <div class="ci-r-toolbar__primary">Search or primary filter</div>
  <div class="ci-r-toolbar__actions">Actions and secondary filters</div>
</div>
```

Toolbars stack on tablet/mobile. Mobile actions become full-width and retain their original order.

## Navigation

- Desktop and laptop retain the persistent/collapsible application navigation.
- Tablet and mobile use the existing accessible off-canvas navigation.
- Selecting a mobile destination closes the off-canvas panel.
- Navigation links retain at least 44 px touch height on coarse-pointer devices.
- Active state, permission filtering, labels, and keyboard behavior remain identical at every tier.

Responsive code must never create a second route list or duplicate RBAC logic.

## Tables

Enterprise comparison tables use `.professional-table`; new design-system tables use `.ci-table.ci-table--responsive`.

At mobile width:

- headers remain available to assistive technology but are visually hidden;
- each row becomes a bounded record card;
- each cell uses its generated `data-label` as a visible field label;
- identifiers and hashes wrap safely;
- row actions remain visible and do not require hover;
- empty and colspan states retain normal layout.

Dynamic tables must call the existing `refreshResponsiveTableLabels` helper after rendering. New renderers should populate `data-label` directly when practical.

Do not remove columns merely to make a table fit. Prioritize the card representation or provide a deliberate drill-down.

## Forms and Touch

- Tablet/mobile controls have a minimum 44 px target.
- Form grids become six columns on tablet and one column on mobile.
- Labels remain visible.
- Text areas resize vertically.
- Toolbars and action groups reflow instead of horizontally scrolling.
- Validation messages remain adjacent to their fields.
- Mobile primary submission appears before cancel in dialog footers while semantic form behavior remains unchanged.

Use `.ci-r-form-grid` and `.ci-r-field-full` for new forms.

## Dialogs

- Desktop/laptop dialogs remain centered and bounded.
- Tablet dialogs use available width with safe viewport margins.
- Mobile dialogs become full-height task surfaces.
- Header and footer remain stable while the body scrolls.
- Actions become full-width with 44 px targets.
- Safe-area bottom padding is respected.

JavaScript focus trapping and focus restoration continue to be owned by the existing Bootstrap dialog implementation.

## Charts

- SVG charts scale to their container.
- Chart wrappers never force page-level horizontal scrolling.
- Dense charts may use `.ci-chart__scroll` with a deliberate minimum chart width.
- New charts require an accessible name and nearby textual interpretation.
- Mobile should reduce simultaneous charts, not reduce text or tap targets to illegibility.

Responsive behavior must not trigger separate chart API requests.

## Reports

- Interactive reports use a readable maximum width.
- Narrative text is limited to approximately 72 characters per line.
- Hashes, code, and technical content wrap safely.
- Wide report tables scroll within their region on mobile.
- Print removes application chrome, restores full report width, prevents card/row splitting where practical, and uses A4 margins.

Report information must remain complete on mobile and print; responsiveness cannot omit findings.

## Performance

- Prefer CSS media/container behavior over resize handlers.
- Use `matchMedia` rather than continuously reading layout dimensions.
- Do not duplicate DOM trees for desktop and mobile.
- Do not issue device-specific API calls.
- Keep images responsive and declare intrinsic dimensions when introduced.
- Defer low-priority visualizations using the page module, not the global responsive layer.
- Avoid layout-thrashing measurement loops.

## Accessibility

- DOM and heading order follow mobile priority and remain logical on desktop.
- Visual CSS reordering must not create a conflicting keyboard order.
- All functionality remains keyboard accessible.
- Coarse-pointer targets meet 44 px minimum.
- Focus is visible at every tier.
- Horizontal scroll regions remain keyboard accessible.
- Responsive tables expose field labels.
- Charts retain accessible descriptions.
- Reduced-motion removes off-canvas, modal, and collapse transitions.
- Zoom to 200% must not cause loss of content or functionality.

## Adoption Checklist

For each module:

1. Identify the one primary task.
2. Mark primary and secondary regions.
3. Use shared layout primitives rather than new breakpoint values.
4. Verify navigation and actions at all four tiers.
5. Verify loading, empty, error, forbidden, and degraded states.
6. Verify tables, forms, dialogs, charts, and long technical strings.
7. Test keyboard, 200% zoom, reduced motion, and coarse pointer.
8. Confirm no additional requests occur because of viewport size.

