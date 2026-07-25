# CyberInvestigator Information Architecture

## Product Model

CyberInvestigator navigation is organized around the investigation lifecycle rather than implementation features.

```text
Command
└── Command center

Investigation lifecycle
├── 01 Cases
├── 02 Evidence
├── 03 Timeline
├── 04 AI investigation
└── 05 Reports

Platform operations (permission controlled)
├── Operations
├── Security center
├── Monitoring
├── User management
├── Integrations
└── Platform settings

Account
├── Profile and activity
├── Preferences
└── Notifications
```

The sequence represents the dominant workflow:

```text
open case → preserve evidence → reconstruct timeline
→ investigate with AI → deliver report
```

It is guidance, not a forced wizard. Investigators may move between stages at any time.

## Navigation Responsibilities

### Global navigation

The sidebar answers:

- Which product area am I in?
- What lifecycle stage comes before or after this one?
- Which platform capabilities are available to my role?
- How do I return to the command center?

The server renders navigation from the existing `can(permission)` checks. Client code must never maintain a separate permission model.

### Contextual navigation

Contextual navigation belongs inside a module and may expose:

- current case;
- related evidence;
- timeline scope;
- report version;
- recommended next action.

It must not duplicate the global route hierarchy. Contextual links retain the current case identifier when the destination supports it.

### Breadcrumbs

Authenticated pages use:

```text
Workspace / [Investigations|Platform] / Current page
```

Breadcrumbs describe hierarchy and return paths. They are not a history trail. The final item uses `aria-current="page"`.

On mobile, the current breadcrumb is prioritized while the drawer provides the full hierarchy.

## Global Search

The command center opens with `Ctrl/Cmd + K`.

It supports:

- immediate filtering of routes and common actions;
- deferred search of cases, evidence, timeline events, and reports;
- keyboard navigation with arrow keys and Enter;
- Escape and backdrop dismissal;
- role and ownership scoping through existing APIs.

Entity search begins after two characters, waits briefly for intentional input, and cancels stale requests. It performs no polling and introduces no new endpoints.

Search results use existing collection APIs:

- `/api/v1/cases?q=`
- `/api/v1/evidence?q=`
- `/api/v1/timeline?q=`
- `/api/v1/reports?q=`

The UI only calls an entity endpoint when the current principal has its read permission. The server remains authoritative.

## Role-based Navigation

### Investigator

Primary hierarchy:

- Command center
- Investigation lifecycle
- Account, preferences, and notifications

### Administrator

Administrators receive the same investigation lifecycle plus platform operations. Administrative capability does not replace the investigation workflow.

When future roles are introduced, navigation should be generated from named capabilities rather than role-name conditionals.

## Responsive Navigation

### Desktop

- Persistent sidebar
- Visible lifecycle groups and stage numbers
- Full breadcrumbs
- Command search in the top bar

### Laptop

- Persistent but collapsible sidebar
- Reduced spacing
- Full route availability
- Collapsed state preserves tooltips and active indication

### Tablet

- Off-canvas navigation
- Touch-sized links
- Priority actions at the top of the drawer
- Breadcrumb and page title remain in the shell

### Mobile

- Drawer navigation
- New case, add evidence, and Ask AI prioritized when permitted
- Current location remains visible in the top bar
- Selecting a route closes the drawer
- No desktop capability is removed

## Labels and Icon Vocabulary

Canonical route labels:

| Capability | Label | Icon |
| --- | --- | --- |
| Dashboard | Command center | `grid-1x2` |
| Cases | Cases | `briefcase` |
| Evidence | Evidence | `fingerprint` |
| Timeline | Timeline | `clock-history` |
| AI | AI investigation | `stars` |
| Reports | Reports | `file-earmark-bar-graph` |
| Security | Security center | `shield-check` |
| Monitoring | Monitoring | `activity` |
| Plugins | Integrations | `puzzle` |

Labels describe user intent, not internal implementation. Avoid synonyms across sidebar, breadcrumbs, command search, and page headings.

## Expansion Rules

A future capability belongs:

- in the lifecycle when it advances an investigation;
- in platform operations when it administers or monitors the product;
- in account when it affects only the current principal;
- in contextual navigation when it is meaningful only within a selected case or artifact.

Before adding a global item, confirm that it:

1. represents a durable product area;
2. has a named permission;
3. has a stable route;
4. cannot be discovered more appropriately through context or search;
5. remains understandable on mobile.

Do not add more than one level of sidebar nesting. Use module-local navigation for deeper structures.

## Accessibility Contract

- Navigation uses landmarks and accessible names.
- Active routes use `aria-current="page"`.
- Drawers preserve focus and close after selection.
- Search is a labelled modal dialog.
- Results are announced through a polite live region.
- Icons are supplementary to text labels.
- Attention state uses text/notification context in addition to color.
- Keyboard order follows DOM hierarchy at every breakpoint.

