# Global search: design

Status: draft for owner approval, 2026-11-23.

## Why

The owner wants one search box in the top bar, right of the sensr wordmark. Typing should find both the
page or setting they mean and their own things: hosts, aliases, rules, reservations, peers and so on.
The menu tree is deep (OPNsense layout), and today the only way to find an object is to know which page
holds it.

## Goals

- **Box placement.** A search box in the top bar, directly right of the wordmark. `/` focuses it, and so
  does Ctrl+K / ⌘K.
- **Grouped results.** Results appear as you type, in a dropdown grouped as "Pages", "Settings",
  "Hosts", then one group per object type ("Aliases", "Firewall rules", "Port forwards", "DHCP
  reservations", "DNS overrides", "Gateways", "WireGuard peers", ...).
- **Keyboard.** ↑/↓ moves, Enter opens, Esc closes. Mouse and touch work the same way.
- **Where a result goes:**
  - **Page:** that page.
  - **Setting:** its page, scrolled to the field, which is briefly highlighted.
  - **Object:** its grid page with that row's edit dialog open.
  - **Host:** the dashboard Hosts card, filtered to it.
- **Permissions.** A user only ever sees results on pages they may open (`may_access`). Read-only users
  can search everything they can read.
- **Phone layout.** On phones the box collapses to a magnifier icon. Tapping it opens a full-width
  search sheet.

## Non-goals

- No full-text search of logs, IDS alerts or DNS queries; those pages keep their own filters.
- No fuzzy or typo-tolerant matching beyond case-insensitive substring and word-prefix matching.
- No search history or saved searches.

## Anti-goals

- **Leaks.** Showing an object to a user who cannot open its page.
- **Slow typing.** Typing must not feel slow; one keystroke must never mean one config read per grid.
- **Bundle budget.** Growing the island bundle past its budget without saying so.

## Approaches considered

1. **Pages only** (OPNsense's menu search). Small and offline, but it does not find the owner's things.
2. **Pages + things, searched on the router (chosen).** One server function takes the query and returns
   grouped, ranked, permission-filtered results. It builds them from:
   - the menu manifest and form field labels (pages and settings);
   - every `GridModel` page's rows in the config document;
   - the host inventory.
3. **Ship an index to the browser.** Fast after the first load, but it puts every object in the page
   for every user. That clashes with per-page permissions and costs bundle and transfer size.

The owner picked "pages + things".

## Design

**Server function** `global_search(q: String) -> SearchResults`, in sensr-ui actions, implemented in
the sensr-api `UiBackend`:

- **Query handling.** Trimmed, case-folded and capped at 64 chars. Fewer than 2 characters returns
  nothing.
- **Index.** Built per request from the current applied document, plus any staged candidate, so new
  objects are found.
  - It is cached in memory, keyed by the config revision and the user's privilege set, so typing does
    not rebuild it.
  - Inventory hosts are re-read on each call; they are cheap.
- **Pages.** Every menu leaf, matched on its label and its breadcrumb ("Services › DHCPv4 › LAN").
- **Settings.** Every `FormModel` field label and help text on single-form pages, linked as
  `<page>#field-<id>`.
- **Objects.** For each grid page, the row's display fields (name, description, addresses, MAC, ports;
  whatever its grid columns show), linked as `<grid page>?edit=<uuid>`. Each object group is named
  after its menu entry.
- **Hosts.** Name, MAC, IPv4/IPv6 and smart label text (maker · type), linked as
  `/ui/core/dashboard?host=<mac or key>#w-hosts`.
- **Filtering.** Every result is checked with `may_access(url)` before it is returned.
- **Ranking.** Exact > prefix > word-prefix > substring; ties are broken by group order and then by
  name. At most 5 per group and 30 in total. Each group reports its total, e.g. "Aliases (12)", and
  has a "Show all" link that opens the grid with `?q=`.

**Grid deep links** (shared grid island):

- `?q=<text>` prefills the grid search.
- `?edit=<uuid>` opens that row's edit dialog once the grid loads. An unknown uuid leaves the grid as
  it is.
- On the dashboard, `?host=` prefills the Hosts card search and shows the matching row.

**Field anchors.** Form fields get stable ids (`field-<id>`). On load, a `#field-…` hash scrolls to the
field and gives it a 2 s highlight.

**Top-bar island** `GlobalSearch`:

- **Markup.** An `<input type="search">` using the ARIA combobox pattern (`role="combobox"`,
  `aria-expanded`, `aria-activedescendant`), with a `role="listbox"` popup grouped by `role="group"`.
- **Calls.** A 150 ms debounce, one server call in flight at a time, and stale responses dropped.
- **Empty and failure states.** "No matches for …", or an error line on failure.
- **Bundle.** The island stays small: it renders result rows from plain data, with no per-group
  components.
  - The bundle is at about 397 KB of 400 KB today.
  - My call: if this feature pushes it over after reasonable slimming, I raise the budget to 430 KB,
    note why in the script, and report the numbers.

## Constraints

- Leptos islands; latest dependencies; no new JS libraries; `unsafe` forbidden; no AI attribution.
- WCAG: the existing `a11y_contrast`/`assert_all_labelled` tests stay green, and keyboard-only use
  works.
- Tests:
  - unit tests for ranking, limits and the permission filter (a user without `page-firewall-alias`
    gets no alias results);
  - component tests for the island markup;
  - Playwright for typing, keyboard navigation, the `?edit=` deep link, field anchors, `/` and ⌘K
    focus, and the phone sheet.

## Left to the builder

- Exact group names and order beyond Pages, Settings, Hosts first.
- How the index cache is invalidated: config revision or apply/commit events, whichever the backend
  already exposes.
