# Global Search Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a search box in the top bar, right of the wordmark, that finds pages, settings, hosts and every config object the user may see. Each result links straight to the item.

**Architecture:**
- **Pure search core** (`crates/sensr-ui/src/search.rs`):
  - builds candidates from the menu manifest, every `FormKind` field, every `GridKind` row in a config document, and the host inventory;
  - ranks them and groups them;
  - filters them through a `may_access` predicate.
- **Server function** `global_search`: runs the core over the backend's current document (staged candidate if any, else applied), behind a small per-user cache.
- **Deep links:** grids honour `?q=` / `?edit=<uuid>`, forms honour `#<field dom id>`, and the dashboard honours `?host=`.
- **`GlobalSearch` island:** renders the box with the ARIA combobox pattern, the keyboard shortcuts and a phone sheet.

**Tech Stack:** Rust, Leptos 0.8 SSR + islands, Playwright.

**Spec:** docs/superpowers/specs/2026-11-23-global-search-design.md

## Global Constraints

- **Placement and shortcuts:** the box is directly right of the wordmark in `.topbar`. `/` focuses it (unless focus is already in an input, textarea, select or contenteditable), and so does Ctrl+K / ⌘K.
- **Groups, in this order:** `Pages`, `Settings`, `Hosts`, then one group per grid type, named after that grid's menu label (e.g. `Aliases`, `Rules`, `Port Forward`, `DHCP reservations`, `Host Overrides`, `Gateways`, `Peers`). Order follows menu order.
- **Query:** trimmed, case-folded, capped at **64** chars. Fewer than **2** chars returns no results.
- **Ranking:** exact (score 4) > prefix (3) > word-prefix (2) > substring (1) on the best-matching field. Ties sort by group order, then by name.
- **Limits:** at most **5** per group and **30** in total. Each group carries its `total`.
- **Links:**
  - page: its URL;
  - setting: `<page url>#<FieldSpec::dom_id(form)>`;
  - grid row: `<grid page url>?edit=<uuid>`;
  - group "Show all": `<grid page url>?q=<query>`;
  - host: `/ui/core/dashboard?host=<url-encoded key>#w-hosts`.
- **Permissions:** every result URL passes `Backend::may_access(url)`. A user without the page privilege gets no results from that page.
- **Island behaviour:** 150 ms debounce, one request in flight, stale responses dropped.
- **Empty and error copy:** empty result copy is exactly `No matches for “<q>”`; the error copy is `Search failed: <message>`.
- **Phone (≤600px):** the box collapses to a magnifier `icon-btn` with `aria-label="Search"`. It opens a full-width sheet with the same combobox; Esc or the close button dismisses it.
- **Bundle budget:** CI enforces 400 KB brotli (`crates/sensr-ui/scripts/bundle-size.sh`); it is about 397 KB today.
  - Controller ruling: if the feature exceeds it after reasonable slimming, raise the budget to **430 KB** in the script, with the comment `global search (2026-11-23)`, and report the numbers.
- **Project rules:**
  - latest deps, no new crates or JS libraries;
  - `unsafe` forbidden;
  - no AI attribution in commits;
  - commit prefix `ui:` / `api:`.
- **Toolchain:**
  - `export PATH=$HOME/.cargo/bin:$PATH CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=$HOME/workspace/itpick/sensr/target`;
  - `touch crates/sensr-ui/src/lib.rs` before `cargo leptos build --release`, because the target dir is shared between worktrees.

## Review Focus

1. **Permission leak through the cache.** User A (full access) searches, then user B (no firewall privileges) searches the same text within the cache window. B must get no alias or rule results. Pin in Task 2 with `cache_is_per_privilege_set`.
2. **Secrets in results.** Grid rows hold secret-like fields: WireGuard private/preshared keys, user password hashes, OIDC client secrets, API secrets. Searching for a fragment of a key must not match it, and a snippet must never show it. Pin in Task 1 with `secret_fields_are_not_indexed`, which covers every field whose `FieldKind` is a password/secret kind or whose name contains `key`, `secret`, `password` or `hash`.
3. **`?edit=` to a uuid that no longer exists** (deleted since the search ran). The grid loads normally, with no dialog and no error toast. Pin in Task 3 with `edit_param_unknown_uuid_is_ignored`.
4. **Hostile text in config** (an alias description like `<img onerror=…>`) must render as text in the dropdown. Pin in Task 4 with `results_escape_text`.
5. **Typing fast:** 8 keystrokes inside 150 ms must produce exactly 1 server call, and a slow early response must not overwrite a later one. Pin in Task 5 (e2e) with `debounces_and_drops_stale`.

---

### Task 1: Pure search core (`crates/sensr-ui/src/search.rs`)

**Files:**
- Create: `crates/sensr-ui/src/search.rs`. Register it in `lib.rs`, available to both the ssr and hydrate builds; the hydrate build needs only the result types.
- Test: the module's own tests.

**Interfaces:**
- **Produces the result types**, all `Serialize`/`Deserialize`/`Clone`/`PartialEq`/`Debug`:
  - `pub struct SearchHit { pub title: String, pub detail: String, pub url: String }`. `detail` holds the breadcrumb for a page, the page name for a setting, and the matched secondary text for a row (description, IP, MAC).
  - `pub struct SearchGroup { pub name: String, pub total: usize, pub more_url: Option<String>, pub hits: Vec<SearchHit> }`.
  - `pub struct SearchResults { pub query: String, pub groups: Vec<SearchGroup> }`.
- **Produces the candidate type:** `pub struct Candidate { pub group: String, pub group_order: u32, pub title: String, pub detail: String, pub url: String, pub haystack: Vec<String> }`. Not serialized; ssr only.
- **Produces the builders:**
  - `pub fn page_candidates(menu: &[crate::menu::MenuItem]) -> Vec<Candidate>`.
  - `pub fn setting_candidates() -> Vec<Candidate>`, built from every `FormKind` page.
    - It needs a page URL per `FormId` and per `GridId`. Find or add a single `fn page_url(id) -> &'static str` registry next to `FormId`/`GridId` in `models.rs`.
    - Scoped forms (Interface, DHCP per interface) use their default scope.
  - `pub fn row_candidates(doc: &serde_json::Value) -> Vec<Candidate>`. For every `GridKind`, read its rows from `doc` the same way the grid backend does (reuse the existing path/adapter code; do not duplicate the JSON walking) and index the fields its `columns()` display.
  - `pub fn host_candidates(hosts: &crate::runtime::HostList) -> Vec<Candidate>`. Index name, MAC, IPv4, IPv6 and the smart label text (if the label field exists on `main`; skip it gracefully otherwise).
- **Produces the search function:** `pub fn search(cands: &[Candidate], q: &str, may_access: &dyn Fn(&str) -> bool) -> SearchResults`.

- [ ] **Step 1: Write failing tests:**
  - `short_query_returns_nothing`: `"a"` gives empty groups.
  - `query_is_capped_and_folded`: `"  ALIASES  "` finds the Aliases page; a 100-char query is truncated to 64 in `SearchResults.query`.
  - `ranking_exact_prefix_word_substring`: candidates titled `lan`, `lanbridge`, `guest lan`, `wlan` for query `lan` rank in that order.
  - `limits_per_group_and_total`: 12 alias matches return 5 hits with `total == 12`, and `more_url == Some("/ui/firewall/alias?q=…")` (whatever the real aliases URL is, plus `?q=` URL-encoded). Many groups cap the total at 30.
  - `group_order_pages_settings_hosts_first`.
  - `permission_filter_drops_hits`: a `may_access` that denies the aliases URL removes the Aliases group entirely.
  - `secret_fields_are_not_indexed`: a WireGuard peer document with `preshared_key` / `public_key` / `private_key` values. Searching a key fragment of the private or preshared key gives nothing.
    - A *public* key may be indexed only if the peers grid shows it as a column. Decide by `columns()`: never index fields of a password/secret `FieldKind`, nor fields named `*private*`, `*secret*`, `*password*`, `*hash*`, `*preshared*`.
  - `setting_links_use_dom_id`: the "Hostname" setting links to `<system general url>#<FieldSpec::dom_id(form)>`.
  - `row_links_use_edit_uuid`.
  - `host_links_dashboard`: `/ui/core/dashboard?host=aa%3Abb%3A…#w-hosts`.
- [ ] **Step 2:** `cargo test -p sensr-ui --features ssr --lib search` must FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Pass, plus `cargo clippy -p sensr-ui --features ssr --all-targets -- -D warnings`.
- [ ] **Step 5:** Commit: `ui: global search core over pages, settings, config rows and hosts`.

### Task 2: Server function, backend wiring and cache

**Files:**
- Modify: `crates/sensr-ui/src/api.rs`. Add Backend `fn search_document(&self) -> BoxFuture<'_, ApiResult<serde_json::Value>>`, returning the staged candidate if one exists, else the applied document.
  - If an existing method already returns that, reuse it and skip the new method.
- Modify: `crates/sensr-api/src/ui.rs` (impl), `crates/sensr-ui/src/mock.rs` (impl over the mock doc).
- Modify: `crates/sensr-ui/src/actions.rs`. Add the server fn `global_search(q: String) -> Result<SearchResults, ServerFnError>`, which:
  1. gets the menu (the same way the shell builds it);
  2. gets the doc and the host list, where the caller may see hosts;
  3. builds candidates;
  4. calls `search` with `b.may_access`.
- Cache: an in-process `Mutex<Option<(key, Arc<Vec<Candidate>>)>>`. The key is the config revision or doc hash plus the caller's privilege set, sorted and joined. Host candidates are rebuilt per call and are not cached.

- [ ] **Step 1: Write failing tests** in `crates/sensr-ui/tests/components.rs`, or a new `tests/search.rs` using the mock backend:
  - `global_search_finds_mock_alias`;
  - `global_search_read_only_user_still_searches`;
  - `cache_is_per_privilege_set`: a full user, then a user without the firewall pages, searching the same query; the second gets no Aliases/Rules groups;
  - `global_search_sees_staged_objects`: stage a new alias in the mock and it is found.
- [ ] **Step 2:** They fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `cargo test -p sensr-ui --features ssr` and `cargo test -p sensr-api` pass; clippy is clean.
- [ ] **Step 5:** Commit: `ui: global_search server function with a per-user index cache`.

### Task 3: Deep links (grid `?q=` / `?edit=`, form field anchors, dashboard `?host=`)

**Files:**
- Modify: the shared grid island in `crates/sensr-ui/src/pages.rs` / `islands.rs` (`Grid<T: GridKind>`):
  - on hydrate, read `?q=` into the grid search;
  - after the first load, if `?edit=<uuid>` matches a row, open that row's edit dialog exactly as clicking its edit button does;
  - an unknown uuid is ignored;
  - then remove `edit` from the URL with `history.replaceState`, so a reload doesn't reopen it.
- Modify: the settings form.
  - The field inputs already use `FieldSpec::dom_id`.
  - On hydrate, if `location.hash` names an element in the form, scroll it into view, focus it, and add the class `field-flash` to its `.field` row for 2 s.
  - Add the CSS: a 2 s background fade using `var(--accent-bg)`, or an existing highlight token.
- Modify: the dashboard `HostsCard`. Read `?host=` into its search signal on hydrate.
- Test: `crates/sensr-ui/tests/components.rs` where the SSR output can show it (e.g. the grid renders `?q=` into the search input's value when the page is server-rendered with that query). The rest goes in Task 5 e2e.

- [ ] **Step 1: Write failing tests:**
  - `grid_q_param_prefills_search` (SSR);
  - `hosts_card_host_param_prefills_search` (SSR);
  - `edit_param_unknown_uuid_is_ignored`, as a unit test of the pure helper `fn edit_target(rows: &[String], param: Option<&str>) -> Option<usize>`.
- [ ] **Step 2:** They fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Tests and both clippy runs (ssr, and wasm hydrate) pass.
- [ ] **Step 5:** Commit: `ui: grid ?q= and ?edit= deep links, field anchors, dashboard ?host=`.

### Task 4: `GlobalSearch` island in the top bar

**Files:**
- Modify: `crates/sensr-ui/src/app.rs` `.topbar`. Place `<GlobalSearch/>` right after the wordmark link, and only for logged-in pages: the login page has no search.
- Create the island in `crates/sensr-ui/src/islands.rs`, or `src/search_box.rs` if islands.rs is the convention.
- Markup:
  - `<div class="gsearch">`;
  - `<input type="search" role="combobox" aria-label="Search sensr" aria-autocomplete="list" aria-controls="gsearch-list" aria-expanded=… aria-activedescendant=… placeholder="Search  /">`;
  - `<div id="gsearch-list" role="listbox">`, with groups as `role="group" aria-label=<name>` and options as `role="option" id="gsearch-opt-N"`, each holding title and detail;
  - per group, a "Show all (<total>)" option when `total > hits.len()` and `more_url` is set.
- Behaviour:
  - Debounce, single flight and stale-drop, per Global Constraints.
  - ↑/↓ wraps over options; Enter navigates to the active option (`window.location.assign`); Esc closes, or clears if already closed.
  - Clicking outside closes it.
  - `/` and Ctrl/⌘K focus it.
  - Phone sheet per Global Constraints.
- Bundle: keep it small. Render the options as plain views from data, with no per-group components. Measure before and after.
- CSS in `style/main.css`: width about 320px, growing to 420px on focus. The dropdown uses card styling with max-height 70vh and scrolls. Colours come only from tokens. Dark mode and phone layout must both work.
- Tests in `crates/sensr-ui/tests/components.rs`:
  - `gsearch_renders_after_wordmark`;
  - `gsearch_absent_on_login`;
  - `results_escape_text`: render a `SearchResults` whose title is `<img src=x onerror=alert(1)>` through the island's result view and assert there is no `<img` element, only text;
  - `assert_all_labelled` on the top bar.

- [ ] **Step 1: Write the failing tests.**
- [ ] **Step 2:** They fail.
- [ ] **Step 3:** Implement, then build: `touch crates/sensr-ui/src/lib.rs && cargo leptos build --release && crates/sensr-ui/scripts/bundle-size.sh`. Apply the budget ruling if needed.
- [ ] **Step 4:** Tests, both clippy runs and the a11y contrast test pass.
- [ ] **Step 5:** Commit: `ui: global search box in the top bar`.

### Task 5: End-to-end tests (Playwright)

**Files:**
- Create: `crates/sensr-ui/e2e/tests/global-search.spec.ts`, following the existing specs' helpers.

- [ ] **Step 1: Write the specs:**
  - `finds a page`: type `dhcp`, get a Pages hit, Enter lands on the DHCP page.
  - `finds a setting and flashes it`: type `hostname`, open the Settings hit; the field is focused and has `field-flash`.
  - `finds an alias and opens its dialog`: type a mock alias name, open it; the edit dialog is open with that alias.
  - `show all opens the filtered grid`.
  - `finds a host`: type the bench-pi MAC prefix; it lands on the dashboard with the Hosts search prefilled.
  - `keyboard`: `/` focuses, ↓↓ Enter navigates, Esc closes, ⌘K / Ctrl+K focuses.
  - `read-only user sees no hidden pages`: use the existing read-only fixture.
  - `debounces_and_drops_stale`: route-intercept the server fn, count requests (exactly 1 for 8 fast keystrokes), delay the first response, and assert the later query's results win.
  - `phone sheet`: at 390px, the magnifier opens the sheet, results appear, and Esc closes it.
  - `no matches`: shows `No matches for “zzzz”`.
  - An a11y check with the dropdown open, in both themes, if the suite has an axe helper.
- [ ] **Step 2:** Run the new spec, then the whole suite (after a fresh `touch` + release build).
- [ ] **Step 3:** Fix selectors and fixtures only; product bugs go back to the owning task.
- [ ] **Step 4:** The whole suite passes.
- [ ] **Step 5:** Commit: `ui: e2e for global search`.

---

## Done when

- `cargo test --workspace`, clippy (workspace and wasm), fmt, `xtask parity --check`, `lint-fixtures`, bundle-size and the Playwright suite all pass in CI. The nix VM jobs are flaky on main and are not a gate.
- PR merged, released and installed on the router (pre-authorized), with a health check after.
