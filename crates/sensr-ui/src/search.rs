//! Global search: one query over pages, settings, the owner's objects and the host inventory.
//!
//! The server builds [`Candidate`]s from the menu, every settings form's fields, every grid's
//! rows in the config document and the inventory, then [`search`] ranks, filters by
//! permission and groups them. The browser only ever sees [`SearchResults`].
//!
//! Secrets never enter the index: a grid row contributes only the columns its grid displays,
//! after [`GridId::redact`], and never a column whose field is a [`FieldKind::Secret`] or whose
//! name looks secret ([`is_secret_name`]).

use serde::{Deserialize, Serialize};

#[cfg(feature = "ssr")]
use crate::form::FieldKind;
#[cfg(feature = "ssr")]
use crate::grid::{Column, ColumnKind};
#[cfg(feature = "ssr")]
use crate::models::{FormId, GridId};

/// Longest query, in characters; the rest is cut off.
pub const MAX_QUERY: usize = 64;
/// Shortest query, in characters, that returns anything.
pub const MIN_QUERY: usize = 2;
/// Hits shown per group.
pub const PER_GROUP: usize = 5;
/// Hits shown in total.
pub const MAX_HITS: usize = 30;

/// Group of menu pages.
pub const PAGES: &str = "Pages";
/// Group of form fields.
pub const SETTINGS: &str = "Settings";
/// Group of inventory hosts.
pub const HOSTS: &str = "Hosts";

/// One result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchHit {
    /// Main text.
    pub title: String,
    /// Second line: the breadcrumb of a page, the page of a setting, the matched secondary
    /// text of a row (description, IP, MAC).
    pub detail: String,
    /// Where it leads.
    pub url: String,
}

/// The hits of one kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchGroup {
    /// Group name ("Pages", "Aliases").
    pub name: String,
    /// Matches in this group, shown or not.
    pub total: usize,
    /// The grid page filtered by the query ("Show all"); `None` for pages, settings, hosts.
    pub more_url: Option<String>,
    /// The best matches, at most [`PER_GROUP`].
    pub hits: Vec<SearchHit>,
}

/// The answer to one query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchResults {
    /// The query as searched: trimmed, case-folded, capped.
    pub query: String,
    /// Groups in display order.
    pub groups: Vec<SearchGroup>,
}

/// Trims, case-folds and caps a query at [`MAX_QUERY`] characters.
pub fn normalize(q: &str) -> String {
    let q: String = q.trim().to_lowercase().chars().take(MAX_QUERY).collect();
    q.trim_end().to_owned()
}

/// Percent-encodes `s` for a query value (RFC 3986 unreserved characters stay).
pub fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A field name that may hold a secret: keys, secrets, passwords, hashes, tokens.
pub fn is_secret_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "key",
        "secret",
        "password",
        "passwd",
        "hash",
        "private",
        "preshared",
        "psk",
        "token",
    ]
    .iter()
    .any(|s| n.contains(s))
}

/// One searchable thing, before ranking.
#[cfg(feature = "ssr")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Group name.
    pub group: String,
    /// Group position: pages, settings, hosts, then grids in menu order.
    pub group_order: u32,
    /// Main text.
    pub title: String,
    /// Default second line.
    pub detail: String,
    /// Link target.
    pub url: String,
    /// Texts matched against the query; the title comes first.
    pub haystack: Vec<String>,
}

#[cfg(feature = "ssr")]
const ORDER_PAGES: u32 = 0;
#[cfg(feature = "ssr")]
const ORDER_SETTINGS: u32 = 1;
#[cfg(feature = "ssr")]
const ORDER_HOSTS: u32 = 2;
#[cfg(feature = "ssr")]
const ORDER_GRIDS: u32 = 3;

#[cfg(feature = "ssr")]
const CRUMB_SEP: &str = " › ";

/// Every menu link inside the UI, matched on its label and its breadcrumb.
#[cfg(feature = "ssr")]
pub fn page_candidates(menu: &[crate::menu::MenuItem]) -> Vec<Candidate> {
    fn walk(items: &[crate::menu::MenuItem], trail: &mut Vec<String>, out: &mut Vec<Candidate>) {
        for item in items {
            trail.push(item.label.clone());
            if let Some(url) = item.url.as_ref().filter(|u| u.starts_with('/')) {
                let crumb = trail.join(CRUMB_SEP);
                out.push(Candidate {
                    group: PAGES.to_owned(),
                    group_order: ORDER_PAGES,
                    title: item.label.clone(),
                    detail: crumb.clone(),
                    url: url.clone(),
                    haystack: vec![item.label.clone(), crumb],
                });
            }
            walk(&item.children, trail, out);
            trail.pop();
        }
    }
    let mut out = Vec::new();
    walk(menu, &mut Vec::new(), &mut out);
    out
}

/// The menu as a router with a LAN that serves DHCP sees it, for page names of scoped forms.
#[cfg(feature = "ssr")]
fn default_menu() -> Vec<crate::menu::MenuItem> {
    crate::menu::build(&[crate::menu::MenuInterface {
        id: "lan".to_owned(),
        description: "LAN".to_owned(),
        dhcp_capable: true,
    }])
}

/// Every field of every settings form (scoped forms at their default scope), matched on its
/// label and help text, linked to the field's input.
#[cfg(feature = "ssr")]
pub fn setting_candidates() -> Vec<Candidate> {
    let menu = default_menu();
    FormId::ALL
        .iter()
        .flat_map(|&form| {
            let page = form.page_url();
            let crumb = crate::menu::breadcrumb(&menu, page).join(CRUMB_SEP);
            let dom = form.dom_id();
            form.fields().iter().map(move |f| {
                let mut haystack = vec![f.label.to_owned()];
                if !f.help.is_empty() {
                    haystack.push(f.help.to_owned());
                }
                Candidate {
                    group: SETTINGS.to_owned(),
                    group_order: ORDER_SETTINGS,
                    title: f.label.to_owned(),
                    detail: crumb.clone(),
                    url: format!("{page}#{}", f.dom_id(&dom)),
                    haystack,
                }
            })
        })
        .collect()
}

/// Whether a grid column may be indexed: it is displayed as text, its field is not a secret
/// input, and its name does not look secret.
#[cfg(feature = "ssr")]
fn indexable(grid: GridId, col: &Column) -> bool {
    !matches!(col.kind, ColumnKind::Bool | ColumnKind::Status)
        && !is_secret_name(col.path)
        && !grid
            .meta()
            .fields
            .iter()
            .any(|f| f.path == col.path && f.kind == FieldKind::Secret)
}

/// The scopes a grid's rows live in: every interface for per-interface grids (and floating
/// rules), the one unscoped view otherwise.
#[cfg(feature = "ssr")]
fn scopes(grid: GridId, doc: &serde_json::Value) -> Vec<String> {
    let interfaces = || {
        crate::adapt::rows(GridId::Assignments, "", doc)
            .into_iter()
            .map(|r| r.key)
    };
    match grid {
        GridId::FilterRules => interfaces().chain(["floating".to_owned()]).collect(),
        GridId::DhcpRanges | GridId::StaticMaps => interfaces().collect(),
        _ => vec![grid.scope(&None)],
    }
}

/// Column paths that name a row, best first.
#[cfg(feature = "ssr")]
const TITLE_PATHS: &[&str] = &["name", "hostname", "description"];

/// Every row of every grid in `doc`, read the way the grid shows it, matched on the columns
/// the grid displays and linked to the row's edit dialog.
#[cfg(feature = "ssr")]
pub fn row_candidates(doc: &serde_json::Value) -> Vec<Candidate> {
    let mut out = Vec::new();
    for (i, &grid) in GridId::ALL.iter().enumerate() {
        let cols: Vec<&Column> = grid
            .columns()
            .iter()
            .filter(|c| indexable(grid, c))
            .collect();
        let order = ORDER_GRIDS + u32::try_from(i).unwrap_or(u32::MAX - ORDER_GRIDS);
        for scope in scopes(grid, doc) {
            let page = grid.scoped_url(&scope);
            for row in crate::adapt::rows(grid, &scope, doc) {
                let view = grid.redact(&row.view);
                let fields: Vec<(&str, String)> = cols
                    .iter()
                    .map(|c| (c.path, crate::grid::cell_text(&view, c)))
                    .filter(|(_, t)| !t.trim().is_empty())
                    .collect();
                let Some(t) = TITLE_PATHS
                    .iter()
                    .find_map(|p| fields.iter().position(|(path, _)| path == p))
                    .or((!fields.is_empty()).then_some(0))
                else {
                    continue;
                };
                let title = fields[t].1.clone();
                let detail = fields
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != t)
                    .find(|(_, (p, _))| *p == "description")
                    .or_else(|| fields.iter().enumerate().find(|(j, _)| *j != t))
                    .map(|(_, (_, text))| text.clone())
                    .unwrap_or_default();
                let mut haystack = vec![title.clone()];
                haystack.extend(
                    fields
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| *j != t)
                        .map(|(_, (_, text))| text.clone()),
                );
                out.push(Candidate {
                    group: grid.group_name().to_owned(),
                    group_order: order,
                    title,
                    detail,
                    url: format!("{page}?edit={}", encode_component(&row.key)),
                    haystack,
                });
            }
        }
    }
    out
}

/// Every inventory host, matched on its names, MAC, addresses and smart label, linked to the
/// dashboard Hosts card filtered to it.
#[cfg(feature = "ssr")]
pub fn host_candidates(hosts: &crate::runtime::HostList) -> Vec<Candidate> {
    hosts
        .hosts
        .iter()
        .map(|h| {
            let label = h.host_label.as_ref().map(|l| l.text()).unwrap_or_default();
            let texts: Vec<String> = [
                h.name.clone(),
                h.reserved_name.clone(),
                h.lease_hostname.clone(),
                h.mac.clone(),
                h.ipv4.clone(),
            ]
            .into_iter()
            .flatten()
            .chain(h.ipv6.iter().cloned())
            .chain([label])
            .filter(|t| !t.trim().is_empty())
            .collect();
            let title = texts.first().cloned().unwrap_or_else(|| h.key.clone());
            let detail = [&h.ipv4, &h.mac]
                .into_iter()
                .flatten()
                .find(|t| **t != title)
                .cloned()
                .unwrap_or_default();
            let mut haystack = vec![title.clone()];
            haystack.extend(texts.into_iter().filter(|t| *t != title));
            Candidate {
                group: HOSTS.to_owned(),
                group_order: ORDER_HOSTS,
                title,
                detail,
                url: format!(
                    "/ui/core/dashboard?host={}#w-hosts",
                    encode_component(&h.key)
                ),
                haystack,
            }
        })
        .collect()
}

#[cfg(feature = "ssr")]
/// How well `field` (case-folded) matches `q`: exact 4, prefix 3, word prefix 2,
/// substring 1, none 0.
fn score(field: &str, q: &str) -> u8 {
    if field == q {
        4
    } else if field.starts_with(q) {
        3
    } else if field.match_indices(q).any(|(i, _)| {
        field[..i]
            .chars()
            .next_back()
            .is_some_and(|c| !c.is_alphanumeric())
    }) {
        2
    } else if field.contains(q) {
        1
    } else {
        0
    }
}

#[cfg(feature = "ssr")]
/// The page part of a link, which is what page privileges cover.
fn page_of(url: &str) -> &str {
    url.split(['?', '#']).next().unwrap_or(url)
}

/// Ranks `cands` against `q`, drops those whose page `may_access` refuses, and groups the
/// best: [`PER_GROUP`] per group, [`MAX_HITS`] in all, groups in their order.
#[cfg(feature = "ssr")]
pub fn search(cands: &[Candidate], q: &str, may_access: &dyn Fn(&str) -> bool) -> SearchResults {
    use std::collections::HashMap;
    let query = normalize(q);
    if query.chars().count() < MIN_QUERY {
        return SearchResults {
            query,
            groups: Vec::new(),
        };
    }
    // Page privilege checks, one per page.
    let mut allowed: HashMap<String, bool> = HashMap::new();
    let mut ok = |url: &str| -> bool {
        let page = page_of(url);
        if let Some(&a) = allowed.get(page) {
            return a;
        }
        let a = may_access(page);
        allowed.insert(page.to_owned(), a);
        a
    };
    // (score, best field, candidate)
    let mut matched: Vec<(u8, usize, &Candidate)> = Vec::new();
    for c in cands {
        let best = c
            .haystack
            .iter()
            .enumerate()
            .map(|(i, h)| (score(&h.to_lowercase(), &query), i))
            .max_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        if let Some((s, i)) = best.filter(|(s, _)| *s > 0)
            && ok(&c.url)
        {
            matched.push((s, i, c));
        }
    }
    matched.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then(a.2.group_order.cmp(&b.2.group_order))
            .then_with(|| a.2.title.to_lowercase().cmp(&b.2.title.to_lowercase()))
            .then_with(|| a.2.title.cmp(&b.2.title))
    });
    let mut totals: HashMap<&str, usize> = HashMap::new();
    for (_, _, c) in &matched {
        *totals.entry(c.group.as_str()).or_default() += 1;
    }
    let mut groups: Vec<(u32, SearchGroup)> = Vec::new();
    let mut shown = 0;
    for (_, field, c) in &matched {
        if shown == MAX_HITS {
            break;
        }
        let idx = match groups.iter().position(|(_, g)| g.name == c.group) {
            Some(i) => i,
            None => {
                let more_url = GridId::ALL
                    .iter()
                    .find(|g| g.group_name() == c.group)
                    .map(|g| format!("{}?q={}", g.page_url(), encode_component(&query)))
                    .filter(|u| ok(u));
                groups.push((
                    c.group_order,
                    SearchGroup {
                        name: c.group.clone(),
                        total: totals.get(c.group.as_str()).copied().unwrap_or(0),
                        more_url,
                        hits: Vec::new(),
                    },
                ));
                groups.len() - 1
            }
        };
        let group = &mut groups[idx].1;
        if group.hits.len() == PER_GROUP {
            continue;
        }
        let matched_text = c.haystack.get(*field).filter(|t| **t != c.title);
        let detail = match matched_text {
            Some(t) if *field > 0 && c.group != PAGES && c.group != SETTINGS => t.clone(),
            _ => c.detail.clone(),
        };
        group.hits.push(SearchHit {
            title: c.title.clone(),
            detail,
            url: c.url.clone(),
        });
        shown += 1;
    }
    groups.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.name.cmp(&b.1.name)));
    SearchResults {
        query,
        groups: groups.into_iter().map(|(_, g)| g).collect(),
    }
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use crate::runtime::{HostLabelView, HostList, HostRow};
    use serde_json::{Value, json};

    fn all() -> &'static dyn Fn(&str) -> bool {
        &|_| true
    }

    fn cand(group: &str, order: u32, title: &str) -> Candidate {
        Candidate {
            group: group.to_owned(),
            group_order: order,
            title: title.to_owned(),
            detail: String::new(),
            url: format!("/x/{group}/{title}"),
            haystack: vec![title.to_owned()],
        }
    }

    fn menu_cands() -> Vec<Candidate> {
        page_candidates(&crate::menu::build(&[]))
    }

    fn aliases(n: usize, name: &str) -> Value {
        let map: serde_json::Map<String, Value> = (1..=n)
            .map(|i| {
                (
                    format!("uuid-{i}"),
                    json!({"enabled": true, "name": format!("{name}{i}"),
                           "content": {"type": "host", "entries": ["10.0.0.1"]},
                           "description": "office"}),
                )
            })
            .collect();
        json!({"firewall": {"aliases": map}})
    }

    fn group<'a>(r: &'a SearchResults, name: &str) -> Option<&'a SearchGroup> {
        r.groups.iter().find(|g| g.name == name)
    }

    #[test]
    fn short_query_returns_nothing() {
        let r = search(&menu_cands(), "a", all());
        assert!(r.groups.is_empty());
        assert!(search(&menu_cands(), "   ", all()).groups.is_empty());
    }

    #[test]
    fn query_is_capped_and_folded() {
        let r = search(&menu_cands(), "  ALIASES  ", all());
        assert_eq!(r.query, "aliases");
        let pages = group(&r, PAGES).expect("pages group");
        assert_eq!(pages.hits[0].title, "Aliases");
        assert_eq!(pages.hits[0].url, "/ui/firewall/alias");
        assert_eq!(pages.hits[0].detail, "Firewall › Aliases");
        let long = "x".repeat(100);
        assert_eq!(
            search(&menu_cands(), &long, all()).query.chars().count(),
            64
        );
    }

    #[test]
    fn ranking_exact_prefix_word_substring() {
        let cands: Vec<_> = ["wlan", "guest lan", "lanbridge", "lan"]
            .iter()
            .map(|t| cand("Aliases", 5, t))
            .collect();
        let r = search(&cands, "lan", all());
        let titles: Vec<_> = r.groups[0].hits.iter().map(|h| h.title.as_str()).collect();
        assert_eq!(titles, ["lan", "lanbridge", "guest lan", "wlan"]);
        assert_eq!(score("x-lan", "lan"), 2);
        assert_eq!(score("lan", "zz"), 0);
    }

    #[test]
    fn limits_per_group_and_total() {
        let r = search(&row_candidates(&aliases(12, "web")), "web", all());
        let g = group(&r, "Aliases").unwrap();
        assert_eq!(g.hits.len(), PER_GROUP);
        assert_eq!(g.total, 12);
        assert_eq!(g.more_url.as_deref(), Some("/ui/firewall/alias?q=web"));
        let r = search(&row_candidates(&aliases(1, "a b")), "a b", all());
        assert_eq!(
            group(&r, "Aliases").unwrap().more_url.as_deref(),
            Some("/ui/firewall/alias?q=a%20b")
        );
        // Many groups: 10 groups of 5 matches each are cut at 30 in all.
        let many: Vec<_> = (0..10)
            .flat_map(|g| (0..5).map(move |i| cand(&format!("G{g}"), 3 + g, &format!("item{i}"))))
            .collect();
        let r = search(&many, "item", all());
        let shown: usize = r.groups.iter().map(|g| g.hits.len()).sum();
        assert_eq!(shown, MAX_HITS);
        assert!(
            r.groups
                .iter()
                .all(|g| g.hits.len() <= PER_GROUP && g.total == 5)
        );
    }

    #[test]
    fn group_order_pages_settings_hosts_first() {
        let doc = aliases(1, "dns_servers");
        let hosts = HostList {
            hosts: vec![HostRow {
                key: "aa:bb:cc:dd:ee:01".into(),
                mac: Some("aa:bb:cc:dd:ee:01".into()),
                name: Some("dns-box".into()),
                ..HostRow::default()
            }],
            ..HostList::default()
        };
        // Built in the "wrong" order on purpose.
        let mut cands = row_candidates(&doc);
        cands.extend(host_candidates(&hosts));
        cands.extend(setting_candidates());
        cands.extend(menu_cands());
        let r = search(&cands, "dns", all());
        let names: Vec<_> = r.groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, [PAGES, SETTINGS, HOSTS, "Aliases"]);
    }

    #[test]
    fn grid_groups_follow_menu_order() {
        let doc = json!({
            "firewall": {
                "aliases": {"a": {"name": "zeta"}},
                "rules": {"r": {"description": "zeta", "interfaces": ["lan"]}}
            },
            "interfaces": {"lan": {"description": "LAN"}},
            "gateways": {"gateways": {"g": {"name": "zeta"}}},
            "wireguard": {"peers": {"p": {"name": "zeta"}}}
        });
        let r = search(&row_candidates(&doc), "zeta", all());
        let names: Vec<_> = r.groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, ["Gateways", "Aliases", "Rules", "Peers"]);
    }

    #[test]
    fn permission_filter_drops_hits() {
        let mut cands = row_candidates(&aliases(3, "web"));
        cands.extend(menu_cands());
        let deny = |u: &str| !u.starts_with("/ui/firewall/alias");
        let r = search(&cands, "web", &deny);
        assert!(group(&r, "Aliases").is_none());
        let r = search(&cands, "aliases", &deny);
        assert!(
            r.groups
                .iter()
                .flat_map(|g| &g.hits)
                .all(|h| !h.url.starts_with("/ui/firewall/alias")),
            "{r:?}"
        );
        // The check sees the page, not the query string.
        let seen = std::cell::RefCell::new(Vec::new());
        let spy = |u: &str| {
            seen.borrow_mut().push(u.to_owned());
            true
        };
        search(&cands, "web", &spy);
        assert!(seen.borrow().iter().all(|u| !u.contains(['?', '#'])));
        assert!(seen.borrow().contains(&"/ui/firewall/alias".to_owned()));
    }

    #[test]
    fn secret_fields_are_not_indexed() {
        let private = "PRIVATEkeyAAAAbbbbCCCCddddEEEEffffGGGGhhhh=";
        let preshared = "PRESHAREDkeyQQQQrrrrSSSSttttUUUUvvvvWWWW=";
        let public = "PUBLICkeyMMMMnnnnOOOOppppQQQQrrrrSSSSzzzz=";
        let hash = "$6$saltsalt$HASHEDpasswordXYZ";
        let client = "OIDCclientSECRETvalue123";
        let doc = json!({
            "wireguard": {
                "peers": {"p1": {"name": "phone", "public_key": public,
                                 "preshared_key": preshared, "private_key": private}},
                "servers": {"s1": {"name": "wg0", "public_key": public,
                                   "private_key": private, "peers": ["p1"]}}
            },
            "system": {
                "users": {"u1": {"name": "alice", "password_hash": hash}},
                "oidc": {"providers": {"o1": {"name": "Login", "client_secret": client}}}
            }
        });
        let cands = row_candidates(&doc);
        assert!(cands.iter().any(|c| c.title == "phone"), "peer indexed");
        for secret in [private, preshared, public, hash, client] {
            for frag in [&secret[..12], &secret[secret.len() - 12..]] {
                let r = search(&cands, frag, all());
                assert!(r.groups.is_empty(), "{frag} matched: {r:?}");
            }
            assert!(
                cands.iter().all(|c| !c.detail.contains(&secret[..12])
                    && !c.haystack.iter().any(|h| h.contains(&secret[..12]))),
                "{secret} reached the index"
            );
        }
        for name in [
            "privkey",
            "psk",
            "pubkey",
            "password_hash",
            "client_secret",
            "api_secret",
            "private_key",
            "preshared_key",
        ] {
            assert!(is_secret_name(name), "{name}");
        }
        assert!(!is_secret_name("description"));
        // No grid indexes a secret input or a secret-looking column.
        for g in GridId::ALL {
            for c in g.columns().iter().filter(|c| indexable(g, c)) {
                assert!(!is_secret_name(c.path), "{g:?} {}", c.path);
                assert!(
                    !g.meta()
                        .fields
                        .iter()
                        .any(|f| f.path == c.path && f.kind == FieldKind::Secret)
                );
            }
        }
    }

    #[test]
    fn setting_links_use_dom_id() {
        let r = search(&setting_candidates(), "hostname", all());
        let spec = FormId::SystemGeneral
            .fields()
            .iter()
            .find(|f| f.path == "hostname")
            .unwrap();
        let want = format!(
            "{}#{}",
            FormId::SystemGeneral.page_url(),
            spec.dom_id(&FormId::SystemGeneral.dom_id())
        );
        assert_eq!(want, "/ui/system/general#form-systemgeneral--hostname");
        let hit = group(&r, SETTINGS)
            .unwrap()
            .hits
            .iter()
            .find(|h| h.url == want)
            .expect("Hostname setting");
        assert_eq!(hit.title, "Hostname");
        assert_eq!(hit.detail, "System › Settings › General");
    }

    #[test]
    fn row_links_use_edit_uuid() {
        let doc = json!({
            "interfaces": {"lan": {"description": "LAN"}, "wan": {"description": "WAN"}},
            "firewall": {
                "aliases": {"0b6e-41": {"name": "printers", "description": "office printers"}},
                "rules": {"r-9": {"description": "printers out", "interfaces": ["wan"]}}
            }
        });
        let r = search(&row_candidates(&doc), "printers", all());
        let alias = &group(&r, "Aliases").unwrap().hits[0];
        assert_eq!(alias.url, "/ui/firewall/alias?edit=0b6e-41");
        assert_eq!(alias.title, "printers");
        assert_eq!(alias.detail, "office printers");
        let rule = &group(&r, "Rules").unwrap().hits[0];
        assert_eq!(rule.url, "/ui/firewall/filter/wan?edit=r-9");
        // A match on a secondary column shows that column.
        let r = search(&row_candidates(&doc), "office", all());
        assert_eq!(
            group(&r, "Aliases").unwrap().hits[0].detail,
            "office printers"
        );
    }

    #[test]
    fn host_links_dashboard() {
        let hosts = HostList {
            hosts: vec![HostRow {
                key: "aa:bb:cc:dd:ee:ff".into(),
                mac: Some("aa:bb:cc:dd:ee:ff".into()),
                name: Some("doorbell".into()),
                ipv4: Some("192.168.1.40".into()),
                ipv6: vec!["fd00::40".into()],
                host_label: Some(HostLabelView {
                    maker: Some("Wyze".into()),
                    kind: "camera".into(),
                    confidence: "high".into(),
                    ..HostLabelView::default()
                }),
                ..HostRow::default()
            }],
            ..HostList::default()
        };
        let cands = host_candidates(&hosts);
        for q in ["doorbell", "AA:BB:CC", "192.168.1.40", "fd00::40", "wyze"] {
            let r = search(&cands, q, all());
            let hit = &group(&r, HOSTS).unwrap_or_else(|| panic!("{q}")).hits[0];
            assert_eq!(
                hit.url,
                "/ui/core/dashboard?host=aa%3Abb%3Acc%3Add%3Aee%3Aff#w-hosts"
            );
            assert_eq!(hit.title, "doorbell");
        }
    }

    #[test]
    fn every_grid_indexes_a_column() {
        for g in GridId::ALL {
            assert!(
                g.columns().iter().any(|c| indexable(g, c)),
                "{g:?} has nothing to search"
            );
        }
    }
}
