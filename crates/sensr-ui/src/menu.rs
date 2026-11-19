//! The menu manifest: the OPNsense menu tree (same names, same order) as data, merged from
//! per-module fragments the way OPNsense merges each module's `Menu.xml`.
//!
//! Ordering rule (OPNsense `MenuItem`): siblings sort by `order` (default 0), then by id.
//! Only entries whose page sensr really has are listed, so no menu link lands on the "not yet
//! available" page. Entries return as their pages are implemented.

/// Section icons (drawn inline, see `components::icon`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    /// Star.
    Star,
    /// Laptop.
    Lobby,
    /// Chart.
    Reporting,
    /// Server.
    System,
    /// Network tree.
    Interfaces,
    /// Flame.
    Firewall,
    /// Globe.
    Vpn,
    /// Gear.
    Services,
    /// Plug.
    Power,
    /// Life ring.
    Help,
}

/// One node of a manifest fragment.
#[derive(Debug, Clone, Copy)]
pub struct Node {
    /// Id (XML tag in OPNsense), used for merging and ordering.
    pub id: &'static str,
    /// Visible name when it differs from the id.
    pub label: Option<&'static str>,
    /// Sort order.
    pub order: u32,
    /// Link target for leaves.
    pub url: Option<&'static str>,
    /// Section icon (top level only).
    pub icon: Option<Icon>,
    /// Children.
    pub children: &'static [Node],
}

const fn n(id: &'static str) -> Node {
    Node {
        id,
        label: None,
        order: 0,
        url: None,
        icon: None,
        children: &[],
    }
}

impl Node {
    const fn label(mut self, l: &'static str) -> Self {
        self.label = Some(l);
        self
    }
    const fn order(mut self, o: u32) -> Self {
        self.order = o;
        self
    }
    const fn url(mut self, u: &'static str) -> Self {
        self.url = Some(u);
        self
    }
    const fn icon(mut self, i: Icon) -> Self {
        self.icon = Some(i);
        self
    }
    const fn kids(mut self, c: &'static [Node]) -> Self {
        self.children = c;
        self
    }
}

/// Core fragment (OPNsense `Core/Menu/Menu.xml`), limited to what sensr implements.
///
/// OPNsense entries whose page sensr does not have yet are left out on purpose: every link in
/// the tree opens a real page. An entry comes back here when its page exists.
const CORE: &[Node] = &[
    n("Lobby").order(10).icon(Icon::Lobby).kids(&[
        n("Dashboard").order(0).url("/ui/core/dashboard"),
        n("Password").order(2).url("/ui/core/password"),
        n("Logout").order(3).url("/logout"),
    ]),
    n("Reporting").order(15).icon(Icon::Reporting).kids(&[
        n("Traffic").order(20).url("/ui/diagnostics/traffic"),
        n("DNS")
            .order(30)
            .label("Unbound DNS")
            .url("/ui/unbound/overview"),
    ]),
    n("System").order(20).icon(Icon::System).kids(&[
        n("Configuration").kids(&[n("History").url("/ui/core/backup/history")]),
        n("Gateways").kids(&[
            n("Configuration")
                .order(10)
                .url("/ui/routing/configuration"),
            // sensr addition: OPNsense shows the monitor state as a column of Configuration.
            n("Status").order(15).url("/ui/routing/status"),
        ]),
        n("Settings").kids(&[n("General").url("/ui/system/general")]),
    ]),
    n("Interfaces").order(30).icon(Icon::Interfaces),
    n("Firewall")
        .order(40)
        .icon(Icon::Firewall)
        .kids(&[n("Aliases").url("/ui/firewall/alias"), n("NAT")]),
    n("Services").order(60).icon(Icon::Services),
    n("VPN")
        .order(50)
        .icon(Icon::Vpn)
        .kids(&[n("WireGuard").kids(&[
            n("Instances").order(10).url("/ui/wireguard/instances"),
            n("Peers").order(20).url("/ui/wireguard/peers"),
        ])]),
    n("Help").order(80).icon(Icon::Help).kids(&[
        n("Documentation")
            .order(10)
            .url("https://itpick.github.io/sensr/"),
        n("Issues")
            .order(20)
            .label("Issue Tracker")
            .url("https://github.com/itpick/sensr/issues"),
    ]),
];

const FIREWALL: &[Node] = &[n("Firewall").kids(&[
    n("Rule").label("Rules").url("/ui/firewall/filter"),
    n("NAT").kids(&[
        n("SourceNat")
            .order(80)
            .label("Source NAT")
            .url("/ui/firewall/source_nat"),
        n("DNat")
            .order(100)
            .label("Destination NAT")
            .url("/ui/firewall/d_nat"),
    ]),
])];

const INTERFACES: &[Node] = &[n("Interfaces").kids(&[
    n("Assignments").order(200).url("/ui/interfaces/assignment"),
    n("Overview").order(230).url("/ui/interfaces/overview"),
])];

const DIAGNOSTICS: &[Node] =
    &[n("Reporting").kids(&[n("Insight").url("/ui/diagnostics/networkinsight")])];

const SERVICES: &[Node] = &[n("Services").kids(&[
    n("DHCPv4"),
    n("IDS")
        .label("Intrusion Detection")
        .kids(&[n("Administration").order(10).url("/ui/ids")]),
    n("Unbound").label("Unbound DNS").kids(&[
        n("General").order(10).url("/ui/unbound/general"),
        n("Overrides").order(20).url("/ui/unbound/overrides"),
        n("Advanced").order(30).url("/ui/unbound/advanced"),
        n("ACL")
            .order(40)
            .label("Access Lists")
            .url("/ui/unbound/acl"),
        n("Blocklists").order(50).url("/ui/unbound/dnsbl"),
        n("Forward")
            .order(60)
            .label("Query Forwarding")
            .url("/ui/unbound/forward"),
    ]),
])];

const VPN: &[Node] = &[n("VPN").kids(&[n("WireGuard").kids(&[
    n("Instances").order(10).url("/ui/wireguard/instances"),
    n("Peers").order(20).url("/ui/wireguard/peers"),
])])];

/// Every fragment, merged in this order.
pub const FRAGMENTS: &[&[Node]] = &[CORE, FIREWALL, INTERFACES, DIAGNOSTICS, SERVICES, VPN];

/// A merged, sorted menu item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuItem {
    /// Id.
    pub id: String,
    /// Visible name.
    pub label: String,
    /// Sort order.
    pub order: u32,
    /// Link target.
    pub url: Option<String>,
    /// Section icon.
    pub icon: Option<Icon>,
    /// Children, sorted.
    pub children: Vec<MenuItem>,
}

impl MenuItem {
    fn from_node(node: &Node) -> Self {
        let mut item = Self {
            id: node.id.to_owned(),
            label: node.label.unwrap_or(node.id).to_owned(),
            order: node.order,
            url: node.url.map(str::to_owned),
            icon: node.icon,
            children: Vec::new(),
        };
        item.merge_children(node.children);
        item
    }

    fn merge_children(&mut self, nodes: &[Node]) {
        for node in nodes {
            match self.children.iter_mut().find(|c| c.id == node.id) {
                Some(existing) => existing.merge(node),
                None => self.children.push(Self::from_node(node)),
            }
        }
    }

    fn merge(&mut self, node: &Node) {
        // Later fragments may set attributes the first mention left out (OPNsense semantics).
        if let Some(l) = node.label {
            l.clone_into(&mut self.label);
        }
        if node.order != 0 {
            self.order = node.order;
        }
        if let Some(u) = node.url {
            self.url = Some(u.to_owned());
        }
        if node.icon.is_some() {
            self.icon = node.icon;
        }
        self.merge_children(node.children);
    }

    fn sort(&mut self) {
        sort_items(&mut self.children);
    }

    /// True if this item or a descendant links to `path`.
    pub fn contains(&self, path: &str) -> bool {
        self.url.as_deref().is_some_and(|u| url_matches(u, path))
            || self.children.iter().any(|c| c.contains(path))
    }
}

fn sort_items(items: &mut [MenuItem]) {
    items.sort_by(|a, b| a.order.cmp(&b.order).then_with(|| a.id.cmp(&b.id)));
    for i in items {
        i.sort();
    }
}

/// A link matches the current path exactly, or as a prefix at a `/` boundary.
pub fn url_matches(url: &str, path: &str) -> bool {
    path == url || (path.starts_with(url) && path.as_bytes().get(url.len()) == Some(&b'/'))
}

/// An interface known to the menu (assignments and their DHCP state).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MenuInterface {
    /// Assignment id (`lan`).
    pub id: String,
    /// Description (`LAN`).
    pub description: String,
    /// Has a static IPv4 address, so it can serve DHCPv4.
    pub dhcp_capable: bool,
}

/// Builds the full menu: static fragments plus per-interface entries, sorted.
pub fn build(interfaces: &[MenuInterface]) -> Vec<MenuItem> {
    let mut root = MenuItem::from_node(&n("root"));
    for frag in FRAGMENTS {
        root.merge_children(frag);
    }
    for (i, iface) in interfaces.iter().enumerate() {
        let order = u32::try_from(i).unwrap_or(u32::MAX);
        let item = |url: String| MenuItem {
            id: iface.id.clone(),
            label: format!("[{}]", iface.description),
            order,
            url: Some(url),
            icon: None,
            children: Vec::new(),
        };
        if let Some(menu) = root.children.iter_mut().find(|c| c.id == "Interfaces") {
            menu.children
                .push(item(format!("/ui/interfaces/if/{}", iface.id)));
        }
        if iface.dhcp_capable
            && let Some(dhcp) = root
                .children
                .iter_mut()
                .find(|c| c.id == "Services")
                .and_then(|s| s.children.iter_mut().find(|c| c.id == "DHCPv4"))
        {
            dhcp.children.push(item(format!("/ui/dhcpv4/{}", iface.id)));
        }
    }
    // An empty container (no interfaces can serve DHCP) is hidden, as in OPNsense.
    if let Some(s) = root.children.iter_mut().find(|c| c.id == "Services") {
        s.children
            .retain(|c| c.url.is_some() || !c.children.is_empty());
    }
    root.sort();
    root.children
}

/// The URL of the menu item that best matches `path` (longest matching URL).
pub fn best_url(menu: &[MenuItem], path: &str) -> Option<String> {
    fn walk(items: &[MenuItem], path: &str, best: &mut Option<String>) {
        for item in items {
            if let Some(u) = &item.url
                && url_matches(u, path)
                && best.as_ref().is_none_or(|b| u.len() > b.len())
            {
                *best = Some(u.clone());
            }
            walk(&item.children, path, best);
        }
    }
    let mut best = None;
    walk(menu, path, &mut best);
    best
}

/// The breadcrumb (labels from the section down) of the item whose URL best matches `path`.
pub fn breadcrumb(menu: &[MenuItem], path: &str) -> Vec<String> {
    fn walk(
        items: &[MenuItem],
        path: &str,
        trail: &mut Vec<String>,
        best: &mut (usize, Vec<String>),
    ) {
        for item in items {
            trail.push(item.label.clone());
            if let Some(u) = &item.url
                && url_matches(u, path)
                && u.len() > best.0
            {
                *best = (u.len(), trail.clone());
            }
            walk(&item.children, path, trail, best);
            trail.pop();
        }
    }
    let mut best = (0, Vec::new());
    walk(menu, path, &mut Vec::new(), &mut best);
    best.1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(items: &[MenuItem]) -> Vec<&str> {
        items.iter().map(|i| i.label.as_str()).collect()
    }

    fn find<'a>(items: &'a [MenuItem], path: &[&str]) -> &'a MenuItem {
        let (first, rest) = path.split_first().unwrap();
        let item = items.iter().find(|i| i.id == *first).unwrap();
        if rest.is_empty() {
            item
        } else {
            find(&item.children, rest)
        }
    }

    #[test]
    fn top_level_order_matches_opnsense() {
        let m = build(&[]);
        assert_eq!(
            labels(&m),
            [
                "Lobby",
                "Reporting",
                "System",
                "Interfaces",
                "Firewall",
                "VPN",
                "Services",
                "Help"
            ]
        );
    }

    #[test]
    fn siblings_sort_by_order_then_id() {
        let m = build(&[]);
        assert_eq!(
            labels(&find(&m, &["System"]).children),
            ["Configuration", "Gateways", "Settings"]
        );
        assert_eq!(
            labels(&find(&m, &["Firewall", "NAT"]).children),
            ["Source NAT", "Destination NAT"]
        );
    }

    #[test]
    fn fragments_merge_into_existing_sections() {
        let m = build(&[]);
        assert_eq!(
            labels(&find(&m, &["System", "Settings"]).children),
            ["General"]
        );
        assert_eq!(
            labels(&find(&m, &["Firewall"]).children),
            ["Aliases", "NAT", "Rules"]
        );
        assert_eq!(
            labels(&find(&m, &["Services", "Unbound"]).children),
            [
                "General",
                "Overrides",
                "Advanced",
                "Access Lists",
                "Blocklists",
                "Query Forwarding"
            ]
        );
    }

    /// Every menu link opens a page: internal links are routes `app.rs` serves, the only
    /// exceptions being the logout handler and the per-interface pages built from assignments.
    #[test]
    fn every_menu_link_has_a_page() {
        const ROUTES: &[&str] = &[
            "/ui/core/dashboard",
            "/ui/core/password",
            "/ui/core/backup/history",
            "/ui/diagnostics/traffic",
            "/ui/diagnostics/networkinsight",
            "/ui/interfaces/assignment",
            "/ui/interfaces/overview",
            "/ui/routing/configuration",
            "/ui/routing/status",
            "/ui/firewall/alias",
            "/ui/firewall/filter",
            "/ui/firewall/source_nat",
            "/ui/firewall/d_nat",
            "/ui/ids",
            "/ui/unbound/overview",
            "/ui/unbound/general",
            "/ui/unbound/overrides",
            "/ui/unbound/advanced",
            "/ui/unbound/acl",
            "/ui/unbound/dnsbl",
            "/ui/unbound/forward",
            "/ui/wireguard/instances",
            "/ui/wireguard/peers",
            "/ui/system/general",
        ];
        fn walk(items: &[MenuItem], out: &mut Vec<String>) {
            for item in items {
                if let Some(u) = &item.url {
                    out.push(u.clone());
                }
                walk(&item.children, out);
            }
        }
        let m = build(&[]);
        let mut urls = Vec::new();
        walk(&m, &mut urls);
        for url in urls {
            if url.starts_with("https://") || url == "/logout" {
                continue;
            }
            assert!(
                ROUTES.contains(&url.as_str()),
                "menu link without a page: {url}"
            );
        }
    }

    #[test]
    fn interfaces_are_injected_first_and_dhcp_only_where_capable() {
        let ifs = [
            MenuInterface {
                id: "wan".into(),
                description: "WAN".into(),
                dhcp_capable: false,
            },
            MenuInterface {
                id: "lan".into(),
                description: "LAN".into(),
                dhcp_capable: true,
            },
        ];
        let m = build(&ifs);
        let i = labels(&find(&m, &["Interfaces"]).children);
        assert_eq!(&i[..3], ["[WAN]", "[LAN]", "Assignments"]);
        assert_eq!(
            labels(&find(&m, &["Services", "DHCPv4"]).children),
            ["[LAN]"]
        );
        assert!(
            build(&ifs[..1])
                .iter()
                .all(|s| s.children.iter().all(|c| c.id != "DHCPv4"))
        );
    }

    #[test]
    fn gateway_status_sits_between_configuration_and_group() {
        let m = build(&[]);
        assert_eq!(
            labels(&find(&m, &["System", "Gateways"]).children),
            ["Configuration", "Status"]
        );
        assert_eq!(
            breadcrumb(&m, "/ui/routing/status"),
            ["System", "Gateways", "Status"]
        );
        assert_eq!(
            breadcrumb(&m, "/ui/interfaces/overview"),
            ["Interfaces", "Overview"]
        );
    }

    #[test]
    fn breadcrumb_uses_longest_match() {
        let m = build(&[]);
        assert_eq!(
            breadcrumb(&m, "/ui/firewall/alias"),
            ["Firewall", "Aliases"]
        );
        assert_eq!(
            breadcrumb(&m, "/ui/firewall/filter/lan"),
            ["Firewall", "Rules"]
        );
        assert_eq!(
            breadcrumb(&m, "/ui/core/backup/history"),
            ["System", "Configuration", "History"]
        );
        assert!(url_matches("/ui/a", "/ui/a/b") && !url_matches("/ui/a", "/ui/ab"));
    }
}
