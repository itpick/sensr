//! The menu manifest: the OPNsense menu tree (same names, same order) as data, merged from
//! per-module fragments the way OPNsense merges each module's `Menu.xml`.
//!
//! Ordering rule (OPNsense `MenuItem`): siblings sort by `order` (default 0), then by id.
//! Items sensr implements point at sensr routes; the rest keep their OPNsense URL and land on
//! the "not yet available" page, so the tree is complete from day one.

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

/// Core fragment (OPNsense `Core/Menu/Menu.xml`).
const CORE: &[Node] = &[
    n("Lobby").order(10).icon(Icon::Lobby).kids(&[
        n("Dashboard").order(0).url("/ui/core/dashboard"),
        // no License item: sensr has no license page (and the OPNsense URL
        // only landed on "not yet available")
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
        n("Access").kids(&[
            n("Users").order(10).url("/ui/auth/user"),
            n("Groups").order(20).url("/ui/auth/group"),
            n("Privileges").order(25).url("/ui/auth/priv"),
            n("Servers").order(30).url("/ui/auth/server"),
            n("Tester").order(40).url("/ui/auth/tester"),
        ]),
        n("Configuration").kids(&[
            n("Backups").url("/ui/core/backup"),
            n("Defaults").url("/ui/core/defaults"),
            n("History").url("/ui/core/backup/history"),
            n("Wizard").url("/ui/core/initial_setup"),
        ]),
        n("Firmware").kids(&[
            n("Status").order(10).url("/ui/core/firmware/status"),
            n("Settings").order(20).url("/ui/core/firmware/settings"),
            n("Changelog").order(30).url("/ui/core/firmware/changelog"),
            n("Updates").order(40).url("/ui/core/firmware/updates"),
            n("Plugins").order(50).url("/ui/core/firmware/plugins"),
            n("Packages").order(60).url("/ui/core/firmware/packages"),
            n("Reporter").order(70).url("/ui/core/crash_reporter"),
            n("LogFile")
                .order(80)
                .label("Log File")
                .url("/ui/diagnostics/log/core/pkg"),
        ]),
        n("Gateways").kids(&[
            n("Configuration")
                .order(10)
                .url("/ui/routing/configuration"),
            // sensr addition: OPNsense shows the monitor state as a column of Configuration.
            n("Status").order(15).url("/ui/routing/status"),
            n("Group").order(20).url("/ui/routing/gateway_groups"),
            n("LogFile")
                .order(30)
                .label("Log File")
                .url("/ui/diagnostics/log/core/gateways"),
        ]),
        n("HighAvailability").label("High Availability").kids(&[
            n("Settings").order(100).url("/ui/core/hasync"),
            n("Status").order(200).url("/ui/core/hasync_status"),
        ]),
        n("Routes").kids(&[
            n("Configuration").order(10).url("/ui/routes"),
            n("LogFile")
                .order(100)
                .label("Log File")
                .url("/ui/diagnostics/log/core/routing"),
        ]),
        n("Settings").kids(&[
            n("Administration").url("/ui/system/administration"),
            n("General").url("/ui/system/general"),
            n("Miscellaneous").url("/ui/system/miscellaneous"),
            n("Tunables").url("/ui/core/tunables"),
        ]),
        n("Snapshots").url("/ui/core/snapshots"),
        n("Trust").kids(&[
            n("Authorities").url("/ui/trust/ca"),
            n("Certificates").url("/ui/trust/cert"),
            n("Revocation").url("/ui/trust/crl"),
            n("Settings").url("/ui/trust/settings"),
        ]),
        n("LogFiles").order(150).label("Log Files").kids(&[
            n("Audit").url("/ui/diagnostics/log/core/audit"),
            n("Backend").url("/ui/diagnostics/log/core/configd"),
            n("Boot").url("/ui/diagnostics/log/core/boot"),
            n("General").url("/ui/diagnostics/log/core/system"),
            n("WebGUI")
                .label("Web GUI")
                .url("/ui/diagnostics/log/core/webgui"),
        ]),
        n("Diagnostics")
            .order(160)
            .kids(&[n("Services").url("/ui/core/service")]),
    ]),
    n("Interfaces").order(30).icon(Icon::Interfaces),
    n("Firewall").order(40).icon(Icon::Firewall).kids(&[
        n("Aliases").url("/ui/firewall/alias"),
        n("Categories").url("/ui/firewall/category"),
        n("Groups").url("/ui/firewall/group"),
        n("NAT"),
        n("Schedules").order(210).url("/ui/firewall/schedule"),
        n("Diagnostics").order(500).kids(&[
            n("Aliases").url("/ui/firewall/alias_util"),
            n("States").url("/ui/diagnostics/firewall/states"),
            n("Sessions").url("/ui/diagnostics/firewall/sessions"),
            n("Statistics").url("/ui/diagnostics/firewall/statistics"),
        ]),
        n("LogFiles").order(400).label("Log Files").kids(&[
            n("General").url("/ui/diagnostics/log/core/firewall"),
            n("Live")
                .label("Live View")
                .url("/ui/diagnostics/firewall/log"),
            n("Overview").url("/ui/diagnostics/firewall/stats"),
            n("Plain")
                .label("Plain View")
                .url("/ui/diagnostics/log/core/filter"),
        ]),
    ]),
    n("Services").order(60).icon(Icon::Services),
    n("VPN")
        .order(50)
        .icon(Icon::Vpn)
        .kids(&[n("OpenVPN").kids(&[
            n("Instances").order(10).url("/ui/openvpn/instances"),
            n("CSC")
                .order(30)
                .label("Client Specific Overrides")
                .url("/ui/openvpn/client_overwrites"),
            n("ClientExport")
                .order(40)
                .label("Client Export")
                .url("/ui/openvpn/export"),
            n("Status")
                .order(60)
                .label("Connection Status")
                .url("/ui/openvpn/status"),
            n("LogFile")
                .order(70)
                .label("Log File")
                .url("/ui/diagnostics/log/core/openvpn"),
        ])]),
    n("Power").order(70).icon(Icon::Power).kids(&[
        n("Reboot").order(10).url("/ui/core/reboot"),
        n("PowerOff")
            .order(20)
            .label("Power Off")
            .url("/ui/core/halt"),
    ]),
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
        n("OneToOne")
            .order(200)
            .label("One-to-One NAT")
            .url("/ui/firewall/one_to_one"),
        n("NPTv6").order(500).url("/ui/firewall/npt"),
    ]),
    n("Settings").order(200).url("/ui/firewall/settings"),
])];

const INTERFACES: &[Node] = &[n("Interfaces").kids(&[
    n("Assignments").order(200).url("/ui/interfaces/assignment"),
    n("Devices").order(210).kids(&[
        n("Bridge").url("/ui/interfaces/bridge"),
        n("GIF").url("/ui/interfaces/gif"),
        n("GRE").url("/ui/interfaces/gre"),
        n("LAGG").url("/ui/interfaces/lagg"),
        n("Loopback").url("/ui/interfaces/loopback"),
        n("PPP").label("Point-to-Point").url("/ui/interfaces/ppp"),
        n("TAP").url("/ui/interfaces/tap"),
        n("VLAN").url("/ui/interfaces/vlan"),
        n("VXLAN").url("/ui/interfaces/vxlan"),
    ]),
    n("Neighbors").order(225).url("/ui/interfaces/neighbor"),
    n("Overview").order(230).url("/ui/interfaces/overview"),
    n("Settings").order(240).url("/ui/interfaces/settings"),
    n("VIP").order(250).label("Virtual IPs").kids(&[
        n("Settings").url("/ui/interfaces/vip"),
        n("Status").url("/ui/diagnostics/interface/vip"),
    ]),
    n("Wireless")
        .order(260)
        .kids(&[n("Devices").url("/ui/interfaces/wireless")]),
    n("Diagnostics").order(270).kids(&[
        n("ARPTable")
            .label("ARP Table")
            .url("/ui/diagnostics/interface/arp"),
        n("DNSLookup")
            .label("DNS Lookup")
            .url("/ui/diagnostics/dns_diagnostics"),
        n("NDPTable")
            .label("NDP Table")
            .url("/ui/diagnostics/interface/ndp"),
        n("Netstat").url("/ui/diagnostics/interface/netstat"),
        n("PacketCapture")
            .label("Packet Capture")
            .url("/ui/diagnostics/packet_capture"),
        n("Ping").url("/ui/diagnostics/ping"),
        n("TestPort")
            .label("Port Probe")
            .url("/ui/diagnostics/portprobe"),
        n("Traceroute")
            .label("Trace Route")
            .url("/ui/diagnostics/traceroute"),
    ]),
])];

const DIAGNOSTICS: &[Node] = &[
    n("Reporting").kids(&[
        n("Health").url("/ui/diagnostics/systemhealth"),
        n("Insight").url("/ui/diagnostics/networkinsight"),
        n("NetFlow").url("/ui/diagnostics/netflow"),
    ]),
    n("System").kids(&[
        n("Diagnostics").kids(&[
            n("Activity").url("/ui/diagnostics/activity"),
            n("Statistics").url("/ui/diagnostics/system/memory"),
        ]),
        n("Routes").kids(&[n("Status")
            .order(20)
            .url("/ui/diagnostics/interface/routes")]),
        n("Settings").kids(&[n("Cron").url("/ui/cron"), n("Logging").url("/ui/syslog")]),
    ]),
];

const SERVICES: &[Node] = &[n("Services").kids(&[
    n("CaptivePortal").label("Captive Portal").kids(&[
        n("Administration").order(10).url("/ui/captiveportal"),
        n("Sessions").order(20).url("/ui/captiveportal/session"),
        n("Vouchers").order(30).url("/ui/captiveportal/voucher"),
        n("Log")
            .order(40)
            .label("Log File")
            .url("/ui/diagnostics/log/core/portalauth"),
    ]),
    n("DHCRelay").kids(&[
        n("Configuration").url("/ui/dhcrelay/relay"),
        n("LogFile")
            .label("Log File")
            .url("/ui/diagnostics/log/core/dhcrelay"),
    ]),
    n("DHCPv4"),
    n("IDS").label("Intrusion Detection").kids(&[
        n("Administration").order(10).url("/ui/ids"),
        n("Policy").order(20).url("/ui/ids/policy"),
        n("Log")
            .order(100)
            .label("Log File")
            .url("/ui/diagnostics/log/core/suricata"),
    ]),
    n("Monit").kids(&[
        n("Settings").url("/ui/monit"),
        n("Status").url("/ui/monit/status"),
        n("Log")
            .order(100)
            .label("Log File")
            .url("/ui/diagnostics/log/core/monit"),
    ]),
    n("NTP").label("Network Time").kids(&[
        n("General").order(10).url("/ui/ntpd/general"),
        n("Status").order(40).url("/ui/ntpd/status"),
        n("Log")
            .order(50)
            .label("Log File")
            .url("/ui/diagnostics/log/core/ntpd"),
    ]),
    n("RouterAdv")
        .label("Router Advertisements")
        .url("/ui/radvd/settings"),
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
        n("Dot")
            .order(70)
            .label("DNS over TLS")
            .url("/ui/unbound/dot"),
        n("Statistics").order(90).url("/ui/unbound/stats"),
        n("LogFile")
            .order(100)
            .label("Log File")
            .url("/ui/diagnostics/log/core/resolver"),
    ]),
])];

const VPN: &[Node] = &[n("VPN").kids(&[
    n("IPsec").kids(&[
        n("Connections").order(5).url("/ui/ipsec/connections"),
        n("Keys")
            .order(30)
            .label("Pre-Shared Keys")
            .url("/ui/ipsec/pre_shared_keys"),
        n("KeyPairs")
            .order(40)
            .label("Key Pairs")
            .url("/ui/ipsec/key_pairs"),
        n("Status")
            .order(60)
            .label("Status Overview")
            .url("/ui/ipsec/sessions"),
        n("LogFile")
            .order(100)
            .label("Log File")
            .url("/ui/diagnostics/log/core/ipsec"),
    ]),
    n("WireGuard").kids(&[
        n("Instances").order(10).url("/ui/wireguard/instances"),
        n("Peers").order(20).url("/ui/wireguard/peers"),
        n("Status").order(40).url("/ui/wireguard/diagnostics"),
        n("LogFile")
            .order(50)
            .label("Log File")
            .url("/ui/diagnostics/log/core/wireguard"),
    ]),
])];

/// Firewall › Shaper (TrafficShaper module).
const SHAPER: &[Node] = &[n("Firewall").kids(&[n("Shaper").kids(&[
    n("Pipes").order(10).url("/ui/trafficshaper/pipes"),
    n("Queues").order(20).url("/ui/trafficshaper/queues"),
    n("Rules").order(30).url("/ui/trafficshaper/rules"),
    n("Status").order(40).url("/ui/trafficshaper/status"),
])])];

/// Every fragment, merged in this order.
pub const FRAGMENTS: &[&[Node]] = &[
    CORE,
    FIREWALL,
    INTERFACES,
    DIAGNOSTICS,
    SERVICES,
    VPN,
    SHAPER,
];

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
                "Power",
                "Help"
            ]
        );
    }

    #[test]
    fn siblings_sort_by_order_then_id() {
        let m = build(&[]);
        // System children without order sort by id; LogFiles (150) and Diagnostics (160) last.
        assert_eq!(
            labels(&find(&m, &["System"]).children),
            [
                "Access",
                "Configuration",
                "Firmware",
                "Gateways",
                "High Availability",
                "Routes",
                "Settings",
                "Snapshots",
                "Trust",
                "Log Files",
                "Diagnostics"
            ]
        );
        assert_eq!(
            labels(&find(&m, &["Firewall", "NAT"]).children),
            ["Source NAT", "Destination NAT", "One-to-One NAT", "NPTv6"]
        );
    }

    #[test]
    fn fragments_merge_into_existing_sections() {
        let m = build(&[]);
        let settings = find(&m, &["System", "Settings"]);
        assert_eq!(
            labels(&settings.children),
            [
                "Administration",
                "Cron",
                "General",
                "Logging",
                "Miscellaneous",
                "Tunables"
            ]
        );
        let fw = labels(&find(&m, &["Firewall"]).children);
        assert_eq!(
            fw,
            [
                "Aliases",
                "Categories",
                "Groups",
                "NAT",
                "Rules",
                "Shaper",
                "Settings",
                "Schedules",
                "Log Files",
                "Diagnostics"
            ]
        );
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
            ["Configuration", "Status", "Group", "Log File"]
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
