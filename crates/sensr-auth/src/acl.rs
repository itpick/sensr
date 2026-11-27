//! Privileges and URL access control with OPNsense semantics.
//!
//! A *privilege* (e.g. `page-system-firmware-manualupdate`) names a set of
//! URL patterns, or none at all: token-only privileges such as
//! `user-config-readonly` gate behaviour, never pages. Users hold privileges
//! directly and through groups; a group may restrict its privileges to
//! source networks. OPNsense counterpart: `Core/ACL.php` + `*/ACL/ACL.xml`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// URLs every authenticated user may reach (logout and the menu), so an
/// unauthorised page never bounces the user to a page they cannot see either.
const ALWAYS_ALLOWED: [&str; 2] = ["index.php?logout", "api/core/menu/*"];

/// The privilege that grants every URL.
pub const PAGE_ALL: &str = "page-all";

/// The token privilege that forbids config writes.
pub const CONFIG_READONLY: &str = "user-config-readonly";

/// An OPNsense ACL URL pattern such as `ui/diagnostics/interface/arp/*`.
///
/// Semantics: the pattern is anchored and matched against the URL path with
/// its leading `/` (a `#fragment` is ignored); `*` matches any run of
/// characters, everything else is literal. A pattern ending in `/*`, `&*` or
/// `?*` also matches the URL without that tail, so `api/core/menu/*` covers
/// `/api/core/menu` too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub struct UrlPattern {
    mask: String,
}

impl UrlPattern {
    /// Builds a pattern from its OPNsense spelling (no leading `/`).
    pub fn new(mask: &str) -> Self {
        Self {
            mask: mask.trim().trim_start_matches('/').to_owned(),
        }
    }

    /// The pattern text.
    pub fn as_str(&self) -> &str {
        &self.mask
    }

    /// Does `url` (e.g. `/ui/firewall/alias/`) fall under this pattern?
    pub fn matches(&self, url: &str) -> bool {
        let url = url.split('#').next().unwrap_or_default();
        let Some(url) = url.strip_prefix('/') else {
            return false;
        };
        if glob(self.mask.as_bytes(), url.as_bytes()) {
            return true;
        }
        let m = self.mask.as_bytes();
        // The "flat" variant: `a/b/*` also matches `a/b`.
        m.len() >= 2
            && m[m.len() - 1] == b'*'
            && matches!(m[m.len() - 2], b'/' | b'&' | b'?')
            && glob(&m[..m.len() - 2], url.as_bytes())
    }
}

impl From<UrlPattern> for String {
    fn from(p: UrlPattern) -> Self {
        p.mask
    }
}

impl From<String> for UrlPattern {
    fn from(s: String) -> Self {
        Self::new(&s)
    }
}

/// Anchored glob match where only `*` is special. Iterative with single
/// backtrack point: linear-ish, no regex, no recursion depth to exhaust.
fn glob(pat: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pat.len() && pat[p] == b'*' {
            star = Some((p, t));
            p += 1;
        } else if p < pat.len() && pat[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some((sp, st)) = star {
            p = sp + 1;
            t = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    pat[p..].iter().all(|&c| c == b'*')
}

/// One privilege definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Privilege {
    /// Display name, e.g. `System: Firmware`.
    pub description: String,
    /// URL patterns; empty for token-only privileges.
    pub patterns: Vec<UrlPattern>,
}

/// All known privileges, by name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    privileges: BTreeMap<String, Privilege>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces a privilege.
    pub fn insert(&mut self, name: &str, description: &str, patterns: &[&str]) {
        self.privileges.insert(
            name.to_owned(),
            Privilege {
                description: description.to_owned(),
                patterns: patterns.iter().map(|p| UrlPattern::new(p)).collect(),
            },
        );
    }

    /// Looks a privilege up.
    pub fn get(&self, name: &str) -> Option<&Privilege> {
        self.privileges.get(name)
    }

    /// All privileges in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Privilege)> {
        self.privileges.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// The privileges sensr itself defines for the routes it serves. Names
    /// match OPNsense's so imported users and groups keep their access.
    pub fn builtin() -> Self {
        let mut r = Self::new();
        r.insert(PAGE_ALL, "All pages", &["*"]);
        r.insert(CONFIG_READONLY, "System: Deny config write", &[]);
        r.insert(
            "page-system-firmware-manualupdate",
            "System: Firmware",
            &["ui/core/firmware/*", "api/core/firmware/*"],
        );
        r.insert(
            "page-status-interfaces",
            "Status: Interfaces",
            &["ui/interfaces/overview", "api/interfaces/overview/*"],
        );
        r.insert(
            "page-firewall-alias-edit",
            "Firewall: Alias: Edit",
            &["ui/firewall/alias/*", "api/firewall/alias/*"],
        );
        r.insert(
            "page-sensr-config",
            "sensr: Configuration (native API)",
            &["api/v1/config/*", "api/v1/apply/*"],
        );
        r.insert(
            "page-sensr-hosts",
            "sensr: Hosts",
            &["ui/core/dashboard/hosts", "api/v1/hosts", "api/v1/hosts/*"],
        );
        r.insert(
            "page-interfaces-assignnetworkports",
            "Interfaces: Assign network ports",
            &["ui/interfaces/assignment", "api/v1/interfaces/*"],
        );
        r.insert(
            "page-services-ids",
            "Services: Intrusion Detection",
            &["ui/ids/*", "api/ids/*", "api/v1/ids/*"],
        );
        r.insert(
            "page-diagnostics-networkinsight",
            "Diagnostics: Network Insight",
            &[
                "ui/diagnostics/networkinsight/*",
                "api/diagnostics/networkinsight/*",
                "api/v1/insight/*",
            ],
        );
        r.insert(
            "page-services-portscan",
            "Services: Port Scanner",
            &["ui/portscan", "ui/portscan/*", "api/v1/portscan/*"],
        );
        r.insert(
            "page-services-guard",
            "Services: Runtime Guard",
            &["ui/guard", "ui/guard/*", "api/v1/guard/*"],
        );
        r.insert(
            "page-sensr-status",
            "sensr: Status (native API)",
            &["api/v1/status", "api/v1/status/*"],
        );
        r.insert(
            "page-status-gateways",
            "Status: Gateways",
            &["ui/routing/gateways/status", "api/routes/gateway/status"],
        );
        r
    }

    /// The first privilege other than [`PAGE_ALL`] whose patterns cover
    /// `url`. Used to prove every served route is guarded (T-0368).
    pub fn covering(&self, url: &str) -> Option<&str> {
        self.privileges
            .iter()
            .filter(|(name, _)| name.as_str() != PAGE_ALL)
            .find(|(_, p)| p.patterns.iter().any(|pat| pat.matches(url)))
            .map(|(name, _)| name.as_str())
    }

    /// Does holding `privileges` give access to `url`?
    pub fn grants<'a>(&self, privileges: impl IntoIterator<Item = &'a str>, url: &str) -> bool {
        privileges
            .into_iter()
            .filter_map(|name| self.privileges.get(name))
            .flat_map(|p| &p.patterns)
            .chain(always_allowed())
            .any(|pat| pat.matches(url))
    }
}

fn always_allowed() -> &'static [UrlPattern] {
    static PATTERNS: std::sync::OnceLock<[UrlPattern; 2]> = std::sync::OnceLock::new();
    PATTERNS.get_or_init(|| ALWAYS_ALLOWED.map(UrlPattern::new))
}

/// An IPv4/IPv6 network in CIDR notation, for group source restrictions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

/// A source network that does not parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid network {0:?}")]
pub struct CidrError(pub String);

impl FromStr for Cidr {
    type Err = CidrError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || CidrError(s.to_owned());
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr.trim().parse().map_err(|_| err())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.trim().parse::<u8>().map_err(|_| err())?,
            None => max,
        };
        if prefix > max {
            return Err(err());
        }
        Ok(Self { addr, prefix })
    }
}

impl Cidr {
    /// Is `ip` inside this network? Different address families never match.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// A user as the ACL sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// Login name.
    pub name: String,
    /// Numeric uid; group membership is by uid.
    pub uid: u32,
    /// Directly assigned privilege names.
    pub privileges: Vec<String>,
}

/// A group as the ACL sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Group name.
    pub name: String,
    /// Member uids.
    pub members: Vec<u32>,
    /// Privilege names granted to members.
    pub privileges: Vec<String>,
    /// When non-empty, the group's privileges apply only to clients from
    /// these networks.
    pub source_networks: Vec<Cidr>,
}

#[derive(Debug)]
struct GroupGrant {
    name: String,
    privileges: BTreeSet<String>,
    source_networks: Vec<Cidr>,
}

impl GroupGrant {
    fn applies_from(&self, remote: Option<IpAddr>) -> bool {
        if self.source_networks.is_empty() {
            return true;
        }
        remote.is_some_and(|ip| self.source_networks.iter().any(|n| n.contains(ip)))
    }
}

#[derive(Debug)]
struct Subject {
    uid: u32,
    direct: BTreeSet<String>,
    groups: Vec<Arc<GroupGrant>>,
}

/// Resolved access rights of every user.
#[derive(Debug)]
pub struct Acl {
    registry: Arc<Registry>,
    users: HashMap<String, Subject>,
}

impl Acl {
    /// Resolves users' group memberships. A group lists members by uid;
    /// unknown uids are ignored.
    pub fn new(registry: Arc<Registry>, users: &[User], groups: &[Group]) -> Self {
        let grants: Vec<(Arc<GroupGrant>, &[u32])> = groups
            .iter()
            .map(|g| {
                (
                    Arc::new(GroupGrant {
                        name: g.name.clone(),
                        privileges: g.privileges.iter().cloned().collect(),
                        source_networks: g.source_networks.clone(),
                    }),
                    g.members.as_slice(),
                )
            })
            .collect();
        let users = users
            .iter()
            .map(|u| {
                let groups = grants
                    .iter()
                    .filter(|(_, members)| members.contains(&u.uid))
                    .map(|(g, _)| g.clone())
                    .collect();
                let subject = Subject {
                    uid: u.uid,
                    direct: u.privileges.iter().cloned().collect(),
                    groups,
                };
                (u.name.clone(), subject)
            })
            .collect();
        Self { registry, users }
    }

    /// The registry the ACL resolves patterns from.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// The uid of `user`, if known.
    pub fn uid(&self, user: &str) -> Option<u32> {
        self.users.get(user).map(|s| s.uid)
    }

    /// Names of the groups `user` belongs to.
    pub fn groups(&self, user: &str) -> Vec<String> {
        self.users
            .get(user)
            .map(|s| s.groups.iter().map(|g| g.name.clone()).collect())
            .unwrap_or_default()
    }

    /// Every privilege `user` holds when connecting from `remote`.
    pub fn effective_privileges(&self, user: &str, remote: Option<IpAddr>) -> BTreeSet<String> {
        let Some(s) = self.users.get(user) else {
            return BTreeSet::new();
        };
        let mut all = s.direct.clone();
        for g in s.groups.iter().filter(|g| g.applies_from(remote)) {
            all.extend(g.privileges.iter().cloned());
        }
        all
    }

    /// Does `user` hold `privilege` (directly or via a group reachable from
    /// `remote`)? `page-all` does not imply token privileges.
    pub fn has_privilege(&self, user: &str, privilege: &str, remote: Option<IpAddr>) -> bool {
        let Some(s) = self.users.get(user) else {
            return false;
        };
        s.direct.contains(privilege)
            || s.groups
                .iter()
                .any(|g| g.privileges.contains(privilege) && g.applies_from(remote))
    }

    /// May `user` open `url` from `remote`?
    pub fn is_page_accessible(&self, user: &str, url: &str, remote: Option<IpAddr>) -> bool {
        let privs = self.effective_privileges(user, remote);
        self.registry.grants(privs.iter().map(String::as_str), url)
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    //! Loads the upstream `AclConfig/config.xml` users/groups and the
    //! upstream ACL XML pattern files into the types above.

    use super::*;
    use quick_xml::events::Event;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/opnsense");

    /// Minimal element tree: enough for `<system><user>…` and `<acl>`.
    #[derive(Debug, Default)]
    pub struct Node {
        pub name: String,
        pub text: String,
        pub children: Vec<Node>,
    }

    impl Node {
        pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
            self.children.iter().filter(move |c| c.name == name)
        }
        pub fn text_of(&self, name: &str) -> String {
            self.all(name)
                .next()
                .map(|n| n.text.clone())
                .unwrap_or_default()
        }
    }

    pub fn parse(path: &str) -> Node {
        let xml = std::fs::read_to_string(path).unwrap();
        let mut reader = quick_xml::Reader::from_str(&xml);
        let mut stack = vec![Node::default()];
        loop {
            match reader.read_event().unwrap() {
                Event::Start(e) => stack.push(Node {
                    name: e.name().as_ref().to_owned(),
                    ..Node::default()
                }),
                Event::Empty(e) => stack.last_mut().unwrap().children.push(Node {
                    name: e.name().as_ref().to_owned(),
                    ..Node::default()
                }),
                Event::Text(t) => {
                    stack.last_mut().unwrap().text += &t;
                }
                Event::CData(t) => {
                    stack.last_mut().unwrap().text += &t;
                }
                Event::End(_) => {
                    let done = stack.pop().unwrap();
                    stack.last_mut().unwrap().children.push(done);
                }
                Event::Eof => break,
                _ => {}
            }
        }
        stack.pop().unwrap().children.pop().unwrap()
    }

    fn csv(nodes: impl Iterator<Item = String>) -> Vec<String> {
        nodes
            .flat_map(|s| s.split(',').map(str::to_owned).collect::<Vec<_>>())
            .filter(|s| !s.is_empty())
            .collect()
    }

    pub fn registry() -> Registry {
        let mut r = Registry::new();
        // `page-all` and the token privilege come from upstream Core/ACL/ACL.xml.
        r.insert(PAGE_ALL, "All pages", &["*"]);
        r.insert(CONFIG_READONLY, "System: Deny config write", &[]);
        let acl = parse(&format!("{DIR}/Diagnostics-ACL.xml"));
        for privilege in &acl.children {
            let patterns: Vec<String> = privilege
                .all("patterns")
                .flat_map(|p| p.all("pattern"))
                .map(|p| p.text.trim().to_owned())
                .collect();
            let refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
            r.insert(&privilege.name, &privilege.text_of("name"), &refs);
        }
        r
    }

    pub fn acl() -> Acl {
        let cfg = parse(&format!("{DIR}/AclConfig/config.xml"));
        let system = cfg.all("system").next().unwrap();
        let users: Vec<User> = system
            .all("user")
            .map(|u| User {
                name: u.text_of("name"),
                uid: u.text_of("uid").parse().unwrap(),
                privileges: csv(u.all("priv").map(|p| p.text.clone())),
            })
            .collect();
        let groups: Vec<Group> = system
            .all("group")
            .map(|g| Group {
                name: g.text_of("name"),
                members: csv(g.all("member").map(|m| m.text.clone()))
                    .iter()
                    .map(|m| m.parse().unwrap())
                    .collect(),
                privileges: csv(g.all("priv").map(|p| p.text.clone())),
                source_networks: csv(g.all("source_networks").map(|n| n.text.clone()))
                    .iter()
                    .map(|n| n.parse().unwrap())
                    .collect(),
            })
            .collect();
        Acl::new(Arc::new(registry()), &users, &groups)
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::acl;
    use super::*;

    const ARP: &str = "/ui/diagnostics/interface/arp/";

    #[test]
    fn fixture_loads_t0012() {
        let acl = acl();
        assert_eq!(acl.uid("root"), Some(0));
        assert_eq!(acl.groups("root"), vec!["admins".to_owned()]);
        assert!(acl.registry().get("page-diagnostics-arptable").is_some());
    }

    #[test]
    fn root_lacks_readonly_priv_t0013() {
        assert!(!acl().has_privilege("root", CONFIG_READONLY, None));
    }

    #[test]
    fn user_priv_direct_t0014() {
        assert!(acl().has_privilege("test1", CONFIG_READONLY, None));
    }

    #[test]
    fn user_priv_via_group_member_t0015() {
        assert!(acl().has_privilege("test2", CONFIG_READONLY, None));
    }

    #[test]
    fn user_priv_denied_t0016() {
        assert!(!acl().has_privilege("test3", CONFIG_READONLY, None));
    }

    #[test]
    fn page_all_known_url_t0017() {
        assert!(acl().is_page_accessible("root", ARP, None));
    }

    #[test]
    fn page_all_unknown_url_t0018() {
        assert!(acl().is_page_accessible("root", "/non_existing_page", None));
    }

    #[test]
    fn page_priv_direct_url_match_t0019() {
        assert!(acl().is_page_accessible("test2", ARP, None));
    }

    #[test]
    fn page_priv_via_group_t0020() {
        assert!(acl().is_page_accessible("test4", ARP, None));
    }

    #[test]
    fn token_priv_grants_no_page_t0021() {
        assert!(!acl().is_page_accessible("test1", ARP, None));
    }

    #[test]
    fn unknown_user_has_nothing() {
        let acl = acl();
        assert!(!acl.has_privilege("nobody", PAGE_ALL, None));
        assert!(!acl.is_page_accessible("nobody", ARP, None));
    }

    #[test]
    fn menu_and_logout_always_allowed() {
        let acl = acl();
        assert!(acl.is_page_accessible("test3", "/api/core/menu/tree", None));
        assert!(acl.is_page_accessible("test3", "/api/core/menu", None));
        assert!(acl.is_page_accessible("test3", "/index.php?logout", None));
        assert!(!acl.is_page_accessible("test3", "/index.php", None));
    }

    #[test]
    fn url_pattern_semantics() {
        let p = UrlPattern::new("ui/diagnostics/interface/arp/*");
        assert!(p.matches("/ui/diagnostics/interface/arp/"));
        assert!(p.matches("/ui/diagnostics/interface/arp"));
        assert!(p.matches("/ui/diagnostics/interface/arp/x/y#frag"));
        assert!(!p.matches("/ui/diagnostics/interface/arpx"));
        assert!(!p.matches("ui/diagnostics/interface/arp/"));
        // `.` and `?` are literal, not regex.
        let p = UrlPattern::new("diag_backup.php*");
        assert!(p.matches("/diag_backup.php?x=1"));
        assert!(!p.matches("/diag_backupXphp"));
        let p = UrlPattern::new("api/diagnostics/interface/get_arp*");
        assert!(p.matches("/api/diagnostics/interface/get_arp"));
        assert!(p.matches("/api/diagnostics/interface/get_arp_table"));
        let p = UrlPattern::new("ui/routing/configuration");
        assert!(p.matches("/ui/routing/configuration"));
        assert!(!p.matches("/ui/routing/configuration/x"));
    }

    #[test]
    fn source_networks_restrict_group_privileges() {
        let registry = Arc::new(Registry::builtin());
        let users = [User {
            name: "op".into(),
            uid: 10,
            privileges: vec![],
        }];
        let groups = [Group {
            name: "lan-admins".into(),
            members: vec![10],
            privileges: vec![PAGE_ALL.into()],
            source_networks: vec![
                "192.168.1.0/24".parse().unwrap(),
                "fd00::/8".parse().unwrap(),
            ],
        }];
        let acl = Acl::new(registry, &users, &groups);
        let lan: IpAddr = "192.168.1.7".parse().unwrap();
        let wan: IpAddr = "203.0.113.9".parse().unwrap();
        let ula: IpAddr = "fd12::1".parse().unwrap();
        assert!(acl.is_page_accessible("op", "/api/v1/status", Some(lan)));
        assert!(acl.is_page_accessible("op", "/api/v1/status", Some(ula)));
        assert!(!acl.is_page_accessible("op", "/api/v1/status", Some(wan)));
        assert!(!acl.is_page_accessible("op", "/api/v1/status", None));
        assert!(acl.has_privilege("op", PAGE_ALL, Some(lan)));
        assert!(!acl.has_privilege("op", PAGE_ALL, Some(wan)));
    }

    #[test]
    fn cidr_parsing() {
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("garbage".parse::<Cidr>().is_err());
        let host: Cidr = "10.1.2.3".parse().unwrap();
        assert!(host.contains("10.1.2.3".parse().unwrap()));
        assert!(!host.contains("10.1.2.4".parse().unwrap()));
        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
        assert!(!all.contains("::1".parse().unwrap()));
    }

    #[test]
    fn builtin_registry_covers_sensr_routes() {
        let r = Registry::builtin();
        assert_eq!(
            r.covering("/api/v1/config/system/hostname"),
            Some("page-sensr-config")
        );
        assert_eq!(
            r.covering("/api/core/firmware/info"),
            Some("page-system-firmware-manualupdate")
        );
        assert_eq!(r.covering("/nowhere"), None);
    }

    #[test]
    fn runtime_guard_privilege_covers_its_pages_and_api_only() {
        let r = Registry::builtin();
        for url in [
            "/ui/guard",
            "/ui/guard/rules",
            "/api/v1/guard/status",
            "/api/v1/guard/events",
            "/api/v1/guard/kill-switch",
        ] {
            assert_eq!(r.covering(url), Some("page-services-guard"), "{url}");
            assert!(r.grants(["page-services-guard"], url), "{url}");
            assert!(!r.grants(["page-services-ids"], url), "{url}");
        }
        assert!(!r.grants(["page-services-guard"], "/api/v1/ids/alerts"));
        assert!(!r.grants(["page-services-guard"], "/ui/guardian"));
        assert_eq!(
            r.get("page-services-guard").unwrap().description,
            "Services: Runtime Guard"
        );
    }

    proptest::proptest! {
        /// A pattern without `*` matches exactly its own URL.
        #[test]
        fn literal_pattern_matches_only_itself(mask in "[a-z/._?&=]{1,24}", other in "[a-z/._?&=]{0,24}") {
            let p = UrlPattern::new(&mask);
            let mask = p.as_str().to_owned();
            let own = format!("/{mask}");
            proptest::prop_assert!(p.matches(&own));
            if other != mask {
                let url = format!("/{other}");
                proptest::prop_assert!(!p.matches(&url));
            }
        }

        /// `prefix*` matches every extension of the prefix.
        #[test]
        fn trailing_star_is_prefix_match(prefix in "[a-z/._]{1,16}", rest in "[a-z/._?&=]{0,16}") {
            let p = UrlPattern::new(&format!("{prefix}*"));
            let prefix = p.as_str().trim_end_matches('*').to_owned();
            let url = format!("/{prefix}{rest}");
            proptest::prop_assert!(p.matches(&url));
        }

        #[test]
        fn matcher_never_panics(mask in ".{0,32}", url in ".{0,64}") {
            let _ = UrlPattern::new(&mask).matches(&url);
        }
    }
}
