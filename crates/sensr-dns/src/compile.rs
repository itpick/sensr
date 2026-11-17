//! Blocklist policies → Unbound local zones.
//!
//! OPNsense keeps every listed name in a Python dict inside Unbound and
//! decides per query (policy by client network, passlist regex, wildcard
//! walk). sensr decides at compile time and hands Unbound plain local
//! zones, which it answers natively:
//!
//! - policies without source networks go to the global `server:` zones;
//! - clients in a policy's source networks get an Unbound `view` holding
//!   their policies, consulted first (`view-first: yes`), so the most
//!   specific policy for a client wins and global policies still apply to
//!   names it does not list;
//! - within one zone set, a name listed by several policies keeps the
//!   highest-priority policy (smallest source network first, then
//!   configuration order), names below a blocked subtree are dropped, and
//!   allowed or local names inside a blocked subtree become `transparent`
//!   holes.
//!
//! Answers: a subtree with the default `0.0.0.0` is `always_null` (A
//! `0.0.0.0`, AAAA `::`); another address is a `redirect` zone with that A
//! record; NXDOMAIN is `always_nxdomain`. An exact name is a `local-data` A
//! record (its subdomains resolve normally); an exact name with NXDOMAIN
//! also covers its subdomains, as Unbound has no exact NXDOMAIN zone.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use sensr_apply::appliers::dns_runtime::{BlocklistRuntime, PolicyRuntime};
use sensr_apply::appliers::unbound::AclAction;
use sensr_schema::Uuid;
use sensr_schema::models::dnsbl::{AllowEntry, BlockAnswer};

use crate::name::{Key, ancestors};
use crate::parse::Entry;

/// A policy as the compiler uses it.
#[derive(Debug)]
pub struct Policy {
    /// The policy's UUID.
    pub id: Uuid,
    /// Its description.
    pub description: String,
    /// Answer for its names.
    pub answer: BlockAnswer,
    /// Client networks; empty for everyone.
    pub nets: Vec<IpNet>,
    allow_exact: BTreeSet<Key>,
    allow_subtree: Vec<Key>,
    allow_patterns: Vec<fancy_regex::Regex>,
}

impl Policy {
    /// From the runtime configuration; invalid regexes (the schema already
    /// rejects them) are skipped.
    pub fn new(p: &PolicyRuntime) -> Self {
        let mut allow_exact = BTreeSet::new();
        let mut allow_subtree = Vec::new();
        let mut allow_patterns = Vec::new();
        for a in &p.policy.allow {
            match a {
                AllowEntry::Domain(d) => {
                    allow_exact.extend(Key::parse(d.as_str()));
                }
                AllowEntry::Subtree(d) => {
                    allow_subtree.extend(Key::parse(d.as_str()));
                }
                AllowEntry::Pattern(r) => {
                    // OPNsense matches with re.match: anchored at the start,
                    // case-insensitive.
                    if let Ok(re) = fancy_regex::Regex::new(&format!("(?i)^(?:{r})")) {
                        allow_patterns.push(re);
                    }
                }
            }
        }
        Self {
            id: p.id,
            description: p.policy.description.to_string(),
            answer: p.policy.answer,
            nets: p.policy.source_nets.clone(),
            allow_exact,
            allow_subtree,
            allow_patterns,
        }
    }

    fn allows(&self, key: &Key) -> bool {
        self.allow_exact.contains(key)
            || self.allow_subtree.iter().any(|a| key.is_within(a))
            || (!self.allow_patterns.is_empty() && {
                let name = key.name();
                self.allow_patterns
                    .iter()
                    .any(|re| re.is_match(&name).unwrap_or(false))
            })
    }

    /// OPNsense's priority: the largest source network of the policy (in
    /// addresses); policies without networks come last.
    fn priority(&self) -> u128 {
        self.nets
            .iter()
            .map(|n| match n {
                IpNet::V4(n) => 1u128 << (32 - n.prefix_len()),
                IpNet::V6(n) => 1u128
                    .checked_shl(128 - u32::from(n.prefix_len()))
                    .unwrap_or(u128::MAX),
            })
            .max()
            .unwrap_or(u128::MAX)
    }
}

/// A compiled zone entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    /// The name.
    pub key: Key,
    /// Covers the subtree.
    pub subtree: bool,
    /// Index into [`Compiled::policies`].
    pub policy: usize,
}

/// One set of zones (global, or one view).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Group {
    /// Blocked names, sorted by key.
    pub zones: Vec<Zone>,
    /// Allowed names inside blocked subtrees, sorted.
    pub holes: Vec<Key>,
}

impl Group {
    fn find(&self, key: &str) -> Option<&Zone> {
        self.zones
            .binary_search_by(|z| z.key.as_str().cmp(key))
            .ok()
            .map(|i| &self.zones[i])
    }

    fn is_hole(&self, key: &str) -> bool {
        self.holes.binary_search_by(|h| h.as_str().cmp(key)).is_ok()
    }

    /// The closest zone at or above `key` that covers it, as Unbound picks
    /// the closest enclosing local zone.
    fn decide(&self, key: &Key) -> Option<Verdict> {
        for (i, cand) in std::iter::once(key.as_str())
            .chain(ancestors(key.as_str()))
            .enumerate()
        {
            if self.is_hole(cand) {
                return Some(Verdict::Allowed);
            }
            if let Some(z) = self.find(cand) {
                // An exact name is a transparent zone with data at its apex
                // only: names below it resolve normally.
                return Some(if i == 0 || z.subtree {
                    Verdict::Blocked(z.policy)
                } else {
                    Verdict::Allowed
                });
            }
        }
        None
    }
}

/// A view: the zone set for clients in `nets`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    /// Unbound view name.
    pub name: String,
    /// Client networks.
    pub nets: Vec<IpNet>,
    /// Zones.
    pub group: Group,
}

/// What the resolver does with a name for a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Blocked by this policy (index into [`Compiled::policies`]).
    Blocked(usize),
    /// Explicitly allowed (a hole), or not covered by a blocking zone.
    Allowed,
}

/// The compiled blocklist.
#[derive(Debug)]
pub struct Compiled {
    /// Policies, in priority order.
    pub policies: Vec<Policy>,
    /// Zones for every client.
    pub global: Group,
    /// Zones for clients in source networks.
    pub views: Vec<View>,
    /// Access control, to keep each view network's action.
    pub default_action: AclAction,
    /// Access lists.
    pub acls: Vec<(IpNet, AclAction)>,
}

/// The names a policy's sources produced (curated lists and URLs).
pub type Sources<'a> = &'a BTreeMap<String, Vec<Entry>>;

/// Compiles `cfg`'s policies from the downloaded `sources` (URL → entries).
/// Missing sources contribute nothing.
pub fn compile(cfg: &BlocklistRuntime, sources: Sources<'_>) -> Compiled {
    let mut indexed: Vec<(usize, &PolicyRuntime, Policy)> = cfg
        .policies
        .iter()
        .enumerate()
        .map(|(i, p)| (i, p, Policy::new(p)))
        .collect();
    // Smallest source network first, then configuration order.
    indexed.sort_by_key(|(i, _, p)| (p.priority(), *i));
    let protected: Vec<Key> = cfg
        .protected
        .iter()
        .filter_map(|d| Key::parse(d.as_str()))
        .collect();
    let runtimes: Vec<&PolicyRuntime> = indexed.iter().map(|(_, r, _)| *r).collect();
    let policies: Vec<Policy> = indexed.into_iter().map(|(_, _, p)| p).collect();

    let global_members: Vec<usize> = (0..policies.len())
        .filter(|&i| policies[i].nets.is_empty())
        .collect();
    let global = build_group(&policies, &runtimes, &global_members, sources, &protected);

    // One view per distinct set of policies a network is subject to: every
    // policy with a network that contains it.
    let mut by_members: BTreeMap<Vec<usize>, Vec<IpNet>> = BTreeMap::new();
    for net in policies.iter().flat_map(|p| p.nets.iter()) {
        let members: Vec<usize> = (0..policies.len())
            .filter(|&i| policies[i].nets.iter().any(|n| n.contains(net)))
            .collect();
        let nets = by_members.entry(members).or_default();
        if !nets.contains(net) {
            nets.push(*net);
        }
    }
    let views = by_members
        .into_iter()
        .enumerate()
        .map(|(i, (members, nets))| View {
            name: format!("sensr-bl-{}", i + 1),
            nets,
            group: build_group(&policies, &runtimes, &members, sources, &protected),
        })
        .collect();
    Compiled {
        policies,
        global,
        views,
        default_action: cfg.default_action,
        acls: cfg.acls.clone(),
    }
}

fn policy_entries<'a>(
    rt: &'a PolicyRuntime,
    sources: Sources<'a>,
) -> impl Iterator<Item = (Key, bool)> + 'a {
    let listed = rt
        .policy
        .sources()
        .into_iter()
        .flat_map(move |u| sources.get(&u).into_iter().flatten())
        .map(|e| (e.key.clone(), e.subtree));
    let exact = rt
        .policy
        .block
        .iter()
        .filter_map(|d| Key::parse(d.as_str()))
        .map(|k| (k, false));
    let subtrees = rt
        .policy
        .block_subtrees
        .iter()
        .filter_map(|d| Key::parse(d.as_str()))
        .map(|k| (k, true));
    listed.chain(exact).chain(subtrees)
}

fn is_localhost(k: &Key) -> bool {
    // OPNsense's default exclude `.*localhost$`.
    k.as_str() == "localhost" || k.as_str().starts_with("localhost\x01")
}

fn build_group(
    policies: &[Policy],
    runtimes: &[&PolicyRuntime],
    members: &[usize],
    sources: Sources<'_>,
    protected: &[Key],
) -> Group {
    // (key, subtree, policy index) for every member; members are in
    // priority order, so the policy index doubles as the rank.
    let mut all: Vec<(Key, bool, usize)> = Vec::new();
    for &m in members {
        let p = &policies[m];
        all.extend(
            policy_entries(runtimes[m], sources)
                .filter(|(k, _)| {
                    !is_localhost(k) && !protected.iter().any(|pr| k.is_within(pr)) && !p.allows(k)
                })
                .map(|(k, s)| (k, s, m)),
        );
    }
    all.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.2.cmp(&b.2)));

    let mut zones: Vec<Zone> = Vec::with_capacity(all.len());
    // The last kept subtree: names below it are already blocked.
    let mut cover: Option<usize> = None;
    for (key, subtree, policy) in all {
        if let Some(last) = zones.last_mut()
            && last.key == key
        {
            // Listed again (another list or a lower-priority policy): the
            // first policy keeps it, the subtree flag accumulates.
            last.subtree |= subtree;
            if last.subtree && cover != Some(zones.len() - 1) {
                cover = Some(zones.len() - 1);
            }
            continue;
        }
        if let Some(c) = cover {
            let cz = &zones[c];
            if key.is_within(&cz.key)
                && (policy >= cz.policy || policies[policy].answer == policies[cz.policy].answer)
            {
                continue;
            }
        }
        zones.push(Zone {
            key,
            subtree,
            policy,
        });
        if subtree {
            cover = Some(zones.len() - 1);
        }
    }

    // Holes: allowed or local names that a kept subtree still covers.
    let group = Group {
        zones,
        holes: Vec::new(),
    };
    let mut holes = BTreeSet::new();
    let candidates = members
        .iter()
        .flat_map(|&m| {
            policies[m]
                .allow_exact
                .iter()
                .chain(policies[m].allow_subtree.iter())
        })
        .chain(protected.iter());
    for k in candidates {
        if ancestors(k.as_str())
            .filter_map(|a| group.find(a))
            .next()
            .is_some_and(|z| z.subtree)
        {
            holes.insert(k.clone());
        }
    }
    Group {
        holes: holes.into_iter().collect(),
        ..group
    }
}

impl Compiled {
    /// Total blocked names (global and views).
    pub fn len(&self) -> usize {
        self.global.zones.len()
            + self
                .views
                .iter()
                .map(|v| v.group.zones.len())
                .sum::<usize>()
    }

    /// True when nothing is blocked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Names per policy (by UUID).
    pub fn counts(&self) -> BTreeMap<Uuid, u64> {
        let mut out: BTreeMap<Uuid, u64> = self.policies.iter().map(|p| (p.id, 0)).collect();
        for z in self
            .global
            .zones
            .iter()
            .chain(self.views.iter().flat_map(|v| v.group.zones.iter()))
        {
            *out.entry(self.policies[z.policy].id).or_default() += 1;
        }
        out
    }

    /// What Unbound will answer `name` for `client` with this compilation
    /// (`None`: no blocklist zone applies).
    pub fn lookup(&self, client: IpAddr, name: &str) -> Option<Verdict> {
        let key = Key::parse(name)?;
        let view = self
            .views
            .iter()
            .filter_map(|v| {
                v.nets
                    .iter()
                    .filter(|n| n.contains(&client))
                    .map(|n| n.prefix_len())
                    .max()
                    .map(|len| (len, v))
            })
            .max_by_key(|(len, _)| *len)
            .map(|(_, v)| v);
        if let Some(v) = view
            && let Some(verdict) = v.group.decide(&key)
        {
            return Some(verdict);
        }
        self.global.decide(&key)
    }

    /// The effective access-control action for `net`: the most specific
    /// access list containing it, else the default.
    fn action_for(&self, net: &IpNet) -> AclAction {
        self.acls
            .iter()
            .filter(|(n, _)| n.contains(net))
            .max_by_key(|(n, _)| n.prefix_len())
            .map(|(_, a)| *a)
            .unwrap_or(self.default_action)
    }

    /// The Unbound include file.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(self.len() * 40 + 256);
        out.push_str("# Generated by sensr-dns; do not edit.\nserver:\n");
        render_group(&mut out, &self.global, &self.policies);
        for v in &self.views {
            for n in &v.nets {
                // A view entry is an access-control element of its own: give
                // it the action the network already has.
                if !self.acls.iter().any(|(a, _)| a == n) {
                    let _ = writeln!(
                        out,
                        "  access-control: {n} {}",
                        acl_keyword(self.action_for(n))
                    );
                }
                let _ = writeln!(out, "  access-control-view: {n} \"{}\"", v.name);
            }
        }
        for v in &self.views {
            let _ = writeln!(out, "view:\n  name: \"{}\"\n  view-first: yes", v.name);
            render_group(&mut out, &v.group, &self.policies);
        }
        out
    }
}

/// Unbound's keyword for an action.
pub fn acl_keyword(a: AclAction) -> &'static str {
    match a {
        AclAction::Allow => "allow",
        AclAction::Deny => "deny",
        AclAction::Refuse => "refuse",
        AclAction::AllowSnoop => "allow_snoop",
        AclAction::DenyNonLocal => "deny_non_local",
        AclAction::RefuseNonLocal => "refuse_non_local",
    }
}

/// The include lines for one zone (one or two).
pub fn zone_lines(z: &Zone, answer: BlockAnswer, out: &mut String) {
    let name = z.key.name();
    match (answer, z.subtree) {
        (BlockAnswer::Address { address }, true) if address == Ipv4Addr::UNSPECIFIED => {
            let _ = writeln!(out, "  local-zone: \"{name}.\" always_null");
        }
        (BlockAnswer::Address { address }, true) => {
            let _ = writeln!(out, "  local-zone: \"{name}.\" redirect");
            let _ = writeln!(out, "  local-data: \"{name}. A {address}\"");
        }
        (BlockAnswer::Address { address }, false) => {
            let _ = writeln!(out, "  local-data: \"{name}. A {address}\"");
        }
        (BlockAnswer::Nxdomain, _) => {
            let _ = writeln!(out, "  local-zone: \"{name}.\" always_nxdomain");
        }
    }
}

fn render_group(out: &mut String, g: &Group, policies: &[Policy]) {
    for z in &g.zones {
        zone_lines(z, policies[z.policy].answer, out);
    }
    for h in &g.holes {
        let _ = writeln!(out, "  local-zone: \"{}.\" transparent", h.name());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensr_schema::models::dnsbl::Blocklist;

    fn rt(id: u128, desc: &str, f: impl FnOnce(&mut Blocklist)) -> PolicyRuntime {
        let mut b = Blocklist::new(desc.parse().unwrap());
        f(&mut b);
        PolicyRuntime {
            id: Uuid::from_u128(id),
            policy: b,
        }
    }

    fn cfg(policies: Vec<PolicyRuntime>) -> BlocklistRuntime {
        BlocklistRuntime {
            policies,
            protected: vec!["home.arpa".parse().unwrap()],
            default_action: AclAction::Allow,
            acls: Vec::new(),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn blocked_by(c: &Compiled, client: &str, name: &str) -> Option<Uuid> {
        match c.lookup(ip(client), name) {
            Some(Verdict::Blocked(i)) => Some(c.policies[i].id),
            _ => None,
        }
    }

    /// OPNsense's dnsbl test fixture (scripts/unbound-dnsbl/tests/dnsbl.json)
    /// as policies: `580e7f8b…` for three source networks with custom
    /// blocks and wildcards plus the `0.beer` list entry, and the catch-all
    /// `709af075…` with only `0.beer`. Its passlist regex
    /// `^always_allow\..*` becomes the allow entry for the one name the
    /// tests pass: sensr compiles allowlists, and a regex cannot carve a hole
    /// into a blocked subtree.
    fn opnsense_fixture() -> Compiled {
        const A: u128 = 0x580e7f8b_3242_401a_b32e_ed56c3e8cf4a;
        const B: u128 = 0x709af075_f67f_40ca_959a_ec7c900991da;
        let list = "https://lists.example/hgz007.txt";
        let mut sources = BTreeMap::new();
        sources.insert(
            list.to_owned(),
            vec![Entry {
                key: Key::parse("0.beer").unwrap(),
                subtree: true,
            }],
        );
        let c = cfg(vec![
            rt(A, "xxxx2", |b| {
                b.urls = vec![list.parse().unwrap()];
                b.block = vec![
                    "block.1.local".parse().unwrap(),
                    "block.2.local".parse().unwrap(),
                ];
                b.block_subtrees = vec![
                    "wildcard.1.local".parse().unwrap(),
                    "wildcard.2.local".parse().unwrap(),
                ];
                b.source_nets = vec![
                    "10.0.0.0/24".parse().unwrap(),
                    "10.0.1.0/24".parse().unwrap(),
                    "::/24".parse().unwrap(),
                ];
                b.allow = vec!["always_allow.wildcard.2.local".parse().unwrap()];
            }),
            rt(B, "xxxx", |b| b.urls = vec![list.parse().unwrap()]),
        ]);
        compile(&c, &sources)
    }

    const POLICY_A: &str = "580e7f8b-3242-401a-b32e-ed56c3e8cf4a";
    const POLICY_B: &str = "709af075-f67f-40ca-959a-ec7c900991da";

    #[test]
    fn net_matches_policy_t0335() {
        let c = opnsense_fixture();
        for name in ["block.1.local", "0.beer"] {
            assert_eq!(
                blocked_by(&c, "10.0.0.1", name).map(|u| u.to_string()),
                Some(POLICY_A.into()),
                "{name}"
            );
        }
    }

    #[test]
    fn wildcard_and_passlist_boundary_t0336() {
        let c = opnsense_fixture();
        for name in [
            "a.wildcard.2.local",
            "wildcard.2.local",
            "always_allowx.wildcard.2.local",
        ] {
            assert_eq!(
                blocked_by(&c, "10.0.0.1", name).map(|u| u.to_string()),
                Some(POLICY_A.into()),
                "{name}"
            );
        }
    }

    #[test]
    fn catch_all_policy_t0337() {
        let c = opnsense_fixture();
        assert_eq!(
            blocked_by(&c, "10.10.10.1", "0.beer").map(|u| u.to_string()),
            Some(POLICY_B.into())
        );
        // The custom names are only for the policy's networks.
        assert_eq!(blocked_by(&c, "10.10.10.1", "block.1.local"), None);
    }

    #[test]
    fn passlist_exempts_t0338() {
        let c = opnsense_fixture();
        assert_eq!(
            c.lookup(ip("10.0.0.1"), "always_allow.wildcard.2.local"),
            Some(Verdict::Allowed)
        );
    }

    #[test]
    fn subtrees_absorb_their_names_and_duplicates() {
        let mut sources: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
        let e = |n: &str, s| Entry {
            key: Key::parse(n).unwrap(),
            subtree: s,
        };
        sources.insert(
            "u1".into(),
            vec![
                e("ads.example.com", true),
                e("x.ads.example.com", false),
                e("y.ads.example.com", true),
                e("other.example.com", false),
                e("ads.localhost", false),
                e("printer.home.arpa", false),
            ],
        );
        sources.insert(
            "u2".into(),
            vec![e("other.example.com", false), e("ads.example.com", false)],
        );
        let c = compile(
            &cfg(vec![rt(1, "one", |b| {
                b.urls = vec!["https://u1.example/".parse().unwrap()];
            })]),
            &BTreeMap::new(),
        );
        assert!(c.is_empty());
        let mut s2 = BTreeMap::new();
        s2.insert(
            "https://u1.example/".to_owned(),
            sources.remove("u1").unwrap(),
        );
        s2.insert(
            "https://u2.example/".to_owned(),
            sources.remove("u2").unwrap(),
        );
        let c = compile(
            &cfg(vec![rt(1, "one", |b| {
                b.urls = vec![
                    "https://u1.example/".parse().unwrap(),
                    "https://u2.example/".parse().unwrap(),
                ];
            })]),
            &s2,
        );
        let names: Vec<(String, bool)> = c
            .global
            .zones
            .iter()
            .map(|z| (z.key.name(), z.subtree))
            .collect();
        assert_eq!(
            names,
            [
                ("ads.example.com".into(), true),
                ("other.example.com".into(), false)
            ]
        );
        assert_eq!(
            c.render(),
            "# Generated by sensr-dns; do not edit.\nserver:\n  local-zone: \"ads.example.com.\" always_null\n  local-data: \"other.example.com. A 0.0.0.0\"\n"
        );
        assert_eq!(
            c.lookup(ip("192.0.2.1"), "sub.other.example.com"),
            Some(Verdict::Allowed)
        );
        assert_eq!(
            c.lookup(ip("192.0.2.1"), "z.ads.example.com"),
            Some(Verdict::Blocked(0))
        );
        assert_eq!(c.lookup(ip("192.0.2.1"), "example.com"), None);
    }

    #[test]
    fn answers_holes_views_and_acls() {
        let mut c = cfg(vec![
            rt(1, "ads", |b| {
                b.block_subtrees = vec![
                    "ads.example.net".parse().unwrap(),
                    "home.arpa".parse().unwrap(),
                ];
                b.block = vec!["tracker.example.net".parse().unwrap()];
                b.allow = vec![
                    "ok.ads.example.net".parse().unwrap(),
                    "/^cdn[0-9]+\\./".parse().unwrap(),
                ];
                b.block_subtrees.push("cdn7.example.net".parse().unwrap());
            }),
            rt(2, "iot", |b| {
                b.block_subtrees = vec!["tif.example.net".parse().unwrap()];
                b.source_nets = vec!["192.168.20.0/24".parse().unwrap()];
                b.answer = BlockAnswer::Nxdomain;
            }),
            rt(3, "redirect", |b| {
                b.block_subtrees = vec!["shop.example.org".parse().unwrap()];
                b.answer = BlockAnswer::Address {
                    address: "192.168.1.1".parse().unwrap(),
                };
            }),
        ]);
        c.acls = vec![("192.168.0.0/16".parse().unwrap(), AclAction::RefuseNonLocal)];
        let compiled = compile(&c, &BTreeMap::new());
        let text = compiled.render();
        pretty_assertions::assert_eq!(
            text,
            "# Generated by sensr-dns; do not edit.
server:
  local-zone: \"ads.example.net.\" always_null
  local-data: \"tracker.example.net. A 0.0.0.0\"
  local-zone: \"shop.example.org.\" redirect
  local-data: \"shop.example.org. A 192.168.1.1\"
  local-zone: \"ok.ads.example.net.\" transparent
  access-control: 192.168.20.0/24 refuse_non_local
  access-control-view: 192.168.20.0/24 \"sensr-bl-1\"
view:
  name: \"sensr-bl-1\"
  view-first: yes
  local-zone: \"tif.example.net.\" always_nxdomain
"
        );
        let iot = ip("192.168.20.5");
        let lan = ip("192.168.1.5");
        assert_eq!(
            compiled.lookup(iot, "a.tif.example.net"),
            Some(Verdict::Blocked(0))
        );
        assert_eq!(compiled.lookup(lan, "a.tif.example.net"), None);
        // Global policies still apply to view clients.
        assert!(matches!(
            compiled.lookup(iot, "x.ads.example.net"),
            Some(Verdict::Blocked(_))
        ));
        assert_eq!(
            compiled.lookup(lan, "a.ok.ads.example.net"),
            Some(Verdict::Allowed)
        );
        // Regex allow removes the listed name; protected names never block.
        assert_eq!(compiled.lookup(lan, "cdn7.example.net"), None);
        assert_eq!(compiled.lookup(lan, "nas.home.arpa"), None);
        let counts = compiled.counts();
        assert_eq!(counts[&Uuid::from_u128(1)], 2);
        assert_eq!(counts[&Uuid::from_u128(2)], 1);
    }

    #[test]
    fn most_specific_network_first() {
        // Two overlapping policies: the /24 is consulted before the /16,
        // and its clients still get the /16's names.
        let c = compile(
            &cfg(vec![
                rt(1, "wide", |b| {
                    b.block_subtrees = vec![
                        "wide.example".parse().unwrap(),
                        "both.example".parse().unwrap(),
                    ];
                    b.source_nets = vec!["10.0.0.0/16".parse().unwrap()];
                    b.answer = BlockAnswer::Nxdomain;
                }),
                rt(2, "narrow", |b| {
                    b.block_subtrees = vec![
                        "narrow.example".parse().unwrap(),
                        "both.example".parse().unwrap(),
                    ];
                    b.source_nets = vec!["10.0.5.0/24".parse().unwrap()];
                }),
            ]),
            &BTreeMap::new(),
        );
        assert_eq!(c.policies[0].description, "narrow");
        let narrow = ip("10.0.5.9");
        let wide = ip("10.0.9.9");
        assert_eq!(
            c.lookup(narrow, "x.both.example"),
            Some(Verdict::Blocked(0))
        );
        assert_eq!(
            c.lookup(narrow, "x.wide.example"),
            Some(Verdict::Blocked(1))
        );
        assert_eq!(c.lookup(wide, "x.both.example"), Some(Verdict::Blocked(1)));
        assert_eq!(c.lookup(wide, "x.narrow.example"), None);
        assert_eq!(c.views.len(), 2);
    }
}
