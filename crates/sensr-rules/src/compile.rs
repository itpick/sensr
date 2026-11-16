//! Lowering expanded [`FilterRule`]s to nft matches and compiling chains.
//!
//! pf semantics on Linux hooks:
//!
//! - `in` rules see packets entering an interface: those for the host
//!   (`input`) and those being forwarded (`forward`). `out` rules see packets
//!   leaving one (`forward`, `output`). A forwarded packet must pass both, as
//!   in pf.
//! - Inside a direction, `quick` rules are first-match; a packet that matches
//!   no quick rule gets the verdict of the *last* matching non-quick rule. That
//!   is exactly "quick rules in order, then non-quick rules in reverse order,
//!   first match wins", which is what the chains contain.
//! - Rules are dispatched per interface with one verdict map on the device
//!   name, so a packet only walks the rules that can apply to it.
//! - Runs of rules with the same match shape become one verdict-map lookup
//!   and runs that differ in one value become one anonymous-set match
//!   (07-performance-evaluation: 1,000 linear rules cost 44 % of the
//!   connection rate).

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use ipnet::IpNet;

use crate::icmp::IcmpType;
use crate::ir::{
    Action, Addr, Endpoint, FilterRule, InterfaceMap, IpFamily, PortMatch, StateKind, TcpFlags,
};
use crate::proto::ProtoMatch;

/// A problem that did not stop rendering.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Warning {
    /// rule label (empty for system-level warnings)
    pub label: String,
    /// what was degraded or skipped
    pub message: String,
}

/// A match field, in the order matches are emitted (cheapest first).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Field {
    /// `meta nfproto`
    Nfproto,
    /// `meta l4proto`
    L4proto,
    /// `ip/ip6 saddr`
    Saddr(IpFamily),
    /// `th sport`
    Sport,
    /// `ip/ip6 daddr`
    Daddr(IpFamily),
    /// `th dport`
    Dport,
    /// `fib saddr type local`
    FibSaddr,
    /// `fib daddr type local`
    FibDaddr,
    /// `icmp/icmpv6 type`
    Icmp(IpFamily),
    /// `tcp flags & mask == set`
    TcpFlags,
}

/// A match value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Val {
    /// address family
    Fam(IpFamily),
    /// protocol number
    Proto(u8),
    /// host address
    Ip(IpAddr),
    /// network (host bits cleared)
    Net(IpNet),
    /// port
    Port(u16),
    /// inclusive port range
    Ports(u16, u16),
    /// named set reference (without `@`)
    SetRef(String),
    /// anonymous set of keyable values
    Set(Vec<Val>),
    /// `local` (fib result)
    Local,
    /// ICMP types
    Icmp(Vec<IcmpKey>),
    /// TCP flags (set, mask) as nft flag names
    Flags(Vec<&'static str>, Vec<&'static str>),
}

/// One ICMP type for nft: keyword when nft has one, else the number.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IcmpKey {
    /// nft keyword
    Name(&'static str),
    /// numeric type
    Num(u8),
}

impl Val {
    /// Values that can be a set element or verdict-map key.
    fn keyable(&self) -> bool {
        matches!(
            self,
            Val::Fam(_) | Val::Proto(_) | Val::Ip(_) | Val::Net(_) | Val::Port(_) | Val::Ports(..)
        )
    }

    /// Exact (non-interval) value.
    fn exact(&self) -> bool {
        match self {
            Val::Net(n) => n.prefix_len() == n.max_prefix_len(),
            Val::Ports(a, b) => a == b,
            v => v.keyable(),
        }
    }

    /// Inclusive numeric span for overlap tests.
    fn span(&self) -> (u128, u128) {
        match self {
            Val::Fam(f) => (*f as u128, *f as u128),
            Val::Proto(p) => (u128::from(*p), u128::from(*p)),
            Val::Ip(ip) => {
                let v = ip_u128(ip);
                (v, v)
            }
            Val::Net(n) => (ip_u128(&n.network()), ip_u128(&n.broadcast())),
            Val::Port(p) => (u128::from(*p), u128::from(*p)),
            Val::Ports(a, b) => (u128::from(*a), u128::from(*b)),
            _ => (0, u128::MAX),
        }
    }
}

fn ip_u128(ip: &IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v) => u128::from(u32::from(*v)),
        IpAddr::V6(v) => u128::from(*v),
    }
}

/// One match: `field [!=|==] val`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Match {
    /// tested field
    pub field: Field,
    /// `!=`
    pub neg: bool,
    /// value
    pub val: Val,
}

/// Terminal action inside a direction chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// pass: leave the direction chain, evaluation continues in the hook
    Return,
    /// block
    Drop,
    /// block return
    Reject {
        /// with TCP RST
        tcp: bool,
    },
}

/// A rule lowered to nft matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Low<'a> {
    /// matches in emission order
    pub matches: Vec<Match>,
    /// log the match
    pub log: bool,
    /// verdict
    pub verdict: Verdict,
    /// source rule label
    pub label: &'a str,
}

/// Names of the sets a ruleset refers to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetRefs {
    /// automation tables (`<bogons>`) referenced
    pub tables: BTreeSet<String>,
}

/// Set name of a logical interface's networks.
pub fn iface_net_set(iface: &str, fam: IpFamily) -> String {
    format!("if_{iface}_n{}", fam_digit(fam))
}

/// Set name of a logical interface's addresses.
pub fn iface_addr_set(iface: &str, fam: IpFamily) -> String {
    format!("if_{iface}_a{}", fam_digit(fam))
}

/// Set name of an address alias.
pub fn alias_set(name: &str, fam: IpFamily) -> String {
    format!("a_{name}_{}", fam_digit(fam))
}

/// Set name of a port alias.
pub fn port_alias_set(name: &str) -> String {
    format!("a_{name}_p")
}

/// Set name of an automation table.
pub fn table_set(name: &str, fam: IpFamily) -> String {
    format!("t_{name}_{}", fam_digit(fam))
}

fn fam_digit(f: IpFamily) -> char {
    match f {
        IpFamily::V4 => '4',
        IpFamily::V6 => '6',
    }
}

/// The match part of any rule-shaped object (filter, NAT).
#[derive(Clone, Copy, Debug)]
pub struct MatchSpec<'r> {
    /// explicit family
    pub family: Option<IpFamily>,
    /// family implied by something outside the matches (a NAT target)
    pub family_hint: Option<IpFamily>,
    /// protocol
    pub proto: ProtoMatch,
    /// source
    pub src: &'r Endpoint,
    /// destination
    pub dst: &'r Endpoint,
    /// ICMP types
    pub icmp: &'r [IcmpType],
    /// ICMPv6 types
    pub icmp6: &'r [IcmpType],
    /// TCP flags
    pub tcp_flags: Option<&'r TcpFlags>,
}

impl<'r> MatchSpec<'r> {
    /// The match part of a filter rule.
    pub fn of_filter(rule: &'r FilterRule) -> MatchSpec<'r> {
        MatchSpec {
            family: rule.family,
            family_hint: None,
            proto: rule.proto,
            src: &rule.src,
            dst: &rule.dst,
            icmp: &rule.icmp_types,
            icmp6: &rule.icmp6_types,
            tcp_flags: rule.tcp_flags.as_ref(),
        }
    }
}

/// Lowered alternatives: each is one nft rule, for the family it names.
pub type Alternatives = Vec<(Option<IpFamily>, Vec<Match>)>;

/// Lowers a match spec into alternatives (each one nft rule), with the family
/// each alternative is for.
pub fn lower_matches(
    spec: &MatchSpec<'_>,
    ifs: &InterfaceMap,
    refs: &mut SetRefs,
) -> Result<Alternatives, String> {
    let has_port = spec.src.port.is_some() || spec.dst.port.is_some();
    // A pf port test only ever matches TCP and UDP packets, so a port
    // without a protocol is exactly "TCP or UDP".
    let proto = match spec.proto {
        ProtoMatch::Any if has_port => ProtoMatch::TcpUdp,
        p if has_port && !p.has_ports() => {
            return Err("port match on a protocol without ports; rule skipped".into());
        }
        p => p,
    };
    let mut out = Vec::new();
    for fam in families(spec)? {
        let srcs = addr_alternatives(spec.src, false, fam, ifs, refs)?;
        let dsts = addr_alternatives(spec.dst, true, fam, ifs, refs)?;
        for s in &srcs {
            for d in &dsts {
                let mut matches = Vec::with_capacity(8);
                match proto {
                    ProtoMatch::Any => {}
                    ProtoMatch::One(p) => matches.push(eq(Field::L4proto, Val::Proto(p.number))),
                    ProtoMatch::TcpUdp => matches.push(eq(
                        Field::L4proto,
                        Val::Set(vec![Val::Proto(6), Val::Proto(17)]),
                    )),
                }
                matches.extend(s.iter().cloned());
                if let Some(p) = &spec.src.port {
                    matches.push(eq(Field::Sport, port_val(p)));
                }
                matches.extend(d.iter().cloned());
                if let Some(p) = &spec.dst.port {
                    matches.push(eq(Field::Dport, port_val(p)));
                }
                if let (Some(f), Some(types)) = (fam, icmp_for(spec, fam)) {
                    let keys = types
                        .iter()
                        .filter_map(|t| {
                            t.nft_name(f)
                                .map(IcmpKey::Name)
                                .or_else(|| t.number(f).map(IcmpKey::Num))
                        })
                        .collect();
                    matches.push(eq(Field::Icmp(f), Val::Icmp(keys)));
                }
                if let Some(TcpFlags::Test { set, mask }) = spec.tcp_flags {
                    matches.push(eq(
                        Field::TcpFlags,
                        Val::Flags(tcp_flag_names(set), tcp_flag_names(mask)),
                    ));
                }
                let implied = matches
                    .iter()
                    .any(|m| matches!(m.field, Field::Saddr(_) | Field::Daddr(_) | Field::Icmp(_)));
                if let (Some(f), false) = (fam, implied) {
                    matches.push(eq(Field::Nfproto, Val::Fam(f)));
                }
                matches.sort_by_key(|m| m.field);
                out.push((fam, matches));
            }
        }
    }
    Ok(out)
}

/// Lowers one expanded rule. Returns no lows for disabled rules or rules
/// that can never match (with a warning).
pub fn lower<'a>(
    rule: &'a FilterRule,
    ifs: &InterfaceMap,
    refs: &mut SetRefs,
    warnings: &mut Vec<Warning>,
) -> Vec<Low<'a>> {
    if !rule.enabled {
        return Vec::new();
    }
    let warn = |warnings: &mut Vec<Warning>, m: String| {
        warnings.push(Warning {
            label: rule.label.clone(),
            message: m,
        })
    };
    degraded_features(rule, |m| warn(warnings, m));
    match lower_matches(&MatchSpec::of_filter(rule), ifs, refs) {
        Ok(alts) => {
            let mut out = Vec::new();
            for (_, matches) in alts {
                push_verdicts(rule, matches, &mut out);
            }
            out
        }
        Err(m) => {
            warn(warnings, m);
            Vec::new()
        }
    }
}

fn eq(field: Field, val: Val) -> Match {
    Match {
        field,
        neg: false,
        val,
    }
}

fn port_val(p: &PortMatch) -> Val {
    match p {
        PortMatch::Single(n) => Val::Port(*n),
        PortMatch::Range(a, b) => Val::Ports(*a, *b),
        PortMatch::Alias(a) => Val::SetRef(port_alias_set(a)),
    }
}

fn tcp_flag_names(letters: &str) -> Vec<&'static str> {
    letters
        .chars()
        .filter_map(|c| match c {
            'F' => Some("fin"),
            'S' => Some("syn"),
            'R' => Some("rst"),
            'P' => Some("psh"),
            'A' => Some("ack"),
            'U' => Some("urg"),
            'E' => Some("ecn"),
            'W' => Some("cwr"),
            _ => None,
        })
        .collect()
}

/// pf features nftables has no direct counterpart for in this renderer: the
/// rule still loads, the import report says what changed.
fn degraded_features(rule: &FilterRule, mut warn: impl FnMut(String)) {
    if rule.gateway.is_some() {
        warn("policy routing (gateway) not rendered yet; rule passes without route-to".into());
    }
    if rule.tag.is_some() || rule.tagged.is_some() {
        warn("packet tags not rendered yet".into());
    }
    if rule.set_prio.is_some() {
        warn("set prio not rendered yet".into());
    }
    if let Some(st) = &rule.state {
        match st.kind {
            StateKind::Keep | StateKind::None => {}
            StateKind::Sloppy => warn("sloppy state is conntrack's default behaviour".into()),
            StateKind::Modulate => warn("modulate state has no nftables equivalent".into()),
            StateKind::Synproxy => warn("synproxy state not rendered yet".into()),
        }
        if !st.options.is_empty() {
            warn(format!(
                "state options not rendered yet: {}",
                st.options.join(", ")
            ));
        }
    }
}

fn icmp_for<'r>(spec: &MatchSpec<'r>, fam: Option<IpFamily>) -> Option<&'r [IcmpType]> {
    let v = match fam? {
        IpFamily::V4 => spec.icmp,
        IpFamily::V6 => spec.icmp6,
    };
    (!v.is_empty()).then_some(v)
}

fn literal_family(a: &Addr) -> Option<IpFamily> {
    match a {
        Addr::Host(ip) => Some(IpFamily::of(ip)),
        Addr::Net(n) => Some(IpFamily::of(&n.addr())),
        _ => None,
    }
}

fn needs_family(a: &Addr) -> bool {
    matches!(
        a,
        Addr::Alias(_)
            | Addr::Table(_)
            | Addr::IfaceNet { .. }
            | Addr::IfaceAddr(_)
            | Addr::Device(_)
    )
}

/// Family variants a rule must be rendered for.
fn families(rule: &MatchSpec<'_>) -> Result<Vec<Option<IpFamily>>, String> {
    let mut implied = BTreeSet::new();
    implied.extend(rule.family_hint);
    for a in [&rule.src.addr, &rule.dst.addr] {
        if let Some(f) = literal_family(a) {
            implied.insert(f);
        }
    }
    if let ProtoMatch::One(p) = rule.proto {
        match p.number {
            1 => {
                implied.insert(IpFamily::V4);
            }
            58 => {
                implied.insert(IpFamily::V6);
            }
            _ => {}
        }
    }
    if rule.family.is_none() {
        if !rule.icmp.is_empty() {
            implied.insert(IpFamily::V4);
        }
        if !rule.icmp6.is_empty() {
            implied.insert(IpFamily::V6);
        }
    }
    if implied.len() > 1 {
        return Err("mixes IPv4 and IPv6 literals; rule can never match".into());
    }
    let implied = implied.into_iter().next();
    match (rule.family, implied) {
        (Some(a), Some(b)) if a != b => {
            Err("address family conflicts with its addresses; rule can never match".into())
        }
        (Some(f), _) | (None, Some(f)) => Ok(vec![Some(f)]),
        (None, None) => {
            if needs_family(&rule.src.addr) || needs_family(&rule.dst.addr) {
                Ok(IpFamily::BOTH.into_iter().map(Some).collect())
            } else {
                Ok(vec![None])
            }
        }
    }
}

/// The address matches an endpoint lowers to, as alternatives (one lowered
/// rule each): a pf term can be a union (interface network plus link-local).
fn addr_alternatives(
    ep: &Endpoint,
    dst: bool,
    fam: Option<IpFamily>,
    ifs: &InterfaceMap,
    refs: &mut SetRefs,
) -> Result<Vec<Vec<Match>>, String> {
    let field = |f: IpFamily| {
        if dst {
            Field::Daddr(f)
        } else {
            Field::Saddr(f)
        }
    };
    let m = |field: Field, val: Val| Match {
        field,
        neg: ep.negate,
        val,
    };
    let need = |what: &str| fam.ok_or_else(|| format!("{what} needs an address family"));
    Ok(match &ep.addr {
        Addr::Any => vec![vec![]],
        Addr::SelfAddr => vec![vec![m(
            if dst {
                Field::FibDaddr
            } else {
                Field::FibSaddr
            },
            Val::Local,
        )]],
        Addr::Host(ip) => vec![vec![m(field(IpFamily::of(ip)), Val::Ip(*ip))]],
        Addr::Net(n) => vec![vec![m(field(IpFamily::of(&n.addr())), net_val(n))]],
        Addr::Alias(a) => {
            let f = need("alias")?;
            vec![vec![m(field(f), Val::SetRef(alias_set(a, f)))]]
        }
        Addr::Table(t) => {
            let f = need("table")?;
            refs.tables.insert(t.clone());
            vec![vec![m(field(f), Val::SetRef(table_set(t, f)))]]
        }
        Addr::IfaceNet { iface, link_local } => {
            let f = need("interface network")?;
            let net = m(field(f), Val::SetRef(iface_net_set(iface, f)));
            if *link_local && f == IpFamily::V6 {
                let ll = m(
                    field(f),
                    Val::Net("fe80::/10".parse().expect("static prefix")),
                );
                if ep.negate {
                    // !(A ∪ B) = !A ∧ !B
                    vec![vec![net, ll]]
                } else {
                    vec![vec![net], vec![ll]]
                }
            } else {
                vec![vec![net]]
            }
        }
        Addr::IfaceAddr(i) => {
            let f = need("interface address")?;
            vec![vec![m(field(f), Val::SetRef(iface_addr_set(i, f)))]]
        }
        Addr::Device(d) => {
            let (dev, network) = match d.split_once(':') {
                Some((dev, "network")) => (dev, true),
                Some((dev, _)) => (dev, false),
                None => (d.as_str(), false),
            };
            let (name, _) = ifs
                .iter()
                .find(|(_, i)| i.device == dev)
                .ok_or_else(|| format!("device {dev} is not a known interface"))?;
            let f = need("device address")?;
            let set = if network {
                iface_net_set(name, f)
            } else {
                iface_addr_set(name, f)
            };
            vec![vec![m(field(f), Val::SetRef(set))]]
        }
        Addr::Invalid(s) => return Err(format!("invalid address {s:?}")),
    })
}

fn net_val(n: &IpNet) -> Val {
    if n.prefix_len() == n.max_prefix_len() {
        Val::Ip(n.addr())
    } else {
        Val::Net(n.trunc())
    }
}

fn push_verdicts<'a>(rule: &'a FilterRule, matches: Vec<Match>, out: &mut Vec<Low<'a>>) {
    let low = |matches: Vec<Match>, verdict| Low {
        matches,
        log: rule.log,
        verdict,
        label: &rule.label,
    };
    match rule.action {
        Action::Pass => out.push(low(matches, Verdict::Return)),
        Action::Block => out.push(low(matches, Verdict::Drop)),
        // pf `block return`: RST for TCP, ICMP unreachable for the rest
        Action::Reject => match rule.proto {
            ProtoMatch::One(p) if p.number == 6 => {
                out.push(low(matches, Verdict::Reject { tcp: true }))
            }
            ProtoMatch::One(_) => out.push(low(matches, Verdict::Reject { tcp: false })),
            ProtoMatch::Any | ProtoMatch::TcpUdp => {
                let mut tcp = matches.clone();
                tcp.retain(|m| m.field != Field::L4proto);
                tcp.push(eq(Field::L4proto, Val::Proto(6)));
                tcp.sort_by_key(|m| m.field);
                out.push(low(tcp, Verdict::Reject { tcp: true }));
                let mut rest = matches;
                if rule.proto == ProtoMatch::TcpUdp {
                    rest.retain(|m| m.field != Field::L4proto);
                    rest.push(eq(Field::L4proto, Val::Proto(17)));
                    rest.sort_by_key(|m| m.field);
                }
                out.push(low(rest, Verdict::Reject { tcp: false }));
            }
        },
    }
}

/// A compiled chain element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item<'l, 'a> {
    /// one linear rule (owned only when set merging changed it)
    Rule(Cow<'l, Low<'a>>),
    /// one verdict-map lookup standing for a run of rules
    Vmap {
        /// key fields, in order
        fields: Vec<Field>,
        /// `(key values, verdict)` in rule order
        entries: Vec<(Vec<Val>, Verdict)>,
        /// first and last rule label of the run
        labels: (&'a str, &'a str),
    },
}

/// Chain compilation knobs.
#[derive(Clone, Copy, Debug)]
pub struct ChainOptions {
    /// shortest run that becomes a verdict map
    pub vmap_min: usize,
}

impl Default for ChainOptions {
    fn default() -> Self {
        ChainOptions { vmap_min: 8 }
    }
}

/// The verdict-map shape of a rule: its key fields, when every match is a
/// keyable equality and the verdict needs no per-rule statement.
fn shape(low: &Low<'_>) -> Option<Vec<Field>> {
    if low.log || matches!(low.verdict, Verdict::Reject { .. }) || low.matches.is_empty() {
        return None;
    }
    low.matches
        .iter()
        .all(|m| !m.neg && m.val.keyable())
        .then(|| low.matches.iter().map(|m| m.field).collect())
}

/// Compiles a chain's lowered rules (already in evaluation order).
pub fn compile_chain<'l, 'a>(lows: &[&'l Low<'a>], opts: ChainOptions) -> Vec<Item<'l, 'a>> {
    let mut items: Vec<Item<'l, 'a>> = Vec::new();
    let mut i = 0;
    while i < lows.len() {
        let Some(sh) = shape(lows[i]) else {
            items.push(Item::Rule(Cow::Borrowed(lows[i])));
            i += 1;
            continue;
        };
        let mut j = i + 1;
        while j < lows.len() && shape(lows[j]).as_ref() == Some(&sh) {
            j += 1;
        }
        if j - i >= opts.vmap_min {
            vmap_runs(&lows[i..j], sh, opts, &mut items);
        } else {
            items.extend(lows[i..j].iter().map(|l| Item::Rule(Cow::Borrowed(*l))));
        }
        i = j;
    }
    merge_sets(items)
}

/// Turns one same-shape run into verdict maps, starting a new map whenever an
/// element overlaps an earlier one (first match must stay first).
fn vmap_runs<'l, 'a>(
    run: &[&'l Low<'a>],
    fields: Vec<Field>,
    opts: ChainOptions,
    out: &mut Vec<Item<'l, 'a>>,
) {
    // Fields exact in every element bucket the overlap search: two keys that
    // differ in an exact field can never overlap.
    let exact: Vec<bool> = (0..fields.len())
        .map(|k| run.iter().all(|l| l.matches[k].val.exact()))
        .collect();
    let mut start = 0;
    let mut entries: Vec<(Vec<Val>, Verdict)> = Vec::new();
    let mut buckets: HashMap<Vec<Val>, Vec<usize>> = HashMap::new();
    let flush = |entries: &mut Vec<(Vec<Val>, Verdict)>,
                 from: usize,
                 to: usize,
                 out: &mut Vec<Item<'l, 'a>>| {
        if entries.len() >= opts.vmap_min {
            out.push(Item::Vmap {
                fields: fields.clone(),
                entries: std::mem::take(entries),
                labels: (run[from].label, run[to - 1].label),
            });
        } else {
            out.extend(run[from..to].iter().map(|l| Item::Rule(Cow::Borrowed(*l))));
            entries.clear();
        }
    };
    for (idx, low) in run.iter().enumerate() {
        let key: Vec<Val> = low.matches.iter().map(|m| m.val.clone()).collect();
        let bucket_key: Vec<Val> = key
            .iter()
            .zip(&exact)
            .filter(|(_, e)| **e)
            .map(|(v, _)| v.clone())
            .collect();
        let candidates = buckets.get(&bucket_key);
        let mut shadowed = false;
        let mut overlaps = false;
        for &c in candidates.into_iter().flatten() {
            let other = &entries[c].0;
            let all = key
                .iter()
                .zip(other)
                .all(|(a, b)| spans_overlap(a.span(), b.span()));
            if all {
                if key == *other {
                    shadowed = true;
                } else {
                    overlaps = true;
                }
                break;
            }
        }
        if shadowed {
            // an identical earlier key always wins: this rule can never match
            continue;
        }
        if overlaps {
            flush(&mut entries, start, idx, out);
            buckets.clear();
            start = idx;
        }
        buckets.entry(bucket_key).or_default().push(entries.len());
        entries.push((key, low.verdict));
    }
    flush(&mut entries, start, run.len(), out);
}

fn spans_overlap(a: (u128, u128), b: (u128, u128)) -> bool {
    a.0 <= b.1 && b.0 <= a.1
}

/// Merges consecutive rules that differ only in one keyable value into an
/// anonymous-set match. Same verdict, so union is exact for first-match.
fn merge_sets<'l, 'a>(items: Vec<Item<'l, 'a>>) -> Vec<Item<'l, 'a>> {
    let mut out: Vec<Item<'l, 'a>> = Vec::with_capacity(items.len());
    for item in items {
        if let (Some(Item::Rule(prev)), Item::Rule(cur)) = (out.last_mut(), &item)
            && let Some(k) = single_difference(prev, cur)
        {
            {
                let add = cur.matches[k].val.clone();
                let slot = &mut prev.to_mut().matches[k].val;
                match slot {
                    Val::Set(v) => {
                        if !v.contains(&add) {
                            v.push(add);
                        }
                    }
                    other => *other = Val::Set(vec![other.clone(), add]),
                }
                continue;
            }
        }
        out.push(item);
    }
    out
}

fn single_difference(a: &Low<'_>, b: &Low<'_>) -> Option<usize> {
    if a.verdict != b.verdict
        || a.log != b.log
        || (a.log && a.label != b.label)
        || a.matches.len() != b.matches.len()
    {
        return None;
    }
    let mut diff = None;
    for (k, (x, y)) in a.matches.iter().zip(&b.matches).enumerate() {
        if x == y {
            continue;
        }
        let set_ok = |v: &Val| v.keyable() || matches!(v, Val::Set(_));
        if diff.is_some()
            || x.field != y.field
            || x.neg
            || y.neg
            || !set_ok(&x.val)
            || !y.val.keyable()
        {
            return None;
        }
        diff = Some(k);
    }
    diff
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::Ipv4Addr;

    /// A packet reduced to the fields the generator uses.
    #[derive(Clone, Debug)]
    struct Pkt {
        proto: u8,
        saddr: Ipv4Addr,
        daddr: Ipv4Addr,
        dport: u16,
    }

    fn field_value(p: &Pkt, f: Field) -> u128 {
        match f {
            Field::L4proto => u128::from(p.proto),
            Field::Saddr(_) => u128::from(u32::from(p.saddr)),
            Field::Daddr(_) => u128::from(u32::from(p.daddr)),
            Field::Dport => u128::from(p.dport),
            other => unreachable!("{other:?}"),
        }
    }

    fn val_matches(v: &Val, x: u128) -> bool {
        match v {
            Val::Set(items) => items.iter().any(|i| val_matches(i, x)),
            v => {
                let (lo, hi) = v.span();
                lo <= x && x <= hi
            }
        }
    }

    fn low_matches(l: &Low<'_>, p: &Pkt) -> bool {
        l.matches
            .iter()
            .all(|m| val_matches(&m.val, field_value(p, m.field)) != m.neg)
    }

    fn linear(lows: &[Low<'_>], p: &Pkt) -> Option<Verdict> {
        lows.iter().find(|l| low_matches(l, p)).map(|l| l.verdict)
    }

    fn compiled(items: &[Item<'_, '_>], p: &Pkt) -> Option<Verdict> {
        for it in items {
            match it {
                Item::Rule(l) => {
                    if low_matches(l, p) {
                        return Some(l.verdict);
                    }
                }
                Item::Vmap {
                    fields, entries, ..
                } => {
                    let hits: Vec<_> = entries
                        .iter()
                        .filter(|(k, _)| {
                            k.iter()
                                .zip(fields)
                                .all(|(v, f)| val_matches(v, field_value(p, *f)))
                        })
                        .collect();
                    assert!(hits.len() <= 1, "overlapping verdict-map keys");
                    if let Some((_, v)) = hits.first() {
                        return Some(*v);
                    }
                }
            }
        }
        None
    }

    fn arb_addr() -> impl Strategy<Value = Val> {
        (
            0u8..4,
            0u8..4,
            prop_oneof![Just(32u8), Just(31), Just(30), Just(24)],
        )
            .prop_map(|(c, d, len)| {
                let ip = Ipv4Addr::new(10, 0, c, d);
                if len == 32 {
                    Val::Ip(IpAddr::V4(ip))
                } else {
                    Val::Net(IpNet::new(IpAddr::V4(ip), len).unwrap().trunc())
                }
            })
    }

    fn arb_low() -> impl Strategy<Value = Low<'static>> {
        (
            proptest::option::of(prop_oneof![Just(6u8), Just(17)]),
            proptest::option::of(arb_addr()),
            proptest::option::of(arb_addr()),
            proptest::option::of(prop_oneof![
                (1u16..5).prop_map(Val::Port),
                (1u16..4).prop_map(|a| Val::Ports(a, a + 2)),
            ]),
            any::<bool>(),
        )
            .prop_map(|(proto, s, d, port, pass)| {
                let mut matches = Vec::new();
                let fam = IpFamily::V4;
                if let Some(p) = proto {
                    matches.push(eq(Field::L4proto, Val::Proto(p)));
                }
                if let Some(s) = s {
                    matches.push(eq(Field::Saddr(fam), s));
                }
                if let Some(d) = d {
                    matches.push(eq(Field::Daddr(fam), d));
                }
                if let (Some(_), Some(p)) = (proto, port) {
                    matches.push(eq(Field::Dport, p));
                }
                Low {
                    matches,
                    log: false,
                    verdict: if pass { Verdict::Return } else { Verdict::Drop },
                    label: "",
                }
            })
    }

    fn arb_pkt() -> impl Strategy<Value = Pkt> {
        (
            prop_oneof![Just(6u8), Just(17)],
            0u8..4,
            0u8..4,
            0u8..4,
            0u8..4,
            1u16..7,
        )
            .prop_map(|(proto, a, b, c, d, dport)| Pkt {
                proto,
                saddr: Ipv4Addr::new(10, 0, a, b),
                daddr: Ipv4Addr::new(10, 0, c, d),
                dport,
            })
    }

    proptest! {
        /// Verdict maps and set merging never change which rule wins.
        #[test]
        fn prop_compiled_chain_equals_linear(
            lows in proptest::collection::vec(arb_low(), 0..60),
            pkts in proptest::collection::vec(arb_pkt(), 32),
            vmap_min in 2usize..10,
        ) {
            let refs: Vec<&Low<'_>> = lows.iter().collect();
            let items = compile_chain(&refs, ChainOptions { vmap_min });
            for p in &pkts {
                prop_assert_eq!(linear(&lows, p), compiled(&items, p), "{:?}", p);
            }
        }
    }

    #[test]
    fn identical_keys_keep_the_first() {
        let l = |v| Low {
            matches: vec![eq(Field::Dport, Val::Port(80))],
            log: false,
            verdict: v,
            label: "",
        };
        let lows = [l(Verdict::Drop), l(Verdict::Return), l(Verdict::Return)];
        let refs: Vec<&Low<'_>> = lows.iter().collect();
        let items = compile_chain(&refs, ChainOptions { vmap_min: 1 });
        let [Item::Vmap { entries, .. }] = &items[..] else {
            panic!("{items:?}")
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, Verdict::Drop);
    }
}
