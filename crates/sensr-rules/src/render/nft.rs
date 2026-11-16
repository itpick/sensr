//! nftables JSON renderer: the whole sensr table as one atomic transaction
//! for `nft -j -f -`.
//!
//! Layout of `table inet sensr`:
//!
//! ```text
//! input    (hook)  ct state vmap { established/related: accept, invalid: drop }
//!                  iifname lo accept; jump in_dispatch; accept
//! forward  (hook)  [flow add @ft]; ct state vmap …; jump in_dispatch; jump out_dispatch; accept
//! output   (hook)  ct state vmap …; oifname lo accept; jump out_dispatch; accept
//! in_dispatch      iifname vmap { "<dev>": goto in_<iface> … }; goto in__any
//! in_<iface>       that interface's `in` rules in evaluation order; pass = return
//! out_…            the same for `out`
//! ```
//!
//! Every interface address, interface network, alias and automation table is
//! a named set, so address changes (DHCP WAN, alias refresh) are set-element
//! updates, not re-renders.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use ipnet::IpNet;

use crate::compile::{
    self, ChainOptions, Field, Item, Low, SetRefs, Val, Verdict as LowVerdict, Warning,
};
use crate::ir::{Addr, FilterRule, InterfaceMap, IpFamily, PortMatch};
use crate::nat::{NatRules, RdrRule, SnatTarget};
use crate::render::json::{Expr, Hook, Nat, Object, SetType, Stmt, Verdict, Writer};
use crate::routing::{PolicyRouting, REPLY_MASK, ROUTE_MASK};

/// Contents of one alias after resolution (nested aliases flattened).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolvedAlias {
    /// addresses and networks of both families
    pub nets: Vec<IpNet>,
    /// inclusive port ranges (single ports have `lo == hi`)
    pub ports: Vec<(u16, u16)>,
}

/// Render options.
#[derive(Clone, Debug)]
pub struct Options {
    /// table name (family is always `inet`)
    pub table: String,
    /// offload established TCP/UDP flows between the interfaces' devices
    pub flowtable: bool,
    /// per-rule counters on linear rules
    pub counters: bool,
    /// nflog group for logged rules (`None`: kernel log)
    pub log_group: Option<u16>,
    /// chain compilation
    pub chain: ChainOptions,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            table: "sensr".into(),
            flowtable: false,
            counters: true,
            log_group: Some(0),
            chain: ChainOptions::default(),
        }
    }
}

/// What to render.
#[derive(Clone, Copy, Debug)]
pub struct Policy<'a> {
    /// expanded filter rules in registration order
    pub rules: &'a [FilterRule],
    /// logical interfaces
    pub interfaces: &'a InterfaceMap,
    /// resolved alias contents
    pub aliases: &'a BTreeMap<String, ResolvedAlias>,
    /// NAT rules; `None` renders no NAT chains
    pub nat: Option<&'a NatRules>,
    /// policy-routing targets; `None` (or empty) renders no route marking
    pub routing: Option<&'a PolicyRouting>,
}

/// Counts that make the compilation visible (and benchmarkable).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Stats {
    /// enabled input rules
    pub filter_rules: usize,
    /// nft rules emitted in direction chains
    pub nft_rules: usize,
    /// verdict maps emitted
    pub vmaps: usize,
    /// elements across all verdict maps
    pub vmap_entries: usize,
}

/// Result of a render.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Report {
    /// degraded or skipped rules
    pub warnings: Vec<Warning>,
    /// compilation counts
    pub stats: Stats,
}

const FAMILY: &str = "inet";

/// Renders `policy` into `out` as one nft JSON document.
pub fn render<W: io::Write>(
    policy: &Policy<'_>,
    opts: &Options,
    out: &mut W,
) -> io::Result<Report> {
    let mut report = Report::default();
    let mut refs = SetRefs::default();

    // Upstream: ksort by priority, registration order within a priority.
    let mut order: Vec<&FilterRule> = policy.rules.iter().collect();
    order.sort_by_key(|r| r.priority);
    // quick rules first-match in order, then non-quick in reverse (last match wins)
    let eval: Vec<&FilterRule> = order
        .iter()
        .copied()
        .filter(|r| r.quick)
        .chain(order.iter().copied().filter(|r| !r.quick).rev())
        .collect();
    report.stats.filter_rules = eval.iter().filter(|r| r.enabled).count();

    let lows: Vec<Vec<Low<'_>>> = eval
        .iter()
        .map(|r| compile::lower(r, policy.interfaces, &mut refs, &mut report.warnings))
        .collect();
    let nat = match policy.nat {
        Some(n) => Some(lower_nat(
            n,
            policy.interfaces,
            policy.aliases,
            &mut refs,
            opts,
            &mut report.warnings,
        )),
        None => None,
    };

    let mut w = Writer::new(out, FAMILY, &opts.table)?;
    // add + delete + add replaces only our table, atomically
    w.add(Object::Table)?;
    w.cmd(&crate::render::json::Command::Delete(Object::Table))?;
    w.add(Object::Table)?;

    emit_sets(&mut w, policy, &refs)?;

    let devices: Vec<&str> = policy
        .interfaces
        .values()
        .map(|i| i.device.as_str())
        .filter(|d| !d.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if opts.flowtable && !devices.is_empty() {
        w.add(Object::Flowtable {
            name: "ft".into(),
            devices: devices.iter().map(|d| (*d).into()).collect(),
        })?;
    }

    // chain keys: every logical interface, then the catch-all
    let keys: Vec<Option<&str>> = policy
        .interfaces
        .keys()
        .map(|k| Some(k.as_str()))
        .chain([None])
        .collect();

    for (name, hook, policy_kw) in [
        ("input", "input", "drop"),
        ("forward", "forward", "drop"),
        ("output", "output", "drop"),
    ] {
        w.add(Object::Chain {
            name: name.into(),
            hook: Some(Hook {
                kind: "filter",
                hook,
                prio: 0,
                policy: policy_kw,
            }),
        })?;
    }
    if nat.is_some() {
        for (name, hook, prio) in [
            ("nat_pre", "prerouting", -100),
            ("nat_post", "postrouting", 100),
        ] {
            w.add(Object::Chain {
                name: name.into(),
                hook: Some(Hook {
                    kind: "nat",
                    hook,
                    prio,
                    policy: "accept",
                }),
            })?;
        }
    }
    let route = route_plan(policy, &eval);
    if route.is_none() {
        for r in eval.iter().filter(|r| routes(r)) {
            report.warnings.push(Warning {
                label: r.label.clone(),
                message: "no policy-routing targets; rule passes without route-to".into(),
            });
        }
    }
    if let Some(r) = &route {
        w.add(Object::Chain {
            name: "route_pre".into(),
            hook: Some(Hook {
                kind: "filter",
                hook: "prerouting",
                prio: -150,
                policy: "accept",
            }),
        })?;
        // the firewall's own replies (to connections that came in on a WAN)
        // are routed in output; a `route` chain re-routes on a mark change
        w.add(Object::Chain {
            name: "route_out".into(),
            hook: Some(Hook {
                kind: "route",
                hook: "output",
                prio: -150,
                policy: "accept",
            }),
        })?;
        for k in &r.chains {
            w.add(Object::Chain {
                name: route_chain(*k).into(),
                hook: None,
            })?;
        }
    }
    for dir in ["in", "out"] {
        w.add(Object::Chain {
            name: format!("{dir}_dispatch").into(),
            hook: None,
        })?;
        for k in &keys {
            w.add(Object::Chain {
                name: chain_name(dir, *k).into(),
                hook: None,
            })?;
        }
    }

    let rdr_pass = nat.as_ref().is_some_and(|n| n.rdr_pass);
    base_chains(&mut w, opts, !devices.is_empty(), rdr_pass)?;
    if let Some(n) = nat {
        for (chain, rules) in [("nat_pre", n.pre), ("nat_post", n.post)] {
            for (expr, comment) in rules {
                w.add(Object::Rule {
                    chain: chain.into(),
                    expr,
                    comment,
                })?;
            }
        }
    }
    dispatch(&mut w, "in", "iifname", policy.interfaces)?;
    dispatch(&mut w, "out", "oifname", policy.interfaces)?;
    if let Some(r) = &route {
        emit_route(&mut w, policy, r, &eval, &lows, opts, &mut report.warnings)?;
    }

    for (dir, wants) in [
        (
            "in",
            (|r: &FilterRule| r.direction.matches_in()) as fn(&FilterRule) -> bool,
        ),
        ("out", |r: &FilterRule| r.direction.matches_out()),
    ] {
        for k in &keys {
            let chain_lows: Vec<&Low<'_>> = eval
                .iter()
                .zip(&lows)
                .filter(|(r, _)| wants(r) && applies_to(r, *k))
                .flat_map(|(_, l)| l.iter())
                .collect();
            let chain = chain_name(dir, *k);
            for item in compile::compile_chain(&chain_lows, opts.chain) {
                emit_item(&mut w, &chain, item, opts, &mut report.stats)?;
            }
        }
    }
    w.finish()?;
    Ok(report)
}

fn chain_name(dir: &str, key: Option<&str>) -> String {
    match key {
        Some(i) => format!("{dir}_{i}"),
        None => format!("{dir}__any"),
    }
}

fn applies_to(r: &FilterRule, key: Option<&str>) -> bool {
    match (&r.interface, key) {
        (None, _) => true,
        (Some(x), Some(k)) => (x == k) != r.interface_not,
        (Some(_), None) => r.interface_not,
    }
}

fn add_rule<W: io::Write>(
    w: &mut Writer<'_, W>,
    chain: &str,
    expr: Vec<Stmt<'_>>,
) -> io::Result<()> {
    w.add(Object::Rule {
        chain: chain.into(),
        expr,
        comment: None,
    })
}

fn ct_state_fast_path() -> Stmt<'static> {
    Stmt::Vmap {
        key: Expr::Ct("state"),
        data: vec![
            (Expr::s("established"), Verdict::Accept),
            (Expr::s("related"), Verdict::Accept),
            (Expr::s("invalid"), Verdict::Drop),
        ],
    }
}

fn base_chains<W: io::Write>(
    w: &mut Writer<'_, W>,
    opts: &Options,
    has_devices: bool,
    rdr_pass: bool,
) -> io::Result<()> {
    let lo = |key: &'static str| Stmt::Match {
        op: "==",
        left: Expr::Meta(key),
        right: Expr::s("lo"),
    };
    let jump = |c: &'static str| Stmt::Verdict(Verdict::Jump(c.into()));
    let accept = || Stmt::Verdict(Verdict::Accept);

    add_rule(w, "input", vec![ct_state_fast_path()])?;
    add_rule(w, "input", vec![lo("iifname"), accept()])?;
    add_rule(w, "input", vec![jump("in_dispatch")])?;
    add_rule(w, "input", vec![accept()])?;

    if opts.flowtable && has_devices {
        add_rule(
            w,
            "forward",
            vec![
                Stmt::Match {
                    op: "==",
                    left: Expr::Meta("l4proto"),
                    right: Expr::Set(vec![Expr::Num(6), Expr::Num(17)]),
                },
                Stmt::FlowAdd("ft".into()),
            ],
        )?;
    }
    add_rule(w, "forward", vec![ct_state_fast_path()])?;
    if rdr_pass {
        // `rdr pass`: the redirect marked the connection; skip the filter
        add_rule(
            w,
            "forward",
            vec![
                Stmt::Match {
                    op: "==",
                    left: Expr::And(
                        Box::new(Expr::Ct("mark")),
                        Box::new(Expr::Num(RDR_PASS_MARK)),
                    ),
                    right: Expr::Num(RDR_PASS_MARK),
                },
                accept(),
            ],
        )?;
    }
    add_rule(w, "forward", vec![jump("in_dispatch")])?;
    add_rule(w, "forward", vec![jump("out_dispatch")])?;
    add_rule(w, "forward", vec![accept()])?;

    add_rule(w, "output", vec![ct_state_fast_path()])?;
    add_rule(w, "output", vec![lo("oifname"), accept()])?;
    add_rule(w, "output", vec![jump("out_dispatch")])?;
    add_rule(w, "output", vec![accept()])
}

fn dispatch<W: io::Write>(
    w: &mut Writer<'_, W>,
    dir: &str,
    meta: &'static str,
    ifs: &InterfaceMap,
) -> io::Result<()> {
    let chain = format!("{dir}_dispatch");
    let mut seen = BTreeSet::new();
    let data: Vec<_> = ifs
        .iter()
        .filter(|(_, i)| !i.device.is_empty() && seen.insert(i.device.as_str()))
        .map(|(name, i)| {
            (
                Expr::s(i.device.as_str()),
                Verdict::Goto(chain_name(dir, Some(name)).into()),
            )
        })
        .collect();
    if !data.is_empty() {
        add_rule(
            w,
            &chain,
            vec![Stmt::Vmap {
                key: Expr::Meta(meta),
                data,
            }],
        )?;
    }
    add_rule(
        w,
        &chain,
        vec![Stmt::Verdict(Verdict::Goto(chain_name(dir, None).into()))],
    )
}

fn emit_sets<W: io::Write>(
    w: &mut Writer<'_, W>,
    policy: &Policy<'_>,
    refs: &SetRefs,
) -> io::Result<()> {
    for fam in IpFamily::BOTH {
        let ty = addr_type(fam);
        for (name, i) in policy.interfaces {
            let nets: BTreeSet<IpNet> = i.addrs_of(fam).filter_map(|a| a.network()).collect();
            w.add(Object::Set {
                name: compile::iface_net_set(name, fam).into(),
                ty: SetType(vec![ty]),
                interval: true,
                elem: nets.iter().map(net_elem).collect(),
            })?;
            let addrs: BTreeSet<_> = i.addrs_of(fam).map(|a| a.addr).collect();
            w.add(Object::Set {
                name: compile::iface_addr_set(name, fam).into(),
                ty: SetType(vec![ty]),
                interval: false,
                elem: addrs.into_iter().map(Expr::Ip).collect(),
            })?;
        }
        for (name, a) in policy.aliases {
            let nets: Vec<Expr<'_>> = a
                .nets
                .iter()
                .filter(|n| IpFamily::of(&n.addr()) == fam)
                .map(net_elem)
                .collect();
            w.add(Object::Set {
                name: compile::alias_set(name, fam).into(),
                ty: SetType(vec![ty]),
                interval: true,
                elem: nets,
            })?;
        }
        for t in &refs.tables {
            w.add(Object::Set {
                name: compile::table_set(t, fam).into(),
                ty: SetType(vec![ty]),
                interval: true,
                elem: Vec::new(),
            })?;
        }
    }
    for (name, a) in policy.aliases {
        w.add(Object::Set {
            name: compile::port_alias_set(name).into(),
            ty: SetType(vec!["inet_service"]),
            interval: true,
            elem: a
                .ports
                .iter()
                .map(|&(lo, hi)| {
                    if lo == hi {
                        Expr::Num(u32::from(lo))
                    } else {
                        Expr::Range(
                            Box::new(Expr::Num(u32::from(lo))),
                            Box::new(Expr::Num(u32::from(hi))),
                        )
                    }
                })
                .collect(),
        })?;
    }
    Ok(())
}

fn addr_type(fam: IpFamily) -> &'static str {
    match fam {
        IpFamily::V4 => "ipv4_addr",
        IpFamily::V6 => "ipv6_addr",
    }
}

fn net_elem(n: &IpNet) -> Expr<'static> {
    if n.prefix_len() == n.max_prefix_len() {
        Expr::Ip(n.addr())
    } else {
        let t = n.trunc();
        Expr::Prefix(t.addr(), t.prefix_len())
    }
}

fn field_expr(f: Field) -> Expr<'static> {
    match f {
        Field::Nfproto => Expr::Meta("nfproto"),
        Field::L4proto => Expr::Meta("l4proto"),
        Field::Saddr(IpFamily::V4) => Expr::Payload("ip", "saddr"),
        Field::Saddr(IpFamily::V6) => Expr::Payload("ip6", "saddr"),
        Field::Daddr(IpFamily::V4) => Expr::Payload("ip", "daddr"),
        Field::Daddr(IpFamily::V6) => Expr::Payload("ip6", "daddr"),
        Field::Sport => Expr::Payload("th", "sport"),
        Field::Dport => Expr::Payload("th", "dport"),
        Field::FibSaddr => Expr::Fib(&["saddr"], "type"),
        Field::FibDaddr => Expr::Fib(&["daddr"], "type"),
        Field::Icmp(IpFamily::V4) => Expr::Payload("icmp", "type"),
        Field::Icmp(IpFamily::V6) => Expr::Payload("icmpv6", "type"),
        Field::TcpFlags => Expr::Payload("tcp", "flags"),
    }
}

fn val_expr(v: &Val) -> Expr<'static> {
    match v {
        Val::Fam(IpFamily::V4) => Expr::s("ipv4"),
        Val::Fam(IpFamily::V6) => Expr::s("ipv6"),
        Val::Proto(p) => Expr::Num(u32::from(*p)),
        Val::Ip(ip) => Expr::Ip(*ip),
        Val::Net(n) => Expr::Prefix(n.addr(), n.prefix_len()),
        Val::Port(p) => Expr::Num(u32::from(*p)),
        Val::Ports(a, b) => Expr::Range(
            Box::new(Expr::Num(u32::from(*a))),
            Box::new(Expr::Num(u32::from(*b))),
        ),
        Val::SetRef(s) => Expr::set_ref(s),
        Val::Set(items) => Expr::Set(items.iter().map(val_expr).collect()),
        Val::Local => Expr::s("local"),
        Val::Icmp(keys) => {
            let mut e: Vec<Expr<'static>> = keys
                .iter()
                .map(|k| match k {
                    compile::IcmpKey::Name(n) => Expr::s(n),
                    compile::IcmpKey::Num(n) => Expr::Num(u32::from(*n)),
                })
                .collect();
            if e.len() == 1 {
                e.pop().expect("one element")
            } else {
                Expr::Set(e)
            }
        }
        Val::Flags(set, _) => Expr::Flags(set.clone()),
    }
}

fn match_stmt(m: &compile::Match) -> Stmt<'static> {
    let mut left = field_expr(m.field);
    if let (Field::TcpFlags, Val::Flags(_, mask)) = (m.field, &m.val) {
        left = Expr::And(Box::new(left), Box::new(Expr::Flags(mask.clone())));
    }
    Stmt::Match {
        op: if m.neg { "!=" } else { "==" },
        left,
        right: val_expr(&m.val),
    }
}

fn verdict_stmt(v: LowVerdict) -> Stmt<'static> {
    match v {
        LowVerdict::Return => Stmt::Verdict(Verdict::Return),
        LowVerdict::Drop => Stmt::Verdict(Verdict::Drop),
        LowVerdict::Reject { tcp } => Stmt::Reject { tcp_reset: tcp },
    }
}

fn map_verdict(v: LowVerdict) -> Verdict<'static> {
    match v {
        LowVerdict::Return => Verdict::Return,
        // shapes never contain rejects (see compile::shape)
        LowVerdict::Drop | LowVerdict::Reject { .. } => Verdict::Drop,
    }
}

/// nft rule comments are limited to 128 bytes.
fn comment(s: &str) -> Option<std::borrow::Cow<'static, str>> {
    if s.is_empty() {
        return None;
    }
    let mut end = s.len().min(127);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    Some(s[..end].to_owned().into())
}

fn emit_item<W: io::Write>(
    w: &mut Writer<'_, W>,
    chain: &str,
    item: Item<'_, '_>,
    opts: &Options,
    stats: &mut Stats,
) -> io::Result<()> {
    stats.nft_rules += 1;
    match item {
        Item::Rule(low) => {
            let mut expr: Vec<Stmt<'_>> = low.matches.iter().map(match_stmt).collect();
            if opts.counters {
                expr.push(Stmt::Counter);
            }
            if low.log {
                expr.push(Stmt::Log {
                    prefix: comment(low.label).unwrap_or_default(),
                    group: opts.log_group,
                });
            }
            expr.push(verdict_stmt(low.verdict));
            w.add(Object::Rule {
                chain: chain.into(),
                expr,
                comment: comment(low.label),
            })
        }
        Item::Vmap {
            fields,
            entries,
            labels,
        } => {
            stats.vmaps += 1;
            stats.vmap_entries += entries.len();
            let key = concat(fields.iter().map(|f| field_expr(*f)).collect());
            let data = entries
                .iter()
                .map(|(k, v)| (concat(k.iter().map(val_expr).collect()), map_verdict(*v)))
                .collect();
            w.add(Object::Rule {
                chain: chain.into(),
                expr: vec![Stmt::Vmap { key, data }],
                comment: comment(&format!("{}..{}", labels.0, labels.1)),
            })
        }
    }
}

fn concat(mut v: Vec<Expr<'static>>) -> Expr<'static> {
    if v.len() == 1 {
        v.pop().expect("one element")
    } else {
        Expr::Concat(v)
    }
}

pub use crate::routing::RDR_PASS_MARK;

type RuleStmts = (Vec<Stmt<'static>>, Option<std::borrow::Cow<'static, str>>);

struct LoweredNat {
    pre: Vec<RuleStmts>,
    post: Vec<RuleStmts>,
    rdr_pass: bool,
}

fn nat_family(f: IpFamily) -> &'static str {
    match f {
        IpFamily::V4 => "ip",
        IpFamily::V6 => "ip6",
    }
}

fn iface_match(
    meta: &'static str,
    iface: &Option<String>,
    ifs: &InterfaceMap,
) -> Option<Stmt<'static>> {
    let dev = ifs.get(iface.as_ref()?)?.device.clone();
    Some(Stmt::Match {
        op: "==",
        left: Expr::Meta(meta),
        right: Expr::Str(dev.into()),
    })
}

fn port_expr(p: &PortMatch) -> Option<Expr<'static>> {
    match p {
        PortMatch::Single(n) => Some(Expr::Num(u32::from(*n))),
        PortMatch::Range(a, b) => Some(Expr::Range(
            Box::new(Expr::Num(u32::from(*a))),
            Box::new(Expr::Num(u32::from(*b))),
        )),
        PortMatch::Alias(_) => None,
    }
}

fn addr_range(n: &IpNet) -> Expr<'static> {
    Expr::Range(
        Box::new(Expr::Ip(n.network())),
        Box::new(Expr::Ip(n.broadcast())),
    )
}

fn common_stmts(
    head: Option<Stmt<'static>>,
    matches: &[compile::Match],
    log: bool,
    opts: &Options,
) -> Vec<Stmt<'static>> {
    let mut v: Vec<Stmt<'static>> = head.into_iter().collect();
    v.extend(matches.iter().map(match_stmt));
    if opts.counters {
        v.push(Stmt::Counter);
    }
    if log {
        v.push(Stmt::Log {
            prefix: "nat".into(),
            group: opts.log_group,
        });
    }
    v
}

fn lower_nat(
    nat: &NatRules,
    ifs: &InterfaceMap,
    aliases: &BTreeMap<String, ResolvedAlias>,
    refs: &mut SetRefs,
    opts: &Options,
    warnings: &mut Vec<Warning>,
) -> LoweredNat {
    let carp = || {
        vec![
            Stmt::Match {
                op: "==",
                left: Expr::Meta("l4proto"),
                right: Expr::Num(112),
            },
            Stmt::Verdict(Verdict::Accept),
        ]
    };
    // "no nat proto carp all" / "no rdr proto carp all"
    let mut pre: Vec<RuleStmts> = vec![(carp(), None)];
    let mut post_rows: Vec<(u32, RuleStmts)> = Vec::new();
    let mut rdr_pass = false;
    let mut warn = |descr: &str, m: String| {
        warnings.push(Warning {
            label: descr.to_owned(),
            message: m,
        })
    };

    for r in nat.rdr.iter().filter(|r| r.enabled) {
        let target = r.target.as_ref().map(|t| expand_target(t, aliases));
        let hint = target.as_ref().and_then(|t| t.as_ref().ok()).map(|t| t.0);
        let spec = compile::MatchSpec {
            family: r.family,
            family_hint: hint,
            proto: r.proto,
            src: &r.src,
            dst: &r.dst,
            icmp: &[],
            icmp6: &[],
            tcp_flags: None,
        };
        let alts = match compile::lower_matches(&spec, ifs, refs) {
            Ok(a) => a,
            Err(m) => {
                warn(&r.descr, m);
                continue;
            }
        };
        for (fam, matches) in alts {
            let head = iface_match("iifname", &r.interface, ifs);
            if r.nordr {
                let mut v = common_stmts(head, &matches, r.log, opts);
                v.push(Stmt::Verdict(Verdict::Accept));
                pre.push((v, comment(&r.descr)));
                continue;
            }
            rdr_pass |= r.pass;
            for (extra, stmt) in rdr_actions(r, target.as_ref(), fam, &mut warn) {
                let mut m = matches.clone();
                m.extend(extra);
                m.sort_by_key(|x| x.field);
                let mut v = common_stmts(head.clone(), &m, r.log, opts);
                if r.pass {
                    v.push(Stmt::CtMarkOr(RDR_PASS_MARK));
                }
                v.push(stmt);
                pre.push((v, comment(&r.descr)));
            }
            if r.helper
                && let Some(Ok((tf, texpr))) = &target
                && let Some(v) = hairpin(r, fam.unwrap_or(*tf), texpr, ifs)
            {
                post_rows.push((r.priority, (v, comment(&r.descr))));
            }
        }
    }

    for r in nat.snat.iter().filter(|r| r.enabled) {
        let hint = match &r.target {
            SnatTarget::Host(ip) => Some(IpFamily::of(ip)),
            SnatTarget::Net(n) => Some(IpFamily::of(&n.addr())),
            _ => None,
        };
        let spec = compile::MatchSpec {
            family: r.family,
            family_hint: hint,
            proto: r.proto,
            src: &r.src,
            dst: &r.dst,
            icmp: &[],
            icmp6: &[],
            tcp_flags: None,
        };
        let alts = match compile::lower_matches(&spec, ifs, refs) {
            Ok(a) => a,
            Err(m) => {
                warn(&r.descr, m);
                continue;
            }
        };
        for (fam, matches) in alts {
            let head = iface_match("oifname", &r.interface, ifs);
            let mut v = common_stmts(head, &matches, r.log, opts);
            let port = match &r.target_port {
                Some(p) if r.proto.has_ports() => port_expr(p),
                Some(_) => {
                    warn(&r.descr, "translation port needs TCP/UDP; ignored".into());
                    None
                }
                None => None,
            };
            let stmt = match &r.target {
                SnatTarget::NoNat => Stmt::Verdict(Verdict::Accept),
                SnatTarget::Interface(_) => Stmt::Masquerade(Nat {
                    family: None,
                    addr: None,
                    port,
                    flags: Vec::new(),
                }),
                SnatTarget::Host(ip) => Stmt::Snat(Nat {
                    family: Some(nat_family(fam.unwrap_or(IpFamily::of(ip)))),
                    addr: Some(Expr::Ip(*ip)),
                    port,
                    flags: Vec::new(),
                }),
                SnatTarget::Net(n) => Stmt::Snat(Nat {
                    family: Some(nat_family(fam.unwrap_or(IpFamily::of(&n.addr())))),
                    addr: Some(addr_range(n)),
                    port,
                    flags: Vec::new(),
                }),
                SnatTarget::Alias(a) => {
                    warn(&r.descr, format!("alias pool target {a} not rendered yet"));
                    continue;
                }
            };
            v.push(stmt);
            post_rows.push((r.priority, (v, comment(&r.descr))));
        }
    }
    post_rows.sort_by_key(|(p, _)| *p);
    let mut post: Vec<RuleStmts> = vec![(carp(), None)];
    post.extend(post_rows.into_iter().map(|(_, r)| r));
    LoweredNat {
        pre,
        post,
        rdr_pass,
    }
}

/// A redirect target as one nft address expression: a host, a range, or
/// round-robin over the hosts of an alias (pf's pool semantics).
fn expand_target(
    t: &Addr,
    aliases: &BTreeMap<String, ResolvedAlias>,
) -> Result<(IpFamily, Expr<'static>), String> {
    match t {
        Addr::Host(ip) => Ok((IpFamily::of(ip), Expr::Ip(*ip))),
        Addr::Net(n) => Ok((IpFamily::of(&n.addr()), addr_range(n))),
        Addr::Alias(a) => {
            let nets = aliases.get(a).map(|r| r.nets.as_slice()).unwrap_or(&[]);
            // pool members: hosts, or the hosts of small networks
            let mut hosts: Vec<std::net::IpAddr> = Vec::new();
            for n in nets {
                match n {
                    IpNet::V4(v) if v.prefix_len() == 32 => hosts.push(v.addr().into()),
                    IpNet::V4(v) if v.prefix_len() >= 24 => {
                        hosts.extend(v.hosts().map(std::net::IpAddr::V4))
                    }
                    IpNet::V6(v) if v.prefix_len() == 128 => hosts.push(v.addr().into()),
                    _ => {}
                }
            }
            let fam = hosts
                .first()
                .map(IpFamily::of)
                .ok_or_else(|| format!("redirect alias {a} has no usable hosts"))?;
            if hosts.iter().any(|h| IpFamily::of(h) != fam) {
                return Err(format!("redirect alias {a} mixes address families"));
            }
            if hosts.len() == 1 {
                return Ok((fam, Expr::Ip(hosts[0])));
            }
            Ok((
                fam,
                Expr::Map(
                    Box::new(Expr::NumgenInc(hosts.len() as u32)),
                    hosts
                        .iter()
                        .enumerate()
                        .map(|(i, h)| (Expr::Num(i as u32), Expr::Ip(*h)))
                        .collect(),
                ),
            ))
        }
        other => Err(format!("redirect target {other:?} not supported")),
    }
}

/// The dnat statement(s) of a forward: `(extra matches, statement)` each.
fn rdr_actions(
    r: &RdrRule,
    target: Option<&Result<(IpFamily, Expr<'static>), String>>,
    fam: Option<IpFamily>,
    warn: &mut impl FnMut(&str, String),
) -> Vec<(Vec<compile::Match>, Stmt<'static>)> {
    let (f, addr) = match target {
        None => return Vec::new(),
        Some(Ok((f, e))) => (*f, e.clone()),
        Some(Err(m)) => {
            warn(&r.descr, m.clone());
            return Vec::new();
        }
    };
    if fam.is_some_and(|x| x != f) {
        return Vec::new();
    }
    let dnat = |port: Option<Expr<'static>>| {
        Stmt::Dnat(Nat {
            family: Some(nat_family(f)),
            addr: Some(addr.clone()),
            port,
            flags: Vec::new(),
        })
    };
    match (&r.local_port, &r.dst.port) {
        (None, _) => vec![(Vec::new(), dnat(None))],
        (Some(PortMatch::Single(p)), _) => vec![(Vec::new(), dnat(Some(Expr::Num(u32::from(*p)))))],
        // same range: ports are kept
        (Some(PortMatch::Range(a, _)), Some(PortMatch::Range(lo, _))) if a == lo => {
            vec![(Vec::new(), dnat(None))]
        }
        // shifted range: one rule per port keeps the offset exact
        (Some(PortMatch::Range(a, _)), Some(PortMatch::Range(lo, hi))) if hi - lo < 64 => (0..=hi
            - lo)
            .map(|k| {
                (
                    vec![compile::Match {
                        field: compile::Field::Dport,
                        neg: false,
                        val: Val::Port(lo + k),
                    }],
                    dnat(Some(Expr::Num(u32::from(a + k)))),
                )
            })
            .collect(),
        _ => {
            warn(&r.descr, "redirect port mapping not rendered yet".into());
            Vec::new()
        }
    }
}

/// Reflection helper: hairpin SNAT on the forward's interface so replies
/// come back through the firewall.
fn hairpin(
    r: &RdrRule,
    f: IpFamily,
    target: &Expr<'static>,
    ifs: &InterfaceMap,
) -> Option<Vec<Stmt<'static>>> {
    let iface = r.interface.as_ref()?;
    let mut v = vec![iface_match("oifname", &r.interface, ifs)?];
    match r.proto {
        crate::proto::ProtoMatch::Any => {}
        crate::proto::ProtoMatch::One(p) => v.push(Stmt::Match {
            op: "==",
            left: Expr::Meta("l4proto"),
            right: Expr::Num(u32::from(p.number)),
        }),
        crate::proto::ProtoMatch::TcpUdp => v.push(Stmt::Match {
            op: "==",
            left: Expr::Meta("l4proto"),
            right: Expr::Set(vec![Expr::Num(6), Expr::Num(17)]),
        }),
    }
    let (saddr, daddr) = match f {
        IpFamily::V4 => (Expr::Payload("ip", "saddr"), Expr::Payload("ip", "daddr")),
        IpFamily::V6 => (Expr::Payload("ip6", "saddr"), Expr::Payload("ip6", "daddr")),
    };
    v.push(Stmt::Match {
        op: "==",
        left: saddr,
        right: Expr::set_ref(&compile::iface_net_set(iface, f)),
    });
    let right = match target {
        Expr::Ip(_) | Expr::Range(..) => target.clone(),
        // round-robin pool: hairpin every member
        Expr::Map(_, pairs) => Expr::Set(pairs.iter().map(|(_, v)| v.clone()).collect()),
        _ => return None,
    };
    v.push(Stmt::Match {
        op: "==",
        left: daddr,
        right,
    });
    if let Some(p) = r.local_port.as_ref().and_then(port_expr) {
        v.push(Stmt::Match {
            op: "==",
            left: Expr::Payload("th", "dport"),
            right: p,
        });
    }
    v.push(Stmt::Masquerade(Nat {
        family: None,
        addr: None,
        port: None,
        flags: Vec::new(),
    }));
    Some(v)
}

/// New contents for one named set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetContents {
    /// addresses / networks (one family, matching the set)
    Nets(Vec<IpNet>),
    /// inclusive port ranges
    Ports(Vec<(u16, u16)>),
}

/// Replaces the contents of named sets in one transaction (`flush set` +
/// `add element` per set): how DHCP address changes and alias refreshes reach
/// the kernel without re-rendering the ruleset (07: 10k entries in 0.05 s).
pub fn render_set_updates<W: io::Write>(
    table: &str,
    updates: &[(String, SetContents)],
    out: &mut W,
) -> io::Result<()> {
    let mut w = Writer::new(out, FAMILY, table)?;
    for (name, contents) in updates {
        w.cmd(&crate::render::json::Command::Flush(Object::SetName(
            name.clone().into(),
        )))?;
        let elem: Vec<Expr<'_>> = match contents {
            SetContents::Nets(nets) => nets.iter().map(net_elem).collect(),
            SetContents::Ports(ports) => ports
                .iter()
                .map(|&(lo, hi)| {
                    if lo == hi {
                        Expr::Num(u32::from(lo))
                    } else {
                        Expr::Range(
                            Box::new(Expr::Num(u32::from(lo))),
                            Box::new(Expr::Num(u32::from(hi))),
                        )
                    }
                })
                .collect(),
        };
        if !elem.is_empty() {
            w.add(Object::Element {
                name: name.clone().into(),
                elem,
            })?;
        }
    }
    w.finish()
}

/// The four sets of a logical interface with its current addresses.
pub fn interface_set_updates(
    name: &str,
    iface: &crate::ir::Interface,
) -> Vec<(String, SetContents)> {
    let mut v = Vec::new();
    for fam in IpFamily::BOTH {
        let nets: BTreeSet<IpNet> = iface.addrs_of(fam).filter_map(|a| a.network()).collect();
        v.push((
            compile::iface_net_set(name, fam),
            SetContents::Nets(nets.into_iter().collect()),
        ));
        let addrs: BTreeSet<IpNet> = iface.addrs_of(fam).map(|a| IpNet::from(a.addr)).collect();
        v.push((
            compile::iface_addr_set(name, fam),
            SetContents::Nets(addrs.into_iter().collect()),
        ));
    }
    v
}

/// The sets of one alias with resolved contents.
pub fn alias_set_updates(name: &str, a: &ResolvedAlias) -> Vec<(String, SetContents)> {
    let mut v: Vec<(String, SetContents)> = IpFamily::BOTH
        .into_iter()
        .map(|fam| {
            (
                compile::alias_set(name, fam),
                SetContents::Nets(
                    a.nets
                        .iter()
                        .filter(|n| IpFamily::of(&n.addr()) == fam)
                        .copied()
                        .collect(),
                ),
            )
        })
        .collect();
    v.push((
        compile::port_alias_set(name),
        SetContents::Ports(a.ports.clone()),
    ));
    v
}

/// What the route-marking chains need.
struct RoutePlan<'p> {
    routing: &'p PolicyRouting,
    /// interface chains (by logical name; `None` = catch-all) with rules
    /// that pick a gateway
    chains: Vec<Option<&'p str>>,
}

fn route_chain(k: Option<&str>) -> String {
    match k {
        Some(i) => format!("pr_{i}"),
        None => "pr__any".into(),
    }
}

fn routes(r: &FilterRule) -> bool {
    r.enabled
        && r.action == crate::ir::Action::Pass
        && r.gateway.is_some()
        && r.direction.matches_in()
}

fn route_plan<'p>(policy: &Policy<'p>, eval: &[&'p FilterRule]) -> Option<RoutePlan<'p>> {
    let routing = policy.routing.filter(|r| !r.is_empty())?;
    let keys: Vec<Option<&'p str>> = policy
        .interfaces
        .keys()
        .map(|k| Some(k.as_str()))
        .chain([None])
        .collect();
    let chains: Vec<Option<&'p str>> = keys
        .into_iter()
        .filter(|k| eval.iter().any(|r| routes(r) && applies_to(r, *k)))
        .collect();
    (!chains.is_empty() || !routing.reply.is_empty()).then_some(RoutePlan { routing, chains })
}

fn mark_and(mask: u32) -> Expr<'static> {
    Expr::And(Box::new(Expr::Ct("mark")), Box::new(Expr::Num(mask)))
}

fn emit_route<W: io::Write>(
    w: &mut Writer<'_, W>,
    policy: &Policy<'_>,
    plan: &RoutePlan<'_>,
    eval: &[&FilterRule],
    lows: &[Vec<Low<'_>>],
    opts: &Options,
    warnings: &mut Vec<Warning>,
) -> io::Result<()> {
    let established = || Stmt::Match {
        op: "==",
        left: Expr::Ct("state"),
        right: Expr::Set(vec![Expr::s("established"), Expr::s("related")]),
    };
    let direction = |d: &'static str| Stmt::Match {
        op: "==",
        left: Expr::Ct("direction"),
        right: Expr::s(d),
    };
    let ret = || Stmt::Verdict(Verdict::Return);
    // later packets: restore the connection's choice
    add_rule(
        w,
        "route_pre",
        vec![
            established(),
            direction("original"),
            Stmt::MetaMarkSet(mark_and(ROUTE_MASK)),
            ret(),
        ],
    )?;
    add_rule(
        w,
        "route_pre",
        vec![
            established(),
            direction("reply"),
            Stmt::MetaMarkSet(Expr::And(
                Box::new(Expr::Shr(
                    Box::new(Expr::Ct("mark")),
                    Box::new(Expr::Num(8)),
                )),
                Box::new(Expr::Num(ROUTE_MASK)),
            )),
            ret(),
        ],
    )?;
    add_rule(
        w,
        "route_out",
        vec![
            established(),
            direction("reply"),
            Stmt::MetaMarkSet(Expr::And(
                Box::new(Expr::Shr(
                    Box::new(Expr::Ct("mark")),
                    Box::new(Expr::Num(8)),
                )),
                Box::new(Expr::Num(ROUTE_MASK)),
            )),
        ],
    )?;
    // new connections arriving on a WAN reply through it
    for (iface, gw) in &plan.routing.reply {
        let (Some(i), Some(mark)) = (policy.interfaces.get(iface), plan.routing.mark(gw)) else {
            continue;
        };
        add_rule(
            w,
            "route_pre",
            vec![
                Stmt::Match {
                    op: "==",
                    left: Expr::Meta("iifname"),
                    right: Expr::Str(i.device.clone().into()),
                },
                Stmt::CtMarkSet(Expr::Or(
                    Box::new(mark_and(!REPLY_MASK)),
                    Box::new(Expr::Num(mark << 8)),
                )),
            ],
        )?;
    }
    // new connections from inside: the first matching inbound rule decides
    let mut by_dev = Vec::new();
    for k in plan.chains.iter().flatten() {
        if let Some(i) = policy.interfaces.get(*k) {
            by_dev.push((
                Expr::Str(i.device.clone().into()),
                Verdict::Goto(route_chain(Some(k)).into()),
            ));
        }
    }
    if !by_dev.is_empty() {
        add_rule(
            w,
            "route_pre",
            vec![Stmt::Vmap {
                key: Expr::Meta("iifname"),
                data: by_dev,
            }],
        )?;
    }
    if plan.chains.contains(&None) {
        add_rule(
            w,
            "route_pre",
            vec![Stmt::Verdict(Verdict::Goto(route_chain(None).into()))],
        )?;
    }
    for k in &plan.chains {
        let chain = route_chain(*k);
        let members: Vec<(&FilterRule, &Vec<Low<'_>>)> = eval
            .iter()
            .copied()
            .zip(lows)
            .filter(|(r, _)| r.direction.matches_in() && applies_to(r, *k))
            .collect();
        // rules after the last gateway rule cannot pick a gateway
        let Some(last) = members.iter().rposition(|(r, _)| routes(r)) else {
            continue;
        };
        for (r, ls) in &members[..=last] {
            let mark = if routes(r) {
                let gw = r.gateway.as_deref().unwrap_or_default();
                match plan.routing.mark(gw) {
                    Some(m) => Some(m),
                    None => {
                        warnings.push(Warning {
                            label: r.label.clone(),
                            message: format!("unknown gateway {gw}; not policy-routed"),
                        });
                        None
                    }
                }
            } else {
                None
            };
            for l in ls.iter() {
                let mut expr: Vec<Stmt<'_>> = l.matches.iter().map(match_stmt).collect();
                if let Some(m) = mark {
                    if opts.counters {
                        expr.push(Stmt::Counter);
                    }
                    expr.push(Stmt::MetaMarkSet(Expr::Num(m)));
                    expr.push(Stmt::CtMarkSet(Expr::Or(
                        Box::new(mark_and(!ROUTE_MASK)),
                        Box::new(Expr::Num(m)),
                    )));
                }
                expr.push(ret());
                w.add(Object::Rule {
                    chain: chain.clone().into(),
                    expr,
                    comment: comment(l.label),
                })?;
            }
        }
    }
    Ok(())
}
