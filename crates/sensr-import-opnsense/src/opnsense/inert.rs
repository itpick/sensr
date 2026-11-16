//! Sections that configure nothing in this particular file: a service that
//! is switched off, an HA peer that was never set up, the factory's built-in
//! monitor types. Whether such a node matters depends on its content, so a
//! static expected-unmapped pattern cannot decide it: the same section with
//! the service switched on must stay *unexpected* (sensr would silently drop
//! a feature in use). After every mapper ran, each rule here checks its
//! node and, only when it is inert, reports it as expected with the reason.

use sensr_schema::Document;

use crate::mapper::{MapContext, Mapper};
use crate::tree::{Document as Tree, Element};

pub struct InertMapper;

/// A node and the test that it is inert.
struct Rule {
    path: &'static [&'static str],
    reason: &'static str,
    inert: fn(&Element, &Tree) -> bool,
}

fn text_at(e: &Element, path: &[&str]) -> Option<String> {
    let mut cur = e;
    for p in path {
        cur = cur.child(p)?;
    }
    Some(cur.text().trim().to_owned())
}

/// An MVC `general/enabled` that is not `1`.
fn general_disabled(e: &Element, _: &Tree) -> bool {
    text_at(e, &["general", "enabled"]).as_deref() != Some("1")
}

const RULES: &[Rule] = &[
    Rule {
        path: &["OPNsense", "IPsec"],
        reason: "IPsec is disabled (sensr has no IPsec yet)",
        inert: general_disabled,
    },
    Rule {
        path: &["OPNsense", "Kea", "dhcp6"],
        reason: "Kea DHCPv6 is disabled",
        inert: general_disabled,
    },
    Rule {
        path: &["OPNsense", "monit"],
        reason: "Monit is disabled (systemd restarts sensr's services; sensr-monitor watches gateways)",
        inert: general_disabled,
    },
    Rule {
        // dhcpd.inc dhcpd_dhcpv6_enabled(): `enable` = -1 is "explicitly off",
        // which the tracking-interface form writes when its server is unticked.
        path: &["dhcpdv6"],
        reason: "the ISC DHCPv6 server is explicitly off on every interface (enable = -1)",
        inert: |e, _| {
            e.elements().all(|i| {
                text_at(i, &["enable"]).as_deref() == Some("-1") && i.elements().count() == 1
            })
        },
    },
    Rule {
        // The legacy bsnmpd settings of the factory config; OPNsense core has
        // no SNMP service (it is the os-net-snmp plugin, `OPNsense/netsnmp`).
        path: &["snmpd"],
        reason: "legacy SNMP community/location settings; no SNMP service is configured",
        inert: |e, _| {
            e.elements()
                .all(|c| ["syslocation", "syscontact", "rocommunity"].contains(&c.name.as_str()))
        },
    },
    Rule {
        path: &["hasync"],
        reason: "high-availability sync is not set up (no pfsync interface or peer)",
        inert: |e, _| {
            ["pfsyncinterface", "pfsyncpeerip", "synchronizetoip"]
                .iter()
                .all(|f| text_at(e, &[f]).unwrap_or_default().is_empty())
        },
    },
    Rule {
        path: &["load_balancer"],
        reason: "only OPNsense's built-in monitor types; no load-balancer pool is configured",
        inert: |e, _| {
            e.elements().all(|c| {
                c.name == "monitor_type"
                    && ["ICMP", "TCP", "HTTP", "HTTPS", "SMTP"]
                        .contains(&text_at(c, &["name"]).unwrap_or_default().as_str())
            })
        },
    },
];

/// A leaf and the test that it is inert, given its parent.
struct LeafRule {
    path: &'static [&'static str],
    reason: &'static str,
    inert: fn(&Element, &Element, &Tree) -> bool,
}

const LEAF_RULES: &[LeafRule] = &[
    LeafRule {
        // The mask bits of the translation address; meaningless without one.
        path: &["nat", "outbound", "rule", "targetip_subnet"],
        reason: "mask of a translation address the rule does not set",
        inert: |_, rule, _| text_at(rule, &["target"]).unwrap_or_default().is_empty(),
    },
    LeafRule {
        // filter.inc: a filter rule a port forward created carries the
        // forward's id; once no forward refers back to it, it is an ordinary
        // rule (and is imported as one).
        path: &["filter", "rule", "associated-rule-id"],
        reason: "link to a port forward that no longer refers to this rule; the rule is imported on its own",
        inert: |e, _, doc| {
            let id = e.text();
            let id = id.trim();
            doc.root
                .child("nat")
                .into_iter()
                .flat_map(|n| n.elements().filter(|r| r.name == "rule"))
                .all(|r| text_at(r, &["associated-rule-id"]).as_deref() != Some(id))
        },
    },
];

fn find_all<'a>(root: &'a Element, path: &[&str]) -> Vec<&'a Element> {
    let mut cur = vec![root];
    for p in path {
        cur = cur
            .into_iter()
            .flat_map(|e| e.elements().filter(move |c| c.name == *p))
            .collect();
    }
    cur
}

impl Mapper<Document> for InertMapper {
    fn name(&self) -> &'static str {
        "inert"
    }

    fn sections(&self) -> &'static [&'static str] {
        &[]
    }

    fn map<'doc>(&self, _: &'doc Element, _: &mut MapContext<'doc>, _: &mut Document) {}

    fn finish<'doc>(&self, doc: &'doc Tree, ctx: &mut MapContext<'doc>, _: &mut Document) {
        for rule in RULES {
            for e in find_all(&doc.root, rule.path) {
                if (rule.inert)(e, doc) {
                    ctx.expect(e, rule.reason);
                }
            }
        }
        for rule in LEAF_RULES {
            let (leaf, parent) = rule.path.split_last().expect("non-empty path");
            for p in find_all(&doc.root, parent) {
                for e in p.elements().filter(|c| c.name == *leaf) {
                    if (rule.inert)(e, p, doc) {
                        ctx.expect(e, rule.reason);
                    }
                }
            }
        }
    }
}
