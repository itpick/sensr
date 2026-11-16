//! `OPNsense/IDS` (Suricata) and `OPNsense/Netflow` (Insight).
//!
//! Behaviour comes from `IDS.xml` and the Suricata templates
//! (`service/templates/OPNsense/IDS/*`): only the enabled rules files load;
//! netmap and divert are the two IPS modes, both of which sensr runs as
//! NFQUEUE; the rule-update cron job referenced by `UpdateCron` is what
//! downloads rules at all.

use std::collections::HashMap;

use sensr_schema::Document;
use sensr_schema::fields::InterfaceId;
use sensr_schema::ipnet::IpNet;
use sensr_schema::models::ids::{
    DetectProfile, IdsMode, IdsPolicy, MetadataMatch, PatternMatcher, PolicyAction, RuleAction,
    RuleFile, RuleOverride, RuleProfile, UserRule, UserRuleAction,
};
use sensr_schema::models::interfaces::InterfaceRole;

use super::common::{description, interface_id, item_uuid, list, parse_or_warn};
use crate::mapper::{MapContext, Mapper};
use crate::report::Severity;
use crate::tree::{Document as XmlDocument, Element};

pub struct IdsMapper;

/// Rules-file prefixes of the ET Open archive (what the default source ships).
const ET_OPEN_PREFIXES: &[&str] = &[
    "emerging-",
    "botcc",
    "ciarmy",
    "compromised",
    "drop",
    "dshield",
    "threatview",
    "tor",
];

impl Mapper<Document> for IdsMapper {
    fn name(&self) -> &'static str {
        "ids"
    }

    fn sections(&self) -> &'static [&'static str] {
        &["OPNsense/IDS"]
    }

    fn map<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        // rules files first: policies refer to them by uuid
        let mut files: HashMap<String, RuleFile> = HashMap::new();
        let mut enabled_files = Vec::new();
        if let Some(fs) = ctx.child(s, "files") {
            for f in ctx.children(fs, "file") {
                let id = item_uuid(ctx, f).to_string();
                let Some(name_el) = ctx.child(f, "filename") else {
                    continue;
                };
                let Some(name) =
                    parse_or_warn::<RuleFile>(ctx, name_el, &name_el.text(), "rules file")
                else {
                    ctx.release(f);
                    continue;
                };
                if ctx.bool01(f, "enabled") {
                    if !ET_OPEN_PREFIXES
                        .iter()
                        .any(|p| name.as_str().starts_with(p))
                    {
                        ctx.warn(
                            f,
                            Severity::Degraded,
                            format!(
                                "{name} is not part of ET Open, the only source imported; add its source under ids.sources"
                            ),
                        );
                    }
                    enabled_files.push(name.clone());
                }
                files.insert(id, name);
            }
        }
        let ids = &mut out.ids;
        if enabled_files.is_empty() {
            // nothing selected loads nothing on OPNsense; sensr's curated set
            // is the useful equivalent of "the defaults"
            ids.profile = RuleProfile::Home;
        } else {
            ids.profile = RuleProfile::Custom;
            ids.rule_files = enabled_files;
        }

        if let Some(g) = ctx.child(s, "general") {
            general(g, ctx, out);
        }

        if let Some(rs) = ctx.child(s, "rules") {
            for r in ctx.children(rs, "rule") {
                let sid = ctx.parse::<u32>(r, "sid");
                let enabled = ctx.bool01(r, "enabled");
                let action = match ctx.text(r, "action").as_deref().map(str::trim) {
                    Some("drop") => RuleAction::Drop,
                    _ => RuleAction::Alert,
                };
                // msg and source are volatile (filled from the ruleset)
                ctx.text(r, "msg");
                ctx.text(r, "source");
                match sid {
                    Some(sid) if sid > 0 => out.ids.rule_overrides.push(RuleOverride {
                        sid,
                        enabled,
                        action,
                    }),
                    _ => ctx.release(r),
                }
            }
        }

        if let Some(ps) = ctx.child(s, "policies") {
            for p in ctx.children(ps, "policy") {
                let id = item_uuid(ctx, p);
                let rulesets = ctx
                    .text(p, "rulesets")
                    .map(|t| list(&t, &[',']))
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|u| files.get(&u).cloned())
                    .collect();
                let matched = ctx.text(p, "action").unwrap_or_default();
                let matched = list(&matched, &[',']);
                if !matched.is_empty() && matched.len() < 3 {
                    ctx.warn(
                        p,
                        Severity::Degraded,
                        format!(
                            "the policy matched only rules whose current action is {}; sensr applies it to every matching rule",
                            matched.join(" or ")
                        ),
                    );
                }
                let metadata = ctx
                    .text(p, "content")
                    .map(|t| list(&t, &[',']))
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|c| {
                        let (k, v) = c.split_once('.')?;
                        Some(MetadataMatch {
                            key: k.to_owned(),
                            value: v.replace('_', " "),
                        })
                    })
                    .collect();
                let action = match ctx.text(p, "new_action").as_deref().map(str::trim) {
                    Some("default") => PolicyAction::Default,
                    Some("drop") => PolicyAction::Drop,
                    Some("disable") => PolicyAction::Disable,
                    _ => PolicyAction::Alert,
                };
                let desc = ctx.text(p, "description");
                let policy = IdsPolicy {
                    enabled: ctx.bool01(p, "enabled"),
                    priority: ctx.parse(p, "prio").unwrap_or(0),
                    rulesets,
                    metadata,
                    action,
                    description: description(ctx, p, desc),
                };
                out.ids.policies.insert(id, policy);
            }
        }

        if let Some(us) = ctx.child(s, "userDefinedRules") {
            for r in ctx.children(us, "rule") {
                let id = item_uuid(ctx, r);
                let net = |ctx: &mut MapContext<'doc>, name: &str| -> Option<IpNet> {
                    let t = ctx.non_empty(r, name)?;
                    let n = t
                        .parse::<IpNet>()
                        .ok()
                        .or_else(|| t.parse::<std::net::IpAddr>().ok().map(IpNet::from));
                    if n.is_none() {
                        ctx.warn(r, Severity::Invalid, format!("{name} {t:?} not imported"));
                    }
                    n
                };
                let source = net(ctx, "source");
                let destination = net(ctx, "destination");
                let fingerprint = ctx.non_empty(r, "fingerprint");
                let action = match ctx.text(r, "action").as_deref().map(str::trim) {
                    Some("drop") => UserRuleAction::Drop,
                    Some("pass") => UserRuleAction::Pass,
                    _ => UserRuleAction::Alert,
                };
                let bypass = ctx.bool01(r, "bypass");
                let desc = ctx.text(r, "description");
                let Some(description) = description(ctx, r, desc) else {
                    ctx.release(r);
                    continue;
                };
                out.ids.user_rules.insert(
                    id,
                    UserRule {
                        enabled: ctx.bool01(r, "enabled"),
                        source,
                        destination,
                        fingerprint,
                        action,
                        bypass: bypass && action == UserRuleAction::Pass,
                        description,
                    },
                );
            }
        }
    }

    fn expected_unmapped(&self) -> &'static [(&'static str, &'static str)] {
        &[(
            "OPNsense/IDS/fileTags",
            "ruleset metadata cache; suricata-update reads the sources' own metadata",
        )]
    }

    fn finish<'doc>(&self, doc: &'doc XmlDocument, ctx: &mut MapContext<'doc>, out: &mut Document) {
        let Some(ids) = doc.root.path(&["OPNsense", "IDS", "general"]) else {
            return;
        };
        let Some(cron_id) = ids.child("UpdateCron").map(Element::text) else {
            return;
        };
        let Some(jobs) = doc.root.path(&["OPNsense", "cron", "jobs"]) else {
            return;
        };
        let Some(job) = jobs
            .children_named("job")
            .find(|j| j.attribute("uuid") == Some(cron_id.trim()))
        else {
            return;
        };
        ctx.consume_subtree(job);
        let enabled = job.child("enabled").is_some_and(|e| e.text().trim() == "1");
        let num = |name: &str| {
            job.child(name)
                .and_then(|e| e.text().trim().parse::<u8>().ok())
        };
        if let (Some(h), Some(m)) = (num("hours"), num("minutes"))
            && h < 24
            && m < 60
        {
            out.ids.updates.hour = h;
            out.ids.updates.minute = m;
        }
        out.ids.updates.enabled = true;
        if !enabled && out.ids.enabled {
            ctx.warn(
                job,
                Severity::Info,
                "the rule update job was disabled, so OPNsense never downloaded any rules; sensr downloads them at start and daily (ids.updates)",
            );
        }
    }
}

fn general<'doc>(g: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
    let enabled = ctx.bool01(g, "enabled");
    let mode = ctx.text(g, "mode").unwrap_or_default();
    let mode = match mode.trim() {
        "netmap" | "divert" => {
            ctx.warn(
                g,
                Severity::Info,
                format!(
                    "{} IPS runs as nftables NFQUEUE on sensr: fail-open, and open connections are picked up midstream",
                    mode.trim()
                ),
            );
            IdsMode::Prevent
        }
        _ => IdsMode::Detect,
    };
    let listeners = ctx.parse::<u8>(g, "divert_listeners");
    let promisc = ctx.bool01(g, "promisc");
    let mut interfaces: Vec<InterfaceId> = Vec::new();
    if let Some(t) = ctx.text(g, "interfaces") {
        for name in list(&t, &[',']) {
            match interface_id(out, &name) {
                Some(id) => interfaces.push(id),
                None => ctx.warn(
                    g,
                    Severity::Invalid,
                    format!("IDS interface {name:?} is not an imported interface"),
                ),
            }
        }
    }
    let mut home_net = Vec::new();
    if let Some(t) = ctx.text(g, "homenet") {
        for n in list(&t, &[',']) {
            match n
                .parse::<IpNet>()
                .ok()
                .or_else(|| n.parse::<std::net::IpAddr>().ok().map(IpNet::from))
            {
                Some(net) => home_net.push(net),
                None => ctx.warn(
                    g,
                    Severity::Invalid,
                    format!("home network {n:?} not imported"),
                ),
            }
        }
    }
    let wan_inspected = interfaces.iter().any(|i| {
        out.interfaces
            .get(i)
            .is_some_and(|x| x.role == InterfaceRole::Wan)
    });
    if enabled && wan_inspected && mode == IdsMode::Detect {
        ctx.warn(
            g,
            Severity::Info,
            "HOME_NET also gets the WAN's current addresses (ids.home_net_auto): after NAT the WAN sees only public addresses, so an RFC 1918 HOME_NET matched almost nothing",
        );
    }
    let packet_size = ctx.parse::<u16>(g, "defaultPacketSize");
    let retention = {
        let rotate = ctx.text(g, "AlertLogrotate").unwrap_or_default();
        let keep = ctx.parse::<u16>(g, "AlertSaveLogs").unwrap_or(4);
        let per = if rotate.trim() == "D0" { 1 } else { 7 };
        keep.saturating_mul(per).clamp(1, 3650)
    };
    let mpm = match ctx.text(g, "MPMAlgo").as_deref().map(str::trim) {
        Some("ac") => Some(PatternMatcher::Ac),
        Some("ac-ks") => Some(PatternMatcher::AcKs),
        Some("hs") => Some(PatternMatcher::Hs),
        _ => None,
    };
    let mut profile = DetectProfile::Medium;
    if let Some(d) = ctx.child(g, "detect") {
        match ctx.text(d, "Profile").as_deref().map(str::trim) {
            Some("low") => profile = DetectProfile::Low,
            Some("high") => profile = DetectProfile::High,
            Some("custom") => ctx.warn(
                d,
                Severity::Degraded,
                "custom detection group sizes are not imported; the medium profile is used",
            ),
            _ => {}
        }
        ctx.text(d, "toclient_groups");
        ctx.text(d, "toserver_groups");
    }
    let syslog = ctx.bool01(g, "syslog");
    let payload = ctx.bool01(g, "LogPayload");
    ctx.defaults(g, &[("syslog_eve", "0"), ("verbosity", "")]);
    let (mut http, mut tls) = (false, false);
    if let Some(e) = ctx.child(g, "eveLog") {
        if let Some(h) = ctx.child(e, "http") {
            http = ctx.bool01(h, "enable");
            ctx.defaults(h, &[("extended", "0"), ("dumpAllHeaders", "")]);
        }
        if let Some(t) = ctx.child(e, "tls") {
            tls = ctx.bool01(t, "enable");
            ctx.defaults(
                t,
                &[
                    ("extended", "0"),
                    ("sessionResumption", "0"),
                    ("custom", ""),
                ],
            );
        }
    }
    // the job itself is read in `finish`
    ctx.text(g, "UpdateCron");

    let ids = &mut out.ids;
    ids.enabled = enabled;
    ids.mode = mode;
    ids.promiscuous = promisc;
    ids.interfaces = interfaces;
    if !home_net.is_empty() {
        ids.home_net = home_net;
    }
    ids.tuning.default_packet_size = packet_size;
    ids.tuning.pattern_matcher = mpm;
    ids.tuning.detect_profile = profile;
    if mode == IdsMode::Prevent
        && let Some(n) = listeners.filter(|n| *n > 1)
    {
        ids.tuning.workers = Some(n.min(64));
    }
    ids.logging.retention_days = retention;
    ids.logging.syslog = syslog;
    ids.logging.payload = payload;
    ids.logging.http = http;
    ids.logging.tls = tls;
}

/// `OPNsense/Netflow`: capture + local collection become sensr's in-kernel
/// accounting. Export to a remote collector is not implemented, so such
/// targets stay in the report.
pub struct NetflowMapper;

/// OPNsense's own collector (flowd) for Insight.
const LOCAL_COLLECTOR: &str = "127.0.0.1:2056";

impl Mapper<Document> for NetflowMapper {
    fn name(&self) -> &'static str {
        "netflow"
    }

    fn sections(&self) -> &'static [&'static str] {
        &["OPNsense/Netflow"]
    }

    fn map<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        let collect = ctx
            .child(s, "collect")
            .map(|c| ctx.bool01(c, "enable"))
            .unwrap_or(false);
        out.insight.enabled = collect;
        // flow cache timeouts mean nothing to counters read every few seconds
        ctx.text(s, "activeTimeout");
        ctx.text(s, "inactiveTimeout");
        let Some(c) = ctx.child(s, "capture") else {
            return;
        };
        let captured: Vec<InterfaceId> = ctx
            .text(c, "interfaces")
            .map(|t| list(&t, &[',']))
            .unwrap_or_default()
            .iter()
            .filter_map(|n| interface_id(out, n))
            .collect();
        // local hosts live behind the non-WAN interfaces that were captured;
        // if that is all of them, keep the default (empty = every non-WAN)
        let locals: Vec<InterfaceId> = out
            .interfaces
            .iter()
            .filter(|(_, i)| i.role != InterfaceRole::Wan)
            .map(|(id, _)| id.clone())
            .collect();
        let chosen: Vec<InterfaceId> = captured
            .into_iter()
            .filter(|i| locals.contains(i))
            .collect();
        if !chosen.is_empty() && chosen.len() < locals.len() {
            out.insight.interfaces = chosen;
        }
        ctx.text(c, "egress_only");
        ctx.text(c, "version");
        if let Some(t) = c.child("targets") {
            let targets = list(&t.text(), &[',']);
            if targets.iter().all(|t| t == LOCAL_COLLECTOR) {
                ctx.consume_subtree(t);
            } else {
                ctx.warn(
                    t,
                    Severity::Degraded,
                    "NetFlow export to remote collectors is not implemented yet; sensr accounts traffic itself (Reporting › Insight)",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::opnsense::{ImportOptions, import_config};
    use sensr_schema::models::ids::{IdsMode, RuleProfile};

    fn wrap(body: &str) -> String {
        format!(
            r#"<?xml version="1.0"?>
<opnsense>
  <interfaces>
    <wan><if>igc0</if><enable>1</enable><ipaddr>dhcp</ipaddr></wan>
    <lan><if>igc1</if><enable>1</enable><ipaddr>192.168.68.1</ipaddr><subnet>22</subnet></lan>
    <opt1><if>igc2</if><enable>1</enable><ipaddr>192.168.72.1</ipaddr><subnet>22</subnet></opt1>
  </interfaces>
  <OPNsense>{body}</OPNsense>
</opnsense>"#
        )
    }

    const IDS: &str = r#"
    <IDS version="1.1.2">
      <rules><rule uuid="11111111-61be-4036-ae90-57b4bc44e243"><sid>2024897</sid><enabled>0</enabled><action>alert</action></rule></rules>
      <policies>
        <policy uuid="22222222-61be-4036-ae90-57b4bc44e243">
          <enabled>1</enabled><prio>0</prio><action>alert</action>
          <rulesets>7a66e391-61be-4036-ae90-57b4bc44e243</rulesets>
          <content>signature_severity.Major</content>
          <new_action>drop</new_action><description>drop botcc</description>
        </policy>
      </policies>
      <userDefinedRules>
        <rule uuid="33333333-61be-4036-ae90-57b4bc44e243">
          <enabled>1</enabled><source>192.168.68.0/22</source><destination/><fingerprint/>
          <description>lan bypass</description><action>pass</action><bypass>1</bypass>
        </rule>
      </userDefinedRules>
      <files>
        <file uuid="7a66e391-61be-4036-ae90-57b4bc44e243"><filename>botcc.rules</filename><enabled>1</enabled></file>
        <file uuid="e8b5d6c0-af45-4ec5-8452-d21cc17dade1"><filename>emerging-malware.rules</filename><enabled>1</enabled></file>
        <file uuid="ecba145e-0918-4b1d-ad84-520ed210fa7d"><filename>emerging-info.rules</filename><enabled>0</enabled></file>
      </files>
      <fileTags/>
      <general>
        <enabled>1</enabled><mode>pcap</mode><divert_listeners>1</divert_listeners><promisc>0</promisc>
        <interfaces>wan</interfaces><homenet>192.168.0.0/16,10.0.0.0/8,172.16.0.0/12</homenet>
        <defaultPacketSize/><UpdateCron>4f744c06-6cb8-4b62-bd7b-8a8423a79fe5</UpdateCron>
        <AlertLogrotate>W0D23</AlertLogrotate><AlertSaveLogs>4</AlertSaveLogs><MPMAlgo>hs</MPMAlgo>
        <detect><Profile/><toclient_groups/><toserver_groups/></detect>
        <syslog>0</syslog><syslog_eve>0</syslog_eve><LogPayload>0</LogPayload><verbosity/>
        <eveLog>
          <http><enable>0</enable><extended>0</extended><dumpAllHeaders/></http>
          <tls><enable>1</enable><extended>0</extended><sessionResumption>0</sessionResumption><custom/></tls>
        </eveLog>
      </general>
    </IDS>
    <cron><jobs><job uuid="4f744c06-6cb8-4b62-bd7b-8a8423a79fe5">
      <origin>IDS</origin><enabled>0</enabled><minutes>0</minutes><hours>0</hours><days>*</days>
      <months>*</months><weekdays>*</weekdays><who>root</who><command>ids update</command>
      <parameters/><description>ids rule updates</description>
    </job></jobs></cron>"#;

    #[test]
    fn ids_section_imports_like_the_owners_router() {
        let r = import_config(&wrap(IDS), &ImportOptions::default()).unwrap();
        let ids = &r.document.ids;
        assert!(ids.enabled);
        assert_eq!(ids.mode, IdsMode::Detect);
        assert_eq!(ids.interfaces[0].as_str(), "wan");
        assert_eq!(ids.home_net.len(), 3);
        assert!(ids.home_net_auto);
        assert_eq!(ids.profile, RuleProfile::Custom);
        let files: Vec<&str> = ids.rule_files.iter().map(|f| f.as_str()).collect();
        assert_eq!(files, ["botcc.rules", "emerging-malware.rules"]);
        assert!(ids.updates.enabled && ids.updates.hour == 0);
        assert_eq!(ids.logging.retention_days, 28);
        assert!(ids.logging.tls && !ids.logging.http);
        assert_eq!(ids.rule_overrides.len(), 1);
        let p = ids.policies.values().next().unwrap();
        assert_eq!(p.rulesets[0].as_str(), "botcc.rules");
        assert_eq!(p.metadata[0].value, "Major");
        let u = ids.user_rules.values().next().unwrap();
        assert!(u.bypass && u.source.is_some());
        assert!(
            r.document.validate().is_empty(),
            "{}",
            r.document.validate()
        );
        let text = r.report.to_string();
        assert!(
            r.report.unmapped_unexpected.is_empty(),
            "nothing of the section may vanish: {text}"
        );
        assert!(text.contains("never downloaded"), "{text}");
        assert!(text.contains("HOME_NET also gets"), "{text}");
    }

    #[test]
    fn netmap_becomes_prevent() {
        let xml = wrap(&IDS.replace("<mode>pcap</mode>", "<mode>netmap</mode>"));
        let r = import_config(&xml, &ImportOptions::default()).unwrap();
        assert_eq!(r.document.ids.mode, IdsMode::Prevent);
        assert!(r.report.to_string().contains("NFQUEUE"));
    }

    #[test]
    fn netflow_local_collection_becomes_insight() {
        let nf = r#"<Netflow version="1.0.1">
          <capture><interfaces>lan,wan,opt1</interfaces><egress_only>wan</egress_only>
          <version>v9</version><targets>127.0.0.1:2056</targets></capture>
          <collect><enable>1</enable></collect>
          <activeTimeout>1800</activeTimeout><inactiveTimeout>15</inactiveTimeout></Netflow>"#;
        let r = import_config(&wrap(nf), &ImportOptions::default()).unwrap();
        assert!(r.document.insight.enabled);
        assert!(
            r.document.insight.interfaces.is_empty(),
            "all LANs: default"
        );
        assert!(r.report.unmapped_unexpected.is_empty(), "{}", r.report);

        let only_lan = nf.replace("lan,wan,opt1", "lan,wan");
        let r = import_config(&wrap(&only_lan), &ImportOptions::default()).unwrap();
        assert_eq!(r.document.insight.interfaces[0].as_str(), "lan");

        let remote = nf.replace("127.0.0.1:2056", "10.0.0.9:2055");
        let r = import_config(&wrap(&remote), &ImportOptions::default()).unwrap();
        assert_eq!(r.report.unmapped_unexpected.len(), 1, "{}", r.report);
    }
}
