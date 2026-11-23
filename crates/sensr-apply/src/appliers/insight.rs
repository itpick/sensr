//! Traffic accounting and alert storage: the `sensr-insight` daemon's
//! configuration and the in-kernel accounting table (`sensr_flow::nft`).

use std::path::PathBuf;

use sensr_flow::config::{
    Config, DNSTAP_SOCKET, DnsConfig, FlowConfig, IdsConfig, Iface, Retention,
};
use sensr_schema::Document;
use sensr_schema::models::interfaces::InterfaceRole;

use super::dns_runtime::QUERY_LOG;
use super::suricata::LOG_DIR;

/// Live directory of the daemon's files.
pub const DIR: &str = "run/sensr/insight";
/// The daemon's configuration (`sensr_flow::config::CONFIG_PATH`).
pub const CONFIG: &str = "insight.json";
/// The accounting table, as a plan file (loaded with `nft -j -f`).
pub const NFT: &str = "flow.nft.json";
/// The daemon.
pub const UNIT: &str = "sensr-insight.service";

/// The daemon's configuration (`None`: neither accounting nor IDS is on).
pub fn config(doc: &Document) -> Option<Config> {
    let flows = doc.insight.enabled.then(|| {
        let chosen = &doc.insight.interfaces;
        let interfaces = doc
            .interfaces
            .iter()
            .filter(|(_, i)| i.enabled)
            .map(|(id, i)| Iface {
                name: id.to_string(),
                device: i.device.to_string(),
                local: if chosen.is_empty() {
                    i.role != InterfaceRole::Wan
                } else {
                    chosen.contains(id)
                },
            })
            .collect();
        let r = &doc.insight.retention;
        // Unbound streams dnstap whenever insight is on (`unbound.rs`)
        let dns = doc.dns.enabled.then(|| DnsConfig {
            service_overrides: doc
                .insight
                .dns
                .service_overrides
                .iter()
                .map(|(_, o)| o.clone())
                .filter(|o| o.enabled)
                .collect(),
            query_log: doc.dns.tuning.log_queries.then(|| PathBuf::from(QUERY_LOG)),
            ..DnsConfig::new(DNSTAP_SOCKET)
        });
        FlowConfig {
            sample_seconds: u32::from(doc.insight.sample_seconds),
            max_entries: doc.insight.max_entries,
            interfaces,
            retention: Retention {
                minute_hours: u32::from(r.minute_hours),
                hour_days: u32::from(r.hour_days),
                day_days: u32::from(r.day_days),
            },
            dns,
        }
    });
    let ids = doc.ids.enabled.then(|| IdsConfig {
        eve: PathBuf::from(LOG_DIR).join("eve.json"),
        retention_days: u32::from(doc.ids.logging.retention_days),
        max_alerts: u64::from(doc.ids.logging.max_alerts),
    });
    (flows.is_some() || ids.is_some()).then_some(Config { flows, ids })
}

/// The accounting table for `cfg`, or its removal when accounting is off.
pub fn ruleset(cfg: &Config) -> String {
    match &cfg.flows {
        Some(f) => sensr_flow::nft::ruleset(f),
        None => sensr_flow::nft::removal(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> Document {
        serde_json::from_str(include_str!(
            "../../../sensr-import-opnsense/tests/golden/home-router.sensr.json"
        ))
        .unwrap()
    }

    #[test]
    fn local_interfaces_default_to_every_non_wan() {
        let mut d = doc();
        assert!(config(&d).is_none());
        d.insight.enabled = true;
        let c = config(&d).unwrap();
        let f = c.flows.as_ref().unwrap();
        let wan = f.interfaces.iter().find(|i| i.name == "wan").unwrap();
        assert!(!wan.local);
        assert!(f.interfaces.iter().any(|i| i.local));
        assert!(c.ids.is_none());
        assert!(ruleset(&c).contains("update"));
        let dns = f.dns.as_ref().expect("the resolver is on in the golden");
        assert_eq!(dns.socket, PathBuf::from(DNSTAP_SOCKET));
        assert!(dns.service_overrides.is_empty());
        d.insight.interfaces = vec!["lan".parse().unwrap()];
        let c = config(&d).unwrap();
        let locals: Vec<_> = c
            .flows
            .unwrap()
            .interfaces
            .into_iter()
            .filter(|i| i.local)
            .map(|i| i.name)
            .collect();
        assert_eq!(locals, ["lan"]);
        // IDS alone runs the daemon for alerts, without the table
        d.insight.enabled = false;
        d.ids.enabled = true;
        let c = config(&d).unwrap();
        assert!(c.flows.is_none() && c.ids.is_some());
        assert!(ruleset(&c).contains("delete"));
    }
}
