//! The OPNsense section mappers: `config.xml` → [`sensr_schema::Document`].
//!
//! Each mapper re-expresses one area of the OPNsense configuration behaviourally
//! (what the box would do), not field by field; the semantics come from the
//! upstream code that consumes the section (`filter.inc`, `interfaces.inc`, the MVC
//! models). Where both a legacy and an MVC form exist (legacy `filter/rule` and
//! `OPNsense/Firewall/Filter`, ISC `dhcpd` and Kea), both are read.

mod aliases;
mod common;
mod dhcp_servers;
mod dhcpd;
mod dnsmasq;
mod export;
mod filter;
mod gateways;
mod ids;
mod interfaces;
mod kea;
mod nat;
mod system;
mod trust;
mod unbound;
mod wireguard;

use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;

use sensr_schema::Document as SensrDocument;
use sensr_schema::fields::DeviceName;

pub use export::export_document;

use crate::mapper::{Imported, Importer};
use crate::tree::Document;
use crate::xml::{XmlError, parse};

/// Choices the operator makes about an import.
#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    /// FreeBSD device name (`igc0`, `vtnet1`) → Linux device name (`enp1s0`). Devices
    /// not listed keep their FreeBSD name and are reported, so the assignment step
    /// (seed file or installer) can rename them.
    pub devices: BTreeMap<String, DeviceName>,
}

/// Parse and import an OPNsense `config.xml`.
pub fn import_config(
    input: &str,
    options: &ImportOptions,
) -> Result<Imported<SensrDocument>, XmlError> {
    let doc = parse(input)?;
    Ok(import_document(&doc, options))
}

/// Import an already parsed `config.xml`.
pub fn import_document(doc: &Document, options: &ImportOptions) -> Imported<SensrDocument> {
    importer(options).import(doc)
}

/// Export `doc` as OPNsense `config.xml` text (the mapped subset; see [`export_document`]).
pub fn export_config(doc: &SensrDocument) -> String {
    crate::xml::to_config_string(&export_document(doc))
}

/// The importer with every OPNsense mapper and the expected-unmapped table.
///
/// Mapper order matters: interfaces and aliases come first because rules, NAT and
/// services refer to them.
pub fn importer(options: &ImportOptions) -> Importer<SensrDocument> {
    let options = Arc::new(options.clone());
    let dhcp = dhcp_servers::SharedLedger::default();
    let mut importer = Importer::new()
        .with_mapper(system::SystemMapper)
        .with_mapper(interfaces::InterfacesMapper::new(Arc::clone(&options)))
        .with_mapper(aliases::AliasMapper)
        .with_mapper(filter::FilterMapper::default())
        .with_mapper(nat::NatMapper::default())
        // Kea last: it sees whether ISC or dnsmasq serve, and its finish step
        // reconciles the three (see dhcp_servers).
        .with_mapper(dhcpd::DhcpdMapper::new(Rc::clone(&dhcp)))
        .with_mapper(dnsmasq::DnsmasqMapper::new(Rc::clone(&dhcp)))
        .with_mapper(kea::KeaMapper::new(dhcp))
        .with_mapper(unbound::UnboundMapper)
        .with_mapper(wireguard::WireGuardMapper)
        .with_mapper(trust::TrustMapper)
        .with_mapper(ids::IdsMapper)
        .with_mapper(ids::NetflowMapper)
        // Last: its fix-ups need the interfaces and the rules the others built.
        .with_mapper(gateways::GatewayMapper);
    for (pattern, reason) in EXPECTED_UNMAPPED {
        importer = importer.expect_unmapped(pattern, reason);
    }
    importer
}

/// Nodes deliberately not imported, with the reason shown in the report.
///
/// "Not modelled yet" entries are features sensr will cover in a later phase; they
/// are listed so the operator sees them, and they move out of this table when their
/// mapper lands.
pub const EXPECTED_UNMAPPED: &[(&str, &str)] = &[
    // Metadata and UI state.
    (
        "version",
        "legacy config format number; sensr documents carry their own schema version",
    ),
    (
        "revision",
        "OPNsense revision metadata; sensr keeps its own revision history",
    ),
    ("theme", "web GUI theme"),
    ("trigger_initial_wizard", "OPNsense setup wizard marker"),
    (
        "**/audit",
        "OPNsense change metadata; sensr keeps its own audit log",
    ),
    (
        "**/created",
        "OPNsense change metadata; sensr keeps its own audit log",
    ),
    (
        "**/updated",
        "OPNsense change metadata; sensr keeps its own audit log",
    ),
    ("system/language", "web GUI language"),
    (
        "system/firmware",
        "FreeBSD package mirror and plugin selection; sensr updates through NixOS generations",
    ),
    (
        "system/optimization",
        "pf state-timeout profile; nftables conntrack uses kernel defaults",
    ),
    (
        "system/powerd_*",
        "FreeBSD powerd; CPU frequency scaling is a NixOS concern",
    ),
    ("system/usevirtualterminal", "FreeBSD console setting"),
    (
        "system/disableconsolemenu",
        "the sensr console menu has its own setting",
    ),
    ("system/pf_share_forward", "pf-specific forwarding option"),
    ("system/lb_use_sticky", "pf load-balancing stickiness"),
    (
        "system/bogons",
        "bogon list update interval; sensr ships bogon lists with the system",
    ),
    (
        "system/backupcount",
        "OPNsense backup retention; sensr keeps every revision",
    ),
    ("system/prefer_ipv4", "FreeBSD resolver preference"),
    (
        "system/dnsallowoverride_exclude",
        "per-interface DNS override exclusion is not modelled yet",
    ),
    (
        "system/webgui",
        "web GUI listener settings are not modelled yet",
    ),
    ("sysctl", "FreeBSD sysctl tunables do not apply to Linux"),
    ("rrd", "RRD graphs are replaced by sensr-monitor"),
    (
        "ntpd",
        "NTP server preferences are not modelled yet (system.time_servers is imported)",
    ),
    ("OPNsense/Syslog", "remote syslog is not modelled yet"),
    (
        "OPNsense/trust",
        "trust store settings are not modelled yet",
    ),
    (
        "OPNsense/unboundplus/dnsbl",
        "DNS blocklists are not modelled yet",
    ),
    (
        "OPNsense/unboundplus/advanced",
        "Unbound tuning options are not modelled yet",
    ),
    (
        "OPNsense/unboundplus/acls",
        "Unbound access lists are not modelled yet",
    ),
    (
        "OPNsense/Kea/dhcp4/ha",
        "Kea high availability is not modelled yet",
    ),
    (
        "OPNsense/Kea/dhcp4/lexpire",
        "Kea lease expiry tuning is not modelled yet",
    ),
    (
        "OPNsense/Gateways",
        "gateways are derived from interface addressing; monitoring is not modelled yet",
    ),
];

#[cfg(test)]
mod tests;
