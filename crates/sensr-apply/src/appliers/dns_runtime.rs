//! What the `sensr-dns` services need from the configuration: the blocklist
//! policies and the DHCP lease registration settings, rendered by the
//! `unbound` module as `sensr-dns.json` next to `unbound.conf`.
//!
//! The resolver itself is configured entirely by `unbound.conf`; these two
//! jobs need runtime data the renderer cannot know (downloaded lists, live
//! leases), so `sensr-dns` writes them as Unbound include files in
//! [`STATE_DIR`] and pushes changes with `unbound-control`.

use std::net::IpAddr;
use std::path::PathBuf;

use ipnet::IpNet;
use sensr_schema::Uuid;
use sensr_schema::fields::DomainName;
use sensr_schema::models::dnsbl::Blocklist;
use serde::{Deserialize, Serialize};

use super::unbound::AclAction;

/// Where `sensr-dns` keeps its state and the include files (the NixOS unit's
/// `StateDirectory`).
pub const STATE_DIR: &str = "/var/lib/sensr-dns";
/// The compiled blocklist, included by `unbound.conf`.
pub const BLOCKLIST_INCLUDE: &str = "/var/lib/sensr-dns/blocklist.conf";
/// The registered DHCP leases, included by `unbound.conf`.
pub const LEASES_INCLUDE: &str = "/var/lib/sensr-dns/leases.conf";
/// Runtime statistics for the web UI.
pub const STATS_FILE: &str = "/run/sensr-dns/unbound-stats.json";
/// Where the runtime configuration is rendered (`sensr-dns --config`).
pub const RUNTIME_CONF: &str = "/run/sensr/unbound/sensr-dns.json";
/// A minimal `unbound-control` configuration: the full `unbound.conf`
/// includes the blocklist, which `unbound-control` would parse on every call.
pub const CONTROL_CONF: &str = "/run/sensr/unbound/control.conf";

/// `sensr-dns.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRuntime {
    /// `unbound-control -c` argument.
    pub control_conf: PathBuf,
    /// State directory (include files, list cache, status).
    pub state_dir: PathBuf,
    /// Collect resolver statistics for the web UI.
    pub statistics: bool,
    /// Blocklists, when any policy is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocklist: Option<BlocklistRuntime>,
    /// Lease registration, when enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leases: Option<LeaseRuntime>,
}

/// The blocklist job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocklistRuntime {
    /// Enabled policies in configuration order (priority is derived from
    /// their source networks by the compiler, as OPNsense does).
    pub policies: Vec<PolicyRuntime>,
    /// Names served from local data (system domain, host overrides, domain
    /// overrides, lease domains): never blocked, so the blocklist cannot
    /// shadow the network's own names.
    pub protected: Vec<DomainName>,
    /// The resolver's access control, so per-network policies (Unbound
    /// views) can keep each network's action.
    pub default_action: AclAction,
    /// Access lists (network, action), as rendered into `unbound.conf`.
    pub acls: Vec<(IpNet, AclAction)>,
}

/// One policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRuntime {
    /// The policy's UUID.
    pub id: Uuid,
    /// The policy.
    pub policy: Blocklist,
}

/// The lease registration job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRuntime {
    /// Kea's memfile lease database (its rotated files sit next to it).
    pub lease_file: PathBuf,
    /// Domain for leases whose subnet has no domain name.
    pub default_domain: DomainName,
    /// Domain per Kea subnet id.
    pub subnets: Vec<(u32, DomainName)>,
    /// Names and addresses already served from static data (reservations,
    /// host overrides): a lease never replaces them.
    pub static_names: Vec<String>,
    /// Addresses whose reverse name is already served.
    pub static_addresses: Vec<IpAddr>,
}
