//! Kea DHCPv4: `kea-dhcp4.conf` generated from the typed model.
//!
//! Behaviour follows OPNsense's `KeaDhcpv4::generateConfig`: subnets bound to
//! an interface are grouped into a shared network named `interface_<dev>`,
//! unbound subnets stay top-level; reservations live in their subnet; a
//! missing `domain-name` option defaults to the system domain; memfile leases
//! and a unix control socket. The file is serialised from typed structs (no
//! template), so it is always valid JSON, and `kea-dhcp4 -t` checks the rest.
//!
//! The input is [`Dhcp4Model`]: `sensr_schema` subnets and reservations with
//! interface ids resolved to devices and Kea subnet ids assigned
//! ([`super::convert`] builds it from a `Document`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sensr_schema::fields::{DeviceName, DomainName};
use sensr_schema::models::dhcp::{ClientMatch, Reservation4, Subnet4};
use serde::Serialize;

use crate::cmd::{Cmd, CmdError, Runner};

/// Default lease file (Kea 3 only accepts files under its data directory).
pub const LEASE_FILE: &str = "/var/lib/kea/dhcp4.leases";
/// Default control socket (Kea 3 only accepts sockets under `/run/kea`).
pub const CONTROL_SOCKET: &str = "/run/kea/kea4-ctrl-socket";

/// A subnet ready for Kea.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeaSubnet {
    /// Kea subnet id; must stay stable across applies so leases survive.
    pub id: u32,
    /// Device the subnet is served on (shared network), if bound.
    pub device: Option<DeviceName>,
    /// The subnet, with automatic options already filled in.
    pub subnet: Subnet4,
    /// Its reservations.
    pub reservations: Vec<Reservation4>,
}

/// The DHCPv4 server input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcp4Model {
    /// Devices Kea listens on.
    pub interfaces: Vec<DeviceName>,
    /// Default lease lifetime in seconds.
    pub valid_lifetime: u32,
    /// System domain (default for option 15).
    pub system_domain: DomainName,
    /// Subnets.
    pub subnets: Vec<KeaSubnet>,
    /// Lease file.
    pub lease_file: PathBuf,
    /// Control socket.
    pub control_socket: PathBuf,
}

/// Model errors the schema's own validation does not catch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeaError {
    /// Two subnets with one Kea id.
    #[error("Kea subnet id {0} used twice")]
    DuplicateSubnetId(u32),
    /// Reservation outside its subnet.
    #[error("reservation {ip} is not inside subnet {subnet}")]
    ReservationOutsideSubnet {
        /// Subnet.
        subnet: ipnet::Ipv4Net,
        /// Address.
        ip: std::net::Ipv4Addr,
    },
    /// The same client reserved twice in one subnet.
    #[error("client {client} reserved twice in subnet {subnet}")]
    DuplicateReservation {
        /// Subnet.
        subnet: ipnet::Ipv4Net,
        /// Client identifier.
        client: String,
    },
    /// Subnet served on a device Kea does not listen on.
    #[error("subnet {subnet} is bound to {device}, which Kea does not listen on")]
    DeviceNotListening {
        /// Subnet.
        subnet: ipnet::Ipv4Net,
        /// Device.
        device: DeviceName,
    },
}

// Kea's JSON shape; field names are Kea's.
#[derive(Serialize)]
struct KeaRoot {
    #[serde(rename = "Dhcp4")]
    dhcp4: KeaDhcp4,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct KeaDhcp4 {
    valid_lifetime: u32,
    interfaces_config: KeaInterfaces,
    lease_database: KeaLeaseDb,
    control_socket: KeaControlSocket,
    loggers: Vec<KeaLogger>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    shared_networks: Vec<KeaSharedNetwork>,
    subnet4: Vec<KeaSubnetJson>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct KeaInterfaces {
    interfaces: Vec<String>,
    dhcp_socket_type: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct KeaLeaseDb {
    #[serde(rename = "type")]
    kind: &'static str,
    persist: bool,
    name: String,
    lfc_interval: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct KeaControlSocket {
    socket_type: &'static str,
    socket_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct KeaLogger {
    name: &'static str,
    output_options: Vec<BTreeMap<&'static str, &'static str>>,
    severity: &'static str,
}

#[derive(Serialize)]
struct KeaSharedNetwork {
    name: String,
    interface: String,
    subnet4: Vec<KeaSubnetJson>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct KeaSubnetJson {
    id: u32,
    subnet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    valid_lifetime: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_server: Option<String>,
    match_client_id: bool,
    option_data: Vec<KeaOption>,
    pools: Vec<KeaPool>,
    reservations: Vec<KeaReservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_context: Option<BTreeMap<&'static str, String>>,
}

#[derive(Serialize)]
struct KeaOption {
    name: &'static str,
    data: String,
}

#[derive(Serialize)]
struct KeaPool {
    pool: String,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct KeaReservation {
    #[serde(skip_serializing_if = "Option::is_none")]
    hw_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_context: Option<BTreeMap<&'static str, String>>,
}

fn join<T: ToString>(v: &[T]) -> String {
    v.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn client_key(c: &ClientMatch) -> String {
    match c {
        ClientMatch::HwAddress(m) => format!("hw {m}"),
        ClientMatch::ClientId(id) => format!("id {id}"),
    }
}

impl Dhcp4Model {
    /// Check the constraints Kea would reject.
    pub fn validate(&self) -> Result<(), KeaError> {
        let mut ids = BTreeSet::new();
        for s in &self.subnets {
            let net = s.subnet.subnet;
            if !ids.insert(s.id) {
                return Err(KeaError::DuplicateSubnetId(s.id));
            }
            if let Some(d) = &s.device
                && !self.interfaces.contains(d)
            {
                return Err(KeaError::DeviceNotListening {
                    subnet: net,
                    device: d.clone(),
                });
            }
            let mut clients = BTreeSet::new();
            for r in &s.reservations {
                if let Some(ip) = r.ip_address
                    && !net.contains(&ip)
                {
                    return Err(KeaError::ReservationOutsideSubnet { subnet: net, ip });
                }
                if !clients.insert(client_key(&r.client)) {
                    return Err(KeaError::DuplicateReservation {
                        subnet: net,
                        client: client_key(&r.client),
                    });
                }
            }
        }
        Ok(())
    }

    fn subnet_json(&self, s: &KeaSubnet) -> KeaSubnetJson {
        let o = &s.subnet.options;
        let mut opts = Vec::new();
        let mut push = |name, data: String| opts.push(KeaOption { name, data });
        if !o.routers.is_empty() {
            push("routers", join(&o.routers));
        }
        if !o.dns_servers.is_empty() {
            push("domain-name-servers", join(&o.dns_servers));
        }
        push(
            "domain-name",
            o.domain_name
                .as_ref()
                .unwrap_or(&self.system_domain)
                .to_string(),
        );
        if !o.domain_search.is_empty() {
            push("domain-search", join(&o.domain_search));
        }
        if !o.ntp_servers.is_empty() {
            push("ntp-servers", join(&o.ntp_servers));
        }
        if let Some(t) = &o.tftp_server_name {
            push("tftp-server-name", t.clone());
        }
        if let Some(b) = &o.boot_file_name {
            push("boot-file-name", b.clone());
        }
        if let Some(v) = o.v6_only_preferred {
            push("v6-only-preferred", v.to_string());
        }
        KeaSubnetJson {
            id: s.id,
            subnet: s.subnet.subnet.trunc().to_string(),
            valid_lifetime: s.subnet.valid_lifetime,
            next_server: s.subnet.next_server.map(|a| a.to_string()),
            match_client_id: s.subnet.match_client_id,
            option_data: opts,
            pools: s
                .subnet
                .pools
                .iter()
                .map(|p| KeaPool {
                    pool: format!("{} - {}", p.start(), p.end()),
                })
                .collect(),
            reservations: s
                .reservations
                .iter()
                .map(|r| {
                    let (hw, id) = match &r.client {
                        ClientMatch::HwAddress(m) => (Some(m.to_string()), None),
                        ClientMatch::ClientId(c) => (None, Some(c.to_string())),
                    };
                    KeaReservation {
                        hw_address: hw,
                        client_id: id,
                        ip_address: r.ip_address.map(|a| a.to_string()),
                        hostname: r.hostname.as_ref().map(ToString::to_string),
                        user_context: r
                            .description
                            .as_ref()
                            .map(|d| [("description", d.to_string())].into()),
                    }
                })
                .collect(),
            user_context: s
                .subnet
                .description
                .as_ref()
                .map(|d| [("description", d.to_string())].into()),
        }
    }

    /// Render `kea-dhcp4.conf` (pretty JSON, deterministic).
    pub fn render(&self) -> Result<String, KeaError> {
        self.validate()?;
        let mut shared: BTreeMap<&DeviceName, Vec<KeaSubnetJson>> = BTreeMap::new();
        let mut single = Vec::new();
        for s in &self.subnets {
            match &s.device {
                Some(d) => shared.entry(d).or_default().push(self.subnet_json(s)),
                None => single.push(self.subnet_json(s)),
            }
        }
        let root = KeaRoot {
            dhcp4: KeaDhcp4 {
                valid_lifetime: self.valid_lifetime,
                interfaces_config: KeaInterfaces {
                    interfaces: self.interfaces.iter().map(ToString::to_string).collect(),
                    // Raw sockets: clients without an address yet need them.
                    dhcp_socket_type: "raw",
                },
                lease_database: KeaLeaseDb {
                    kind: "memfile",
                    persist: true,
                    name: self.lease_file.display().to_string(),
                    lfc_interval: 3600,
                },
                control_socket: KeaControlSocket {
                    socket_type: "unix",
                    socket_name: self.control_socket.display().to_string(),
                },
                loggers: vec![KeaLogger {
                    name: "kea-dhcp4",
                    output_options: vec![[("output", "stdout")].into()],
                    severity: "INFO",
                }],
                shared_networks: shared
                    .into_iter()
                    .map(|(d, subnets)| KeaSharedNetwork {
                        name: format!("interface_{d}"),
                        interface: d.to_string(),
                        subnet4: subnets,
                    })
                    .collect(),
                subnet4: single,
            },
        };
        // Serialising these plain structs cannot fail.
        let mut s = serde_json::to_string_pretty(&root).unwrap_or_default();
        s.push('\n');
        Ok(s)
    }
}

/// Run `kea-dhcp4 -t <file>`: `Ok(None)` when Kea is not installed,
/// `Ok(Some(""))` when the file is accepted, else Kea's message.
pub fn check(runner: &dyn Runner, file: &Path) -> Result<Option<String>, CmdError> {
    if !runner.has_program("kea-dhcp4") {
        return Ok(None);
    }
    let out = runner.run(&Cmd::new("kea-dhcp4").arg("-t").arg(file), None)?;
    Ok(Some(if out.success() {
        String::new()
    } else {
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            out.stderr_text()
        )
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::appliers::convert::tests::slice_models;
    use crate::cmd::SystemRunner;

    pub(crate) fn lan_model() -> Dhcp4Model {
        slice_models().kea.expect("fixture has DHCP on")
    }

    #[test]
    fn kea_dhcp4_golden() {
        let m = lan_model();
        let out = m.render().unwrap();
        assert_eq!(out, m.render().unwrap(), "deterministic");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn invalid_models_name_the_object() {
        let mut m = lan_model();
        let dup = m.subnets[0].clone();
        m.subnets.push(dup);
        assert!(matches!(m.render(), Err(KeaError::DuplicateSubnetId(_))));
        let mut m = lan_model();
        m.interfaces.clear();
        assert!(matches!(
            m.render(),
            Err(KeaError::DeviceNotListening { .. })
        ));
        let mut m = lan_model();
        let r = m.subnets[0].reservations[0].clone();
        m.subnets[0].reservations.push(r);
        assert!(matches!(
            m.render(),
            Err(KeaError::DuplicateReservation { .. })
        ));
    }

    /// `kea-dhcp4 -t` on the golden when Kea is installed (nixtop:
    /// `nix shell nixpkgs#kea -c cargo test -p sensr-apply kea`).
    #[test]
    fn real_kea_accepts_golden() {
        // `-t` requires shared-network devices to exist, so the agent checks
        // after links are configured; use `lo` here. Kea 3 also pins the
        // socket and lease locations, so the production paths stay.
        let mut m = lan_model();
        let lo: DeviceName = "lo".parse().unwrap();
        m.interfaces = vec![lo.clone()];
        for s in &mut m.subnets {
            if s.device.is_some() {
                s.device = Some(lo.clone());
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("kea-dhcp4.conf");
        std::fs::write(&f, m.render().unwrap()).unwrap();
        match check(&SystemRunner, &f).unwrap() {
            None => eprintln!("note: kea-dhcp4 not installed; skipping"),
            Some(msg) => assert!(msg.is_empty(), "kea-dhcp4 -t: {msg}"),
        }
    }
}
