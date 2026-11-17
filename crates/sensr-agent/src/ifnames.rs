//! Binding interfaces to network cards by MAC (Interfaces › Assignments,
//! `sensr interfaces assign`, the seed folder's `seed.toml` and `ifnames`,
//! and first boot).
//!
//! An interface (`wan`, `lan`, `opt1`) is bound to a card through
//! `match_mac`; the apply engine turns that into a `systemd.link` file and
//! renames the card at run time. The card's slot or USB port plays no part,
//! so moving a card never moves a network (VyOS names USB NICs by port,
//! which is how a cutover swapped networks).
//!
//! A pinned card must also carry a name the kernel and udev never hand out
//! on their own: `eth1` or `enp1s0` could be given to another card that
//! appears first, and the pinned card's rename would then fail. Device
//! names in those namespaces are replaced by the interface id (`wan`,
//! `lan`), with every reference to the device updated. Names that only
//! sensr gives (an imported OPNsense `igc0`) are kept.

use std::path::Path;

pub use sensr_apply::inventory::HostNic;
use sensr_schema::Document;
use sensr_schema::fields::{DeviceName, InterfaceId, MacAddr};
use sensr_schema::models::interfaces::{Interface, InterfaceRole};

/// The host's cards (sysfs under `root`, permanent MACs from `ip`).
pub fn host_nics(root: &Path) -> Vec<HostNic> {
    sensr_apply::inventory::discover(root, &sensr_apply::cmd::SystemRunner)
}

/// True for names the kernel (`eth0`, `usb0`, `wlan0`) or udev's predictable
/// naming (`enp1s0`, `end0`, `wlp2s0`, `enx…`) can assign.
pub fn is_kernel_name(name: &str) -> bool {
    const PREFIXES: &[&str] = &["eth", "en", "wl", "ww", "ib", "sl", "usb", "wlan"];
    PREFIXES
        .iter()
        .any(|p| name.strip_prefix(p).is_some_and(|rest| !rest.is_empty()))
}

/// Which card an assignment names: a MAC, or a current kernel name.
pub fn find<'a>(nics: &'a [HostNic], selector: &str) -> Option<&'a HostNic> {
    let sel = selector.trim();
    match sel.parse::<MacAddr>() {
        Ok(mac) => {
            let mac = mac.to_string();
            nics.iter().find(|n| n.pin_mac() == mac || n.mac == mac)
        }
        Err(_) => nics.iter().find(|n| n.name == sel),
    }
}

/// Assignment failures, phrased for the operator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AssignError {
    /// Not a valid interface id.
    #[error("{0:?} is not a valid interface name")]
    BadInterface(String),
    /// No card matches the selector.
    #[error("no network card matches {0:?}")]
    NoSuchNic(String),
    /// The card's MAC is not usable for a pin.
    #[error("card {0} has no usable MAC address")]
    BadMac(String),
    /// The wanted device name is taken by another interface.
    #[error("device name {name} is already used by interface {by}")]
    NameTaken {
        /// The name.
        name: String,
        /// The interface holding it.
        by: String,
    },
}

/// Binds interface `id` to the card with MAC `mac`, creating the interface
/// (disabled, no addressing, like an OPNsense new assignment; `wan` and
/// `lan` enabled with their role) when it does not exist. A card pinned to
/// another interface moves here.
pub fn assign_mac(doc: &mut Document, id: &str, mac: MacAddr) -> Result<(), AssignError> {
    let iid: InterfaceId = id
        .parse()
        .map_err(|_| AssignError::BadInterface(id.to_owned()))?;
    // the card leaves whatever it was bound to
    for (other, i) in doc.interfaces.0.iter_mut() {
        if other != &iid && i.match_mac == Some(mac) {
            i.match_mac = None;
        }
    }
    let current = doc.interfaces.get(&iid).map(|i| i.device.clone());
    let device: DeviceName = match &current {
        Some(d) if !is_kernel_name(d.as_str()) => d.clone(),
        _ => iid
            .as_str()
            .parse()
            .map_err(|_| AssignError::BadInterface(id.to_owned()))?,
    };
    if let Some((by, _)) = doc
        .interfaces
        .iter()
        .find(|(other, i)| **other != iid && i.device == device)
    {
        return Err(AssignError::NameTaken {
            name: device.to_string(),
            by: by.to_string(),
        });
    }
    match current {
        Some(old) => {
            if old != device {
                rename_device(doc, &old, &device);
            }
        }
        None => {
            let role = match iid.as_str() {
                "wan" => InterfaceRole::Wan,
                "lan" => InterfaceRole::Lan,
                _ => InterfaceRole::Other,
            };
            let mut iface = Interface::new(device, role);
            iface.enabled = role != InterfaceRole::Other;
            doc.interfaces.insert(iid.clone(), iface);
        }
    }
    if let Some(i) = doc.interfaces.0.get_mut(&iid) {
        i.match_mac = Some(mac);
    }
    Ok(())
}

/// [`assign_mac`] with the card picked by `selector` from `nics`.
pub fn assign(
    doc: &mut Document,
    id: &str,
    selector: &str,
    nics: &[HostNic],
) -> Result<(), AssignError> {
    let nic = find(nics, selector).ok_or_else(|| AssignError::NoSuchNic(selector.to_owned()))?;
    let mac: MacAddr = nic
        .pin_mac()
        .parse()
        .map_err(|_| AssignError::BadMac(nic.name.clone()))?;
    assign_mac(doc, id, mac)
}

/// Renames device `old` to `new` everywhere the document names devices:
/// interfaces, VLAN parents, bridge and LAGG members.
pub fn rename_device(doc: &mut Document, old: &DeviceName, new: &DeviceName) {
    let swap = |d: &mut DeviceName| {
        if d == old {
            *d = new.clone();
        }
    };
    for i in doc.interfaces.0.values_mut() {
        swap(&mut i.device);
        if let Some(v) = &mut i.vlan {
            swap(&mut v.parent);
        }
    }
    for (_, b) in doc.devices.bridges.iter_mut() {
        swap(&mut b.device);
        b.members.iter_mut().for_each(swap);
        if let Some(stp) = &mut b.stp {
            stp.members.iter_mut().for_each(swap);
            stp.edge.iter_mut().for_each(swap);
        }
    }
    for (_, l) in doc.devices.laggs.iter_mut() {
        swap(&mut l.device);
        l.members.iter_mut().for_each(swap);
        if let Some(p) = &mut l.primary_member {
            swap(p);
        }
    }
}

/// First boot (L3: "first boot records unpinned NICs"): binds every
/// interface that has no pin yet to its card. An interface whose device
/// exists is bound to that card. With `by_order` (the factory document,
/// nothing seeded), interfaces whose device does not exist take the
/// remaining cards in bus order, `lan` first (PLAN §6: the first NIC is
/// lan, the second wan). Returns what was bound, for the revision text.
pub fn first_boot(doc: &mut Document, nics: &[HostNic], by_order: bool) -> Vec<(String, String)> {
    let mut bound = Vec::new();
    let mut used: Vec<String> = doc
        .interfaces
        .iter()
        .filter_map(|(_, i)| i.match_mac.map(|m| m.to_string()))
        .collect();
    let mut ids: Vec<(String, String)> = doc
        .interfaces
        .iter()
        .filter(|(_, i)| i.enabled && i.vlan.is_none() && i.match_mac.is_none())
        .map(|(id, i)| (id.to_string(), i.device.to_string()))
        .collect();
    // lan before wan before the rest, so "first card" means lan
    ids.sort_by_key(|(id, _)| match id.as_str() {
        "lan" => 0,
        "wan" => 1,
        _ => 2,
    });
    let mut pending = Vec::new();
    for (id, device) in ids {
        match nics.iter().find(|n| n.name == device) {
            Some(n) if !used.iter().any(|u| u == n.pin_mac()) => {
                if assign(doc, &id, &n.name, nics).is_ok() {
                    used.push(n.pin_mac().to_owned());
                    bound.push((id, n.pin_mac().to_owned()));
                }
            }
            _ => pending.push(id),
        }
    }
    if by_order {
        for id in pending {
            let Some(n) = nics.iter().find(|n| !used.iter().any(|u| u == n.pin_mac())) else {
                break;
            };
            if assign(doc, &id, &n.name, nics).is_ok() {
                used.push(n.pin_mac().to_owned());
                bound.push((id, n.pin_mac().to_owned()));
            }
        }
    }
    bound
}

/// Parses the seed folder's `ifnames`: `<mac> <name>` per line, `#`
/// comments. Each line binds the interface whose device is `<name>` (an
/// imported OPNsense `igc0`, say) to the card with that MAC.
pub fn parse_ifnames(text: &str) -> Result<Vec<(MacAddr, String)>, String> {
    text.lines()
        .enumerate()
        .map(|(n, l)| (n + 1, l.split('#').next().unwrap_or("").trim()))
        .filter(|(_, l)| !l.is_empty())
        .map(|(n, l)| {
            let mut f = l.split_whitespace();
            let (Some(mac), Some(name), None) = (f.next(), f.next(), f.next()) else {
                return Err(format!("line {n}: expected \"<mac> <name>\""));
            };
            let mac = mac
                .parse()
                .map_err(|_| format!("line {n}: {mac:?} is not a MAC address"))?;
            Ok((mac, name.to_owned()))
        })
        .collect()
}

/// Applies `ifnames` lines: the interface on device `name` is pinned to the
/// MAC. Returns the names no interface uses.
pub fn apply_ifnames(doc: &mut Document, lines: &[(MacAddr, String)]) -> Vec<String> {
    let mut unused = Vec::new();
    for (mac, name) in lines {
        let id = doc
            .interfaces
            .iter()
            .find(|(_, i)| i.device.as_str() == name)
            .map(|(id, _)| id.to_string());
        match id {
            Some(id) => {
                let _ = assign_mac(doc, &id, *mac);
            }
            None => unused.push(name.clone()),
        }
    }
    unused
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensr_schema::PathAccess;

    pub(crate) fn nic(name: &str, mac: &str) -> HostNic {
        HostNic {
            name: name.into(),
            mac: mac.into(),
            permanent_mac: None,
            driver: None,
            bus: Some("pci".into()),
            bus_path: None,
            speed_mbps: None,
            carrier: None,
            operstate: "down".into(),
        }
    }

    #[test]
    fn kernel_names() {
        for k in [
            "eth0",
            "enp1s0",
            "end0",
            "enx525400aa0001",
            "wlan0",
            "wlp2s0",
            "usb0",
        ] {
            assert!(is_kernel_name(k), "{k}");
        }
        for k in ["igc0", "wan", "lan", "re0", "vtnet0", "lagg0", "br0", "eth"] {
            assert!(!is_kernel_name(k), "{k}");
        }
    }

    #[test]
    fn assign_pins_and_renames_kernel_names_with_references() {
        let mut doc = Document::factory();
        // a VLAN on the LAN card refers to it by device name
        doc.set_by_path(
            "interfaces.opt1",
            serde_json::json!({"device": "eth1.20", "vlan": {"parent": "eth1", "tag": 20}}),
        )
        .unwrap();
        let nics = [
            nic("eth0", "52:54:00:aa:00:01"),
            nic("eth1", "52:54:00:aa:00:02"),
        ];
        assign(&mut doc, "lan", "52:54:00:AA:00:02", &nics).unwrap();
        assign(&mut doc, "wan", "eth0", &nics).unwrap();
        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(v["interfaces"]["lan"]["device"], "lan");
        assert_eq!(v["interfaces"]["lan"]["match_mac"], "52:54:00:aa:00:02");
        assert_eq!(v["interfaces"]["wan"]["device"], "wan");
        assert_eq!(v["interfaces"]["opt1"]["vlan"]["parent"], "lan");
        assert!(doc.validate().is_empty(), "{}", doc.validate());

        // moving the card to another interface unpins the first
        assign(&mut doc, "opt2", "52:54:00:aa:00:01", &nics).unwrap();
        let v = serde_json::to_value(&doc).unwrap();
        assert!(v["interfaces"]["wan"].get("match_mac").is_none());
        assert_eq!(v["interfaces"]["opt2"]["device"], "opt2");
        assert_eq!(
            v["interfaces"]["opt2"]["enabled"], false,
            "new ones start disabled"
        );
        assert_eq!(
            assign(&mut doc, "lan", "aa:bb:cc:dd:ee:ff", &nics),
            Err(AssignError::NoSuchNic("aa:bb:cc:dd:ee:ff".into()))
        );
    }

    #[test]
    fn imported_names_are_kept() {
        let mut doc = Document::factory();
        doc.set_by_path("interfaces.wan.device", serde_json::json!("igc0"))
            .unwrap();
        let nics = [nic("end0", "52:54:00:aa:00:09")];
        assign(&mut doc, "wan", "end0", &nics).unwrap();
        assert_eq!(doc.get_by_path("interfaces.wan.device").unwrap(), "igc0");
    }

    #[test]
    fn first_boot_binds_existing_devices_then_by_bus_order() {
        let mut doc = Document::factory();
        // factory: wan=eth0, lan=eth1; this box has enp1s0 and enp2s0
        let nics = [
            nic("enp1s0", "52:54:00:aa:00:01"),
            nic("enp2s0", "52:54:00:aa:00:02"),
        ];
        assert!(first_boot(&mut doc.clone(), &nics, false).is_empty());
        let bound = first_boot(&mut doc, &nics, true);
        assert_eq!(
            bound,
            [
                ("lan".to_owned(), "52:54:00:aa:00:01".to_owned()),
                ("wan".to_owned(), "52:54:00:aa:00:02".to_owned()),
            ]
        );
        assert_eq!(doc.get_by_path("interfaces.lan.device").unwrap(), "lan");
        assert!(doc.validate().is_empty(), "{}", doc.validate());
        // pinned already: nothing more
        assert!(first_boot(&mut doc, &nics, true).is_empty());

        let mut doc = Document::factory();
        let nics = [
            nic("eth0", "52:54:00:aa:00:01"),
            nic("eth1", "52:54:00:aa:00:02"),
        ];
        let bound = first_boot(&mut doc, &nics, false);
        assert_eq!(bound.len(), 2, "existing devices are bound by name");
        assert_eq!(
            doc.get_by_path("interfaces.wan.match_mac").unwrap(),
            "52:54:00:aa:00:01"
        );
    }

    #[test]
    fn ifnames_file() {
        let lines = parse_ifnames(
            "# OPNsense names\n52:54:00:aa:00:01 igc0\n\n52:54:00:aa:00:02  igc1 # lan\n",
        )
        .unwrap();
        assert_eq!(lines.len(), 2);
        assert!(parse_ifnames("52:54:00:aa:00:01").is_err());
        assert!(parse_ifnames("nonsense igc0").is_err());
        let mut doc = Document::factory();
        doc.set_by_path("interfaces.wan.device", serde_json::json!("igc0"))
            .unwrap();
        let unused = apply_ifnames(&mut doc, &lines);
        assert_eq!(unused, ["igc1"]);
        assert_eq!(
            doc.get_by_path("interfaces.wan.match_mac").unwrap(),
            "52:54:00:aa:00:01"
        );
    }
}
