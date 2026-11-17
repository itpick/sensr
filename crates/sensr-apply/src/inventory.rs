//! The network cards on the host, read from sysfs, and the renames that
//! bring their names in line with MAC pins.
//!
//! VyOS names USB NICs by the port they sit in, so moving a dongle to
//! another port swaps networks. sensr binds interface roles to the card's
//! permanent MAC instead: [`crate::appliers::interfaces`] renders one
//! `systemd.link` file per pinned card for boot, and [`renames`] fixes names
//! at run time without a reboot. Where a card sits (`bus_path`) is reported
//! for the operator but never used to decide which network it carries.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cmd::{Cmd, Runner};

/// One physical network card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostNic {
    /// Current kernel name.
    pub name: String,
    /// Current MAC address, lowercase.
    pub mac: String,
    /// Burnt-in MAC when it differs from `mac`.
    pub permanent_mac: Option<String>,
    /// Kernel driver.
    pub driver: Option<String>,
    /// Bus (`pci`, `usb`, `platform`).
    pub bus: Option<String>,
    /// Position on the bus.
    pub bus_path: Option<String>,
    /// Link speed in Mbit/s while up.
    pub speed_mbps: Option<u32>,
    /// Carrier detected.
    pub carrier: Option<bool>,
    /// `operstate`.
    pub operstate: String,
}

impl HostNic {
    /// The MAC a pin matches.
    pub fn pin_mac(&self) -> &str {
        self.permanent_mac.as_deref().unwrap_or(&self.mac)
    }
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
}

fn base(path: &Path) -> Option<String> {
    std::fs::canonicalize(path)
        .ok()?
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
}

/// Every network device under `<root>/sys/class/net` that is backed by
/// hardware (has a `device` link), sorted by bus position so "first NIC"
/// means the same thing on every boot of the same box.
pub fn host_nics(root: &Path) -> Vec<HostNic> {
    let dir = root.join("sys/class/net");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<HostNic> = entries
        .filter_map(Result::ok)
        .filter_map(|e| nic(&e.path()))
        .collect();
    out.sort_by(|a, b| {
        (a.bus.as_deref() != Some("pci"), &a.bus_path, &a.name).cmp(&(
            b.bus.as_deref() != Some("pci"),
            &b.bus_path,
            &b.name,
        ))
    });
    out
}

fn nic(dir: &Path) -> Option<HostNic> {
    let name = dir.file_name()?.to_string_lossy().into_owned();
    let device: PathBuf = std::fs::canonicalize(dir.join("device")).ok()?;
    let mac = read(&dir.join("address"))?.to_ascii_lowercase();
    let mut bus_dev = device.clone();
    let mut bus = base(&bus_dev.join("subsystem"));
    // virtio and similar transports hang off the PCI (or MMIO) device that
    // is the card's real position
    if bus.as_deref() == Some("virtio")
        && let Some(parent) = device.parent()
    {
        bus_dev = parent.to_owned();
        bus = base(&bus_dev.join("subsystem")).or(bus);
    }
    Some(HostNic {
        name,
        mac,
        permanent_mac: None,
        driver: base(&device.join("driver")),
        bus,
        bus_path: bus_dev
            .file_name()
            .map(|n| n.to_string_lossy().into_owned()),
        speed_mbps: read(&dir.join("speed"))
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|s| *s > 0)
            .and_then(|s| u32::try_from(s).ok()),
        carrier: read(&dir.join("carrier")).map(|c| c == "1"),
        operstate: read(&dir.join("operstate")).unwrap_or_else(|| "unknown".into()),
    })
}

/// Fills in permanent MACs from `ip -j link show` (iproute2 prints
/// `permaddr` only when it differs from the current address).
pub fn with_permanent(mut nics: Vec<HostNic>, ip_link_json: &[u8]) -> Vec<HostNic> {
    #[derive(Deserialize)]
    struct Link {
        ifname: String,
        #[serde(default)]
        permaddr: Option<String>,
    }
    let links: Vec<Link> = serde_json::from_slice(ip_link_json).unwrap_or_default();
    for n in &mut nics {
        if let Some(p) = links
            .iter()
            .find(|l| l.ifname == n.name)
            .and_then(|l| l.permaddr.as_ref())
        {
            let p = p.to_ascii_lowercase();
            if p != n.mac {
                n.permanent_mac = Some(p);
            }
        }
    }
    nics
}

/// The host's cards, permanent MACs included when `ip` can tell.
pub fn discover(root: &Path, runner: &dyn Runner) -> Vec<HostNic> {
    let nics = host_nics(root);
    match runner.run(&Cmd::new("ip").args(["-j", "link", "show"]), None) {
        Ok(out) if out.success() => with_permanent(nics, &out.stdout),
        _ => nics,
    }
}

/// Commands renaming cards so that every pinned MAC (`pins`: MAC → name)
/// carries its name now. A card has to be down to be renamed; networkd
/// brings it up again under the new name. Names held by another card are
/// freed first through a temporary name, so two cards can swap.
pub fn renames(pins: &BTreeMap<String, String>, nics: &[HostNic]) -> Vec<Cmd> {
    let by_mac: BTreeMap<&str, &HostNic> = nics.iter().map(|n| (n.pin_mac(), n)).collect();
    let mut moves: Vec<(&str, &str)> = pins
        .iter()
        .filter_map(|(mac, want)| {
            let n = by_mac.get(mac.as_str())?;
            (n.name != *want).then_some((n.name.as_str(), want.as_str()))
        })
        .collect();
    if moves.is_empty() {
        return Vec::new();
    }
    let moving: BTreeSet<&str> = moves.iter().map(|(from, _)| *from).collect();
    let taken: BTreeSet<&str> = nics.iter().map(|n| n.name.as_str()).collect();
    let mut cmds = Vec::new();
    let down = |n: &str| Cmd::new("ip").args(["link", "set", "dev", n, "down"]);
    let rename =
        |from: &str, to: &str| Cmd::new("ip").args(["link", "set", "dev", from, "name", to]);
    // a card that is not pinned but sits on a wanted name steps aside
    let wanted: BTreeSet<&str> = moves.iter().map(|(_, to)| *to).collect();
    let mut tmp = 0;
    let mut temp_name = |cmds: &mut Vec<Cmd>, from: &str| {
        let t = format!("sensrtmp{tmp}");
        tmp += 1;
        cmds.push(down(from));
        cmds.push(rename(from, &t));
        t
    };
    for blocker in wanted
        .iter()
        .filter(|w| taken.contains(*w) && !moving.contains(*w))
    {
        temp_name(&mut cmds, blocker);
    }
    // two phases, so a swap never collides
    let mut staged = Vec::new();
    for (from, to) in moves.drain(..) {
        // phase 2 runs after every phase-1 rename, so only a card whose own
        // name someone else wants needs a temporary one
        let t = if wanted.contains(from) {
            temp_name(&mut cmds, from)
        } else {
            cmds.push(down(from));
            from.to_owned()
        };
        staged.push((t, to));
    }
    for (from, to) in staged {
        cmds.push(rename(&from, to));
    }
    cmds
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// A fake sysfs: `devices/<bus path>` with subsystem and driver links,
    /// `class/net/<name>` pointing at it. A virtio card sits below its PCI
    /// function, as on real hardware.
    pub(crate) fn card(root: &Path, name: &str, mac: &str, bus: &str, path: &[&str], driver: &str) {
        let sys = root.join("sys");
        let subsystem = |b: &str| {
            let d = sys.join("bus").join(b);
            std::fs::create_dir_all(d.join("drivers").join(driver)).unwrap();
            d
        };
        let mut dev = sys.join("devices");
        for p in path {
            dev = dev.join(p);
        }
        std::fs::create_dir_all(&dev).unwrap();
        let _ = symlink(subsystem(bus), dev.join("subsystem"));
        let (card_dev, card_bus) = if driver == "virtio_net" {
            (dev.join("virtio0"), "virtio")
        } else {
            (dev, bus)
        };
        std::fs::create_dir_all(&card_dev).unwrap();
        let _ = symlink(subsystem(card_bus), card_dev.join("subsystem"));
        symlink(
            sys.join("bus").join(card_bus).join("drivers").join(driver),
            card_dev.join("driver"),
        )
        .unwrap();
        let net = sys.join("class/net").join(name);
        std::fs::create_dir_all(&net).unwrap();
        symlink(&card_dev, net.join("device")).unwrap();
        std::fs::write(net.join("address"), format!("{mac}\n")).unwrap();
        std::fs::write(net.join("operstate"), "up\n").unwrap();
        std::fs::write(net.join("carrier"), "1\n").unwrap();
        std::fs::write(net.join("speed"), "1000\n").unwrap();
    }

    #[test]
    fn reads_cards_from_sysfs_in_bus_order() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        card(
            r,
            "eth2",
            "52:54:00:AA:00:03",
            "usb",
            &["usb2", "2-1:1.0"],
            "cdc_ether",
        );
        card(
            r,
            "eth1",
            "52:54:00:aa:00:02",
            "pci",
            &["pci0000:00", "0000:00:11.0"],
            "virtio_net",
        );
        card(
            r,
            "eth0",
            "52:54:00:aa:00:01",
            "pci",
            &["pci0000:00", "0000:00:10.0"],
            "igc",
        );
        // a virtual device has no `device` link
        std::fs::create_dir_all(r.join("sys/class/net/lo")).unwrap();
        std::fs::write(r.join("sys/class/net/lo/address"), "00:00:00:00:00:00").unwrap();
        let nics = host_nics(r);
        let names: Vec<_> = nics.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["eth0", "eth1", "eth2"]);
        assert_eq!(nics[0].driver.as_deref(), Some("igc"));
        assert_eq!(nics[0].bus.as_deref(), Some("pci"));
        assert_eq!(nics[1].driver.as_deref(), Some("virtio_net"));
        assert_eq!(
            nics[1].bus.as_deref(),
            Some("pci"),
            "virtio reports its PCI slot"
        );
        assert_eq!(nics[1].bus_path.as_deref(), Some("0000:00:11.0"));
        assert_eq!(nics[2].bus.as_deref(), Some("usb"));
        assert_eq!(nics[2].mac, "52:54:00:aa:00:03", "lowercased");
        assert_eq!(
            (nics[2].speed_mbps, nics[2].carrier),
            (Some(1000), Some(true))
        );
    }

    #[test]
    fn permanent_macs_come_from_ip_link() {
        let n = HostNic {
            name: "wan".into(),
            mac: "02:00:00:00:00:01".into(),
            permanent_mac: None,
            driver: None,
            bus: None,
            bus_path: None,
            speed_mbps: None,
            carrier: None,
            operstate: "up".into(),
        };
        let json =
            br#"[{"ifname":"wan","address":"02:00:00:00:00:01","permaddr":"52:54:00:AA:00:01"}]"#;
        let out = with_permanent(vec![n], json);
        assert_eq!(out[0].pin_mac(), "52:54:00:aa:00:01");
    }

    fn nic(name: &str, mac: &str) -> HostNic {
        HostNic {
            name: name.into(),
            mac: mac.into(),
            permanent_mac: None,
            driver: None,
            bus: None,
            bus_path: None,
            speed_mbps: None,
            carrier: None,
            operstate: "down".into(),
        }
    }

    fn lines(c: &[Cmd]) -> Vec<String> {
        c.iter().map(Cmd::display).collect()
    }

    #[test]
    fn renames_follow_the_mac_and_swap_safely() {
        let pins: BTreeMap<String, String> = [
            ("aa:aa:aa:aa:aa:01".to_owned(), "wan".to_owned()),
            ("aa:aa:aa:aa:aa:02".to_owned(), "lan".to_owned()),
        ]
        .into();
        // already right: nothing to do
        let ok = [
            nic("wan", "aa:aa:aa:aa:aa:01"),
            nic("lan", "aa:aa:aa:aa:aa:02"),
        ];
        assert!(renames(&pins, &ok).is_empty());
        // fresh names
        let fresh = [
            nic("eth1", "aa:aa:aa:aa:aa:01"),
            nic("eth2", "aa:aa:aa:aa:aa:02"),
        ];
        assert_eq!(
            lines(&renames(&pins, &fresh)),
            [
                "ip 'link' 'set' 'dev' 'eth1' 'down'",
                "ip 'link' 'set' 'dev' 'eth2' 'down'",
                "ip 'link' 'set' 'dev' 'eth1' 'name' 'wan'",
                "ip 'link' 'set' 'dev' 'eth2' 'name' 'lan'",
            ]
        );
        // swapped: through temporary names
        let swapped = [
            nic("lan", "aa:aa:aa:aa:aa:01"),
            nic("wan", "aa:aa:aa:aa:aa:02"),
        ];
        let l = lines(&renames(&pins, &swapped));
        assert_eq!(l.len(), 6, "{l:?}");
        assert!(l[1].contains("'name' 'sensrtmp"), "{l:?}");
        assert!(
            l[4].ends_with("'name' 'wan'") || l[4].ends_with("'name' 'lan'"),
            "{l:?}"
        );
        // an unpinned card on a wanted name steps aside
        let blocked = [
            nic("eth1", "aa:aa:aa:aa:aa:01"),
            nic("wan", "bb:bb:bb:bb:bb:bb"),
        ];
        let l = lines(&renames(&pins, &blocked));
        assert_eq!(
            l,
            [
                "ip 'link' 'set' 'dev' 'wan' 'down'",
                "ip 'link' 'set' 'dev' 'wan' 'name' 'sensrtmp0'",
                "ip 'link' 'set' 'dev' 'eth1' 'down'",
                "ip 'link' 'set' 'dev' 'eth1' 'name' 'wan'",
            ]
        );
        // a pinned card that is absent is left alone
        assert!(renames(&pins, &[nic("eth9", "cc:cc:cc:cc:cc:cc")]).is_empty());
    }
}
