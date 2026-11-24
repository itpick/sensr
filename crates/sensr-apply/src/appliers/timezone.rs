//! The system time zone (`system.timezone`).
//!
//! NixOS leaves `time.timeZone` unset on the router, which keeps the zone
//! mutable through systemd-timedated: `timedatectl set-timezone` repoints
//! `/etc/localtime`. The agent cannot write there itself
//! (`ProtectSystem=strict`), so it asks timedated, which it reaches over the
//! system bus (`AF_UNIX` is allowed in the unit; root needs no polkit rule).
//!
//! The current zone is the `/etc/localtime` symlink target below a
//! `zoneinfo` directory; no link means UTC, the default of a fresh box.
//! Zones are checked against the installed tzdata before anything runs, so a
//! name that parses but does not exist is rejected without a change. When
//! the image carries no tzdata directory at all the check is skipped and
//! `timedatectl` has the last word.

use std::path::{Path, PathBuf};

use crate::cmd::Cmd;

/// Where tzdata lives, relative to the filesystem root, in lookup order
/// (NixOS links `/etc/zoneinfo`).
const ZONEINFO_DIRS: &[&str] = &[
    "etc/zoneinfo",
    "run/current-system/sw/share/zoneinfo",
    "usr/share/zoneinfo",
];

/// Names that all mean UTC with no offset or rules.
const UTC_NAMES: &[&str] = &[
    "UTC",
    "UCT",
    "Zulu",
    "Universal",
    "Etc/UTC",
    "Etc/UCT",
    "Etc/Zulu",
    "Etc/Universal",
];

/// An unusable time zone.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TimezoneError {
    /// Not a zone in the installed tzdata.
    #[error("unknown time zone {0:?}")]
    Unknown(String),
}

fn zoneinfo_dirs(root: &Path) -> impl Iterator<Item = PathBuf> + '_ {
    ZONEINFO_DIRS
        .iter()
        .map(|d| root.join(d))
        .filter(|d| d.is_dir())
}

/// Whether `zone` names a zone file in the installed tzdata. Syntax is
/// re-checked here (no `..`, no empty parts) because the answer decides a
/// path lookup. Accepts anything when no tzdata directory exists to ask.
pub fn validate(root: &Path, zone: &str) -> Result<(), TimezoneError> {
    let unknown = || TimezoneError::Unknown(zone.to_owned());
    if zone.is_empty()
        || zone
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(unknown());
    }
    let mut any = false;
    for dir in zoneinfo_dirs(root) {
        any = true;
        if dir.join(zone).is_file() {
            return Ok(());
        }
    }
    if any { Err(unknown()) } else { Ok(()) }
}

/// The zone `/etc/localtime` points at; UTC when there is no link.
pub fn current(root: &Path) -> String {
    let link = root.join("etc/localtime");
    let Ok(target) = std::fs::read_link(&link) else {
        return "UTC".into();
    };
    let target = target.to_string_lossy();
    match target.rsplit_once("/zoneinfo/") {
        Some((_, zone)) => zone.to_owned(),
        None => target.into_owned(),
    }
}

fn same(a: &str, b: &str) -> bool {
    a == b || (UTC_NAMES.contains(&a) && UTC_NAMES.contains(&b))
}

/// The command that brings the system to `desired`, `None` when it is
/// there already.
pub fn command(root: &Path, desired: &str) -> Option<Cmd> {
    (!same(&current(root), desired))
        .then(|| Cmd::new("timedatectl").arg("set-timezone").arg(desired))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(zones: &[&str], localtime: Option<&str>) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let zi = root.path().join("etc/zoneinfo");
        for z in zones {
            let f = zi.join(z);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, b"TZif2").unwrap();
        }
        if let Some(z) = localtime {
            std::os::unix::fs::symlink(
                format!("/etc/zoneinfo/{z}"),
                root.path().join("etc/localtime"),
            )
            .unwrap();
        }
        root
    }

    #[test]
    fn current_reads_the_link_and_defaults_to_utc() {
        assert_eq!(current(tree(&[], None).path()), "UTC");
        let t = tree(&["America/Chicago"], Some("America/Chicago"));
        assert_eq!(current(t.path()), "America/Chicago");
    }

    #[test]
    fn unchanged_zone_runs_nothing() {
        let t = tree(&["America/Chicago"], Some("America/Chicago"));
        assert_eq!(command(t.path(), "America/Chicago"), None);
        // the default needs no command on a box that never set a zone
        assert_eq!(command(tree(&[], None).path(), "Etc/UTC"), None);
        let t = tree(&["UTC"], Some("UTC"));
        assert_eq!(command(t.path(), "Etc/UTC"), None);
    }

    #[test]
    fn changed_zone_sets_it() {
        let t = tree(&["America/Chicago"], None);
        let c = command(t.path(), "America/Chicago").unwrap();
        assert_eq!(c.display(), "timedatectl 'set-timezone' 'America/Chicago'");
    }

    #[test]
    fn unknown_zones_are_rejected() {
        let t = tree(&["America/Chicago", "Etc/UTC"], None);
        assert!(validate(t.path(), "America/Chicago").is_ok());
        for bad in [
            "America/Chicag",
            "Nowhere",
            "America",
            "../passwd",
            "a//b",
            "",
        ] {
            assert_eq!(
                validate(t.path(), bad),
                Err(TimezoneError::Unknown(bad.into())),
                "{bad}"
            );
        }
    }

    #[test]
    fn no_tzdata_leaves_the_decision_to_timedatectl() {
        assert!(validate(tree(&[], None).path(), "Mars/Olympus").is_ok());
    }
}
