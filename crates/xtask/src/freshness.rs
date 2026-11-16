//! `cargo xtask freshness` (docs/research/06 §5, PLAN §5): fail when a flake
//! input or the Rust toolchain falls more than 14 days behind.
//!
//! - Flake inputs: `lastModified` of every locked root input in `flake.lock`
//!   (offline).
//! - Toolchain: `rust-toolchain.toml`'s channel against the current stable
//!   release (network: static.rust-lang.org), failing once the newer release
//!   is older than the grace period.
//! - Wrapped daemons (`--daemons`, report only): the versions nixpkgs gives
//!   us against release-monitoring.org's latest stable.
//!
//! Crates are covered by `cargo outdated` in CI's deps job.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

const GRACE_DAYS: i64 = 14;
const DAY: i64 = 86_400;
/// Daemons the appliers drive (nix/modules/sensr.nix), as nixpkgs attribute
/// and release-monitoring.org project name.
const DAEMONS: [(&str, &str); 4] = [
    ("nftables", "nftables"),
    ("kea", "kea"),
    ("unbound", "unbound"),
    ("wireguard-tools", "wireguard-tools"),
];

#[derive(clap::Args)]
pub struct Args {
    /// Skip the checks that need the network.
    #[arg(long)]
    offline: bool,
    /// Also report wrapped daemon versions (needs nix and the network).
    #[arg(long)]
    daemons: bool,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// (input, lastModified) for every root input of a flake.lock.
pub fn flake_inputs(lock: &serde_json::Value) -> Result<Vec<(String, i64)>> {
    let nodes = lock["nodes"]
        .as_object()
        .context("flake.lock has no nodes")?;
    let root = lock["root"].as_str().unwrap_or("root");
    let inputs = nodes[root]["inputs"]
        .as_object()
        .context("flake.lock root has no inputs")?;
    let mut out = vec![];
    for (name, target) in inputs {
        // An input is a node name, or a follows path (a list): skip follows.
        let Some(node) = target.as_str() else {
            continue;
        };
        let t = nodes[node]["locked"]["lastModified"]
            .as_i64()
            .with_context(|| format!("{name} has no locked.lastModified"))?;
        out.push((name.clone(), t));
    }
    Ok(out)
}

/// (version, release date as Unix time) from channel-rust-stable.toml.
pub fn stable_release(manifest: &str) -> Result<(String, i64)> {
    let v: toml::Value = toml::from_str(manifest)?;
    let date = v["date"].as_str().context("no date")?;
    let full = v["pkg"]["rust"]["version"]
        .as_str()
        .context("no pkg.rust.version")?;
    let version = full.split_whitespace().next().unwrap_or(full).to_string();
    Ok((version, parse_date(date)?))
}

/// Days since the Unix epoch for a `YYYY-MM-DD` date (proleptic Gregorian).
fn parse_date(s: &str) -> Result<i64> {
    let mut it = s.split('-').map(str::parse::<i64>);
    let (Some(Ok(y)), Some(Ok(m)), Some(Ok(d))) = (it.next(), it.next(), it.next()) else {
        bail!("bad date {s}");
    };
    // Howard Hinnant's days_from_civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok((era * 146_097 + doe - 719_468) * DAY)
}

fn curl(url: &str) -> Result<String> {
    let out = Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            "30",
            "-H",
            "User-Agent: sensr-xtask (github.com/itpick/sensr)",
            url,
        ])
        .output()
        .context("running curl")?;
    if !out.status.success() {
        bail!("curl {url}: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8(out.stdout)?)
}

fn nix_version(root: &Path, attr: &str) -> Result<String> {
    let expr = format!(
        "(builtins.getFlake (toString {})).inputs.nixpkgs.legacyPackages.x86_64-linux.{attr}.version",
        root.display()
    );
    let out = Command::new("nix")
        .args(["eval", "--raw", "--impure", "--expr", &expr])
        .output()?;
    if !out.status.success() {
        bail!("nix eval {attr}: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8(out.stdout)?)
}

pub fn run(root: &Path, args: &Args) -> Result<()> {
    let mut failures = vec![];
    let now = now();

    let lock: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(root.join("flake.lock")).context("flake.lock")?)?;
    for (name, t) in flake_inputs(&lock)? {
        let age = (now - t) / DAY;
        println!("flake input {name}: {age} days old");
        if age > GRACE_DAYS {
            failures.push(format!(
                "flake input {name} is {age} days old (> {GRACE_DAYS}): nix flake update"
            ));
        }
    }

    let tc: toml::Value = toml::from_str(&fs::read_to_string(root.join("rust-toolchain.toml"))?)?;
    let channel = tc["toolchain"]["channel"]
        .as_str()
        .context("rust-toolchain.toml has no channel")?
        .to_string();
    if args.offline {
        println!("toolchain {channel}: not checked (--offline)");
    } else {
        let (latest, released) = stable_release(&curl(
            "https://static.rust-lang.org/dist/channel-rust-stable.toml",
        )?)?;
        let age = (now - released) / DAY;
        if latest == channel {
            println!("toolchain {channel}: latest stable");
        } else if age > GRACE_DAYS {
            failures.push(format!(
                "toolchain {channel}, stable is {latest} since {age} days: bump rust-toolchain.toml"
            ));
        } else {
            println!("toolchain {channel}: {latest} is out since {age} days (grace {GRACE_DAYS})");
        }
    }

    if args.daemons && !args.offline {
        for (attr, project) in DAEMONS {
            let ours = nix_version(root, attr).unwrap_or_else(|e| format!("? ({e})"));
            let body = curl(&format!(
                "https://release-monitoring.org/api/v2/projects/?name={project}"
            ))?;
            let v: serde_json::Value = serde_json::from_str(&body)?;
            let latest = v["items"]
                .as_array()
                .and_then(|items| items.iter().find(|i| i["name"] == project))
                .and_then(|i| i["stable_versions"][0].as_str().or(i["version"].as_str()))
                .unwrap_or("?");
            let mark = if ours == latest { "" } else { "  <- behind" };
            println!("daemon {attr}: nixpkgs {ours}, upstream {latest}{mark}");
        }
    }

    for f in &failures {
        println!("error: {f}");
    }
    if !failures.is_empty() {
        bail!("{} freshness problem(s)", failures.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(parse_date("1970-01-01").unwrap(), 0);
        assert_eq!(parse_date("2026-11-16").unwrap(), 1_794_787_200);
        assert_eq!(
            parse_date("2024-02-29").unwrap() + DAY,
            parse_date("2024-03-01").unwrap()
        );
    }

    #[test]
    fn flake_lock_inputs_skip_follows() {
        let lock = serde_json::json!({
            "root": "root",
            "version": 7,
            "nodes": {
                "root": {"inputs": {"nixpkgs": "nixpkgs", "crane": "crane", "x": ["nixpkgs"]}},
                "nixpkgs": {"locked": {"lastModified": 100}},
                "crane": {"locked": {"lastModified": 200}}
            }
        });
        let mut got = flake_inputs(&lock).unwrap();
        got.sort();
        assert_eq!(
            got,
            vec![("crane".to_string(), 200), ("nixpkgs".to_string(), 100)]
        );
    }

    #[test]
    fn rust_channel_manifest() {
        let m = "date = \"2026-11-12\"\n[pkg.rust]\nversion = \"1.100.0 (abcdef 2026-11-10)\"\n";
        let (v, t) = stable_release(m).unwrap();
        assert_eq!(v, "1.100.0");
        assert_eq!(t, parse_date("2026-11-12").unwrap());
    }

    #[test]
    fn the_checked_in_flake_lock_parses() {
        let root = crate::walk::repo_root().unwrap();
        let lock: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(root.join("flake.lock")).unwrap()).unwrap();
        let inputs = flake_inputs(&lock).unwrap();
        assert!(inputs.iter().any(|(n, _)| n == "nixpkgs"));
    }
}
