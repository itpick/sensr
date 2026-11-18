//! Traffic insight: read-only queries on the database `sensr-insight` writes.
//!
//! The web GUI and the HTTP API read the same three tables through
//! `sensr-api`; the CLI exists so the box can be inspected over SSH, and so the
//! acceptance test can assert that a client's traffic was actually recorded
//! (D4 replaces OPNsense's Insight/NetFlow view).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use sensr_flow::config::{DB_DIR, FLOWS_DB};
use sensr_flow::store::{FlowStore, RowKind};
use serde_json::{Value, json};

/// Where `sensr-insight` writes (SENSR_INSIGHT_DIR overrides, for tests).
fn dir() -> PathBuf {
    std::env::var_os("SENSR_INSIGHT_DIR").map_or_else(|| PathBuf::from(DB_DIR), PathBuf::from)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

/// Hosts ranked by traffic in the window that ends now.
pub fn hosts(since: i64, limit: u32) -> Result<Value> {
    hosts_in(&dir(), since, limit)
}

fn hosts_in(dir: &std::path::Path, since: i64, limit: u32) -> Result<Value> {
    let to = now();
    let from = to - since.max(1);
    let path = dir.join(FLOWS_DB);
    if !path.exists() {
        return Ok(json!({ "available": false, "from": from, "to": to, "rows": [] }));
    }
    let store =
        FlowStore::open_read_only(&path).with_context(|| format!("opening {}", path.display()))?;
    let rows = store
        .top(RowKind::Host, None, from, to, limit)
        .context("querying flows")?;
    Ok(json!({
        "available": true,
        "from": from,
        "to": to,
        "resolution": FlowStore::resolution(from, to),
        "rows": rows,
    }))
}

/// One line per host: address, bytes up and down.
pub fn print_hosts(out: &mut dyn std::io::Write, v: &Value) -> std::io::Result<()> {
    if !v["available"].as_bool().unwrap_or(false) {
        return writeln!(
            out,
            "no traffic data yet (sensr-insight has written nothing)"
        );
    }
    let Some(rows) = v["rows"].as_array() else {
        return Ok(());
    };
    if rows.is_empty() {
        return writeln!(out, "no hosts with traffic in the last window");
    }
    writeln!(out, "{:40} {:>12} {:>12}", "host", "up", "down")?;
    for r in rows {
        writeln!(
            out,
            "{:40} {:>12} {:>12}",
            r["key"].as_str().unwrap_or("?"),
            r["up"].as_u64().unwrap_or(0),
            r["down"].as_u64().unwrap_or(0),
        )?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use sensr_flow::nft::{Count, Dir, Key, Kind};
    use sensr_flow::store::Batch;

    fn key(kind: Kind, dir: Dir, addr: &str) -> Key {
        Key {
            kind,
            dir,
            addr: addr.into(),
            proto: 0,
            port: 0,
        }
    }

    #[test]
    fn missing_database_is_not_an_error() {
        let d = tempfile::tempdir().unwrap();
        let v = hosts_in(d.path(), 3600, 10).unwrap();
        assert_eq!(v["available"], false);
        assert_eq!(v["rows"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn lists_hosts_by_traffic() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join(FLOWS_DB);
        let mut s = FlowStore::open(&path).unwrap();
        let mut b = Batch::default();
        b.add_counters(&[
            (
                key(Kind::Host, Dir::Up, "192.168.69.1"),
                Count {
                    packets: 1,
                    bytes: 100,
                },
            ),
            (
                key(Kind::Host, Dir::Down, "192.168.69.1"),
                Count {
                    packets: 1,
                    bytes: 900,
                },
            ),
        ]);
        s.write_minute(now(), &b).unwrap();

        let v = hosts_in(d.path(), 3600, 10).unwrap();
        assert_eq!(v["available"], true);
        let rows = v["rows"].as_array().unwrap();
        assert_eq!(rows[0]["key"], "192.168.69.1");
        assert_eq!(rows[0]["down"], 900);
    }
}
