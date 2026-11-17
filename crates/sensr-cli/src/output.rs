//! Human-readable rendering of agent replies.

use std::io::{self, Write};

use sensr_ipc::{CommitOutcome, ConfigPath, PlanView, RevisionInfo, ServiceAction, Status};
use serde::Serialize;
use serde_json::Value;

/// Pretty JSON of any reply type.
pub fn json<T: Serialize>(v: &T) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

/// `YYYY-MM-DD HH:MM:SSZ` for milliseconds since the epoch (UTC).
pub fn utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// `path = value` lines for every leaf under `v` (a scalar prints bare).
pub fn flat(out: &mut dyn Write, at: &ConfigPath, v: &Value) -> io::Result<()> {
    fn walk(out: &mut dyn Write, prefix: &str, v: &Value) -> io::Result<()> {
        let join = |k: &str| {
            if prefix.is_empty() {
                k.to_owned()
            } else {
                format!("{prefix}.{k}")
            }
        };
        match v {
            Value::Object(m) if !m.is_empty() => {
                for (k, v) in m {
                    walk(out, &join(k), v)?;
                }
                Ok(())
            }
            Value::Array(l) if !l.is_empty() => {
                for (i, v) in l.iter().enumerate() {
                    walk(out, &join(&i.to_string()), v)?;
                }
                Ok(())
            }
            Value::Object(_) => writeln!(out, "{prefix} = {{}}"),
            Value::Array(_) => writeln!(out, "{prefix} = []"),
            leaf => writeln!(out, "{prefix} = {}", scalar(leaf)),
        }
    }
    match v {
        Value::Object(_) | Value::Array(_) => {
            let prefix = if at.is_root() {
                String::new()
            } else {
                at.to_string()
            };
            walk(out, &prefix, v)
        }
        leaf => writeln!(out, "{}", scalar(leaf)),
    }
}

/// `sensr status`.
pub fn status(out: &mut dyn Write, st: &Status) -> io::Result<()> {
    writeln!(
        out,
        "agent:      sensr-agent {} (ipc v{}), up {}s",
        st.agent_version, st.protocol, st.uptime_secs
    )?;
    match &st.head {
        Some(h) => writeln!(
            out,
            "head:       revision {} by {} at {} ({})",
            h.id,
            h.username,
            utc(h.time_ms),
            h.description
        )?,
        None => writeln!(out, "head:       no revisions yet")?,
    }
    match st.applied {
        Some(a) if st.head.as_ref().is_some_and(|h| h.id == a) => {
            writeln!(out, "applied:    revision {a} (head)")?
        }
        Some(a) => writeln!(out, "applied:    revision {a} (head is not applied)")?,
        None => writeln!(out, "applied:    nothing")?,
    }
    writeln!(
        out,
        "candidate:  {}",
        if st.candidate_dirty {
            "uncommitted changes (see `sensr config diff`)"
        } else {
            "clean"
        }
    )?;
    if let Some(p) = &st.pending_confirm {
        let left = (p.deadline_ms - crate_now_ms()).max(0) / 1000;
        writeln!(
            out,
            "confirm:    revision {} rolls back to {} in {left}s unless `sensr config confirm`",
            p.revision, p.rollback_to
        )?;
    }
    if let Some(e) = &st.last_apply_error {
        writeln!(out, "last error: {e}")?;
    }
    if let Some(e) = &st.seed_error {
        for (n, line) in e.lines().enumerate() {
            writeln!(
                out,
                "{} {line}",
                if n == 0 { "seed:      " } else { "           " }
            )?;
        }
    }
    Ok(())
}

fn crate_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `sensr config commit`.
pub fn committed(out: &mut dyn Write, o: &CommitOutcome) -> io::Result<()> {
    writeln!(out, "committed and applied revision {}", o.revision.id)?;
    if let Some(p) = &o.pending_confirm {
        let left = ((p.deadline_ms - crate_now_ms()).max(0) + 999) / 1000;
        writeln!(
            out,
            "provisional: run `sensr config confirm` within {left}s or revision {} is rolled back to {}",
            p.revision, p.rollback_to
        )?;
    }
    Ok(())
}

/// `sensr config history`.
pub fn history(out: &mut dyn Write, h: &[RevisionInfo]) -> io::Result<()> {
    if h.is_empty() {
        return writeln!(out, "no revisions");
    }
    writeln!(
        out,
        "{:>5}  {:<21} {:<24} description",
        "rev", "time", "user"
    )?;
    for r in h {
        writeln!(
            out,
            "{:>5}  {:<21} {:<24} {}",
            r.id,
            utc(r.time_ms),
            r.username,
            r.description
        )?;
    }
    Ok(())
}

/// `sensr apply --dry-run`.
pub fn plan(out: &mut dyn Write, p: &PlanView) -> io::Result<()> {
    if p.is_empty() {
        return writeln!(out, "nothing to apply: the running system matches");
    }
    if !p.net.is_empty() {
        writeln!(out, "# network")?;
        for step in &p.net {
            writeln!(out, "  {step}")?;
        }
    }
    if !p.nft.is_empty() {
        writeln!(out, "# nftables ruleset")?;
        write!(out, "{}", p.nft)?;
    }
    for s in &p.services {
        let verb = match s.action {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Reload => "reload",
            ServiceAction::Restart => "restart",
        };
        writeln!(out, "# service {} ({verb})", s.unit)?;
        for f in &s.files {
            write!(out, "{}", f.unified)?;
        }
    }
    Ok(())
}

/// The NIC table of `sensr interfaces list` (numbered for prompts).
pub fn nics(out: &mut dyn Write, nics: &[sensr_ipc::Nic], numbered: bool) -> io::Result<()> {
    let opt = |v: &Option<String>| v.clone().unwrap_or_else(|| "-".into());
    let rows: Vec<[String; 7]> = nics
        .iter()
        .map(|n| {
            [
                n.name.clone(),
                n.pin_mac().to_owned(),
                opt(&n.driver),
                match (&n.bus, &n.bus_path) {
                    (Some(b), Some(p)) => format!("{b} {p}"),
                    (Some(b), None) => b.clone(),
                    _ => "-".into(),
                },
                match (n.carrier, n.speed_mbps) {
                    (Some(true), Some(s)) => format!("up {s}M"),
                    (Some(true), None) => "up".into(),
                    (Some(false), _) => "no carrier".into(),
                    (None, _) => n.operstate.clone(),
                },
                opt(&n.assigned),
                String::new(),
            ]
        })
        .collect();
    let head = ["NAME", "MAC", "DRIVER", "BUS", "LINK", "INTERFACE", ""];
    let mut w = [0usize; 7];
    for r in rows
        .iter()
        .map(|r| r.each_ref().map(String::len))
        .chain([head.map(str::len)])
    {
        for (i, l) in r.iter().enumerate() {
            w[i] = w[i].max(*l);
        }
    }
    let line = |out: &mut dyn Write, n: &str, cols: [&str; 6]| -> io::Result<()> {
        let mut s = if numbered {
            format!("{n:>3}  ")
        } else {
            String::new()
        };
        for (i, c) in cols.iter().enumerate() {
            s += &format!("{c:<width$}  ", width = w[i]);
        }
        writeln!(out, "{}", s.trim_end())
    };
    line(
        out,
        "",
        [head[0], head[1], head[2], head[3], head[4], head[5]],
    )?;
    for (i, r) in rows.iter().enumerate() {
        line(
            out,
            &(i + 1).to_string(),
            [&r[0], &r[1], &r[2], &r[3], &r[4], &r[5]],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn utc_formats_known_instants() {
        assert_eq!(utc(0), "1970-01-01 00:00:00Z");
        assert_eq!(utc(951_782_400_000), "2000-02-29 00:00:00Z");
        assert_eq!(utc(1_794_012_345_110), "2026-11-07 00:45:45Z");
    }

    #[test]
    fn flat_lines() {
        let mut buf = Vec::new();
        let v = json!({"a": {"b": "x", "c": [1, {"d": true}]}, "e": {}});
        flat(&mut buf, &ConfigPath::root(), &v).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "a.b = x\na.c.0 = 1\na.c.1.d = true\ne = {}\n"
        );
        let mut buf = Vec::new();
        flat(
            &mut buf,
            &"system".parse().unwrap(),
            &json!({"hostname": "fw"}),
        )
        .unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "system.hostname = fw\n");
        let mut buf = Vec::new();
        flat(&mut buf, &"x".parse().unwrap(), &json!("bare")).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "bare\n");
    }
}
