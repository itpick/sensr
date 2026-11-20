//! The Unbound query log as a source of "top names/clients" and the recent
//! query list for the web UI.
//!
//! Unbound writes one line per query to its log file when `log-queries` is on
//! (`info: <client> <name> <type> <class>`). Reply lines have extra fields, so
//! only the four-field query form is counted. Nothing here parses the time:
//! the sampler reads every few seconds and stamps the rows it sees.
//!
//! The counters live in the sampler process and are never persisted; they
//! describe the period since it started, which the page says.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::stats::{DnsHit, RecentQuery};

/// How many recent queries to keep for the UI.
pub const RECENT: usize = 100;
/// Names/clients tracked before pruning to the most frequent.
const TRACKED: usize = 5_000;
/// Rotate the log file when it grows past this.
pub const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;

/// One query as Unbound logged it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Client address.
    pub client: String,
    /// Queried name, with the trailing dot Unbound logs.
    pub name: String,
    /// Query type (`A`, `AAAA`, `HTTPS`, …).
    pub kind: String,
}

/// Parses one logged query line. Returns `None` for anything else (startup
/// noise, replies, malformed lines).
pub fn parse_line(line: &str) -> Option<Query> {
    let body = line.split_once(" info: ")?.1.trim();
    let fields: Vec<&str> = body.split_whitespace().collect();
    // A reply carries the rcode and timings after the four query fields.
    if fields.len() != 4 {
        return None;
    }
    let (client, name, kind, class) = (fields[0], fields[1], fields[2], fields[3]);
    if class != "IN" && class != "CH" && class != "HS" {
        return None;
    }
    if kind.is_empty() || kind.len() > 12 || !kind.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    if name.is_empty() || name.len() > 255 || client.is_empty() || client.len() > 64 {
        return None;
    }
    Some(Query {
        client: client.to_owned(),
        name: name.to_owned(),
        kind: kind.to_owned(),
    })
}

/// Reads complete lines appended since `offset`. A shorter file means it was
/// rotated or truncated, so reading starts again at the beginning. `offset`
/// only advances over complete lines, so a line still being written is read
/// next time.
pub fn read_new(path: &Path, offset: &mut u64) -> Vec<String> {
    let Ok(mut file) = File::open(path) else {
        return Vec::new();
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if len < *offset {
        *offset = 0;
    }
    if len == *offset {
        return Vec::new();
    }
    if file.seek(SeekFrom::Start(*offset)).is_err() {
        *offset = 0;
        if file.seek(SeekFrom::Start(0)).is_err() {
            return Vec::new();
        }
    }
    let mut buf = Vec::new();
    if file
        .take(len.saturating_sub(*offset))
        .read_to_end(&mut buf)
        .is_err()
    {
        return Vec::new();
    }
    let Some(end) = buf.iter().rposition(|b| *b == b'\n') else {
        return Vec::new();
    };
    *offset += (end + 1) as u64;
    String::from_utf8_lossy(&buf[..=end])
        .lines()
        .map(str::to_owned)
        .collect()
}

/// In-memory counters since the sampler started.
#[derive(Debug, Default)]
pub struct Tally {
    domains: HashMap<String, u64>,
    clients: HashMap<String, u64>,
    recent: VecDeque<RecentQuery>,
    total: u64,
}

impl Tally {
    /// Counts one query, stamped with `at` (RFC 3339).
    pub fn record(&mut self, q: &Query, at: &str) {
        self.total += 1;
        *self.domains.entry(q.name.clone()).or_default() += 1;
        *self.clients.entry(q.client.clone()).or_default() += 1;
        self.recent.push_back(RecentQuery {
            at: at.to_owned(),
            client: q.client.clone(),
            name: q.name.clone(),
            kind: q.kind.clone(),
        });
        while self.recent.len() > RECENT {
            self.recent.pop_front();
        }
        if self.domains.len() > TRACKED {
            prune(&mut self.domains);
        }
        if self.clients.len() > TRACKED {
            prune(&mut self.clients);
        }
    }

    /// Fills a statistics record with the most frequent `limit` names and
    /// clients, newest recent query first.
    pub fn fill(&self, stats: &mut crate::stats::UnboundStats, limit: usize) {
        stats.top_domains = top(&self.domains, limit);
        stats.top_clients = top(&self.clients, limit);
        stats.recent = self.recent.iter().rev().cloned().collect();
        stats.logged_queries = self.total;
    }
}

fn prune(map: &mut HashMap<String, u64>) {
    let mut items: Vec<(String, u64)> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    items.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    map.clear();
    map.extend(items.into_iter().take(TRACKED / 2));
}

fn top(map: &HashMap<String, u64>, limit: usize) -> Vec<DnsHit> {
    let mut items: Vec<(String, u64)> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    items.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items
        .into_iter()
        .take(limit)
        .map(|(name, count)| DnsHit { name, count })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_queries_and_skips_replies() {
        let q = parse_line("Nov 20 02:10:10 unbound[123:0] info: 192.168.1.20 example.com. A IN")
            .unwrap();
        assert_eq!(
            q,
            Query {
                client: "192.168.1.20".into(),
                name: "example.com.".into(),
                kind: "A".into(),
            }
        );
        // A reply has the rcode and timings after the class.
        assert!(
            parse_line(
                "Nov 20 02:10:10 unbound[123:0] info: 192.168.1.20 example.com. A IN NOERROR 0.001 0 63"
            )
            .is_none()
        );
        assert!(parse_line("Nov 20 02:10:10 unbound[123:0] notice: init module 0").is_none());
        assert!(parse_line("").is_none());
    }

    #[test]
    fn tails_only_complete_lines_and_handles_truncation() {
        let dir = std::env::temp_dir().join(format!("sensr-querylog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("query.log");
        let mut f = File::create(&path).unwrap();
        writeln!(f, "a info: 10.0.0.1 one.test. A IN").unwrap();
        writeln!(f, "b info: 10.0.0.2 two.test. AAAA IN").unwrap();
        drop(f);

        let mut offset = 0;
        let lines = read_new(&path, &mut offset);
        assert_eq!(lines.len(), 2);
        assert_eq!(offset, std::fs::metadata(&path).unwrap().len());

        // A partial line is left for the next read.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        write!(f, "c info: 10.0.0.3 three.test. A").unwrap();
        drop(f);
        assert!(read_new(&path, &mut offset).is_empty());
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(f, " IN").unwrap();
        drop(f);
        assert_eq!(read_new(&path, &mut offset).len(), 1);

        // Rotation restarts at the beginning.
        std::fs::write(&path, "d info: 10.0.0.4 four.test. A IN\n").unwrap();
        let lines = read_new(&path, &mut offset);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("four.test."));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn top_lists_are_ordered_and_capped() {
        let mut t = Tally::default();
        for (i, name) in ["a.test.", "b.test.", "a.test.", "c.test.", "a.test."]
            .iter()
            .enumerate()
        {
            t.record(
                &Query {
                    client: format!("10.0.0.{}", i + 1),
                    name: (*name).to_owned(),
                    kind: "A".into(),
                },
                "2026-11-20T02:00:00Z",
            );
        }
        let mut s = crate::stats::UnboundStats::from_counters(&Default::default(), "t".into());
        t.fill(&mut s, 2);
        assert_eq!(s.top_domains[0].name, "a.test.");
        assert_eq!(s.top_domains[0].count, 3);
        assert_eq!(s.top_domains.len(), 2);
        assert_eq!(s.top_clients.len(), 2);
        assert_eq!(s.recent.len(), 5);
        assert_eq!(s.recent[0].name, "a.test.");
        assert_eq!(s.logged_queries, 5);
    }
}
