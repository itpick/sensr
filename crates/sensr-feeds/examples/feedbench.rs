//! Refresh timings and memory with real feeds: fetches a home-router-sized
//! set of public lists into a scratch store, resolves them, renders the set
//! update transaction, and prints per-step times and peak RSS.
//!
//! `cargo run --release -p sensr-feeds --example feedbench -- <store-dir>`

use std::sync::Arc;
use std::time::Instant;

use sensr_feeds::http::HttpFetcher;
use sensr_feeds::{Feeds, SystemResolver, alias_defs};
use sensr_rules::render::nft;
use sensr_schema::Document;
use sensr_schema::models::firewall::{Alias, AliasContent, Families, Refresh};

fn table(name: &str, url: &str) -> Alias {
    Alias {
        enabled: true,
        name: name.parse().unwrap(),
        content: AliasContent::UrlTable {
            url: url.parse().unwrap(),
            refresh: Refresh { days: 1, hours: 0 },
            families: Families::default(),
        },
        description: None,
        counters: false,
    }
}

fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/sensr-feedbench".into());
    let mut doc = Document::default();
    for (n, u) in [
        (
            "GeoIP_CN_zone",
            "https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone",
        ),
        (
            "GeoIP_US_zone",
            "https://www.ipdeny.com/ipblocks/data/aggregated/us-aggregated.zone",
        ),
        ("SpamhausDROP", "https://www.spamhaus.org/drop/drop.txt"),
        ("SpamhausEDROP", "https://www.spamhaus.org/drop/edrop.txt"),
        (
            "EmergingThreats",
            "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        ),
        (
            "FeodoTracker",
            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        ),
        (
            "SSLBlacklist",
            "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        ),
    ] {
        doc.firewall.aliases.push(table(n, u));
    }
    doc.firewall.aliases.push(Alias {
        enabled: true,
        name: "GeoIP_DBIP".parse().unwrap(),
        content: AliasContent::GeoIp {
            countries: ["CN", "RU", "NG", "US"]
                .iter()
                .map(|c| c.parse().unwrap())
                .collect(),
            families: Families::default(),
        },
        description: None,
        counters: false,
    });
    let feeds = Feeds::new(
        &dir,
        Arc::new(HttpFetcher::default()),
        Arc::new(SystemResolver),
        Arc::new(Vec::new),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let t = Instant::now();
    let r = feeds.refresh(&doc, now);
    let refresh = t.elapsed();
    for f in &r.fetches {
        println!(
            "fetch {:<80} {:>6} {:>10} B {:>6} ms",
            f.url, f.outcome, f.bytes, f.millis
        );
    }
    for (name, a) in &r.updates {
        println!("alias {name:<16} {:>7} networks", a.nets.len());
    }
    let t = Instant::now();
    let res = sensr_rules::alias::resolve_all(&alias_defs(&doc), &feeds.sources());
    let resolve = t.elapsed();
    let sets: Vec<_> = res
        .aliases
        .iter()
        .flat_map(|(n, a)| nft::alias_set_updates(n, a))
        .collect();
    let mut buf = Vec::new();
    let t = Instant::now();
    nft::render_set_updates("sensr", &sets, &mut buf).unwrap();
    let render = t.elapsed();
    // second refresh: everything conditional (304) or not due
    let t = Instant::now();
    let again = feeds.refresh(&doc, now + 86_400);
    let conditional = t.elapsed();
    println!(
        "first refresh (download + parse + store): {:.0} ms\nresolve from the store: {:.1} ms\nset-update JSON: {} KB in {:.1} ms\nnext-day refresh: {:.0} ms ({} requests)\npeak RSS: {} MiB",
        refresh.as_secs_f64() * 1e3,
        resolve.as_secs_f64() * 1e3,
        buf.len() / 1024,
        render.as_secs_f64() * 1e3,
        conditional.as_secs_f64() * 1e3,
        again.fetches.len(),
        peak_rss_kib() / 1024
    );
    std::fs::write(format!("{dir}/update.nft.json"), &buf).unwrap();
}
