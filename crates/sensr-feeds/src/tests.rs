//! Refresh scheduling, last-good retention and change detection against a
//! scripted fetcher.
//!
/// Covers: FW-AL-005, FW-AL-008, FW-AL-009, BIZ-012, ISS-C-018
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Mutex;

use sensr_schema::Document;
use sensr_schema::models::firewall::{Alias, AliasContent, Families, Refresh};

use super::*;
use crate::http::{Conditional, HttpError};

#[derive(Default)]
struct Script {
    /// url → responses, consumed front first; the last one repeats
    responses: Mutex<BTreeMap<String, Vec<Result<Fetched, HttpError>>>>,
    calls: Mutex<Vec<(String, Conditional)>>,
}

impl Script {
    fn on(&self, url: &str, r: Result<Fetched, HttpError>) {
        self.responses
            .lock()
            .unwrap()
            .entry(url.to_owned())
            .or_default()
            .push(r);
    }
    fn body(&self, url: &str, body: &[u8], etag: &str) {
        self.on(
            url,
            Ok(Fetched::Body {
                bytes: body.to_vec(),
                conditional: Conditional {
                    etag: Some(etag.into()),
                    last_modified: None,
                },
            }),
        );
    }
    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.0.clone())
            .collect()
    }
}

impl Fetcher for Script {
    fn get(&self, url: &str, _: &Auth, c: &Conditional) -> Result<Fetched, HttpError> {
        self.calls.lock().unwrap().push((url.to_owned(), c.clone()));
        let mut r = self.responses.lock().unwrap();
        let v = r
            .get_mut(url)
            .ok_or_else(|| HttpError("connection refused".into()))?;
        if v.len() > 1 {
            v.remove(0)
        } else {
            v[0].clone()
        }
    }
}

struct NoDns;
impl Resolver for NoDns {
    fn query(&self, name: &str, _: RecordType) -> Result<Vec<Record>, DnsError> {
        Err(DnsError::NxDomain(name.into()))
    }
}

fn feeds(dir: &Path, script: Arc<Script>) -> Feeds {
    Feeds::new(dir, script, Arc::new(NoDns), Arc::new(Vec::new))
}

fn doc_with(aliases: Vec<Alias>) -> Document {
    let mut d = Document::default();
    for a in aliases {
        d.firewall.aliases.push(a);
    }
    d
}

fn alias(name: &str, content: AliasContent) -> Alias {
    Alias {
        enabled: true,
        name: name.parse().unwrap(),
        content,
        description: None,
        counters: false,
    }
}

fn url_table(name: &str, url: &str, hours: u8) -> Alias {
    alias(
        name,
        AliasContent::UrlTable {
            url: url.parse().unwrap(),
            refresh: Refresh { days: 0, hours },
            families: Families::default(),
        },
    )
}

const DROP: &str = "https://lists.example.net/drop.txt";

fn names(r: &Refreshed) -> Vec<&str> {
    r.updates.iter().map(|(n, _)| n.as_str()).collect()
}

#[test]
fn url_table_fetches_parses_and_refreshes_on_schedule() {
    let d = tempfile::tempdir().unwrap();
    let s = Arc::new(Script::default());
    s.body(
        DROP,
        b"; Spamhaus-style comment\n198.51.100.0/24 ; SBL1\n203.0.113.7\n",
        "v1",
    );
    s.on(DROP, Ok(Fetched::NotModified));
    let f = feeds(d.path(), s.clone());
    let doc = doc_with(vec![url_table("DROP", DROP, 1)]);
    let t0 = 1_000_000;
    let r = f.refresh(&doc, t0);
    assert_eq!(names(&r), ["DROP"]);
    assert_eq!(r.updates[0].1.nets.len(), 2);
    assert_eq!(r.fetches[0].outcome, "200");
    // not due again within the hour
    assert!(f.refresh(&doc, t0 + 600).fetches.is_empty());
    // due after an hour: conditional request, 304, nothing to push
    let r = f.refresh(&doc, t0 + 3_600);
    assert_eq!(r.fetches[0].outcome, "304");
    assert!(r.updates.is_empty());
    let conds = s.calls.lock().unwrap().clone();
    assert_eq!(conds[1].1.etag.as_deref(), Some("v1"));
}

#[test]
fn failed_fetch_keeps_last_good_and_backs_off() {
    let d = tempfile::tempdir().unwrap();
    let s = Arc::new(Script::default());
    s.body(DROP, b"198.51.100.0/24\n", "v1");
    s.on(DROP, Err(HttpError("HTTP status 503".into())));
    let f = feeds(d.path(), s.clone());
    let doc = doc_with(vec![url_table("DROP", DROP, 1)]);
    let t0 = 2_000_000;
    assert_eq!(names(&f.refresh(&doc, t0)), ["DROP"]);
    let r = f.refresh(&doc, t0 + 3_600);
    assert!(r.fetches[0].outcome.contains("503"));
    assert!(r.updates.is_empty(), "a failure never empties the alias");
    // the render path still sees the old body
    let body = f.sources().fetch(DROP, &Auth::None).unwrap();
    assert!(body.contains("198.51.100.0/24"));
    let st = f.status(&doc, t0 + 3_600);
    assert!(st[0].error.as_deref().unwrap().contains("503"));
    assert_eq!(st[0].entries, 1);
    // back-off: 30 s after the failure, then 60 s
    assert!(f.refresh(&doc, t0 + 3_600 + 29).fetches.is_empty());
    assert_eq!(f.refresh(&doc, t0 + 3_600 + 30).fetches.len(), 1);
    assert!(f.refresh(&doc, t0 + 3_630 + 59).fetches.is_empty());
    assert_eq!(f.refresh(&doc, t0 + 3_630 + 60).fetches.len(), 1);
}

#[test]
fn survives_a_restart_from_the_store() {
    let d = tempfile::tempdir().unwrap();
    let s = Arc::new(Script::default());
    s.body(DROP, b"198.51.100.0/24\n", "v1");
    let doc = doc_with(vec![url_table("DROP", DROP, 24)]);
    feeds(d.path(), s.clone()).refresh(&doc, 3_000_000);
    // a new process, the network down: the stored body renders
    let down = Arc::new(Script::default());
    let f = feeds(d.path(), down.clone());
    let res = alias::resolve_all(&alias_defs(&doc), &f.sources());
    assert!(res.failed.is_empty());
    assert_eq!(res.aliases["DROP"].nets.len(), 1);
    // and the first refresh (not yet due) pushes the stored contents once
    let r = f.refresh(&doc, 3_000_100);
    assert!(down.calls().is_empty());
    assert_eq!(names(&r), ["DROP"]);
}

#[test]
fn applied_contents_suppress_redundant_pushes() {
    let d = tempfile::tempdir().unwrap();
    let s = Arc::new(Script::default());
    s.body(DROP, b"198.51.100.0/24\n", "v1");
    s.body(DROP, b"198.51.100.0/24\n203.0.113.0/24\n", "v2");
    let f = feeds(d.path(), s.clone());
    let doc = doc_with(vec![url_table("DROP", DROP, 1)]);
    f.refresh(&doc, 10);
    // the next apply rendered the same contents
    let res = alias::resolve_all(&alias_defs(&doc), &f.sources());
    f.applied(res.aliases);
    let r = f.refresh(&doc, 10 + 3_600);
    assert_eq!(names(&r), ["DROP"]);
    assert_eq!(r.updates[0].1.nets.len(), 2);
}

#[test]
fn nested_alias_follows_its_member() {
    let d = tempfile::tempdir().unwrap();
    let s = Arc::new(Script::default());
    s.body(DROP, b"198.51.100.0/24\n", "v1");
    s.body(DROP, b"203.0.113.0/24\n", "v2");
    let f = feeds(d.path(), s);
    let group = alias(
        "BAD",
        AliasContent::NetworkGroup {
            members: vec!["DROP".parse().unwrap()],
        },
    );
    let doc = doc_with(vec![url_table("DROP", DROP, 1), group]);
    f.refresh(&doc, 10);
    let mut r = names(&f.refresh(&doc, 10 + 3_600))
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    r.sort();
    assert_eq!(r, ["BAD", "DROP"]);
}

#[test]
fn disabled_alias_is_not_fetched() {
    let d = tempfile::tempdir().unwrap();
    let s = Arc::new(Script::default());
    let f = feeds(d.path(), s.clone());
    let mut a = url_table("PAUSED", DROP, 1);
    a.enabled = false;
    let doc = doc_with(vec![a]);
    let r = f.refresh(&doc, 10);
    assert!(s.calls().is_empty());
    assert!(r.updates.iter().all(|(_, c)| c.nets.is_empty()));
    assert_eq!(f.status(&doc, 10)[0].entries, 0);
}

fn gz(b: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(b).unwrap();
    e.finish().unwrap()
}

#[test]
fn geoip_from_dbip_default_source_with_previous_month_fallback() {
    let d = tempfile::tempdir().unwrap();
    let s = Arc::new(Script::default());
    // 2026-11-16: the November file is not published yet, October is
    let now = 1_794_830_400;
    s.on(
        &geo::dbip_url(2026, 11),
        Err(HttpError("HTTP status 404".into())),
    );
    s.body(
        &geo::dbip_url(2026, 10),
        &gz(b"198.51.100.0,198.51.100.255,ZZ\n192.0.2.0,192.0.2.255,QQ\n2001:db8::,2001:db8::ffff,ZZ\n"),
        "oct",
    );
    let f = feeds(d.path(), s.clone());
    let doc = doc_with(vec![alias(
        "GEO",
        AliasContent::GeoIp {
            countries: vec!["ZZ".parse().unwrap()],
            families: Families::default(),
        },
    )]);
    let r = f.refresh(&doc, now);
    assert_eq!(names(&r), ["GEO"]);
    assert_eq!(r.updates[0].1.nets.len(), 2);
    // only ZZ was stored
    assert!(f.geo.has("ZZ") && !f.geo.has("QQ"));
    let st = &f.status(&doc, now)[0];
    assert!(st.attribution.as_deref().unwrap().contains("DB-IP"));
    // a day later only a conditional check
    s.on(
        &geo::dbip_url(2026, 11),
        Err(HttpError("HTTP status 404".into())),
    );
    let r = f.refresh(&doc, now + 60);
    assert!(r.fetches.is_empty(), "{:?}", r.fetches);
}

#[test]
fn asn_alias_from_iptoasn() {
    let d = tempfile::tempdir().unwrap();
    let s = Arc::new(Script::default());
    s.body(
        asn::IPTOASN_URL,
        &gz(b"198.51.100.0\t198.51.100.255\t64500\tZZ\tEXAMPLE\n192.0.2.0\t192.0.2.255\t64501\tZZ\tOTHER\n"),
        "a",
    );
    let f = feeds(d.path(), s);
    let doc = doc_with(vec![alias(
        "EXAMPLE_AS",
        AliasContent::Asn {
            asns: vec![64500],
            families: Families::default(),
        },
    )]);
    let r = f.refresh(&doc, 50);
    assert_eq!(
        r.updates[0].1.nets,
        vec!["198.51.100.0/24".parse::<IpNet>().unwrap()]
    );
}

#[test]
fn mac_alias_follows_the_neighbour_table() {
    let d = tempfile::tempdir().unwrap();
    let table = Arc::new(Mutex::new(vec![(
        "02:00:5e:10:00:0a".to_owned(),
        "192.168.1.10".parse::<IpAddr>().unwrap(),
    )]));
    let t = table.clone();
    let f = Feeds::new(
        d.path(),
        Arc::new(Script::default()),
        Arc::new(NoDns),
        Arc::new(move || t.lock().unwrap().clone()),
    );
    let doc = doc_with(vec![alias(
        "TRUSTED",
        AliasContent::Mac {
            addresses: vec!["02:00:5e:10:00:0a".parse().unwrap()],
        },
    )]);
    assert_eq!(f.refresh(&doc, 0).updates[0].1.nets.len(), 1);
    table
        .lock()
        .unwrap()
        .push(("02:00:5e:10:00:0a".into(), "192.168.1.20".parse().unwrap()));
    // not re-read within 30 s
    assert!(f.refresh(&doc, 29).updates.is_empty());
    assert_eq!(f.refresh(&doc, 30).updates[0].1.nets.len(), 2);
}
