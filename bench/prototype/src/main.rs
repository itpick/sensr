//! Throwaway benchmark prototype (NOT sensr code): a lower bound for what a
//! Rust control plane costs when it owns the policy in memory, renders the
//! whole nftables ruleset as JSON and applies it atomically with `nft -j -f -`.
//!
//! Subcommands:
//!   bench  --policy P.json [--extra N] [--set-sizes 1000,10000,100000] [--reps R] [--no-apply]
//!   serve  --policy P.json [--extra N] [--port 8080] [--no-apply]
//!
//! The policy file is the generator's OPNsense payload (aliases + rules), so
//! the prototype enforces exactly the rule list the other routers get.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
enum Proto {
    Any,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Clone, Debug)]
enum Port {
    None,
    Single(u16),
    Range(u16, u16),
    Set(String),
}

#[derive(Clone, Debug)]
enum Addr {
    Any,
    SelfAddr,
    Lan,
    Net(String, u8),
    Set(String),
}

#[derive(Clone, Debug)]
struct Rule {
    pass: bool,
    iface: String,
    proto: Proto,
    src: Addr,
    dst: Addr,
    dport: Port,
    descr: String,
}

#[derive(Clone, Debug)]
struct Alias {
    name: String,
    kind: String,
    content: Vec<String>,
}

#[derive(Clone)]
struct Policy {
    aliases: Vec<Alias>,
    rules: Vec<Rule>,
}

fn parse_addr(s: &str, aliases: &[Alias]) -> Addr {
    match s {
        "any" | "" => Addr::Any,
        "(self)" => Addr::SelfAddr,
        "lan" => Addr::Lan,
        _ if aliases.iter().any(|a| a.name == s) => Addr::Set(s.to_string()),
        _ => {
            let (a, l) = s.split_once('/').unwrap_or((s, "32"));
            Addr::Net(a.to_string(), l.parse().unwrap_or(32))
        }
    }
}

fn parse_port(s: &str, aliases: &[Alias]) -> Port {
    if s.is_empty() {
        Port::None
    } else if aliases.iter().any(|a| a.name == s) {
        Port::Set(s.to_string())
    } else if let Some((a, b)) = s.split_once('-') {
        Port::Range(a.parse().unwrap_or(0), b.parse().unwrap_or(0))
    } else {
        Port::Single(s.parse().unwrap_or(0))
    }
}

fn load_policy(path: &str, extra: usize) -> Policy {
    let v: Value =
        serde_json::from_slice(&std::fs::read(path).expect("read policy")).expect("policy json");
    let aliases: Vec<Alias> = v["aliases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            let a = &a["alias"];
            Alias {
                name: a["name"].as_str().unwrap().into(),
                kind: a["type"].as_str().unwrap().into(),
                content: a["content"]
                    .as_str()
                    .unwrap()
                    .lines()
                    .map(String::from)
                    .collect(),
            }
        })
        .collect();
    let mut rules: Vec<Rule> = v["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let r = &r["rule"];
            Rule {
                pass: r["action"] == "pass",
                iface: r["interface"].as_str().unwrap().into(),
                proto: match r["protocol"].as_str().unwrap() {
                    "TCP" => Proto::Tcp,
                    "UDP" => Proto::Udp,
                    "ICMP" => Proto::Icmp,
                    _ => Proto::Any,
                },
                src: parse_addr(r["source_net"].as_str().unwrap(), &aliases),
                dst: parse_addr(r["destination_net"].as_str().unwrap(), &aliases),
                dport: parse_port(r["destination_port"].as_str().unwrap(), &aliases),
                descr: r["description"].as_str().unwrap().into(),
            }
        })
        .collect();
    // synthetic growth (e.g. 1k -> 10k rules), inserted before "LAN to any"
    let at = rules
        .iter()
        .position(|r| r.descr == "LAN to any")
        .unwrap_or(rules.len());
    let filler: Vec<Rule> = (0..extra)
        .map(|j| Rule {
            pass: j % 3 != 0,
            iface: "lan".into(),
            proto: if j % 2 == 0 { Proto::Udp } else { Proto::Tcp },
            src: Addr::Net(format!("192.168.1.{}", 150 + (j % 100)), 32),
            dst: Addr::Net(format!("100.{}.{}.0", 64 + (j / 250) % 60, j % 250), 24),
            dport: Port::Single(20000 + (j % 40000) as u16),
            descr: format!("synthetic rule {j}"),
        })
        .collect();
    rules.splice(at..at, filler);
    Policy { aliases, rules }
}

const FAM: &str = "inet";
const TBL: &str = "filter";

fn m(left: Value, right: Value) -> Value {
    json!({"match": {"op": "==", "left": left, "right": right}})
}

fn addr_expr(field: &str, a: &Addr) -> Option<Value> {
    let left = json!({"payload": {"protocol": "ip", "field": field}});
    match a {
        Addr::Any | Addr::SelfAddr => None,
        Addr::Lan => Some(m(
            left,
            json!({"prefix": {"addr": "192.168.1.0", "len": 24}}),
        )),
        Addr::Net(ip, 32) => Some(m(left, json!(ip))),
        Addr::Net(ip, l) => Some(m(left, json!({"prefix": {"addr": ip, "len": l}}))),
        Addr::Set(n) => Some(m(left, json!(format!("@{n}")))),
    }
}

fn elem(s: &str) -> Value {
    match s.split_once('/') {
        Some((a, l)) => json!({"prefix": {"addr": a, "len": l.parse::<u8>().unwrap_or(32)}}),
        None => json!(s),
    }
}

fn set_obj(a: &Alias) -> Value {
    let (ty, flags): (&str, Vec<&str>) = match a.kind.as_str() {
        "port" => ("inet_service", vec![]),
        "network" => ("ipv4_addr", vec!["interval"]),
        _ => ("ipv4_addr", vec![]),
    };
    let elems: Vec<Value> = if a.kind == "port" {
        a.content
            .iter()
            .map(|p| json!(p.parse::<u16>().unwrap_or(0)))
            .collect()
    } else {
        a.content.iter().map(|s| elem(s)).collect()
    };
    let mut o = json!({"family": FAM, "table": TBL, "name": a.name, "type": ty, "elem": elems});
    if !flags.is_empty() {
        o["flags"] = json!(flags);
    }
    json!({"add": {"set": o}})
}

fn rule_obj(chain: &str, r: &Rule) -> Value {
    let mut e = vec![m(
        json!({"meta": {"key": "iifname"}}),
        json!(format!("{}0", r.iface)),
    )];
    e.extend(addr_expr("saddr", &r.src));
    e.extend(addr_expr("daddr", &r.dst));
    let l4 = match r.proto {
        Proto::Tcp => Some("tcp"),
        Proto::Udp => Some("udp"),
        Proto::Icmp => {
            e.push(m(
                json!({"payload": {"protocol": "ip", "field": "protocol"}}),
                json!("icmp"),
            ));
            None
        }
        Proto::Any => None,
    };
    if let Some(p) = l4 {
        let left = json!({"payload": {"protocol": p, "field": "dport"}});
        match &r.dport {
            Port::None => e.push(m(json!({"meta": {"key": "l4proto"}}), json!(p))),
            Port::Single(n) => e.push(m(left, json!(n))),
            Port::Range(a, b) => e.push(m(left, json!({"range": [a, b]}))),
            Port::Set(n) => e.push(m(left, json!(format!("@{n}")))),
        }
    }
    e.push(json!({"counter": null}));
    e.push(if r.pass {
        json!({"accept": null})
    } else {
        json!({"drop": null})
    });
    json!({"add": {"rule": {"family": FAM, "table": TBL, "chain": chain, "comment": r.descr, "expr": e}}})
}

/// Streaming variant of `render`: identical nft JSON, but each command is built and
/// serialized one at a time, so peak memory is the output buffer plus one rule.
fn render_bytes(p: &Policy) -> Vec<u8> {
    if std::env::var_os("SENSR_PROTO_DOM").is_some() {
        return serde_json::to_vec(&render(p)).unwrap();
    }
    let mut out = Vec::with_capacity(64 * 1024 + p.rules.len() * 600);
    out.extend_from_slice(b"{\"nftables\":[");
    let mut first = true;
    let mut push = |v: Value, out: &mut Vec<u8>| {
        if !first {
            out.push(b',');
        }
        first = false;
        serde_json::to_writer(&mut *out, &v).unwrap();
    };
    let dom = render_head(p);
    for v in dom {
        push(v, &mut out);
    }
    for r in &p.rules {
        let chain = if matches!(r.dst, Addr::SelfAddr) {
            "input"
        } else {
            "forward"
        };
        push(rule_obj(chain, r), &mut out);
    }
    for v in render_tail() {
        push(v, &mut out);
    }
    out.extend_from_slice(b"]}");
    out
}

fn render_head(p: &Policy) -> Vec<Value> {
    let mut cmds = vec![
        json!({"flush": {"ruleset": null}}),
        json!({"add": {"table": {"family": FAM, "name": TBL}}}),
    ];
    cmds.extend(p.aliases.iter().map(set_obj));
    for (name, hook) in [("input", "input"), ("forward", "forward")] {
        cmds.push(
            json!({"add": {"chain": {"family": FAM, "table": TBL, "name": name, "type": "filter",
            "hook": hook, "prio": 0, "policy": "drop"}}}),
        );
        cmds.push(json!({"add": {"rule": {"family": FAM, "table": TBL, "chain": name, "expr": [
            {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}},
            {"accept": null}]}}}));
    }
    cmds.push(
        json!({"add": {"rule": {"family": FAM, "table": TBL, "chain": "input", "expr": [
        m(json!({"meta": {"key": "iifname"}}), json!("lo")), {"accept": null}]}}}),
    );
    cmds.push(json!({"add": {"rule": {"family": FAM, "table": TBL, "chain": "input", "comment": "anti-lockout", "expr": [
        m(json!({"meta": {"key": "iifname"}}), json!("lan0")),
        m(json!({"payload": {"protocol": "tcp", "field": "dport"}}), json!({"set": [22, 80, 443, 8080]})),
        {"accept": null}]}}}));
    cmds
}

fn render_tail() -> Vec<Value> {
    vec![
        json!({"add": {"table": {"family": "ip", "name": "nat"}}}),
        json!({"add": {"chain": {"family": "ip", "table": "nat", "name": "postrouting", "type": "nat",
            "hook": "postrouting", "prio": 100, "policy": "accept"}}}),
        json!({"add": {"rule": {"family": "ip", "table": "nat", "chain": "postrouting", "expr": [
            m(json!({"meta": {"key": "oifname"}}), json!("wan0")),
            m(json!({"payload": {"protocol": "ip", "field": "saddr"}}), json!({"prefix": {"addr": "192.168.1.0", "len": 24}})),
            {"masquerade": null}]}}}),
    ]
}

/// Full, atomic ruleset: one nft transaction replaces everything (DOM variant).
fn render(p: &Policy) -> Value {
    let mut cmds = vec![
        json!({"flush": {"ruleset": null}}),
        json!({"add": {"table": {"family": FAM, "name": TBL}}}),
    ];
    cmds.extend(p.aliases.iter().map(set_obj));
    for (name, hook) in [("input", "input"), ("forward", "forward")] {
        cmds.push(
            json!({"add": {"chain": {"family": FAM, "table": TBL, "name": name, "type": "filter",
            "hook": hook, "prio": 0, "policy": "drop"}}}),
        );
        cmds.push(json!({"add": {"rule": {"family": FAM, "table": TBL, "chain": name, "expr": [
            {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}},
            {"accept": null}]}}}));
    }
    cmds.push(
        json!({"add": {"rule": {"family": FAM, "table": TBL, "chain": "input", "expr": [
        m(json!({"meta": {"key": "iifname"}}), json!("lo")), {"accept": null}]}}}),
    );
    cmds.push(json!({"add": {"rule": {"family": FAM, "table": TBL, "chain": "input", "comment": "anti-lockout", "expr": [
        m(json!({"meta": {"key": "iifname"}}), json!("lan0")),
        m(json!({"payload": {"protocol": "tcp", "field": "dport"}}), json!({"set": [22, 80, 443, 8080]})),
        {"accept": null}]}}}));
    for r in &p.rules {
        let chain = if matches!(r.dst, Addr::SelfAddr) {
            "input"
        } else {
            "forward"
        };
        cmds.push(rule_obj(chain, r));
    }
    cmds.push(json!({"add": {"table": {"family": "ip", "name": "nat"}}}));
    cmds.push(json!({"add": {"chain": {"family": "ip", "table": "nat", "name": "postrouting", "type": "nat",
        "hook": "postrouting", "prio": 100, "policy": "accept"}}}));
    cmds.push(json!({"add": {"rule": {"family": "ip", "table": "nat", "chain": "postrouting", "expr": [
        m(json!({"meta": {"key": "oifname"}}), json!("wan0")),
        m(json!({"payload": {"protocol": "ip", "field": "saddr"}}), json!({"prefix": {"addr": "192.168.1.0", "len": 24}})),
        {"masquerade": null}]}}}));
    json!({"nftables": cmds})
}

/// Atomic set content replacement (flush + add in one transaction).
fn render_set_replace(name: &str, entries: &[String]) -> Value {
    json!({"nftables": [
        {"flush": {"set": {"family": FAM, "table": TBL, "name": name}}},
        {"add": {"element": {"family": FAM, "table": TBL, "name": name,
            "elem": entries.iter().map(|s| elem(s)).collect::<Vec<_>>()}}}
    ]})
}

fn nft_apply(doc: &[u8], apply: bool) -> f64 {
    if !apply {
        return 0.0;
    }
    let t = Instant::now();
    let mut child = Command::new("nft")
        .args(["-j", "-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn nft");
    child.stdin.take().unwrap().write_all(doc).unwrap();
    let st = child.wait().unwrap();
    assert!(st.success(), "nft failed");
    t.elapsed().as_secs_f64() * 1000.0
}

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .map(|l| l.split_whitespace().nth(1).unwrap().parse().unwrap())
        })
        .unwrap_or(0)
}

fn arg(args: &[String], k: &str, d: &str) -> String {
    args.iter()
        .position(|a| a == k)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| d.to_string())
}

fn bench(args: &[String]) {
    let apply = !args.iter().any(|a| a == "--no-apply");
    let reps: usize = arg(args, "--reps", "5").parse().unwrap();
    let extra: usize = arg(args, "--extra", "0").parse().unwrap();
    let p = load_policy(&arg(args, "--policy", "large.json"), extra);
    for _ in 0..reps {
        let t = Instant::now();
        let doc = render_bytes(&p);
        let render_ms = t.elapsed().as_secs_f64() * 1000.0;
        let apply_ms = nft_apply(&doc, apply);
        println!(
            "{}",
            json!({"what": "full_ruleset", "renderer": if std::env::var_os("SENSR_PROTO_DOM").is_some() {"dom"} else {"stream"}, "rules": p.rules.len(),
            "set_entries": p.aliases.iter().map(|a| a.content.len()).sum::<usize>(),
            "json_bytes": doc.len(), "render_ms": render_ms, "nft_apply_ms": apply_ms, "rss_kib": rss_kib()})
        );
    }
    let sizes = arg(args, "--set-files", "");
    for f in sizes.split(',').filter(|s| !s.is_empty()) {
        let entries: Vec<String> = std::fs::read_to_string(f)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        for _ in 0..reps {
            let t = Instant::now();
            let doc = serde_json::to_vec(&render_set_replace("blocklist_v4", &entries)).unwrap();
            let render_ms = t.elapsed().as_secs_f64() * 1000.0;
            let apply_ms = nft_apply(&doc, apply);
            println!(
                "{}",
                json!({"what": "set_replace", "entries": entries.len(), "json_bytes": doc.len(),
                "render_ms": render_ms, "nft_apply_ms": apply_ms})
            );
        }
    }
}

struct App {
    policy: Policy,
    apply: bool,
}

#[derive(Deserialize)]
struct SearchQ {
    q: Option<String>,
    limit: Option<usize>,
}

async fn search(State(app): State<Arc<Mutex<App>>>, Query(q): Query<SearchQ>) -> Json<Value> {
    let app = app.lock().await;
    let needle = q.q.unwrap_or_default();
    let limit = q.limit.unwrap_or(25);
    let mut total = 0usize;
    let mut rows = Vec::new();
    for (i, r) in app.policy.rules.iter().enumerate() {
        if needle.is_empty() || r.descr.contains(&needle) {
            total += 1;
            if rows.len() < limit {
                rows.push(json!({"seq": i, "action": if r.pass {"pass"} else {"block"}, "interface": r.iface,
                    "src": format!("{:?}", r.src), "dst": format!("{:?}", r.dst), "description": r.descr}));
            }
        }
    }
    Json(json!({"total": total, "rows": rows}))
}

#[derive(Deserialize)]
struct NewRule {
    description: String,
    source: String,
    port: u16,
}

/// Add a block rule at the top of the LAN list and apply the whole ruleset.
async fn add_rule(State(app): State<Arc<Mutex<App>>>, Json(n): Json<NewRule>) -> Json<Value> {
    let mut app = app.lock().await;
    let t = Instant::now();
    let src = parse_addr(&n.source, &app.policy.aliases);
    app.policy.rules.insert(
        0,
        Rule {
            pass: false,
            iface: "lan".into(),
            proto: Proto::Tcp,
            src,
            dst: Addr::Any,
            dport: Port::Single(n.port),
            descr: n.description,
        },
    );
    let doc = render_bytes(&app.policy);
    let render_ms = t.elapsed().as_secs_f64() * 1000.0;
    let apply = app.apply;
    let apply_ms = tokio::task::spawn_blocking(move || nft_apply(&doc, apply))
        .await
        .unwrap();
    Json(
        json!({"result": "applied", "rules": app.policy.rules.len(), "render_ms": render_ms, "nft_apply_ms": apply_ms}),
    )
}

async fn health() -> &'static str {
    "ok"
}

async fn stats() -> Json<Value> {
    Json(json!({"rss_kib": rss_kib()}))
}

fn serve(args: &[String]) {
    let apply = !args.iter().any(|a| a == "--no-apply");
    let extra: usize = arg(args, "--extra", "0").parse().unwrap();
    let port: u16 = arg(args, "--port", "8080").parse().unwrap();
    let policy = load_policy(&arg(args, "--policy", "small.json"), extra);
    // Like any real control plane, enforce the stored policy at startup.
    let doc = render_bytes(&policy);
    if arg(args, "--apply-on-start", "no") == "yes" {
        nft_apply(&doc, apply);
    }
    let state = Arc::new(Mutex::new(App { policy, apply }));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let app = Router::new()
            .route("/api/health", get(health))
            .route("/api/stats", get(stats))
            .route("/api/rules/search", get(search))
            .route("/api/rules", post(add_rule))
            .with_state(state);
        let l = tokio::net::TcpListener::bind(("0.0.0.0", port))
            .await
            .unwrap();
        axum::serve(l, app).await.unwrap();
    });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("bench") => bench(&args[2..]),
        Some("serve") => serve(&args[2..]),
        _ => eprintln!("usage: sensr-proto bench|serve ..."),
    }
}
