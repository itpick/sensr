//! A small, borrowed model of the libnftables JSON schema (`libnftables-json(5)`)
//! and a streaming writer for it.
//!
//! Each command is serialised straight into the output as soon as it is
//! built, so peak memory is the output buffer plus one rule — never a DOM of
//! the whole ruleset (07-performance-evaluation: 337 MiB → 10 MiB at 10k
//! rules came from exactly this).

use std::borrow::Cow;
use std::io;
use std::net::IpAddr;

use serde::Serialize;
use serde::ser::{SerializeMap, SerializeSeq, Serializer};

/// An nft expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr<'a> {
    /// string literal (interface name, keyword, `@set` reference)
    Str(Cow<'a, str>),
    /// number
    Num(u32),
    /// address literal
    Ip(IpAddr),
    /// `addr/len`
    Prefix(IpAddr, u8),
    /// `lo-hi`
    Range(Box<Expr<'a>>, Box<Expr<'a>>),
    /// anonymous set `{ a, b }`
    Set(Vec<Expr<'a>>),
    /// concatenation `a . b`
    Concat(Vec<Expr<'a>>),
    /// `<protocol> <field>` header payload
    Payload(&'static str, &'static str),
    /// `meta <key>`
    Meta(&'static str),
    /// `ct <key>`
    Ct(&'static str),
    /// `fib <flags> <result>`
    Fib(&'static [&'static str], &'static str),
    /// bitwise and `a & b`
    And(Box<Expr<'a>>, Box<Expr<'a>>),
    /// bitwise or `a | b`
    Or(Box<Expr<'a>>, Box<Expr<'a>>),
    /// flag list `a | b | c` (as nft prints it)
    Flags(Vec<&'static str>),
    /// `numgen inc mod <n>`
    NumgenInc(u32),
    /// anonymous map lookup `<key> map { k : v, … }`
    Map(Box<Expr<'a>>, Vec<(Expr<'a>, Expr<'a>)>),
}

impl<'a> Expr<'a> {
    /// Borrowed string.
    pub fn s(v: &'a str) -> Expr<'a> {
        Expr::Str(Cow::Borrowed(v))
    }

    /// `@name` set reference.
    pub fn set_ref(name: &str) -> Expr<'static> {
        Expr::Str(Cow::Owned(format!("@{name}")))
    }
}

impl Serialize for Expr<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Expr::Str(v) => s.serialize_str(v),
            Expr::Num(n) => s.serialize_u32(*n),
            Expr::Ip(ip) => s.collect_str(ip),
            Expr::Prefix(addr, len) => {
                let mut m = s.serialize_map(Some(1))?;
                m.serialize_entry("prefix", &PrefixBody(addr, *len))?;
                m.end()
            }
            Expr::Range(a, b) => one("range", &[&**a, &**b], s),
            Expr::Set(items) => one("set", items, s),
            Expr::Concat(items) => one("concat", items, s),
            Expr::Payload(protocol, field) => one(
                "payload",
                &Kv(&[("protocol", protocol), ("field", field)]),
                s,
            ),
            Expr::Meta(key) => one("meta", &Kv(&[("key", key)]), s),
            Expr::Ct(key) => one("ct", &Kv(&[("key", key)]), s),
            Expr::Fib(flags, result) => one("fib", &FibBody(flags, result), s),
            Expr::And(a, b) => one("&", &[&**a, &**b], s),
            Expr::Or(a, b) => one("|", &[&**a, &**b], s),
            Expr::Flags(f) => {
                if f.len() == 1 {
                    s.serialize_str(f[0])
                } else {
                    s.collect_seq(f)
                }
            }
            Expr::NumgenInc(m) => one("numgen", &NumgenBody(*m), s),
            Expr::Map(key, data) => one("map", &MapBody(key, data), s),
        }
    }
}

fn one<S: Serializer, T: Serialize + ?Sized>(key: &str, v: &T, s: S) -> Result<S::Ok, S::Error> {
    let mut m = s.serialize_map(Some(1))?;
    m.serialize_entry(key, v)?;
    m.end()
}

struct NumgenBody(u32);
impl Serialize for NumgenBody {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(3))?;
        m.serialize_entry("mode", "inc")?;
        m.serialize_entry("mod", &self.0)?;
        m.serialize_entry("offset", &0)?;
        m.end()
    }
}

struct MapBody<'a, 'b>(&'b Expr<'a>, &'b [(Expr<'a>, Expr<'a>)]);
impl Serialize for MapBody<'_, '_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(2))?;
        m.serialize_entry("key", self.0)?;
        m.serialize_entry("data", &ExprPairs(self.1))?;
        m.end()
    }
}

struct ExprPairs<'a, 'b>(&'b [(Expr<'a>, Expr<'a>)]);
impl Serialize for ExprPairs<'_, '_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        one("set", &PairList(self.0), s)
    }
}
struct PairList<'a, 'b>(&'b [(Expr<'a>, Expr<'a>)]);
impl Serialize for PairList<'_, '_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for (k, v) in self.0 {
            seq.serialize_element(&(k, v))?;
        }
        seq.end()
    }
}

struct PrefixBody<'a>(&'a IpAddr, u8);
impl Serialize for PrefixBody<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(2))?;
        m.serialize_entry("addr", &self.0.to_string())?;
        m.serialize_entry("len", &self.1)?;
        m.end()
    }
}

struct Kv<'a>(&'a [(&'static str, &'a &'static str)]);
impl Serialize for Kv<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in self.0 {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

struct FibBody<'a>(&'a [&'static str], &'a &'static str);
impl Serialize for FibBody<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(2))?;
        m.serialize_entry("result", self.1)?;
        m.serialize_entry("flags", self.0)?;
        m.end()
    }
}

/// A verdict.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Verdict<'a> {
    /// `accept`
    Accept,
    /// `drop`
    Drop,
    /// `return`
    Return,
    /// `jump <chain>`
    Jump(Cow<'a, str>),
    /// `goto <chain>`
    Goto(Cow<'a, str>),
}

impl Serialize for Verdict<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(1))?;
        verdict_entry(&mut m, self)?;
        m.end()
    }
}

fn verdict_entry<M: SerializeMap>(m: &mut M, v: &Verdict<'_>) -> Result<(), M::Error> {
    match v {
        Verdict::Accept => m.serialize_entry("accept", &()),
        Verdict::Drop => m.serialize_entry("drop", &()),
        Verdict::Return => m.serialize_entry("return", &()),
        Verdict::Jump(t) => m.serialize_entry("jump", &Target(t)),
        Verdict::Goto(t) => m.serialize_entry("goto", &Target(t)),
    }
}

struct Target<'a>(&'a str);
impl Serialize for Target<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        one("target", self.0, s)
    }
}

/// NAT statement arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nat<'a> {
    /// `ip` / `ip6` when the table is `inet`
    pub family: Option<&'static str>,
    /// translated address
    pub addr: Option<Expr<'a>>,
    /// translated port
    pub port: Option<Expr<'a>>,
    /// nat flags (`persistent`, `random`, …)
    pub flags: Vec<&'static str>,
}

impl Serialize for Nat<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        if let Some(f) = self.family {
            m.serialize_entry("family", f)?;
        }
        if let Some(a) = &self.addr {
            m.serialize_entry("addr", a)?;
        }
        if let Some(p) = &self.port {
            m.serialize_entry("port", p)?;
        }
        if !self.flags.is_empty() {
            m.serialize_entry("flags", &self.flags)?;
        }
        m.end()
    }
}

/// An nft statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stmt<'a> {
    /// `left <op> right`
    Match {
        /// `==`, `!=`, `in`
        op: &'static str,
        /// tested expression
        left: Expr<'a>,
        /// value
        right: Expr<'a>,
    },
    /// anonymous counter
    Counter,
    /// verdict
    Verdict(Verdict<'a>),
    /// `reject` (`with tcp reset` when `tcp_reset`)
    Reject {
        /// send a TCP RST instead of ICMP unreachable
        tcp_reset: bool,
    },
    /// `log [prefix …] [group …]`
    Log {
        /// log prefix
        prefix: Cow<'a, str>,
        /// nflog group
        group: Option<u16>,
    },
    /// `<key> vmap { k : v, … }` with an anonymous map
    Vmap {
        /// lookup key
        key: Expr<'a>,
        /// `(key, verdict)` pairs
        data: Vec<(Expr<'a>, Verdict<'a>)>,
    },
    /// `masquerade`
    Masquerade(Nat<'a>),
    /// `snat to …`
    Snat(Nat<'a>),
    /// `dnat to …`
    Dnat(Nat<'a>),
    /// `flow add @<flowtable>`
    FlowAdd(Cow<'a, str>),
    /// `ct mark set ct mark | <bits>`
    CtMarkOr(u32),
}

impl Serialize for Stmt<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(1))?;
        match self {
            Stmt::Match { op, left, right } => {
                m.serialize_entry("match", &MatchBody { op, left, right })?
            }
            Stmt::Counter => m.serialize_entry("counter", &())?,
            Stmt::Verdict(v) => verdict_entry(&mut m, v)?,
            Stmt::Reject { tcp_reset: true } => {
                m.serialize_entry("reject", &Kv(&[("type", &"tcp reset")]))?
            }
            Stmt::Reject { tcp_reset: false } => m.serialize_entry("reject", &())?,
            Stmt::Log { prefix, group } => m.serialize_entry("log", &LogBody(prefix, *group))?,
            Stmt::Vmap { key, data } => m.serialize_entry("vmap", &VmapBody(key, data))?,
            Stmt::Masquerade(n) => {
                if n.addr.is_none() && n.port.is_none() && n.flags.is_empty() {
                    m.serialize_entry("masquerade", &())?
                } else {
                    m.serialize_entry("masquerade", n)?
                }
            }
            Stmt::Snat(n) => m.serialize_entry("snat", n)?,
            Stmt::Dnat(n) => m.serialize_entry("dnat", n)?,
            Stmt::FlowAdd(ft) => m.serialize_entry("flow", &FlowBody(ft))?,
            Stmt::CtMarkOr(bits) => m.serialize_entry("mangle", &CtMarkBody(*bits))?,
        }
        m.end()
    }
}

struct MatchBody<'a, 'b> {
    op: &'b str,
    left: &'b Expr<'a>,
    right: &'b Expr<'a>,
}
impl Serialize for MatchBody<'_, '_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(3))?;
        m.serialize_entry("op", self.op)?;
        m.serialize_entry("left", self.left)?;
        m.serialize_entry("right", self.right)?;
        m.end()
    }
}

struct LogBody<'a>(&'a str, Option<u16>);
impl Serialize for LogBody<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("prefix", self.0)?;
        if let Some(g) = self.1 {
            m.serialize_entry("group", &g)?;
        }
        m.end()
    }
}

struct VmapBody<'a, 'b>(&'b Expr<'a>, &'b [(Expr<'a>, Verdict<'a>)]);
impl Serialize for VmapBody<'_, '_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(2))?;
        m.serialize_entry("key", self.0)?;
        m.serialize_entry("data", &SetOfPairs(self.1))?;
        m.end()
    }
}

struct SetOfPairs<'a, 'b>(&'b [(Expr<'a>, Verdict<'a>)]);
impl Serialize for SetOfPairs<'_, '_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        one("set", &Pairs(self.0), s)
    }
}
struct Pairs<'a, 'b>(&'b [(Expr<'a>, Verdict<'a>)]);
impl Serialize for Pairs<'_, '_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for (k, v) in self.0 {
            seq.serialize_element(&(k, v))?;
        }
        seq.end()
    }
}

struct FlowBody<'a>(&'a str);
impl Serialize for FlowBody<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(2))?;
        m.serialize_entry("op", "add")?;
        m.serialize_entry("flowtable", &format!("@{}", self.0))?;
        m.end()
    }
}

struct CtMarkBody(u32);
impl Serialize for CtMarkBody {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mark = Expr::Ct("mark");
        let mut m = s.serialize_map(Some(2))?;
        m.serialize_entry("key", &mark)?;
        m.serialize_entry(
            "value",
            &Expr::Or(Box::new(mark.clone()), Box::new(Expr::Num(self.0))),
        )?;
        m.end()
    }
}

/// Element type of a named set (`type a . b`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetType(pub Vec<&'static str>);

impl Serialize for SetType {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.0.len() == 1 {
            s.serialize_str(self.0[0])
        } else {
            s.collect_seq(&self.0)
        }
    }
}

/// A base-chain hook.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hook {
    /// `filter` / `nat`
    pub kind: &'static str,
    /// `input`, `forward`, `output`, `prerouting`, `postrouting`
    pub hook: &'static str,
    /// priority
    pub prio: i32,
    /// `accept` / `drop`
    pub policy: &'static str,
}

/// Top-level objects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Object<'a> {
    /// a table
    Table,
    /// a chain, base chain when `hook` is set
    Chain {
        /// chain name
        name: Cow<'a, str>,
        /// base chain hook
        hook: Option<Hook>,
    },
    /// a rule
    Rule {
        /// chain name
        chain: Cow<'a, str>,
        /// statements
        expr: Vec<Stmt<'a>>,
        /// rule comment (the label)
        comment: Option<Cow<'a, str>>,
    },
    /// a named set
    Set {
        /// set name
        name: Cow<'a, str>,
        /// element type
        ty: SetType,
        /// `interval` flag
        interval: bool,
        /// initial elements
        elem: Vec<Expr<'a>>,
    },
    /// a named set by name only (for `flush`)
    SetName(Cow<'a, str>),
    /// elements of a named set
    Element {
        /// set name
        name: Cow<'a, str>,
        /// elements
        elem: Vec<Expr<'a>>,
    },
    /// a flowtable on ingress
    Flowtable {
        /// flowtable name
        name: Cow<'a, str>,
        /// devices to offload between
        devices: Vec<Cow<'a, str>>,
    },
}

/// A command for one table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command<'a> {
    /// `add`
    Add(Object<'a>),
    /// `delete`
    Delete(Object<'a>),
    /// `flush`
    Flush(Object<'a>),
}

/// Serialises commands against one table.
pub struct Scoped<'a, 'b> {
    /// table family
    pub family: &'b str,
    /// table name
    pub table: &'b str,
    /// the command
    pub cmd: &'b Command<'a>,
}

impl Serialize for Scoped<'_, '_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let (verb, obj) = match self.cmd {
            Command::Add(o) => ("add", o),
            Command::Delete(o) => ("delete", o),
            Command::Flush(o) => ("flush", o),
        };
        let body = ObjBody {
            family: self.family,
            table: self.table,
            obj,
        };
        let mut m = s.serialize_map(Some(1))?;
        m.serialize_entry(verb, &body)?;
        m.end()
    }
}

struct ObjBody<'a, 'b> {
    family: &'b str,
    table: &'b str,
    obj: &'b Object<'a>,
}

impl Serialize for ObjBody<'_, '_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let kind = match self.obj {
            Object::Table => "table",
            Object::Chain { .. } => "chain",
            Object::Rule { .. } => "rule",
            Object::Set { .. } | Object::SetName(_) => "set",
            Object::Element { .. } => "element",
            Object::Flowtable { .. } => "flowtable",
        };
        let mut m = s.serialize_map(Some(1))?;
        m.serialize_entry(kind, &ObjInner(self))?;
        m.end()
    }
}

struct ObjInner<'a, 'b, 'c>(&'c ObjBody<'a, 'b>);
impl Serialize for ObjInner<'_, '_, '_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let b = self.0;
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("family", b.family)?;
        match b.obj {
            Object::Table => m.serialize_entry("name", b.table)?,
            Object::Chain { name, hook } => {
                m.serialize_entry("table", b.table)?;
                m.serialize_entry("name", name)?;
                if let Some(h) = hook {
                    m.serialize_entry("type", h.kind)?;
                    m.serialize_entry("hook", h.hook)?;
                    m.serialize_entry("prio", &h.prio)?;
                    m.serialize_entry("policy", h.policy)?;
                }
            }
            Object::Rule {
                chain,
                expr,
                comment,
            } => {
                m.serialize_entry("table", b.table)?;
                m.serialize_entry("chain", chain)?;
                m.serialize_entry("expr", expr)?;
                if let Some(c) = comment {
                    m.serialize_entry("comment", c)?;
                }
            }
            Object::Set {
                name,
                ty,
                interval,
                elem,
            } => {
                m.serialize_entry("table", b.table)?;
                m.serialize_entry("name", name)?;
                m.serialize_entry("type", ty)?;
                if *interval {
                    m.serialize_entry("flags", &["interval"])?;
                    m.serialize_entry("auto-merge", &true)?;
                }
                if !elem.is_empty() {
                    m.serialize_entry("elem", elem)?;
                }
            }
            Object::SetName(name) => {
                m.serialize_entry("table", b.table)?;
                m.serialize_entry("name", name)?;
            }
            Object::Element { name, elem } => {
                m.serialize_entry("table", b.table)?;
                m.serialize_entry("name", name)?;
                m.serialize_entry("elem", elem)?;
            }
            Object::Flowtable { name, devices } => {
                m.serialize_entry("table", b.table)?;
                m.serialize_entry("name", name)?;
                m.serialize_entry("hook", "ingress")?;
                m.serialize_entry("prio", &0)?;
                m.serialize_entry("dev", devices)?;
            }
        }
        m.end()
    }
}

/// Streams a `{"nftables":[…]}` document command by command.
pub struct Writer<'w, W: io::Write> {
    out: &'w mut W,
    family: &'static str,
    table: String,
    first: bool,
}

impl<'w, W: io::Write> Writer<'w, W> {
    /// Starts the document.
    pub fn new(out: &'w mut W, family: &'static str, table: &str) -> io::Result<Self> {
        out.write_all(br#"{"nftables":[{"metainfo":{"json_schema_version":1}}"#)?;
        Ok(Writer {
            out,
            family,
            table: table.to_owned(),
            first: false,
        })
    }

    /// Writes one command.
    pub fn cmd(&mut self, cmd: &Command<'_>) -> io::Result<()> {
        if !self.first {
            self.out.write_all(b",")?;
        }
        self.first = false;
        let scoped = Scoped {
            family: self.family,
            table: &self.table,
            cmd,
        };
        serde_json::to_writer(&mut *self.out, &scoped).map_err(io::Error::other)
    }

    /// Shorthand for `add`.
    pub fn add(&mut self, obj: Object<'_>) -> io::Result<()> {
        self.cmd(&Command::Add(obj))
    }

    /// Ends the document.
    pub fn finish(self) -> io::Result<()> {
        self.out.write_all(b"]}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statements_serialise_like_nft_json() {
        let st = vec![
            Stmt::Match {
                op: "==",
                left: Expr::Meta("l4proto"),
                right: Expr::Set(vec![Expr::s("tcp"), Expr::s("udp")]),
            },
            Stmt::Counter,
            Stmt::Verdict(Verdict::Goto("x".into())),
            Stmt::Reject { tcp_reset: true },
        ];
        assert_eq!(
            serde_json::to_string(&st).unwrap(),
            r#"[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":{"set":["tcp","udp"]}}},{"counter":null},{"goto":{"target":"x"}},{"reject":{"type":"tcp reset"}}]"#
        );
    }

    #[test]
    fn writer_streams_a_document() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf, "inet", "sensr").unwrap();
        w.add(Object::Table).unwrap();
        w.finish().unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            r#"{"nftables":[{"metainfo":{"json_schema_version":1}},{"add":{"table":{"family":"inet","name":"sensr"}}}]}"#
        );
    }
}
