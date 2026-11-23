//! The accounting table (`inet sensr_flow`) and the parser of its listing.
//!
//! Sets are named `<kind><dir><family>`: kind `h` (local host), `a` (local
//! host . protocol . service port), `r` (remote address), `p` (local host .
//! remote address, for per-host service attribution); dir `u` (in from a
//! local interface: the local host's upload) or `d` (out to one: its
//! download); family `4` or `6`. The service port is the connection's
//! original destination port (`ct original proto-dst`), the same for both
//! directions of a connection, so replies count toward the service.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::de::DeserializeSeed;
use serde_json::{Value, json};

use crate::config::FlowConfig;

/// The table.
pub const TABLE: &str = "sensr_flow";
/// Forward-hook priority: after the filter (0) and the IDS queue (10, 11),
/// so dropped packets are not counted.
pub const PRIORITY: i32 = 20;
/// Idle elements expire after this many seconds (re-created, from zero,
/// when the host or service is seen again).
pub const ELEMENT_TIMEOUT: u32 = 3600;

/// What a set counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// A local host.
    Host,
    /// A local host's service (protocol, port).
    App,
    /// A remote address.
    Remote,
    /// A local host and a remote address it talks to.
    Pair,
}

/// Direction from the local host's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Dir {
    /// Sent by the local host.
    Up,
    /// Received by it.
    Down,
}

const KINDS: [(Kind, char); 4] = [
    (Kind::Host, 'h'),
    (Kind::App, 'a'),
    (Kind::Remote, 'r'),
    (Kind::Pair, 'p'),
];
const DIRS: [(Dir, char); 2] = [(Dir::Up, 'u'), (Dir::Down, 'd')];
const FAMILIES: [(&str, char, &str); 2] = [("ip", '4', "ipv4_addr"), ("ip6", '6', "ipv6_addr")];

fn set_name(k: char, d: char, f: char) -> String {
    format!("{k}{d}{f}")
}

/// The accounting table for `cfg` (replaces any previous one, which resets
/// the counters; the reader treats a counter that went down as new).
pub fn ruleset(cfg: &FlowConfig) -> String {
    let local: Vec<&str> = cfg
        .interfaces
        .iter()
        .filter(|i| i.local)
        .map(|i| i.device.as_str())
        .collect();
    let table = json!({ "table": { "family": "inet", "name": TABLE } });
    let mut cmds = vec![
        json!({ "add": table.clone() }),
        json!({ "delete": table.clone() }),
        json!({ "add": table }),
        json!({ "add": { "chain": {
            "family": "inet", "table": TABLE, "name": "account", "type": "filter",
            "hook": "forward", "prio": PRIORITY, "policy": "accept" } } }),
    ];
    for (proto, f, addr) in FAMILIES {
        for (_, k) in KINDS {
            for (_, d) in DIRS {
                let ty: Value = match k {
                    'a' => json!([addr, "inet_proto", "inet_service"]),
                    'p' => json!([addr, addr]),
                    _ => json!(addr),
                };
                cmds.push(json!({ "add": { "set": {
                    "family": "inet", "table": TABLE, "name": set_name(k, d, f),
                    "type": ty, "size": cfg.max_entries,
                    "flags": ["dynamic", "timeout"], "timeout": ELEMENT_TIMEOUT,
                    "stmt": [{ "counter": null }] } } }));
            }
        }
        if local.is_empty() {
            continue;
        }
        let field = |name: &str| json!({ "payload": { "protocol": proto, "field": name } });
        for (dir, d) in DIRS {
            let (meta, own, other) = match dir {
                Dir::Up => ("iifname", "saddr", "daddr"),
                Dir::Down => ("oifname", "daddr", "saddr"),
            };
            let on_local = json!({ "match": { "op": "==",
                "left": { "meta": { "key": meta } }, "right": { "set": local } } });
            // the family test is implicit in the payload match on `inet`
            let update = |set: String, elem: Value| json!({ "set": { "op": "update", "elem": elem, "set": format!("@{set}") } });
            let rule = |expr: Vec<Value>| {
                json!({ "add": { "rule": {
                    "family": "inet", "table": TABLE, "chain": "account", "expr": expr } } })
            };
            cmds.push(rule(vec![
                on_local.clone(),
                update(set_name('h', d, f), field(own)),
                update(set_name('r', d, f), field(other)),
                update(
                    set_name('p', d, f),
                    json!({ "concat": [field(own), field(other)] }),
                ),
            ]));
            cmds.push(rule(vec![
                on_local,
                json!({ "match": { "op": "==", "left": { "meta": { "key": "l4proto" } },
                    "right": { "set": ["tcp", "udp"] } } }),
                update(
                    set_name('a', d, f),
                    json!({ "concat": [
                        field(own),
                        { "meta": { "key": "l4proto" } },
                        { "ct": { "key": "proto-dst", "dir": "original" } }
                    ] }),
                ),
            ]));
        }
    }
    json!({ "nftables": cmds }).to_string()
}

/// Removes the table if present.
pub fn removal() -> String {
    let table = json!({ "table": { "family": "inet", "name": TABLE } });
    json!({ "nftables": [ { "add": table.clone() }, { "delete": table } ] }).to_string()
}

/// One counter as listed. Addresses are kept parsed (no heap per key): the
/// pair sets can hold tens of thousands of elements, listed every sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key {
    /// What it counts.
    pub kind: Kind,
    /// Which way.
    pub dir: Dir,
    /// The address (local host for `Host`/`App`/`Pair`, remote for `Remote`).
    pub addr: IpAddr,
    /// For `Pair`: the remote address.
    pub remote: Option<IpAddr>,
    /// For `App`: IP protocol number.
    pub proto: u8,
    /// For `App`: service port.
    pub port: u16,
}

impl Key {
    /// A key of a one-address set (`Host`, `Remote`).
    pub fn addr(kind: Kind, dir: Dir, addr: IpAddr) -> Key {
        Key {
            kind,
            dir,
            addr,
            remote: None,
            proto: 0,
            port: 0,
        }
    }
}

/// Packets and bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
pub struct Count {
    /// Packets.
    #[serde(default)]
    pub packets: u64,
    /// Bytes.
    #[serde(default)]
    pub bytes: u64,
}

fn proto_word(s: &str) -> Option<u8> {
    match s {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "ipv6-icmp" | "icmpv6" => Some(58),
        "sctp" => Some(132),
        _ => None,
    }
}

/// Parses `nft -j list table inet sensr_flow` into counters. Unknown sets
/// and malformed elements are skipped; a listing that is not JSON gives an
/// empty map ([`parse_reader`] tells the two apart).
pub fn parse(listing: &[u8]) -> HashMap<Key, Count> {
    let mut out = HashMap::new();
    let mut de = serde_json::Deserializer::from_slice(listing);
    if listing::Listing(&mut out).deserialize(&mut de).is_err() {
        out.clear();
    }
    out
}

/// Like [`parse`], streaming from `r` (the `nft` pipe) so the listing itself
/// is never held in memory, only the counters. An error means the listing
/// was cut short or damaged and nothing should be made of it.
pub fn parse_reader(r: impl std::io::Read) -> serde_json::Result<HashMap<Key, Count>> {
    let mut out = HashMap::new();
    let mut de = serde_json::Deserializer::from_reader(r);
    listing::Listing(&mut out).deserialize(&mut de)?;
    de.end()?;
    Ok(out)
}

/// The typed, streaming reader of a listing: visitors that go from JSON
/// tokens straight to [`Key`]s, with no `serde_json::Value` tree and no heap
/// allocation per element (measured: `cost::listing_cost`).
mod listing {
    use std::collections::HashMap;
    use std::fmt;
    use std::net::IpAddr;

    use serde::Deserialize;
    use serde::de::{
        DeserializeSeed, Deserializer, Error, IgnoredAny, MapAccess, SeqAccess, Visitor,
    };

    use super::{Count, DIRS, Dir, KINDS, Key, Kind, proto_word};

    #[derive(Deserialize)]
    #[serde(field_identifier, rename_all = "lowercase")]
    enum Field {
        Nftables,
        Set,
        Name,
        Elem,
        Val,
        Concat,
        Counter,
        #[serde(other)]
        Other,
    }

    /// One part of an element's value.
    #[derive(Debug, Clone, Copy, Default)]
    enum Part {
        Addr(IpAddr),
        Num(u64),
        #[default]
        Bad,
    }

    impl Part {
        fn of_str(s: &str) -> Part {
            if let Ok(a) = s.parse() {
                Part::Addr(a)
            } else if let Some(p) = proto_word(s) {
                Part::Num(u64::from(p))
            } else {
                s.parse().map_or(Part::Bad, Part::Num)
            }
        }
    }

    /// An element value: one part, or a concatenation (at most three parts
    /// are kept; `n` counts them all, so a longer one is malformed).
    #[derive(Debug, Clone, Copy, Default)]
    struct Val {
        parts: [Part; 3],
        n: usize,
    }

    impl Val {
        fn one(p: Part) -> Val {
            Val {
                parts: [p, Part::Bad, Part::Bad],
                n: 1,
            }
        }

        fn key(self, kind: Kind, dir: Dir) -> Option<Key> {
            let addr = |i: usize| match self.parts.get(i) {
                Some(Part::Addr(a)) => Some(*a),
                _ => None,
            };
            let num = |i: usize| match self.parts.get(i) {
                Some(Part::Num(n)) => Some(*n),
                _ => None,
            };
            let mut k = Key::addr(kind, dir, addr(0)?);
            match (kind, self.n) {
                (Kind::Host | Kind::Remote, 1) => {}
                (Kind::App, 3) => {
                    k.proto = u8::try_from(num(1)?).ok()?;
                    k.port = u16::try_from(num(2)?).ok()?;
                }
                (Kind::Pair, 2) => k.remote = Some(addr(1)?),
                _ => return None,
            }
            Some(k)
        }
    }

    fn drain_map<'de, A: MapAccess<'de>>(mut m: A) -> Result<(), A::Error> {
        while m.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(())
    }

    fn drain_seq<'de, A: SeqAccess<'de>>(mut s: A) -> Result<(), A::Error> {
        while s.next_element::<IgnoredAny>()?.is_some() {}
        Ok(())
    }

    /// Visits any JSON value as a [`Part`] (non-scalars are consumed as
    /// `Bad`), handing it to `$wrap`.
    macro_rules! scalar_visits {
        ($out:ty, $wrap:expr) => {
            fn visit_str<E: Error>(self, s: &str) -> Result<$out, E> {
                Ok($wrap(Part::of_str(s)))
            }
            fn visit_u64<E: Error>(self, v: u64) -> Result<$out, E> {
                Ok($wrap(Part::Num(v)))
            }
            fn visit_i64<E: Error>(self, v: i64) -> Result<$out, E> {
                Ok($wrap(u64::try_from(v).map_or(Part::Bad, Part::Num)))
            }
            fn visit_f64<E: Error>(self, _: f64) -> Result<$out, E> {
                Ok($wrap(Part::Bad))
            }
            fn visit_bool<E: Error>(self, _: bool) -> Result<$out, E> {
                Ok($wrap(Part::Bad))
            }
            fn visit_unit<E: Error>(self) -> Result<$out, E> {
                Ok($wrap(Part::Bad))
            }
        };
    }

    impl<'de> Deserialize<'de> for Part {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Part, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Part;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("an element part")
                }
                scalar_visits!(Part, |p| p);
                fn visit_map<A: MapAccess<'de>>(self, m: A) -> Result<Part, A::Error> {
                    drain_map(m).map(|()| Part::Bad)
                }
                fn visit_seq<A: SeqAccess<'de>>(self, s: A) -> Result<Part, A::Error> {
                    drain_seq(s).map(|()| Part::Bad)
                }
            }
            d.deserialize_any(V)
        }
    }

    /// `[part, …]` (a concatenation) or anything else (malformed: `n` 0).
    struct Concat(Val);

    impl<'de> Deserialize<'de> for Concat {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Concat, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Concat;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("a concatenation")
                }
                scalar_visits!(Concat, |_| Concat(Val::default()));
                fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Concat, A::Error> {
                    let mut v = Val::default();
                    while let Some(p) = s.next_element::<Part>()? {
                        if let Some(slot) = v.parts.get_mut(v.n) {
                            *slot = p;
                        }
                        v.n = v.n.saturating_add(1);
                    }
                    Ok(Concat(v))
                }
                fn visit_map<A: MapAccess<'de>>(self, m: A) -> Result<Concat, A::Error> {
                    drain_map(m).map(|()| Concat(Val::default()))
                }
            }
            d.deserialize_any(V)
        }
    }

    impl<'de> Deserialize<'de> for Val {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Val, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Val;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("an element value")
                }
                scalar_visits!(Val, Val::one);
                fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Val, A::Error> {
                    let mut v = Val::default();
                    while let Some(f) = m.next_key::<Field>()? {
                        if matches!(f, Field::Concat) {
                            v = m.next_value::<Concat>()?.0;
                        } else {
                            m.next_value::<IgnoredAny>()?;
                        }
                    }
                    Ok(v)
                }
                fn visit_seq<A: SeqAccess<'de>>(self, s: A) -> Result<Val, A::Error> {
                    drain_seq(s).map(|()| Val::default())
                }
            }
            d.deserialize_any(V)
        }
    }

    /// One entry of a set's `elem` array: `{"elem": {"val": …, "counter":
    /// …}}` for sets with counters; a bare value otherwise (no counter, so
    /// `None`).
    struct Entry(Option<(Val, Count)>);

    impl<'de> Deserialize<'de> for Entry {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Entry, D::Error> {
            struct Body(Option<(Val, Count)>);
            impl<'de> Deserialize<'de> for Body {
                fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Body, D::Error> {
                    struct V;
                    impl<'de> Visitor<'de> for V {
                        type Value = Body;
                        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                            f.write_str("an element")
                        }
                        scalar_visits!(Body, |_| Body(None));
                        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Body, A::Error> {
                            let (mut val, mut count) = (None, None);
                            while let Some(f) = m.next_key::<Field>()? {
                                match f {
                                    Field::Val => val = Some(m.next_value::<Val>()?),
                                    Field::Counter => count = m.next_value::<Option<Count>>()?,
                                    _ => {
                                        m.next_value::<IgnoredAny>()?;
                                    }
                                }
                            }
                            Ok(Body(val.zip(count)))
                        }
                        fn visit_seq<A: SeqAccess<'de>>(self, s: A) -> Result<Body, A::Error> {
                            drain_seq(s).map(|()| Body(None))
                        }
                    }
                    d.deserialize_any(V)
                }
            }
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Entry;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("a set element")
                }
                scalar_visits!(Entry, |_| Entry(None));
                fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Entry, A::Error> {
                    let mut e = Entry(None);
                    while let Some(f) = m.next_key::<Field>()? {
                        if matches!(f, Field::Elem) {
                            e = Entry(m.next_value::<Body>()?.0);
                        } else {
                            m.next_value::<IgnoredAny>()?;
                        }
                    }
                    Ok(e)
                }
                fn visit_seq<A: SeqAccess<'de>>(self, s: A) -> Result<Entry, A::Error> {
                    drain_seq(s).map(|()| Entry(None))
                }
            }
            d.deserialize_any(V)
        }
    }

    fn kind_dir(name: &str) -> Option<(Kind, Dir)> {
        let mut c = name.chars();
        let (Some(k), Some(d), Some(_f), None) = (c.next(), c.next(), c.next(), c.next()) else {
            return None;
        };
        let kind = KINDS.iter().find(|x| x.1 == k)?.0;
        let dir = DIRS.iter().find(|x| x.1 == d)?.0;
        Some((kind, dir))
    }

    /// A set's `elem` array. Entries go straight into the map when the set's
    /// name was already read (nft lists `name` first), else are held until
    /// the set's end.
    struct Elems<'a> {
        kd: Option<(Kind, Dir)>,
        out: &'a mut HashMap<Key, Count>,
        held: &'a mut Vec<(Val, Count)>,
    }

    impl<'de> DeserializeSeed<'de> for Elems<'_> {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_any(self)
        }
    }

    impl<'de> Visitor<'de> for Elems<'_> {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("set elements")
        }
        scalar_visits!((), |_| ());
        fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<(), A::Error> {
            while let Some(Entry(e)) = s.next_element::<Entry>()? {
                let Some((val, count)) = e else { continue };
                match self.kd {
                    Some((kind, dir)) => {
                        if let Some(k) = val.key(kind, dir) {
                            self.out.insert(k, count);
                        }
                    }
                    None => self.held.push((val, count)),
                }
            }
            Ok(())
        }
        fn visit_map<A: MapAccess<'de>>(self, m: A) -> Result<(), A::Error> {
            drain_map(m)
        }
    }

    /// One `{"set": {…}}` body.
    struct Set<'a>(&'a mut HashMap<Key, Count>);

    impl<'de> DeserializeSeed<'de> for Set<'_> {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_map(self)
        }
    }

    impl<'de> Visitor<'de> for Set<'_> {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a set")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<(), A::Error> {
            let mut kd = None;
            let mut named = false;
            let mut held = Vec::new();
            while let Some(f) = m.next_key::<Field>()? {
                match f {
                    Field::Name => {
                        let name = m.next_value::<std::borrow::Cow<'_, str>>()?;
                        kd = kind_dir(&name);
                        named = true;
                    }
                    // a set we do not know (by name) is skipped
                    Field::Elem if named && kd.is_none() => {
                        m.next_value::<IgnoredAny>()?;
                    }
                    Field::Elem => m.next_value_seed(Elems {
                        kd,
                        out: self.0,
                        held: &mut held,
                    })?,
                    _ => {
                        m.next_value::<IgnoredAny>()?;
                    }
                }
            }
            if let Some((kind, dir)) = kd {
                for (val, count) in held {
                    if let Some(k) = val.key(kind, dir) {
                        self.0.insert(k, count);
                    }
                }
            }
            Ok(())
        }
    }

    /// One item of the `nftables` array; only `set` items matter.
    struct Item<'a>(&'a mut HashMap<Key, Count>);

    impl<'de> DeserializeSeed<'de> for Item<'_> {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_map(self)
        }
    }

    impl<'de> Visitor<'de> for Item<'_> {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a listing item")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<(), A::Error> {
            while let Some(f) = m.next_key::<Field>()? {
                if matches!(f, Field::Set) {
                    m.next_value_seed(Set(&mut *self.0))?;
                } else {
                    m.next_value::<IgnoredAny>()?;
                }
            }
            Ok(())
        }
    }

    struct Items<'a>(&'a mut HashMap<Key, Count>);

    impl<'de> DeserializeSeed<'de> for Items<'_> {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_seq(self)
        }
    }

    impl<'de> Visitor<'de> for Items<'_> {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("the nftables array")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<(), A::Error> {
            while s.next_element_seed(Item(&mut *self.0))?.is_some() {}
            Ok(())
        }
    }

    /// The whole listing, `{"nftables": [...]}`.
    pub(super) struct Listing<'a>(pub(super) &'a mut HashMap<Key, Count>);

    impl<'de> DeserializeSeed<'de> for Listing<'_> {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_map(self)
        }
    }

    impl<'de> Visitor<'de> for Listing<'_> {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an nft listing")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<(), A::Error> {
            while let Some(f) = m.next_key::<Field>()? {
                if matches!(f, Field::Nftables) {
                    m.next_value_seed(Items(&mut *self.0))?;
                } else {
                    m.next_value::<IgnoredAny>()?;
                }
            }
            Ok(())
        }
    }
}

/// Turns successive listings into deltas. A counter that went down (the
/// table was reloaded, or the element expired and came back) counts from
/// zero; the first listing after start is only a baseline.
#[derive(Debug, Default)]
pub struct Deltas {
    last: Option<HashMap<Key, Count>>,
}

impl Deltas {
    /// The change since the previous call.
    pub fn next(&mut self, now: HashMap<Key, Count>) -> Vec<(Key, Count)> {
        let mut out = Vec::new();
        if let Some(prev) = &self.last {
            for (k, c) in &now {
                let d = match prev.get(k) {
                    Some(p) if c.bytes >= p.bytes && c.packets >= p.packets => Count {
                        packets: c.packets - p.packets,
                        bytes: c.bytes - p.bytes,
                    },
                    _ => *c,
                };
                if d.bytes > 0 || d.packets > 0 {
                    out.push((*k, d));
                }
            }
        }
        self.last = Some(now);
        out.sort_by_key(|a| a.0);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Iface, Retention};

    pub(crate) fn cfg() -> FlowConfig {
        FlowConfig {
            sample_seconds: 10,
            max_entries: 65536,
            interfaces: vec![
                Iface {
                    name: "wan".into(),
                    device: "igc0".into(),
                    local: false,
                },
                Iface {
                    name: "lan".into(),
                    device: "igc1".into(),
                    local: true,
                },
            ],
            retention: Retention::default(),
            dns: None,
        }
    }

    #[test]
    fn ruleset_has_sixteen_sets_and_eight_rules() {
        let v: Value = serde_json::from_str(&ruleset(&cfg())).unwrap();
        let cmds = v["nftables"].as_array().unwrap();
        let count = |what: &str| cmds.iter().filter(|c| c["add"].get(what).is_some()).count();
        assert_eq!(count("set"), 16);
        assert_eq!(count("rule"), 8);
        let text = v.to_string();
        assert!(text.contains(r#""right":{"set":["igc1"]}"#), "{text}");
        assert!(!text.contains("igc0"), "the WAN is not local");
        assert!(text.contains(r#""dir":"original""#));
    }

    #[test]
    fn pair_sets_rendered() {
        let v: Value = serde_json::from_str(&ruleset(&cfg())).unwrap();
        let cmds = v["nftables"].as_array().unwrap();
        for (f, addr) in [('4', "ipv4_addr"), ('6', "ipv6_addr")] {
            for d in ['u', 'd'] {
                let name = format!("p{d}{f}");
                let set = cmds
                    .iter()
                    .find_map(|c| c["add"].get("set").filter(|s| s["name"] == name.as_str()))
                    .unwrap_or_else(|| panic!("set {name}"));
                assert_eq!(set["type"], json!([addr, addr]), "{name}");
                assert_eq!(set["size"], 65536);
                assert_eq!(set["timeout"], ELEMENT_TIMEOUT);
                assert_eq!(set["flags"], json!(["dynamic", "timeout"]));
                assert_eq!(set["stmt"], json!([{ "counter": null }]));
            }
        }
        // the host rule updates the pair set with (local . remote)
        let proto = |p: &str, f: &str| json!({ "payload": { "protocol": p, "field": f } });
        for (p, f) in [("ip", '4'), ("ip6", '6')] {
            for (d, own, other) in [('u', "saddr", "daddr"), ('d', "daddr", "saddr")] {
                let want = json!({ "set": { "op": "update",
                    "elem": { "concat": [proto(p, own), proto(p, other)] },
                    "set": format!("@p{d}{f}") } });
                assert!(
                    cmds.iter().any(|c| c["add"]["rule"]["expr"]
                        .as_array()
                        .is_some_and(|e| e.contains(&want))),
                    "no pair update for p{d}{f}"
                );
            }
        }
    }

    #[test]
    fn pair_listing_parsed() {
        let listing = json!({"nftables": [
            {"metainfo": {"version": "1.1.7"}},
            {"set": {"family": "inet", "name": "pd4", "table": TABLE,
                "type": ["ipv4_addr", "ipv4_addr"],
                "elem": [
                    {"elem": {"val": {"concat": ["192.168.1.100", "142.250.1.1"]},
                        "expires": 3599, "counter": {"packets": 7, "bytes": 7000}}},
                    // malformed: one part only
                    {"elem": {"val": {"concat": ["192.168.1.100"]},
                        "counter": {"packets": 1, "bytes": 1}}},
                    // malformed: not a concatenation
                    {"elem": {"val": "192.168.1.100", "counter": {"packets": 1, "bytes": 1}}}
                ]}},
            {"set": {"family": "inet", "name": "pu6", "table": TABLE,
                "type": ["ipv6_addr", "ipv6_addr"],
                "elem": [{"elem": {"val": {"concat": ["fd00::10", "2001:db8::1"]},
                    "counter": {"packets": 2, "bytes": 150}}}]}}
        ]})
        .to_string();
        let m = parse(listing.as_bytes());
        assert_eq!(m.len(), 2, "{m:?}");
        let down = Key {
            kind: Kind::Pair,
            dir: Dir::Down,
            addr: "192.168.1.100".parse().unwrap(),
            remote: Some("142.250.1.1".parse().unwrap()),
            proto: 0,
            port: 0,
        };
        assert_eq!(m[&down].bytes, 7000);
        let up = m.keys().find(|k| k.dir == Dir::Up).unwrap();
        assert_eq!(
            (up.kind, up.addr, up.remote),
            (
                Kind::Pair,
                "fd00::10".parse().unwrap(),
                Some("2001:db8::1".parse().unwrap())
            )
        );
    }

    #[test]
    fn parses_listing_and_computes_deltas() {
        // the shape `nft -j list table` prints (nft 1.1.7)
        let listing = |bytes: u64| {
            json!({"nftables": [
                {"metainfo": {"version": "1.1.7"}},
                {"table": {"family": "inet", "name": TABLE}},
                {"set": {"family": "inet", "name": "hu4", "table": TABLE, "type": "ipv4_addr",
                    "elem": [{"elem": {"val": "192.168.1.100", "expires": 3599,
                        "counter": {"packets": 10, "bytes": bytes}}}]}},
                {"set": {"family": "inet", "name": "au4", "table": TABLE,
                    "type": ["ipv4_addr", "inet_proto", "inet_service"],
                    "elem": [{"elem": {"val": {"concat": ["192.168.1.100", "tcp", 443]},
                        "counter": {"packets": 3, "bytes": 300}}}]}},
                {"set": {"family": "inet", "name": "rd6", "table": TABLE, "type": "ipv6_addr",
                    "elem": [{"elem": {"val": "2001:db8::1", "counter": {"packets": 1, "bytes": 90}}}]}}
            ]})
            .to_string()
        };
        let m = parse(listing(1000).as_bytes());
        assert_eq!(m.len(), 3);
        let app = m.keys().find(|k| k.kind == Kind::App).unwrap();
        assert_eq!((app.proto, app.port, app.dir), (6, 443, Dir::Up));
        let mut d = Deltas::default();
        assert!(d.next(m).is_empty(), "first listing is a baseline");
        let m = parse(listing(1500).as_bytes());
        let delta = d.next(m);
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].1.bytes, 500);
        // reset (table reloaded): counts from zero
        let delta = d.next(parse(listing(200).as_bytes()));
        assert_eq!(delta[0].1.bytes, 200);
        assert!(parse(b"not json").is_empty());
    }
}

#[cfg(test)]
mod cost {
    use super::*;

    /// A listing with `n` elements in each of the four IPv4 pair/host sets.
    pub(crate) fn big_listing(n: usize) -> Vec<u8> {
        let mut s = String::from(
            r#"{"nftables":[{"metainfo":{"version":"1.1.7","release_name":"Commodore Bullmoose #8","json_schema_version":1}},{"table":{"family":"inet","name":"sensr_flow","handle":1}}"#,
        );
        for name in ["pu4", "pd4"] {
            s.push_str(&format!(r#",{{"set":{{"family":"inet","name":"{name}","table":"sensr_flow","type":["ipv4_addr","ipv4_addr"],"handle":3,"size":65536,"flags":["timeout","dynamic"],"timeout":3600,"stmt":[{{"counter":null}}],"elem":["#));
            for i in 0..n {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&format!(
                    r#"{{"elem":{{"val":{{"concat":["192.168.{}.{}","{}.{}.{}.{}"]}},"timeout":3600,"expires":{},"counter":{{"packets":{},"bytes":{}}}}}}}"#,
                    (i >> 8) & 3, i & 0xff, 11 + (i >> 16), (i >> 8) & 0xff, i & 0xff, (i * 7) & 0xff,
                    3000 + i % 600, i * 3, i * 1400
                ));
            }
            s.push_str("]}}");
        }
        s.push_str("]}");
        s.into_bytes()
    }

    /// Cost of one listing with large pair sets. `MODE`: `none` (only
    /// build the listing, for the baseline RSS), `slice`, `reader` (the
    /// daemon's path) or `value` (the old `serde_json::Value` parse).
    #[test]
    #[ignore = "measurement: PAIRS=65536 MODE=reader cargo test -p sensr-flow --release --lib listing_cost -- --ignored --nocapture"]
    fn listing_cost() {
        let n: usize = std::env::var("PAIRS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(65_536);
        let mode = std::env::var("MODE").unwrap_or_else(|_| "reader".into());
        let listing = big_listing(n);
        let t = std::time::Instant::now();
        let keys = match mode.as_str() {
            "none" => 0,
            "slice" => parse(&listing).len(),
            "value" => serde_json::from_slice::<Value>(&listing)
                .map(|v| v.to_string().len())
                .unwrap_or(0),
            _ => parse_reader(std::io::BufReader::new(&listing[..]))
                .unwrap()
                .len(),
        };
        println!(
            "{mode}: listing {} bytes, {} elements -> {keys} keys in {:?}",
            listing.len(),
            2 * n,
            t.elapsed()
        );
    }

    #[test]
    fn typed_parse_matches_every_element() {
        let listing = big_listing(1000);
        let m = parse(&listing);
        assert_eq!(m.len(), 2000);
        assert_eq!(parse_reader(&listing[..]).unwrap(), m);
        // cut short: an error, not a partial map
        assert!(parse_reader(&listing[..listing.len() / 2]).is_err());
        assert!(parse(&listing[..listing.len() / 2]).is_empty());
    }
}
