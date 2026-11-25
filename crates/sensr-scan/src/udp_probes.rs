//! UDP service probes: one request per service and a parser for its reply.
//!
//! Every payload and parser here was written by the sensr authors from the
//! protocol's RFC or public specification (named on each probe). Nothing is
//! taken from nmap's `nmap-service-probes` or `nmap-payloads`.
//!
//! Parsers take untrusted bytes: they never panic, return `None` for anything
//! that is not a reply of their protocol, and pass all text through
//! [`sanitize`].

use std::fmt::Write as _;
use std::net::Ipv4Addr;

use crate::types::{Ident, sanitize};

/// A service-specific UDP request and the parser for its reply.
#[derive(Debug, Clone, Copy)]
pub struct UdpProbe {
    pub port: u16,
    /// Short service name, unique within [`PROBES`].
    pub service: &'static str,
    pub payload: fn() -> Vec<u8>,
    /// `None` when the bytes are not a reply of this protocol.
    pub parse: fn(&[u8]) -> Option<Ident>,
}

macro_rules! probe {
    ($port:expr, $service:expr, $payload:path, $parse:path) => {
        UdpProbe {
            port: $port,
            service: $service,
            payload: $payload,
            parse: $parse,
        }
    };
}

/// The service probes, sent before the empty-datagram sweep, in this order.
pub static PROBES: &[UdpProbe] = &[
    probe!(53, "dns", dns_payload, dns_parse_version),
    probe!(123, "ntp", ntp_payload, ntp_parse),
    probe!(161, "snmp", snmp_payload, snmp_parse),
    probe!(1900, "ssdp", ssdp_payload, ssdp_parse),
    probe!(5353, "googlecast", googlecast_payload, googlecast_parse),
    probe!(5353, "mdns", mdns_payload, mdns_parse),
    probe!(137, "netbios-ns", nbns_payload, nbns_parse),
    probe!(67, "dhcp", dhcp_payload, dhcp_parse),
    probe!(69, "tftp", tftp_payload, tftp_parse),
    probe!(514, "syslog", syslog_payload, no_reply),
    probe!(500, "ike", ike_payload, ike_parse),
    probe!(4500, "ike-natt", ike_natt_payload, ike_natt_parse),
    probe!(3702, "ws-discovery", wsd_payload, wsd_parse),
    probe!(5683, "coap", coap_payload, coap_parse),
    probe!(1883, "mqtt-sn", mqttsn_payload, mqttsn_parse),
    probe!(11211, "memcached", memcached_payload, memcached_parse),
    probe!(520, "rip", rip_payload, rip_parse),
    probe!(5355, "llmnr", llmnr_payload, llmnr_parse),
    probe!(10001, "ubiquiti", ubnt_payload, ubnt_parse),
    probe!(5060, "sip", sip_payload, sip_parse),
    probe!(3478, "stun", stun_payload, stun_parse),
    probe!(111, "rpcbind", rpcbind_payload, rpcbind_parse),
    probe!(2049, "nfs", nfs_payload, nfs_parse),
    probe!(623, "ipmi", ipmi_payload, ipmi_parse),
    probe!(1194, "openvpn", openvpn_payload, openvpn_parse),
    probe!(443, "quic", quic_payload, quic_parse),
    probe!(1701, "l2tp", l2tp_payload, l2tp_parse),
    probe!(5351, "nat-pmp", natpmp_payload, natpmp_parse),
    probe!(427, "slp", slp_payload, slp_parse),
    probe!(1434, "mssql", mssql_payload, mssql_parse),
    probe!(47808, "bacnet", bacnet_payload, bacnet_parse),
    probe!(44818, "enip", enip_payload, enip_parse),
    probe!(5678, "mndp", mndp_payload, mndp_parse),
    probe!(32414, "plex", plex_payload, plex_parse),
    probe!(177, "xdmcp", xdmcp_payload, xdmcp_parse),
    probe!(7, "echo", echo_payload, echo_parse),
    probe!(13, "daytime", daytime_payload, daytime_parse),
    probe!(27015, "a2s", a2s_payload, a2s_parse),
    probe!(27960, "quake3", quake3_payload, quake3_parse),
    probe!(19132, "raknet", raknet_payload, raknet_parse),
];

/// The probes for `port`, in table order.
pub fn probes_for(port: u16) -> impl Iterator<Item = &'static UdpProbe> {
    PROBES.iter().filter(move |p| p.port == port)
}

/// Request id / transaction id used where a protocol has one ("se").
const ID: u16 = 0x7365;
/// 32-bit transaction id ("sens").
const XID: u32 = 0x7365_6e73;

// ---------------------------------------------------------------- helpers

fn text(b: &[u8]) -> Option<String> {
    let s = sanitize(b);
    (!s.is_empty()).then_some(s)
}

fn named(product: &str) -> Ident {
    Ident {
        product: text(product.as_bytes()),
        ..Ident::default()
    }
}

/// Bounds-checked big-endian reader.
#[derive(Debug, Clone)]
struct Rd<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Rd { b, at: 0 }
    }
    fn at(b: &'a [u8], at: usize) -> Self {
        Rd { b, at }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.b.get(self.at..end)?;
        self.at = end;
        Some(s)
    }
    fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.arr::<1>()?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.arr()?))
    }
    fn u16le(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.arr()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.arr()?))
    }
    /// Bytes up to a NUL, consuming the NUL.
    fn cstr(&mut self) -> Option<&'a [u8]> {
        let rest = self.b.get(self.at..)?;
        let n = rest.iter().position(|c| *c == 0)?;
        self.at += n + 1;
        Some(&rest[..n])
    }
    fn rest(&mut self) -> &'a [u8] {
        let r = self.b.get(self.at..).unwrap_or(&[]);
        self.at = self.b.len();
        r
    }
    fn left(&self) -> usize {
        self.b.len().saturating_sub(self.at)
    }
}

/// A status line and lower-cased headers of an HTTP-style text reply.
struct Http {
    status: String,
    headers: Vec<(String, String)>,
}

impl Http {
    fn parse(b: &[u8]) -> Option<Http> {
        let s = String::from_utf8_lossy(b);
        let mut lines = s.split('\n').map(|l| l.trim_end_matches('\r'));
        let status = lines.next()?.to_string();
        let mut headers = Vec::new();
        for l in lines.take(64) {
            if l.is_empty() {
                break;
            }
            if let Some((n, v)) = l.split_once(':') {
                headers.push((n.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }
        Some(Http { status, headers })
    }
    fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
    fn ok(&self) -> bool {
        self.status.starts_with("HTTP/1.") && self.status.split(' ').nth(1) == Some("200")
    }
}

fn ipv4(b: [u8; 4]) -> String {
    Ipv4Addr::from(b).to_string()
}

// ---------------------------------------------------------------- DNS family

/// A DNS query (RFC 1035 §4.1) with one question.
fn dns_query(id: u16, flags: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + name.len());
    for x in [id, flags, 1, 0, 0, 0] {
        v.extend(x.to_be_bytes());
    }
    for l in name.split('.').filter(|l| !l.is_empty()) {
        v.push(u8::try_from(l.len()).unwrap_or(63).min(63));
        v.extend(&l.as_bytes()[..l.len().min(63)]);
    }
    v.push(0);
    v.extend(qtype.to_be_bytes());
    v.extend(qclass.to_be_bytes());
    v
}

/// Read a (possibly compressed) name at `at`; the name and the offset after it.
fn dns_name(msg: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    for _ in 0..128 {
        let len = *msg.get(at)?;
        match len & 0xc0 {
            0x00 if len == 0 => return Some((name, end.unwrap_or(at + 1))),
            0x00 => {
                let l = msg.get(at + 1..at + 1 + usize::from(len))?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(&String::from_utf8_lossy(l));
                if name.len() > 512 {
                    return None;
                }
                at += 1 + usize::from(len);
            }
            0xc0 => {
                let lo = *msg.get(at + 1)?;
                end.get_or_insert(at + 2);
                at = usize::from(len & 0x3f) << 8 | usize::from(lo);
            }
            _ => return None,
        }
    }
    None
}

struct Rr<'a> {
    name: String,
    rtype: u16,
    rdata: &'a [u8],
    /// Offset of `rdata` in the message, for names inside it.
    at: usize,
}

struct Dns<'a> {
    id: u16,
    flags: u16,
    rrs: Vec<Rr<'a>>,
}

/// A DNS response (QR set) with all answer, authority and additional records
/// that parse; a truncated record ends the list.
fn dns_parse(msg: &[u8]) -> Option<Dns<'_>> {
    let mut r = Rd::new(msg);
    let (id, flags, qd) = (r.u16()?, r.u16()?, r.u16()?);
    let n = usize::from(r.u16()?) + usize::from(r.u16()?) + usize::from(r.u16()?);
    if flags & 0x8000 == 0 {
        return None;
    }
    let mut at = 12;
    for _ in 0..qd.min(16) {
        at = dns_name(msg, at)?.1 + 4;
    }
    if at > msg.len() {
        return None;
    }
    let mut rrs = Vec::new();
    for _ in 0..n.min(64) {
        let Some((name, next)) = dns_name(msg, at) else {
            break;
        };
        let mut r = Rd::at(msg, next);
        let rec = (|| {
            let rtype = r.u16()?;
            r.take(6)?; // class, ttl
            let len = r.u16()?;
            let at = r.at;
            Some((rtype, r.take(usize::from(len))?, at))
        })();
        let Some((rtype, rdata, rd_at)) = rec else {
            break;
        };
        rrs.push(Rr {
            name,
            rtype,
            rdata,
            at: rd_at,
        });
        at = r.at;
    }
    Some(Dns { id, flags, rrs })
}

/// The character-strings of a TXT record.
fn txt_strings(rdata: &[u8]) -> Vec<&[u8]> {
    let mut r = Rd::new(rdata);
    let mut out = Vec::new();
    while let Some(n) = r.u8() {
        match r.take(usize::from(n)) {
            Some(s) => out.push(s),
            None => break,
        }
    }
    out
}

/// DNS `version.bind` CH TXT (RFC 1035; RFC 4892 §2).
fn dns_payload() -> Vec<u8> {
    dns_query(ID, 0x0100, "version.bind", 16, 3)
}

fn dns_parse_version(b: &[u8]) -> Option<Ident> {
    let m = dns_parse(b)?;
    if m.id != ID {
        return None;
    }
    let txt = m
        .rrs
        .iter()
        .filter(|r| r.rtype == 16)
        .find_map(|r| txt_strings(r.rdata).first().and_then(|s| text(s)));
    if let Some(v) = txt {
        return Some(Ident {
            version: Some(v),
            ..Ident::default()
        });
    }
    let rcode = match m.flags & 0xf {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "other",
    };
    Some(Ident {
        banner: Some(format!("dns, version.bind {rcode}")),
        ..Ident::default()
    })
}

/// mDNS service enumeration (RFC 6763 §9), unicast-response bit set
/// (RFC 6762 §5.4); sent from a non-5353 port it is a legacy unicast query.
fn mdns_payload() -> Vec<u8> {
    dns_query(0, 0, "_services._dns-sd._udp.local", 12, 0x8001)
}

fn mdns_parse(b: &[u8]) -> Option<Ident> {
    let m = dns_parse(b)?;
    let mut list: Vec<String> = Vec::new();
    for r in &m.rrs {
        if r.rtype == 12
            && r.name.eq_ignore_ascii_case("_services._dns-sd._udp.local")
            && let Some((n, _)) = dns_name(b, r.at)
        {
            let n = n.strip_suffix(".local").unwrap_or(&n).to_string();
            if !list.contains(&n) {
                list.push(n);
            }
        }
    }
    if list.is_empty() {
        return None;
    }
    Some(Ident {
        banner: text(format!("services: {}", list.join(", ")).as_bytes()),
        ..Ident::default()
    })
}

/// Google Cast discovery: `_googlecast._tcp.local` PTR via mDNS.
fn googlecast_payload() -> Vec<u8> {
    dns_query(0, 0, "_googlecast._tcp.local", 12, 0x8001)
}

fn googlecast_parse(b: &[u8]) -> Option<Ident> {
    const SVC: &str = "_googlecast._tcp.local";
    let m = dns_parse(b)?;
    let instance = m
        .rrs
        .iter()
        .filter(|r| r.rtype == 12 && r.name.eq_ignore_ascii_case(SVC))
        .find_map(|r| dns_name(b, r.at).map(|n| n.0));
    let cast_txt = |r: &&Rr<'_>| {
        // Compare bytes: the lossy-decoded name may hold multi-byte chars.
        let n = r.name.as_bytes();
        r.rtype == 16
            && n.len() > SVC.len()
            && n[n.len() - SVC.len()..].eq_ignore_ascii_case(SVC.as_bytes())
    };
    let txt = m.rrs.iter().find(cast_txt);
    if instance.is_none() && txt.is_none() {
        return None;
    }
    let (mut model, mut friendly) = (None, None);
    for s in txt.map(|r| txt_strings(r.rdata)).unwrap_or_default() {
        if let Some(v) = s.strip_prefix(b"md=") {
            model = text(v);
        } else if let Some(v) = s.strip_prefix(b"fn=") {
            friendly = text(v);
        }
    }
    let label = instance
        .as_deref()
        .or(txt.map(|r| r.name.as_str()))
        .and_then(|n| n.split('.').next())
        .and_then(|l| text(l.as_bytes()));
    Some(Ident {
        product: model.or_else(|| Some("Google Cast".into())),
        title: friendly.or(label),
        ..Ident::default()
    })
}

/// LLMNR (RFC 4795) A query for `wpad`. Responders answer only for names they
/// own, so this mostly tells open from closed; an answer names a responder
/// claiming `wpad`.
fn llmnr_payload() -> Vec<u8> {
    dns_query(ID, 0, "wpad", 1, 1)
}

fn llmnr_parse(b: &[u8]) -> Option<Ident> {
    let m = dns_parse(b)?;
    if m.id != ID {
        return None;
    }
    Some(Ident {
        product: Some("llmnr".into()),
        title: m.rrs.first().and_then(|r| text(r.name.as_bytes())),
        ..Ident::default()
    })
}

/// NetBIOS NODE STATUS request for `*` (RFC 1002 §4.2.17).
fn nbns_payload() -> Vec<u8> {
    let mut v = Vec::with_capacity(50);
    for x in [ID, 0, 1, 0, 0, 0] {
        v.extend(x.to_be_bytes());
    }
    v.push(32);
    let mut name = [0u8; 16];
    name[0] = b'*';
    for c in name {
        v.push(b'A' + (c >> 4));
        v.push(b'A' + (c & 0xf));
    }
    v.push(0);
    v.extend([0, 0x21, 0, 1]);
    v
}

fn nbns_parse(b: &[u8]) -> Option<Ident> {
    let m = dns_parse(b)?;
    let rr = m.rrs.iter().find(|r| r.rtype == 0x21)?;
    let mut r = Rd::new(rr.rdata);
    let n = r.u8()?;
    let (mut host, mut group) = (None, None);
    for _ in 0..n {
        let Some(e) = r.take(18) else { break };
        let (name, suffix, flags) = (&e[..15], e[15], u16::from_be_bytes([e[16], e[17]]));
        if suffix != 0 {
            continue;
        }
        let slot = if flags & 0x8000 == 0 {
            &mut host
        } else {
            &mut group
        };
        if slot.is_none() {
            *slot = text(name);
        }
    }
    let mut banner = Vec::new();
    if let Some(g) = group {
        banner.push(format!("workgroup {g}"));
    }
    if let Some(mac) = r.take(6).filter(|m| m.iter().any(|b| *b != 0)) {
        let hex: Vec<String> = mac.iter().map(|b| format!("{b:02x}")).collect();
        banner.push(format!("MAC {}", hex.join(":")));
    }
    Some(Ident {
        title: host,
        banner: text(banner.join(", ").as_bytes()),
        ..Ident::default()
    })
}

// ---------------------------------------------------------------- NTP

/// NTPv4 client request, mode 3 (RFC 5905 §7.3). The transmit timestamp is
/// non-zero so servers do not drop it as bogus.
fn ntp_payload() -> Vec<u8> {
    let mut v = vec![0u8; 48];
    v[0] = 0x23; // LI 0, VN 4, mode 3
    v[40..48].copy_from_slice(b"sensrntp");
    v
}

fn ntp_parse(b: &[u8]) -> Option<Ident> {
    if b.len() < 48 || !matches!(b[0] & 7, 4 | 5) {
        return None;
    }
    let (vn, stratum) = ((b[0] >> 3) & 7, b[1]);
    let refid: [u8; 4] = b[12..16].try_into().ok()?;
    let mut banner = format!("NTPv{vn}, stratum {stratum}");
    if stratum >= 2 {
        let _ = write!(banner, ", ref {}", ipv4(refid));
    } else if let Some(t) = text(refid.split(|c| *c == 0).next().unwrap_or(&[])) {
        let _ = write!(banner, ", ref {t}");
    }
    Some(Ident {
        product: Some("ntp".into()),
        banner: text(banner.as_bytes()),
        ..Ident::default()
    })
}

// ---------------------------------------------------------------- SNMP

fn ber(tag: u8, content: &[u8]) -> Vec<u8> {
    let n = content.len();
    let mut v = vec![tag];
    match n {
        0..=127 => v.push(n as u8),
        128..=255 => v.extend([0x81, n as u8]),
        _ => v.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    v.extend(content);
    v
}

fn ber_read<'a>(r: &mut Rd<'a>) -> Option<(u8, &'a [u8])> {
    let tag = r.u8()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let len = match r.u8()? {
        n @ 0..=0x7f => usize::from(n),
        0x81 => usize::from(r.u8()?),
        0x82 => usize::from(r.u16()?),
        _ => return None,
    };
    Some((tag, r.take(len)?))
}

/// SNMPv2c GetRequest for sysDescr.0 with community `public` (RFC 3416 §3,
/// RFC 1213 for the OID), BER per X.690.
fn snmp_payload() -> Vec<u8> {
    let oid = [0x2b, 6, 1, 2, 1, 1, 1, 0]; // 1.3.6.1.2.1.1.1.0
    let vb = ber(0x30, &[ber(0x06, &oid), ber(0x05, &[])].concat());
    let pdu = [
        ber(0x02, &XID.to_be_bytes()),
        ber(0x02, &[0]),
        ber(0x02, &[0]),
        ber(0x30, &vb),
    ]
    .concat();
    let msg = [ber(0x02, &[1]), ber(0x04, b"public"), ber(0xa0, &pdu)].concat();
    ber(0x30, &msg)
}

fn snmp_parse(b: &[u8]) -> Option<Ident> {
    let (0x30, msg) = ber_read(&mut Rd::new(b))? else {
        return None;
    };
    let mut r = Rd::new(msg);
    let (0x02, ver) = ber_read(&mut r)? else {
        return None;
    };
    let (0x04, _community) = ber_read(&mut r)? else {
        return None;
    };
    let (0xa2, pdu) = ber_read(&mut r)? else {
        return None;
    };
    let ver = match ver {
        [0] => "v1",
        [1] => "v2c",
        _ => "?",
    };
    let mut p = Rd::new(pdu);
    let _reqid = ber_read(&mut p)?;
    let (0x02, err) = ber_read(&mut p)? else {
        return None;
    };
    let mut id = Ident {
        banner: Some(format!("SNMP {ver}, community public")),
        ..Ident::default()
    };
    if err.iter().any(|e| *e != 0) {
        id.banner = Some(format!("SNMP {ver}, error {}", err.last().unwrap_or(&0)));
        return Some(id);
    }
    let value = (|| {
        let _idx = ber_read(&mut p)?;
        let (0x30, vbl) = ber_read(&mut p)? else {
            return None;
        };
        let (0x30, vb) = ber_read(&mut Rd::new(vbl))? else {
            return None;
        };
        let mut v = Rd::new(vb);
        let (0x06, _oid) = ber_read(&mut v)? else {
            return None;
        };
        match ber_read(&mut v)? {
            (0x04, s) => text(s),
            _ => None,
        }
    })();
    id.product = value;
    Some(id)
}

// ---------------------------------------------------------------- HTTP-ish

/// SSDP search for everything (UPnP Device Architecture 2.0 §1.3.2), sent
/// unicast to the device.
fn ssdp_payload() -> Vec<u8> {
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
        .to_vec()
}

fn ssdp_parse(b: &[u8]) -> Option<Ident> {
    let h = Http::parse(b)?;
    if !h.ok() {
        return None;
    }
    let friendly = h
        .headers
        .iter()
        .find(|(n, _)| n.starts_with("x-") && n.contains("friendly"))
        .and_then(|(_, v)| text(v.as_bytes()));
    Some(Ident {
        product: h.get("server").and_then(|v| text(v.as_bytes())),
        title: friendly,
        banner: h.get("location").and_then(|v| text(v.as_bytes())),
        ..Ident::default()
    })
}

/// SIP OPTIONS ping (RFC 3261 §11), `rport` (RFC 3581) so the answer comes
/// back to our source port.
fn sip_payload() -> Vec<u8> {
    b"OPTIONS sip:sensr.invalid SIP/2.0\r\n\
Via: SIP/2.0/UDP sensr.invalid;branch=z9hG4bK73656e7372;rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:probe@sensr.invalid>;tag=73656e73\r\n\
To: <sip:sensr.invalid>\r\n\
Call-ID: 73656e72-probe@sensr.invalid\r\n\
CSeq: 1 OPTIONS\r\n\
Accept: application/sdp\r\n\
Content-Length: 0\r\n\r\n"
        .to_vec()
}

fn sip_parse(b: &[u8]) -> Option<Ident> {
    let h = Http::parse(b)?;
    if !h.status.starts_with("SIP/2.0 ") {
        return None;
    }
    Some(Ident {
        product: h
            .get("server")
            .or(h.get("user-agent"))
            .and_then(|v| text(v.as_bytes())),
        banner: text(h.status.as_bytes()),
        ..Ident::default()
    })
}

/// Plex GDM discovery: an HTTP-style search on 32414.
fn plex_payload() -> Vec<u8> {
    b"M-SEARCH * HTTP/1.1\r\n\r\n".to_vec()
}

fn plex_parse(b: &[u8]) -> Option<Ident> {
    let h = Http::parse(b)?;
    let ct = h.get("content-type")?;
    if !h.ok() || !ct.starts_with("plex/") {
        return None;
    }
    let product = if ct.starts_with("plex/media-server") {
        Some("Plex Media Server".into())
    } else {
        text(ct.as_bytes())
    };
    Some(Ident {
        product,
        title: h.get("name").and_then(|v| text(v.as_bytes())),
        version: h.get("version").and_then(|v| text(v.as_bytes())),
        ..Ident::default()
    })
}

// ---------------------------------------------------------------- DHCP, TFTP, syslog

/// DHCPINFORM (RFC 2131 §3.4) asking for subnet, router, DNS and domain.
fn dhcp_payload() -> Vec<u8> {
    let mut v = vec![0u8; 240];
    v[..4].copy_from_slice(&[1, 1, 6, 0]);
    v[4..8].copy_from_slice(&XID.to_be_bytes());
    v[28..34].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]); // locally administered
    // RFC 2131 §4.4.3 wants ciaddr = the client's own address; the payload is
    // built without knowing our source address, so ciaddr stays 0.0.0.0.
    v[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    v.extend([53, 1, 8, 55, 4, 1, 3, 6, 15, 255]);
    v
}

fn dhcp_parse(b: &[u8]) -> Option<Ident> {
    if b.len() < 240
        || b[0] != 2
        || b[4..8] != XID.to_be_bytes()
        || b[236..240] != [0x63, 0x82, 0x53, 0x63]
    {
        return None;
    }
    let mut r = Rd::at(b, 240);
    let (mut kind, mut server, mut domain) = (None, None, None);
    while let Some(code) = r.u8() {
        match code {
            0 => continue,
            255 => break,
            _ => {}
        }
        let Some(v) = r.u8().and_then(|n| r.take(usize::from(n))) else {
            break;
        };
        match (code, v) {
            (53, [t]) => kind = Some(*t),
            (54, [a, b, c, d]) => server = Some(ipv4([*a, *b, *c, *d])),
            (15, d) => domain = text(d),
            _ => {}
        }
    }
    let kind = match kind {
        Some(2) => "DHCPOFFER",
        Some(5) => "DHCPACK",
        Some(6) => "DHCPNAK",
        _ => "BOOTREPLY",
    };
    let mut banner = kind.to_string();
    if let Some(s) = server {
        let _ = write!(banner, " from {s}");
    }
    if let Some(d) = domain {
        let _ = write!(banner, ", domain {d}");
    }
    Some(Ident {
        product: Some("dhcp".into()),
        banner: text(banner.as_bytes()),
        ..Ident::default()
    })
}

/// TFTP read request for a file that should not exist (RFC 1350 §5).
fn tftp_payload() -> Vec<u8> {
    b"\x00\x01sensr-probe-missing\x00octet\x00".to_vec()
}

fn tftp_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::new(b);
    let banner = match r.u16()? {
        5 => {
            let code = r.u16()?;
            let msg = r.cstr().unwrap_or_else(|| r.rest());
            format!("error {code}: {}", sanitize(msg))
        }
        3 => "served the probe file".into(),
        _ => return None,
    };
    Some(Ident {
        product: Some("tftp".into()),
        banner: text(banner.as_bytes()),
        ..Ident::default()
    })
}

/// An RFC 5424 message; syslog never answers, so this only separates
/// open|filtered from closed.
fn syslog_payload() -> Vec<u8> {
    b"<14>1 - - sensr-scan - - - port scan probe".to_vec()
}

fn no_reply(_: &[u8]) -> Option<Ident> {
    None
}

// ---------------------------------------------------------------- IKE

const IKE_SPI: &[u8; 8] = b"sensrIKE";

/// IKEv2 IKE_SA_INIT (RFC 7296 §1.2, §3): one proposal AES-CBC-256 /
/// HMAC-SHA2-256 / HMAC-SHA2-256-128 / MODP-2048, a KE and a nonce.
fn ike_payload() -> Vec<u8> {
    fn transform(more: bool, ttype: u8, id: u16, attr: &[u8]) -> Vec<u8> {
        let len = 8 + attr.len() as u16;
        let mut v = vec![if more { 3 } else { 0 }, 0];
        v.extend(len.to_be_bytes());
        v.extend([ttype, 0]);
        v.extend(id.to_be_bytes());
        v.extend(attr);
        v
    }
    let transforms = [
        transform(true, 1, 12, &[0x80, 0x0e, 0x01, 0x00]), // ENCR_AES_CBC, 256-bit
        transform(true, 2, 5, &[]),                        // PRF_HMAC_SHA2_256
        transform(true, 3, 12, &[]),                       // AUTH_HMAC_SHA2_256_128
        transform(false, 4, 14, &[]),                      // 2048-bit MODP
    ]
    .concat();
    let mut proposal = vec![0, 0];
    proposal.extend((8 + transforms.len() as u16).to_be_bytes());
    proposal.extend([1, 1, 0, 4]); // #1, IKE, no SPI, 4 transforms
    proposal.extend(transforms);
    let payload = |next: u8, body: &[u8]| {
        let mut v = vec![next, 0];
        v.extend((4 + body.len() as u16).to_be_bytes());
        v.extend(body);
        v
    };
    let sa = payload(34, &proposal);
    let mut ke_body = vec![0, 14, 0, 0];
    ke_body.extend((0..256u16).map(|i| (i * 7 + 1) as u8));
    let ke = payload(40, &ke_body);
    let nonce = payload(0, b"sensr-scan-ike-nonce-0123456789a");
    let body = [sa, ke, nonce].concat();
    let mut v = IKE_SPI.to_vec();
    v.extend([0; 8]);
    v.extend([33, 0x20, 34, 0x08]); // next SA, v2.0, IKE_SA_INIT, initiator
    v.extend(0u32.to_be_bytes());
    v.extend((28 + body.len() as u32).to_be_bytes());
    v.extend(body);
    v
}

fn ike_parse(b: &[u8]) -> Option<Ident> {
    if b.len() < 28 || &b[..8] != IKE_SPI {
        return None;
    }
    let version = match b[17] >> 4 {
        1 => "1",
        2 if b[19] & 0x20 != 0 => "2",
        _ => return None,
    };
    let mut banner = None;
    let (mut next, mut r) = (b[16], Rd::at(b, 28));
    for _ in 0..16 {
        if next == 0 {
            break;
        }
        let Some((n, len)) = (|| Some((r.u8()?, r.take(1).and(r.u16())?)))() else {
            break;
        };
        let Some(body) = r.take(usize::from(len).saturating_sub(4)) else {
            break;
        };
        if next == 41
            && version == "2"
            && let Some(t) = body.get(2..4)
        {
            let t = u16::from_be_bytes([t[0], t[1]]);
            banner = Some(match t {
                5 => "INVALID_MAJOR_VERSION".into(),
                7 => "INVALID_SYNTAX".into(),
                14 => "NO_PROPOSAL_CHOSEN".into(),
                17 => "INVALID_KE_PAYLOAD".into(),
                16390 => "COOKIE".into(),
                t => format!("notify {t}"),
            });
            break;
        }
        next = n;
    }
    Some(Ident {
        product: Some("ike".into()),
        version: Some(version.into()),
        banner: Some(banner.unwrap_or_else(|| "IKE_SA_INIT response".into())),
        ..Ident::default()
    })
}

/// The same IKE_SA_INIT behind the four-byte non-ESP marker (RFC 3948 §2.2).
fn ike_natt_payload() -> Vec<u8> {
    [vec![0; 4], ike_payload()].concat()
}

fn ike_natt_parse(b: &[u8]) -> Option<Ident> {
    ike_parse(b.strip_prefix(&[0, 0, 0, 0]).unwrap_or(b))
}

// ---------------------------------------------------------------- WS-Discovery

/// WS-Discovery Probe (2005/04 draft, the one Windows and ONVIF speak).
fn wsd_payload() -> Vec<u8> {
    concat!(
        r#"<?xml version="1.0" encoding="utf-8"?>"#,
        r#"<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" "#,
        r#"xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" "#,
        r#"xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">"#,
        "<soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>",
        "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>",
        "<wsa:MessageID>urn:uuid:7e1f3c2a-5d4b-4e6f-9a8b-73656e737221</wsa:MessageID>",
        "</soap:Header><soap:Body><wsd:Probe/></soap:Body></soap:Envelope>",
    )
    .as_bytes()
    .to_vec()
}

/// Text of the first `<local>` or `<ns:local>` start tag.
fn xml_text<'a>(s: &'a str, local: &str) -> Option<&'a str> {
    let pat = format!("{local}>");
    let mut from = 0;
    while let Some(i) = s.get(from..)?.find(&pat) {
        let at = from + i;
        let lt = s[..at].rfind('<')?;
        let tag = &s[lt + 1..at];
        if !tag.starts_with('/') && (tag.is_empty() || tag.ends_with(':')) {
            let body = &s[at + pat.len()..];
            return Some(body.split('<').next().unwrap_or(""));
        }
        from = at + pat.len();
    }
    None
}

fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = b
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok());
        match (b[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

fn wsd_parse(b: &[u8]) -> Option<Ident> {
    let s = String::from_utf8_lossy(b);
    if !s.contains("ProbeMatch") {
        return None;
    }
    let scopes = xml_text(&s, "Scopes").unwrap_or("");
    let scope = |key: &str| {
        scopes
            .split_whitespace()
            .find_map(|u| u.split_once(key).map(|(_, v)| text(&percent_decode(v))))
            .flatten()
    };
    Some(Ident {
        product: scope("/hardware/").or_else(|| Some("ws-discovery".into())),
        title: scope("/name/"),
        banner: xml_text(&s, "Types").and_then(|t| text(t.as_bytes())),
        ..Ident::default()
    })
}

// ---------------------------------------------------------------- small binary protocols

/// CoAP confirmable GET /.well-known/core (RFC 7252 §3, RFC 6690 §4).
fn coap_payload() -> Vec<u8> {
    let mut v = vec![0x40, 0x01];
    v.extend(ID.to_be_bytes());
    v.push(0xbb); // Uri-Path (11), length 11
    v.extend(b".well-known");
    v.push(0x04); // Uri-Path again, length 4
    v.extend(b"core");
    v
}

fn coap_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::new(b);
    let first = r.u8()?;
    let code = r.u8()?;
    r.u16()?;
    let (class, detail) = (code >> 5, code & 0x1f);
    if first >> 6 != 1 || first & 0xf > 8 || !matches!(class, 2 | 4 | 5) {
        return None;
    }
    r.take(usize::from(first & 0xf))?;
    let mut payload: &[u8] = &[];
    while let Some(o) = r.u8() {
        if o == 0xff {
            payload = r.rest();
            break;
        }
        let mut ext = |n: u8| -> Option<usize> {
            match n {
                0..=12 => Some(usize::from(n)),
                13 => Some(usize::from(r.u8()?) + 13),
                14 => Some(usize::from(r.u16()?) + 269),
                _ => None,
            }
        };
        ext(o >> 4)?;
        let len = ext(o & 0xf)?;
        r.take(len)?;
    }
    let mut banner = format!("{class}.{detail:02}");
    if let Some(p) = text(payload) {
        let _ = write!(banner, " {p}");
    }
    Some(Ident {
        product: Some("coap".into()),
        banner: text(banner.as_bytes()),
        ..Ident::default()
    })
}

/// MQTT-SN SEARCHGW, radius 1 (MQTT-SN v1.2 §5.4.2).
fn mqttsn_payload() -> Vec<u8> {
    vec![3, 1, 1]
}

fn mqttsn_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::new(b);
    let len = match r.u8()? {
        1 => usize::from(r.u16()?),
        n => usize::from(n),
    };
    if len < 3 || len > b.len() {
        return None;
    }
    let gw = match r.u8()? {
        0x00 | 0x02 => r.u8()?, // ADVERTISE, GWINFO
        _ => return None,
    };
    Some(Ident {
        product: Some("mqtt-sn".into()),
        banner: Some(format!("gateway {gw}")),
        ..Ident::default()
    })
}

/// memcached `stats` with the UDP frame header (memcached protocol.txt).
fn memcached_payload() -> Vec<u8> {
    let mut v = ID.to_be_bytes().to_vec();
    v.extend([0, 0, 0, 1, 0, 0]);
    v.extend(b"stats\r\n");
    v
}

fn memcached_parse(b: &[u8]) -> Option<Ident> {
    if b.len() <= 8 || b[..2] != ID.to_be_bytes() {
        return None;
    }
    let s = String::from_utf8_lossy(&b[8..]);
    if !(s.starts_with("STAT ") || s.starts_with("VERSION ") || s.starts_with("ERROR")) {
        return None;
    }
    let version = s.lines().find_map(|l| {
        let l = l.trim_end_matches('\r');
        l.strip_prefix("STAT version ")
            .or_else(|| l.strip_prefix("VERSION "))
            .and_then(|v| text(v.as_bytes()))
    });
    Some(Ident {
        product: Some("memcached".into()),
        version,
        ..Ident::default()
    })
}

/// RIPv2 request for the whole table (RFC 2453 §3.9.1).
fn rip_payload() -> Vec<u8> {
    let mut v = vec![1, 2, 0, 0];
    v.extend([0; 16]);
    v.extend([0, 0, 0, 16]);
    v
}

fn rip_parse(b: &[u8]) -> Option<Ident> {
    if b.len() < 4 || b[0] != 2 || !matches!(b[1], 1 | 2) || !(b.len() - 4).is_multiple_of(20) {
        return None;
    }
    let n = (b.len() - 4) / 20;
    Some(Ident {
        product: Some("rip".into()),
        version: Some(b[1].to_string()),
        banner: Some(format!("{n} route{}", if n == 1 { "" } else { "s" })),
        ..Ident::default()
    })
}

/// Ubiquiti discovery v1 request.
fn ubnt_payload() -> Vec<u8> {
    vec![1, 0, 0, 0]
}

fn ubnt_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::new(b);
    if r.u8()? != 1 {
        return None;
    }
    r.u8()?;
    let len = usize::from(r.u16()?);
    let mut r = Rd::new(b.get(4..4 + len.min(b.len() - 4))?);
    let (mut fw, mut host, mut model, mut model_full) = (None, None, None, None);
    while let (Some(t), Some(n)) = (r.u8(), r.u16()) {
        let Some(v) = r.take(usize::from(n)) else {
            break;
        };
        match t {
            0x03 => fw = text(v),
            0x0b => host = text(v),
            0x0c => model = text(v),
            0x14 => model_full = text(v),
            _ => {}
        }
    }
    let model = model_full.or(model);
    if fw.is_none() && host.is_none() && model.is_none() {
        return None;
    }
    Some(Ident {
        product: text(format!("Ubiquiti {}", model.unwrap_or_default()).as_bytes()),
        version: fw,
        title: host,
        ..Ident::default()
    })
}

const STUN_TID: &[u8; 12] = b"sensr-stun01";

/// STUN Binding request (RFC 8489 §5).
fn stun_payload() -> Vec<u8> {
    let mut v = vec![0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42];
    v.extend(STUN_TID);
    v
}

fn stun_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::new(b);
    let kind = r.u16()?;
    let len = usize::from(r.u16()?);
    if r.u32()? != 0x2112_a442 || r.take(12)? != STUN_TID {
        return None;
    }
    let banner = match kind {
        0x0101 => "binding success",
        0x0111 => "binding error",
        _ => return None,
    };
    let mut attrs = Rd::new(r.take(len.min(r.left()))?);
    let mut software = None;
    while let (Some(t), Some(n)) = (attrs.u16(), attrs.u16()) {
        let Some(v) = attrs.take(usize::from(n)) else {
            break;
        };
        attrs.take((4 - usize::from(n) % 4) % 4);
        if t == 0x8022 {
            software = text(v);
        }
    }
    Some(Ident {
        product: software.or_else(|| Some("stun".into())),
        banner: Some(banner.into()),
        ..Ident::default()
    })
}

/// ONC RPC NULL call (RFC 5531 §9) with AUTH_NONE.
fn rpc_null(prog: u32, vers: u32) -> Vec<u8> {
    [XID, 0, 2, prog, vers, 0, 0, 0, 0, 0]
        .iter()
        .flat_map(|x| x.to_be_bytes())
        .collect()
}

fn rpc_parse(b: &[u8], name: &str) -> Option<Ident> {
    let mut r = Rd::new(b);
    if r.u32()? != XID || r.u32()? != 1 {
        return None;
    }
    let mut id = named(name);
    if r.u32()? != 0 {
        id.banner = Some("call denied".into());
        return Some(id);
    }
    r.u32()?;
    let vlen = usize::try_from(r.u32()?).ok()?;
    r.take(vlen.checked_add(3)? / 4 * 4)?;
    match r.u32()? {
        0 => {}
        1 => id.banner = Some("program unavailable".into()),
        2 => id.version = Some(format!("{}-{}", r.u32()?, r.u32()?)),
        s => id.banner = Some(format!("accept status {s}")),
    }
    Some(id)
}

fn rpcbind_payload() -> Vec<u8> {
    rpc_null(100_000, 2)
}

fn rpcbind_parse(b: &[u8]) -> Option<Ident> {
    rpc_parse(b, "rpcbind")
}

fn nfs_payload() -> Vec<u8> {
    rpc_null(100_003, 3)
}

fn nfs_parse(b: &[u8]) -> Option<Ident> {
    rpc_parse(b, "nfs")
}

/// IPMI v1.5 Get Channel Authentication Capabilities over RMCP (IPMI v2.0
/// spec §13.6, §22.13), asking for v2.0 extended data.
fn ipmi_payload() -> Vec<u8> {
    let mut v = vec![6, 0, 0xff, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    v.extend([0x20, 0x18, 0xc8, 0x81, 0x00, 0x38, 0x8e, 0x04, 0xb5]);
    v
}

fn ipmi_parse(b: &[u8]) -> Option<Ident> {
    if b.len() < 5 || b[0] != 6 || b[3] & 0x1f != 7 {
        return None;
    }
    let msg = if b[4] == 0 {
        b.get(14..)?
    } else {
        b.get(30..)?
    };
    if msg.get(5) != Some(&0x38) {
        return None;
    }
    let mut id = named("ipmi");
    match (msg.get(6), msg.get(8)) {
        (Some(0), Some(a)) => id.version = Some(if a & 0x80 != 0 { "2.0" } else { "1.5" }.into()),
        (Some(cc), _) => id.banner = Some(format!("completion code {cc:#04x}")),
        _ => {}
    }
    Some(id)
}

/// OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 without tls-auth.
fn openvpn_payload() -> Vec<u8> {
    let mut v = vec![7 << 3];
    v.extend(b"sensrovp");
    v.extend([0, 0, 0, 0, 0]);
    v
}

fn openvpn_parse(b: &[u8]) -> Option<Ident> {
    (b.len() >= 10 && matches!(b[0] >> 3, 2 | 8)).then(|| named("openvpn"))
}

const QUIC_CID: &[u8; 8] = b"sensrqic";

/// A QUIC long-header packet with a reserved version (RFC 9000 §6.3,
/// §15), padded to 1200 bytes, which servers answer with Version Negotiation.
fn quic_payload() -> Vec<u8> {
    let mut v = vec![0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8];
    v.extend(QUIC_CID);
    v.push(0);
    v.resize(1200, 0);
    v
}

fn quic_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::new(b);
    if r.u8()? & 0x80 == 0 || r.u32()? != 0 {
        return None;
    }
    let dcil = r.u8()?;
    r.take(usize::from(dcil))?;
    let scil = r.u8()?;
    if r.take(usize::from(scil))? != QUIC_CID {
        return None;
    }
    let mut names = Vec::new();
    while let Some(v) = r.u32() {
        names.push(match v {
            1 => "v1".to_string(),
            0x6b33_43cf => "v2".to_string(),
            v if v >> 8 == 0x00ff_0000 => format!("draft-{}", v & 0xff),
            v => format!("{v:#010x}"),
        });
    }
    if names.is_empty() {
        return None;
    }
    Some(Ident {
        product: Some("quic".into()),
        banner: text(format!("versions {}", names.join(", ")).as_bytes()),
        ..Ident::default()
    })
}

/// L2TP SCCRQ (RFC 2661 §6.1).
fn l2tp_payload() -> Vec<u8> {
    fn avp(t: u16, v: &[u8]) -> Vec<u8> {
        let mut a = (0x8000 | (6 + v.len() as u16)).to_be_bytes().to_vec();
        a.extend([0, 0]);
        a.extend(t.to_be_bytes());
        a.extend(v);
        a
    }
    let avps = [
        avp(0, &1u16.to_be_bytes()), // Message Type: SCCRQ
        avp(2, &[1, 0]),             // Protocol Version 1.0
        avp(7, b"sensr"),            // Host Name
        avp(3, &3u32.to_be_bytes()), // Framing Capabilities
        avp(9, &1u16.to_be_bytes()), // Assigned Tunnel ID
    ]
    .concat();
    let mut v = vec![0xc8, 0x02];
    v.extend((12 + avps.len() as u16).to_be_bytes());
    v.extend([0; 8]);
    v.extend(avps);
    v
}

fn l2tp_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::new(b);
    let flags = r.u16()?;
    if flags & 0x8000 == 0 || flags & 0xf != 2 {
        return None;
    }
    if flags & 0x4000 != 0 {
        r.u16()?;
    }
    r.take(4)?;
    if flags & 0x0800 != 0 {
        r.take(4)?;
    }
    if flags & 0x0200 != 0 {
        let n = r.u16()?;
        r.take(usize::from(n))?;
    }
    let (mut host, mut vendor) = (None, None);
    while let Some(h) = r.u16() {
        let len = usize::from(h & 0x3ff);
        let Some((v, t)) = r.u16().zip(r.u16()) else {
            break;
        };
        let Some(val) = r.take(len.saturating_sub(6)) else {
            break;
        };
        if len < 6 || v != 0 || h & 0x4000 != 0 {
            continue;
        }
        match t {
            7 => host = text(val),
            8 => vendor = text(val),
            _ => {}
        }
    }
    Some(Ident {
        product: vendor.or_else(|| Some("l2tp".into())),
        title: host,
        ..Ident::default()
    })
}

/// NAT-PMP external address request (RFC 6886 §3.2).
fn natpmp_payload() -> Vec<u8> {
    vec![0, 0]
}

fn natpmp_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::new(b);
    match (r.u8()?, r.u8()?) {
        (2, op) if op & 0x80 != 0 => Some(named("pcp")), // RFC 6887 answering v0
        (0, 0x80) => {
            let res = r.u16()?;
            let ip = r.u32().and(r.arr::<4>());
            Some(Ident {
                product: Some("nat-pmp".into()),
                banner: Some(match (res, ip) {
                    (0, Some(ip)) => format!("external address {}", ipv4(ip)),
                    (res, _) => format!("result {res}"),
                }),
                ..Ident::default()
            })
        }
        _ => None,
    }
}

/// SLP SrvTypeRqst for all naming authorities in scope DEFAULT (RFC 2608 §9.1).
fn slp_payload() -> Vec<u8> {
    let body = [
        &0u16.to_be_bytes()[..],
        &[0xff, 0xff],
        &7u16.to_be_bytes(),
        b"DEFAULT",
    ]
    .concat();
    let len = 16 + body.len();
    let mut v = vec![
        2,
        9,
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        0,
        0,
        0,
        0,
        0,
    ];
    v.extend(ID.to_be_bytes());
    v.extend(2u16.to_be_bytes());
    v.extend(b"en");
    v.extend(body);
    v
}

fn slp_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::new(b);
    if r.u8()? != 2 {
        return None;
    }
    let func = r.u8()?;
    r.take(8)?; // length, flags, next extension offset
    if r.u16()? != ID && func == 10 {
        return None;
    }
    let lang = r.u16()?;
    r.take(usize::from(lang))?;
    let mut id = named("slp");
    match func {
        10 => {
            id.banner = match r.u16()? {
                0 => {
                    let n = r.u16()?;
                    text(r.take(usize::from(n).min(r.left()))?)
                }
                e => Some(format!("error {e}")),
            }
        }
        2 | 8 | 11 => {}
        _ => return None,
    }
    Some(id)
}

/// SQL Server Browser CLNT_UCAST_EX ([MC-SQLR] §2.2.2).
fn mssql_payload() -> Vec<u8> {
    vec![3]
}

fn mssql_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::new(b);
    if r.u8()? != 5 {
        return None;
    }
    let n = usize::from(r.u16le()?);
    let s = String::from_utf8_lossy(r.take(n.min(r.left()))?);
    let f: Vec<&str> = s.split(';').collect();
    let mut id = named("Microsoft SQL Server");
    let mut instances = Vec::new();
    for kv in f.chunks(2) {
        match kv {
            ["ServerName", v] if id.title.is_none() => id.title = text(v.as_bytes()),
            ["InstanceName", v] => instances.push(*v),
            ["Version", v] if id.version.is_none() => id.version = text(v.as_bytes()),
            _ => {}
        }
    }
    if id.title.is_none() && instances.is_empty() {
        return None;
    }
    if !instances.is_empty() {
        id.banner = text(format!("instance {}", instances.join(", ")).as_bytes());
    }
    Some(id)
}

/// BACnet/IP unicast Who-Is (ASHRAE 135 Annex J, clause 16.10).
fn bacnet_payload() -> Vec<u8> {
    vec![0x81, 0x0a, 0, 8, 1, 0, 0x10, 0x08]
}

fn bacnet_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::new(b);
    if r.u8()? != 0x81 {
        return None;
    }
    let func = r.u8()?;
    r.u16()?;
    if func == 0x04 {
        r.take(6)?; // Forwarded-NPDU: originating B/IP address
    }
    if r.u8()? != 1 {
        return None;
    }
    let ctl = r.u8()?;
    if ctl & 0x20 != 0 {
        r.u16()?;
        let n = r.u8()?;
        r.take(usize::from(n))?;
    }
    if ctl & 0x08 != 0 {
        r.u16()?;
        let n = r.u8()?;
        r.take(usize::from(n))?;
    }
    if ctl & 0x20 != 0 {
        r.u8()?;
    }
    let mut id = named("bacnet");
    if ctl & 0x80 == 0
        && r.u8() == Some(0x10)
        && r.u8() == Some(0x00)
        && r.u8() == Some(0xc4)
        && let Some(oid) = r.u32()
    {
        id.banner = Some(format!("device {}", oid & 0x3f_ffff));
    }
    Some(id)
}

/// EtherNet/IP ListIdentity (ODVA CIP Vol 2 §2-4.3); little-endian.
fn enip_payload() -> Vec<u8> {
    let mut v = vec![0x63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    v.extend(b"sensrcip");
    v.extend([0; 4]);
    v
}

fn enip_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::new(b);
    if r.u16le()? != 0x63 {
        return None;
    }
    r.take(22)?;
    let mut id = named("enip");
    if r.u16le()? == 0 || r.u16le()? != 0x0c {
        return Some(id);
    }
    r.u16le()?;
    r.take(18)?; // encapsulation version, socket address
    let (vendor, dtype) = (r.u16le()?, r.u16le()?);
    r.u16le()?;
    let (major, minor) = (r.u8()?, r.u8()?);
    r.take(6)?; // status, serial
    let n = r.u8()?;
    if let Some(name) = r.take(usize::from(n)).and_then(text) {
        id.product = Some(name);
    }
    id.version = Some(format!("{major}.{minor}"));
    id.banner = Some(format!("vendor {vendor}, device type {dtype}"));
    Some(id)
}

/// MikroTik neighbour discovery: a four-byte request.
fn mndp_payload() -> Vec<u8> {
    vec![0, 0, 0, 0]
}

fn mndp_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::at(b, 4);
    if b.len() <= 4 {
        return None;
    }
    let (mut ident, mut version, mut platform, mut board) = (None, None, None, None);
    while let (Some(t), Some(n)) = (r.u16(), r.u16()) {
        let Some(v) = r.take(usize::from(n)) else {
            break;
        };
        match t {
            5 => ident = text(v),
            7 => version = text(v),
            8 => platform = text(v),
            12 => board = text(v),
            _ => {}
        }
    }
    if ident.is_none() && version.is_none() && board.is_none() {
        return None;
    }
    let product = match (board, platform) {
        (Some(b), _) => format!("MikroTik {b}"),
        (None, Some(p)) => p,
        (None, None) => "MikroTik".into(),
    };
    Some(Ident {
        product: text(product.as_bytes()),
        version,
        title: ident,
        ..Ident::default()
    })
}

/// XDMCP Query with no authentication names (XDMCP 1.1 §10).
fn xdmcp_payload() -> Vec<u8> {
    vec![0, 1, 0, 2, 0, 1, 0]
}

fn xdmcp_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::new(b);
    if r.u16()? != 1 {
        return None;
    }
    let op = r.u16()?;
    r.u16()?;
    let mut a8 = || -> Option<&[u8]> {
        let n = r.u16()?;
        r.take(usize::from(n))
    };
    let (host, status, prefix) = match op {
        5 => {
            a8()?;
            (a8()?, a8()?, "")
        }
        6 => (a8()?, a8()?, "unwilling: "),
        _ => return None,
    };
    Some(Ident {
        product: Some("xdmcp".into()),
        title: text(host),
        banner: text(format!("{prefix}{}", sanitize(status)).as_bytes()),
        ..Ident::default()
    })
}

const ECHO: &[u8] = b"sensr-scan echo probe";

/// Echo (RFC 862).
fn echo_payload() -> Vec<u8> {
    ECHO.to_vec()
}

fn echo_parse(b: &[u8]) -> Option<Ident> {
    (b == ECHO).then(|| named("echo"))
}

/// Daytime (RFC 867): any datagram, even an empty one.
fn daytime_payload() -> Vec<u8> {
    Vec::new()
}

fn daytime_parse(b: &[u8]) -> Option<Ident> {
    let plain = b
        .iter()
        .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace());
    if !(6..=128).contains(&b.len()) || !plain || !b.iter().any(u8::is_ascii_digit) {
        return None;
    }
    Some(Ident {
        product: Some("daytime".into()),
        banner: text(b),
        ..Ident::default()
    })
}

// ---------------------------------------------------------------- games

const OOB: &[u8] = b"\xff\xff\xff\xff";

/// Source engine A2S_INFO (Valve "Server queries").
fn a2s_payload() -> Vec<u8> {
    [OOB, b"TSource Engine Query\0"].concat()
}

fn a2s_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::new(b.strip_prefix(OOB)?);
    match r.u8()? {
        b'A' => Some(Ident {
            product: Some("Source engine".into()),
            banner: Some("A2S challenge".into()),
            ..Ident::default()
        }),
        b'I' => {
            r.u8()?;
            let name = r.cstr()?;
            let map = r.cstr()?;
            r.cstr()?;
            let game = r.cstr()?;
            Some(Ident {
                product: text(game).or_else(|| Some("Source engine".into())),
                title: text(name),
                banner: text(map).map(|m| format!("map {m}")),
                ..Ident::default()
            })
        }
        _ => None,
    }
}

/// Quake III engine `getstatus` out-of-band packet.
fn quake3_payload() -> Vec<u8> {
    [OOB, b"getstatus\n"].concat()
}

fn quake3_parse(b: &[u8]) -> Option<Ident> {
    let rest = b.strip_prefix(OOB)?.strip_prefix(b"statusResponse")?;
    let s = String::from_utf8_lossy(rest);
    let info = s
        .trim_start_matches(['\r', '\n'])
        .lines()
        .next()
        .unwrap_or("");
    let mut f = info.split('\\').skip(1);
    let mut id = named("quake3");
    while let (Some(k), Some(v)) = (f.next(), f.next()) {
        // Drop ^N colour codes.
        let mut clean = String::new();
        let mut it = v.chars().peekable();
        while let Some(c) = it.next() {
            if c == '^' && it.peek().is_some_and(char::is_ascii_alphanumeric) {
                it.next();
            } else {
                clean.push(c);
            }
        }
        let v = text(clean.as_bytes());
        match k {
            "sv_hostname" => id.title = v,
            "gamename" => id.product = v.or(id.product),
            "version" => id.version = v,
            _ => {}
        }
    }
    Some(id)
}

const RAKNET_MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];

/// RakNet unconnected ping (Minecraft Bedrock and other RakNet games).
fn raknet_payload() -> Vec<u8> {
    let mut v = vec![0x01];
    v.extend([0; 8]);
    v.extend(RAKNET_MAGIC);
    v.extend(b"sensrrak");
    v
}

fn raknet_parse(b: &[u8]) -> Option<Ident> {
    let mut r = Rd::new(b);
    if r.u8()? != 0x1c {
        return None;
    }
    r.take(16)?; // time, server GUID
    if r.take(16)? != RAKNET_MAGIC {
        return None;
    }
    let s = r.u16().and_then(|n| r.take(usize::from(n))).unwrap_or(&[]);
    let s = String::from_utf8_lossy(s);
    let f: Vec<&str> = s.split(';').collect();
    let product = match f.first() {
        Some(&"MCPE") => "Minecraft Bedrock",
        Some(&"MCEE") => "Minecraft Education",
        _ => "RakNet",
    };
    Some(Ident {
        product: Some(product.into()),
        title: f.get(1).and_then(|v| text(v.as_bytes())),
        version: f.get(3).and_then(|v| text(v.as_bytes())),
        ..Ident::default()
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Ident;

    fn fixture(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/tests/fixtures/udp/{name}.hex",
            env!("CARGO_MANIFEST_DIR")
        );
        let text = std::fs::read_to_string(&path).expect(&path);
        let hex: String = text
            .lines()
            .map(|l| l.split('#').next().unwrap_or(""))
            .flat_map(|l| l.chars().filter(|c| !c.is_whitespace()))
            .collect();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn probe(service: &str) -> &'static UdpProbe {
        PROBES
            .iter()
            .find(|p| p.service == service)
            .unwrap_or_else(|| panic!("no probe {service}"))
    }

    fn parse(service: &str, fx: &str) -> Ident {
        (probe(service).parse)(&fixture(fx)).unwrap_or_else(|| panic!("{service} parsed nothing"))
    }

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    #[test]
    fn udp_probe_table_covers_the_required_services() {
        assert!(PROBES.len() >= 38, "{}", PROBES.len());
        for (port, svc) in [
            (53, "dns"),
            (123, "ntp"),
            (161, "snmp"),
            (1900, "ssdp"),
            (5353, "mdns"),
            (5353, "googlecast"),
            (137, "netbios-ns"),
            (67, "dhcp"),
            (69, "tftp"),
            (514, "syslog"),
            (500, "ike"),
            (3702, "ws-discovery"),
            (5683, "coap"),
            (1883, "mqtt-sn"),
            (11211, "memcached"),
            (520, "rip"),
            (5355, "llmnr"),
            (10001, "ubiquiti"),
            (5060, "sip"),
            (3478, "stun"),
        ] {
            assert_eq!(probe(svc).port, port, "{svc}");
        }
        for p in PROBES {
            assert!(
                !(p.payload)().is_empty() || p.service == "daytime",
                "{}",
                p.service
            );
            assert!((p.payload)().len() <= 1400, "{}", p.service);
        }
    }

    #[test]
    fn udp_dns_version_bind() {
        let q = (probe("dns").payload)();
        // QNAME version.bind, QTYPE TXT (16), QCLASS CH (3).
        assert!(q.ends_with(b"\x07version\x04bind\x00\x00\x10\x00\x03"));
        assert_eq!(&q[4..6], &[0, 1], "one question");
        let i = parse("dns", "dns-version-bind");
        assert_eq!(i.version, s("unbound 1.22"));
    }

    #[test]
    fn udp_ntp_client_and_server() {
        let q = (probe("ntp").payload)();
        assert_eq!(q.len(), 48);
        assert_eq!(q[0] & 7, 3, "mode 3 client");
        let i = parse("ntp", "ntp-server");
        assert_eq!(i.product, s("ntp"));
        let b = i.banner.unwrap();
        assert!(b.contains("stratum 2"), "{b}");
        assert!(b.contains("192.0.2.1"), "{b}");
        // A client-mode packet is not a server reply.
        assert_eq!((probe("ntp").parse)(&q), None);
    }

    #[test]
    fn udp_snmp_sysdescr() {
        let q = (probe("snmp").payload)();
        assert!(q.windows(8).any(|w| w == b"\x04\x06public"));
        assert!(
            q.windows(10)
                .any(|w| w == b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00")
        );
        assert_eq!(q[0], 0x30);
        assert_eq!(usize::from(q[1]) + 2, q.len());
        let i = parse("snmp", "snmp-sysdescr");
        assert_eq!(i.product, s("Linux nas 6.1"));
    }

    #[test]
    fn udp_ssdp_server_and_friendly_name() {
        let q = String::from_utf8((probe("ssdp").payload)()).unwrap();
        assert!(q.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(q.contains("ST: ssdp:all\r\n"));
        assert!(q.ends_with("\r\n\r\n"));
        let i = parse("ssdp", "ssdp-response");
        assert_eq!(i.product, s("Linux/6.1 UPnP/1.0 MiniDLNA/1.3.3"));
        assert_eq!(i.title, s("Living Room NAS"));
        let i = (probe("ssdp").parse)(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n").unwrap();
        assert_eq!((i.product, i.title), (s("x"), None));
    }

    #[test]
    fn udp_mdns_services_and_googlecast() {
        let q = (probe("mdns").payload)();
        assert!(q.ends_with(b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x80\x01"));
        let i = parse("mdns", "mdns-services");
        let b = i.banner.unwrap();
        assert!(
            b.contains("_http._tcp") && b.contains("_googlecast._tcp"),
            "{b}"
        );
        let q = (probe("googlecast").payload)();
        assert!(q.ends_with(b"\x0b_googlecast\x04_tcp\x05local\x00\x00\x0c\x80\x01"));
        let i = parse("googlecast", "mdns-googlecast");
        assert_eq!(i.product, s("Chromecast"));
        assert_eq!(i.title, s("Living Room TV"));
        // The service list is not a cast reply.
        assert_eq!((probe("googlecast").parse)(&fixture("mdns-services")), None);
    }

    #[test]
    fn udp_netbios_nbstat() {
        let q = (probe("netbios-ns").payload)();
        assert_eq!(q.len(), 50);
        assert_eq!(&q[12..15], b"\x20CK");
        assert_eq!(&q[46..], &[0, 0x21, 0, 1]);
        let i = parse("netbios-ns", "nbns-nbstat");
        assert_eq!(i.title, s("NAS"));
        let b = i.banner.unwrap();
        assert!(
            b.contains("WORKGROUP") && b.contains("00:11:22:33:44:55"),
            "{b}"
        );
    }

    #[test]
    fn udp_dhcp_inform() {
        let q = (probe("dhcp").payload)();
        assert_eq!(q[0], 1);
        assert_eq!(&q[236..240], b"\x63\x82\x53\x63");
        assert_eq!(&q[240..243], &[53, 1, 8], "DHCPINFORM");
        let i = parse("dhcp", "dhcp-ack");
        assert_eq!(i.product, s("dhcp"));
        let b = i.banner.unwrap();
        assert!(
            b.contains("DHCPACK") && b.contains("192.168.1.1") && b.contains("lan"),
            "{b}"
        );
    }

    #[test]
    fn udp_tftp_error() {
        let q = (probe("tftp").payload)();
        assert_eq!(&q[..2], &[0, 1], "RRQ");
        assert!(q.ends_with(b"\0octet\0"));
        let i = parse("tftp", "tftp-error");
        assert_eq!(i.product, s("tftp"));
        assert!(i.banner.unwrap().contains("File not found"));
    }

    #[test]
    fn udp_syslog_never_answers() {
        let q = (probe("syslog").payload)();
        assert!(q.starts_with(b"<"));
        assert_eq!((probe("syslog").parse)(b"anything"), None);
    }

    #[test]
    fn udp_ike_sa_init() {
        for svc in ["ike", "ike-natt"] {
            let q = (probe(svc).payload)();
            let h = if svc == "ike" { &q[..] } else { &q[4..] };
            assert_eq!(&h[16..20], &[33, 0x20, 34, 0x08], "{svc}");
            assert_eq!(
                u32::from_be_bytes(h[24..28].try_into().unwrap()) as usize,
                h.len()
            );
        }
        let i = parse("ike", "ike-no-proposal");
        assert_eq!((i.product, i.version), (s("ike"), s("2")));
        assert!(i.banner.unwrap().contains("NO_PROPOSAL_CHOSEN"));
        let mut natt = vec![0; 4];
        natt.extend(fixture("ike-no-proposal"));
        assert_eq!((probe("ike-natt").parse)(&natt).unwrap().product, s("ike"));
    }

    #[test]
    fn udp_ws_discovery() {
        let q = String::from_utf8((probe("ws-discovery").payload)()).unwrap();
        assert!(q.contains("discovery/Probe</") && q.contains("Probe/>"));
        let i = parse("ws-discovery", "wsd-probematches");
        assert_eq!(i.product, s("IPC-T100"));
        assert_eq!(i.title, s("Garage Cam"));
        assert_eq!(i.banner, s("dn:NetworkVideoTransmitter"));
    }

    #[test]
    fn udp_coap() {
        let q = (probe("coap").payload)();
        assert_eq!(q[0] >> 6, 1);
        assert_eq!(q[1], 0x01, "GET");
        assert!(q.ends_with(b"\xbb.well-known\x04core"));
        let i = parse("coap", "coap-core");
        assert_eq!(i.product, s("coap"));
        assert_eq!(i.banner, s("2.05 </sensors/temp>;rt=\"temperature\""));
    }

    #[test]
    fn udp_mqtt_sn() {
        assert_eq!((probe("mqtt-sn").payload)(), vec![3, 1, 1]);
        let i = parse("mqtt-sn", "mqttsn-gwinfo");
        assert_eq!(i.product, s("mqtt-sn"));
        assert_eq!(i.banner, s("gateway 7"));
    }

    #[test]
    fn udp_memcached() {
        let q = (probe("memcached").payload)();
        assert_eq!(&q[4..8], &[0, 1, 0, 0]);
        assert_eq!(&q[8..], b"stats\r\n");
        let i = parse("memcached", "memcached-stats");
        assert_eq!((i.product, i.version), (s("memcached"), s("1.6.21")));
    }

    #[test]
    fn udp_rip() {
        let q = (probe("rip").payload)();
        assert_eq!(q.len(), 24);
        assert_eq!(&q[..2], &[1, 2]);
        assert_eq!(&q[20..], &[0, 0, 0, 16]);
        let i = parse("rip", "rip-response");
        assert_eq!((i.product, i.version), (s("rip"), s("2")));
        assert_eq!(i.banner, s("2 routes"));
    }

    #[test]
    fn udp_llmnr() {
        let q = (probe("llmnr").payload)();
        assert!(q.ends_with(b"\x04wpad\x00\x00\x01\x00\x01"));
        let i = parse("llmnr", "llmnr-response");
        assert_eq!(i.product, s("llmnr"));
        assert_eq!(i.title, s("wpad"));
    }

    #[test]
    fn udp_ubiquiti() {
        assert_eq!((probe("ubiquiti").payload)(), vec![1, 0, 0, 0]);
        let i = parse("ubiquiti", "ubnt-discovery");
        assert_eq!(i.product, s("Ubiquiti U6-Lite"));
        assert_eq!(i.version, s("UAP6.6.55"));
        assert_eq!(i.title, s("office-ap"));
    }

    #[test]
    fn udp_sip_options() {
        let q = String::from_utf8((probe("sip").payload)()).unwrap();
        assert!(q.starts_with("OPTIONS sip:"));
        for h in [
            "Via: SIP/2.0/UDP ",
            ";branch=z9hG4bK",
            "CSeq: 1 OPTIONS",
            "Call-ID: ",
            "Max-Forwards: 70",
            "Content-Length: 0\r\n\r\n",
        ] {
            assert!(q.contains(h), "{h}");
        }
        let i = parse("sip", "sip-options-200");
        assert_eq!(i.product, s("Asterisk PBX 20.5.0"));
        assert_eq!(i.banner, s("SIP/2.0 200 OK"));
    }

    #[test]
    fn udp_stun() {
        let q = (probe("stun").payload)();
        assert_eq!(q.len(), 20);
        assert_eq!(&q[..8], &[0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42]);
        let i = parse("stun", "stun-binding");
        assert_eq!(i.product, s("coturn-4.6.2"));
    }

    #[test]
    fn udp_onc_rpc() {
        for (svc, prog) in [("rpcbind", 100_000u32), ("nfs", 100_003)] {
            let q = (probe(svc).payload)();
            assert_eq!(q.len(), 40);
            assert_eq!(&q[4..8], &[0, 0, 0, 0], "CALL");
            assert_eq!(u32::from_be_bytes(q[12..16].try_into().unwrap()), prog);
            assert_eq!(parse(svc, "rpc-null-reply").product, s(svc));
        }
        assert_eq!(parse("nfs", "rpc-prog-mismatch").version, s("2-4"));
    }

    #[test]
    fn udp_ipmi() {
        let q = (probe("ipmi").payload)();
        assert_eq!(&q[..4], &[6, 0, 0xff, 7]);
        // Both IPMB checksums make their bytes sum to zero.
        let m = &q[14..];
        assert_eq!(m[0].wrapping_add(m[1]).wrapping_add(m[2]), 0);
        assert_eq!(m[3..].iter().fold(0u8, |a, b| a.wrapping_add(*b)), 0);
        let i = parse("ipmi", "ipmi-auth-caps");
        assert_eq!((i.product, i.version), (s("ipmi"), s("2.0")));
    }

    #[test]
    fn udp_openvpn() {
        let q = (probe("openvpn").payload)();
        assert_eq!(q[0], 7 << 3);
        assert_eq!(parse("openvpn", "openvpn-reset").product, s("openvpn"));
    }

    #[test]
    fn udp_quic_version_negotiation() {
        let q = (probe("quic").payload)();
        assert_eq!(q.len(), 1200);
        assert_eq!(q[0] & 0xc0, 0xc0);
        assert_eq!(&q[1..5], &[0x1a, 0x2a, 0x3a, 0x4a]);
        let i = parse("quic", "quic-version-neg");
        assert_eq!(i.product, s("quic"));
        assert_eq!(i.banner, s("versions v1, v2, draft-29"));
    }

    #[test]
    fn udp_l2tp() {
        let q = (probe("l2tp").payload)();
        assert_eq!(&q[..2], &[0xc8, 0x02]);
        assert_eq!(usize::from(u16::from_be_bytes([q[2], q[3]])), q.len());
        let i = parse("l2tp", "l2tp-sccrp");
        assert_eq!((i.product, i.title), (s("xl2tpd"), s("lns-1")));
    }

    #[test]
    fn udp_games() {
        assert!((probe("a2s").payload)().ends_with(b"TSource Engine Query\0"));
        let i = parse("a2s", "a2s-info");
        assert_eq!((i.product, i.title), (s("Counter-Strike"), s("LAN Party")));
        assert_eq!(i.banner, s("map de_dust2"));
        assert_eq!(
            (probe("a2s").parse)(b"\xff\xff\xff\xffA\x01\x02\x03\x04")
                .unwrap()
                .product,
            s("Source engine")
        );
        let i = parse("quake3", "quake3-status");
        assert_eq!(i.title, s("Frag Fest"));
        assert_eq!(i.version, s("ioq3 1.36_GIT linux-x86_64"));
        assert_eq!(i.product, s("baseq3"));
        let q = (probe("raknet").payload)();
        assert_eq!((q[0], q.len()), (1, 33));
        let i = parse("raknet", "raknet-pong");
        assert_eq!(i.product, s("Minecraft Bedrock"));
        assert_eq!((i.title, i.version), (s("Family World"), s("1.20.40")));
    }

    #[test]
    fn udp_bacnet() {
        assert_eq!(
            (probe("bacnet").payload)(),
            vec![0x81, 0x0a, 0, 8, 1, 0, 0x10, 0x08]
        );
        let i = parse("bacnet", "bacnet-iam");
        assert_eq!((i.product, i.banner), (s("bacnet"), s("device 1234")));
    }

    #[test]
    fn udp_nat_pmp() {
        assert_eq!((probe("nat-pmp").payload)(), vec![0, 0]);
        let i = parse("nat-pmp", "natpmp-external");
        assert_eq!(
            (i.product, i.banner),
            (s("nat-pmp"), s("external address 203.0.113.7"))
        );
        assert_eq!(
            (probe("nat-pmp").parse)(&[2, 0x80, 0, 1]).unwrap().product,
            s("pcp")
        );
    }

    #[test]
    fn udp_echo_and_daytime() {
        let q = (probe("echo").payload)();
        assert_eq!((probe("echo").parse)(&q).unwrap().product, s("echo"));
        assert_eq!((probe("echo").parse)(b"other"), None);
        let i = parse("daytime", "daytime");
        assert_eq!(
            (i.product, i.banner),
            (s("daytime"), s("Tue Nov 25 10:20:30 2026"))
        );
    }

    #[test]
    fn udp_xdmcp() {
        assert_eq!((probe("xdmcp").payload)(), vec![0, 1, 0, 2, 0, 1, 0]);
        let i = parse("xdmcp", "xdmcp-willing");
        assert_eq!((i.title, i.banner), (s("devbox"), s("Linux 6.1.0 x86_64")));
    }

    #[test]
    fn udp_enip() {
        let q = (probe("enip").payload)();
        assert_eq!((q.len(), &q[..2]), (24, &[0x63, 0][..]));
        let i = parse("enip", "enip-list-identity");
        assert_eq!((i.product, i.version), (s("1756-L83E/B"), s("32.11")));
    }

    #[test]
    fn udp_plex_slp_mssql_mndp() {
        let i = parse("plex", "plex-gdm");
        assert_eq!(i.product, s("Plex Media Server"));
        assert_eq!(
            (i.title, i.version),
            (s("basement"), s("1.40.2.8395-c67dce28e"))
        );

        let q = (probe("slp").payload)();
        assert_eq!((q[0], q[1]), (2, 9));
        assert_eq!(usize::from(q[4]) | usize::from(q[3]) << 8, q.len());
        let i = parse("slp", "slp-srvtyperply");
        assert_eq!(i.banner, s("service:printer,service:ipp"));

        assert_eq!((probe("mssql").payload)(), vec![3]);
        let i = parse("mssql", "mssql-browser");
        assert_eq!(i.product, s("Microsoft SQL Server"));
        assert_eq!((i.title, i.version), (s("SQLBOX"), s("15.0.2000.5")));
        assert_eq!(i.banner, s("instance SQLEXPRESS"));

        let i = parse("mndp", "mndp");
        assert_eq!(i.product, s("MikroTik RB5009UG+S+"));
        assert_eq!(
            (i.title, i.version),
            (s("core-router"), s("7.16.1 (stable)"))
        );
    }

    #[test]
    fn udp_googlecast_bad_utf8_before_suffix() {
        // Lossy decoding turns 0xff into a 3-byte char straddling the offset
        // where the service suffix would start; this used to panic.
        let b = fixture("mdns-googlecast-badutf8");
        assert_eq!((probe("googlecast").parse)(&b), None);
        for p in PROBES {
            let _ = (p.parse)(&b);
        }
    }

    #[test]
    fn udp_parsers_survive_non_ascii_in_names() {
        // Replace every name byte of the DNS-family fixtures with 0xff, and
        // every pair with a 2-byte char, keeping the label lengths intact.
        for fx in [
            "dns-version-bind",
            "mdns-services",
            "mdns-googlecast",
            "llmnr-response",
            "nbns-nbstat",
        ] {
            let msg = fixture(fx);
            for i in 0..msg.len() {
                let c = msg[i];
                if !(c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
                    continue;
                }
                let mut a = msg.clone();
                a[i] = 0xff;
                let mut variants = vec![a];
                if i + 1 < msg.len() && msg[i + 1].is_ascii_alphanumeric() {
                    let mut e = msg.clone();
                    e[i..i + 2].copy_from_slice("é".as_bytes());
                    variants.push(e);
                }
                for v in &variants {
                    for p in PROBES {
                        let _ = (p.parse)(v);
                    }
                }
            }
        }
    }

    #[test]
    fn udp_parsers_survive_garbage() {
        let mut inputs: Vec<Vec<u8>> = vec![Vec::new(), vec![0xff; 3000], vec![0; 3000]];
        let dir = format!("{}/tests/fixtures/udp", env!("CARGO_MANIFEST_DIR"));
        for e in std::fs::read_dir(dir).unwrap() {
            let name = e.unwrap().file_name().into_string().unwrap();
            if let Some(stem) = name.strip_suffix(".hex") {
                inputs.push(fixture(stem));
            }
        }
        for p in PROBES {
            inputs.push((p.payload)());
        }
        // Every prefix and a few bit flips of each sample.
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut all = Vec::new();
        for i in &inputs {
            for n in 0..=i.len().min(400) {
                all.push(i[..n].to_vec());
            }
            for _ in 0..50 {
                let mut m = i.clone();
                if !m.is_empty() {
                    let len = m.len() as u64;
                    for _ in 0..4 {
                        let at = (next() % len) as usize;
                        m[at] = next() as u8;
                    }
                }
                all.push(m);
            }
        }
        for _ in 0..2000 {
            let n = (next() % 600) as usize;
            all.push((0..n).map(|_| next() as u8).collect());
        }
        for p in PROBES {
            for i in &all {
                if let Some(id) = (p.parse)(i) {
                    for f in [&id.product, &id.version, &id.title, &id.banner]
                        .into_iter()
                        .flatten()
                    {
                        assert!(f.len() <= crate::types::TEXT_MAX, "{}", p.service);
                        assert!(!f.chars().any(char::is_control), "{}", p.service);
                    }
                }
            }
        }
    }
}
