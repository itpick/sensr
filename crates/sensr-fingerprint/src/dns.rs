//! Plain DNS message reading (RFC 1035): the header, the first question and
//! the answer section's A, AAAA and CNAME records.
//!
//! The name reader here is shared with [`crate::mdns`]. Everything is read
//! with bounds-checked accessors: a damaged message gives `None` or what was
//! read before the damage, never a panic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Pointer hops allowed while reading one name.
const MAX_HOPS: usize = 16;
/// RFC 1035 name length limit.
const MAX_NAME: usize = 255;
/// Answer records kept per message (addresses and CNAMEs together).
pub const MAX_ANSWERS: usize = 32;

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// The parts of a DNS message the activity view uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsMessage {
    /// QR bit: a response rather than a query.
    pub response: bool,
    /// AA bit.
    pub authoritative: bool,
    /// The 4-bit RCODE (3 = NXDOMAIN).
    pub rcode: u8,
    /// First question's name, lowercased, dotted, without the root dot.
    pub qname: Option<String>,
    /// First question's type (0 when there is no question).
    pub qtype: u16,
    /// NSCOUNT from the header (authority records, e.g. a negative answer's SOA).
    pub authority_count: u16,
    /// A/AAAA/CNAME records of the answer section, in order.
    pub answers: Vec<Answer>,
}

/// One answer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// Owner name, lowercased, dotted.
    pub name: String,
    pub ttl: u32,
    pub data: RData,
}

/// The record data kinds we keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    Addr(IpAddr),
    /// CNAME target, lowercased, dotted.
    Cname(String),
}

/// Parse a DNS message (query or response). `None` when the 12-byte header
/// is missing; a damaged question or answer section yields what was read
/// before the damage.
pub fn parse_message(p: &[u8]) -> Option<DnsMessage> {
    let flags = u16_at(p, 2)?;
    let qdcount = u16_at(p, 4)?;
    let ancount = u16_at(p, 6)?;
    let nscount = u16_at(p, 8)?;
    u16_at(p, 10)?; // ARCOUNT: the header is 12 bytes
    let mut m = DnsMessage {
        response: flags & 0x8000 != 0,
        authoritative: flags & 0x0400 != 0,
        rcode: (flags & 0x000f) as u8,
        authority_count: nscount,
        ..DnsMessage::default()
    };
    let _ = walk(p, qdcount, ancount, &mut m);
    Some(m)
}

/// [`parse_message`] restricted to responses (QR = 1).
pub fn parse_response(p: &[u8]) -> Option<DnsMessage> {
    parse_message(p).filter(|m| m.response)
}

/// Reads the questions and answers; `None` means it hit damage and stopped.
fn walk(p: &[u8], qdcount: u16, ancount: u16, m: &mut DnsMessage) -> Option<()> {
    let mut pos = 12usize;
    for i in 0..qdcount {
        let (labels, next) = read_name(p, pos)?;
        let qtype = u16_at(p, next)?;
        u16_at(p, next.checked_add(2)?)?; // QCLASS
        if i == 0 {
            m.qname = Some(dotted(&labels));
            m.qtype = qtype;
        }
        pos = next.checked_add(4)?;
    }
    for _ in 0..ancount {
        let (owner, next) = read_name(p, pos)?;
        let rtype = u16_at(p, next)?;
        let class = u16_at(p, next.checked_add(2)?)?;
        let ttl = u32_at(p, next.checked_add(4)?)?;
        let rdlen = usize::from(u16_at(p, next.checked_add(8)?)?);
        let start = next.checked_add(10)?;
        let end = start.checked_add(rdlen)?;
        let rdata = p.get(start..end)?;
        pos = end;
        if m.answers.len() >= MAX_ANSWERS {
            break;
        }
        if class != CLASS_IN {
            continue;
        }
        let data = match rtype {
            TYPE_A => <[u8; 4]>::try_from(rdata)
                .ok()
                .map(|b| RData::Addr(IpAddr::V4(Ipv4Addr::from(b)))),
            TYPE_AAAA => <[u8; 16]>::try_from(rdata)
                .ok()
                .map(|b| RData::Addr(IpAddr::V6(Ipv6Addr::from(b)))),
            // The target's uncompressed part must lie inside rdata.
            TYPE_CNAME => read_name(p, start)
                .filter(|&(_, after)| after <= end)
                .map(|(t, _)| RData::Cname(dotted(&t))),
            _ => None,
        };
        if let Some(data) = data {
            m.answers.push(Answer {
                name: dotted(&owner),
                ttl,
                data,
            });
        }
    }
    Some(())
}

fn dotted(labels: &[String]) -> String {
    labels.join(".").to_ascii_lowercase()
}

pub(crate) fn u16_at(p: &[u8], at: usize) -> Option<u16> {
    let b = p.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
}

fn u32_at(p: &[u8], at: usize) -> Option<u32> {
    let b = p.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes(b.try_into().ok()?))
}

/// Read a possibly compressed name at `pos`; returns its labels and the
/// offset just past it in the record stream. Loops, over-long labels and
/// reserved label types give `None`.
pub(crate) fn read_name(p: &[u8], pos: usize) -> Option<(Vec<String>, usize)> {
    let mut labels = Vec::new();
    let mut at = pos;
    let mut after = None;
    let mut hops = 0;
    let mut total = 0usize;
    loop {
        let len = *p.get(at)?;
        match len & 0xc0 {
            0x00 if len == 0 => return Some((labels, after.unwrap_or(at.checked_add(1)?))),
            // Top bits 00: a plain label, so its length is at most 63.
            0x00 => {
                let n = usize::from(len);
                total = total.checked_add(n + 1)?;
                if total > MAX_NAME {
                    return None;
                }
                let from = at.checked_add(1)?;
                let raw = p.get(from..from.checked_add(n)?)?;
                labels.push(String::from_utf8_lossy(raw).into_owned());
                at = from.checked_add(n)?;
            }
            0xc0 => {
                let lo = *p.get(at.checked_add(1)?)?;
                after.get_or_insert(at.checked_add(2)?);
                hops += 1;
                if hops > MAX_HOPS {
                    return None;
                }
                at = (usize::from(len & 0x3f) << 8) | usize::from(lo);
            }
            // Top bits 01 / 10: extended or reserved label types. A length
            // byte of 64..=191 lands here, which is how a label over 63
            // bytes is rejected.
            _ => return None,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mdns::tests::name;

    pub(crate) fn header(id: u16, flags: u16, qd: u16, an: u16, ns: u16) -> Vec<u8> {
        let mut h = Vec::new();
        for v in [id, flags, qd, an, ns, 0] {
            h.extend_from_slice(&v.to_be_bytes());
        }
        h
    }

    pub(crate) fn rr(out: &mut Vec<u8>, owner: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) {
        out.extend_from_slice(owner);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }

    /// `www.youtube.com` → CNAME `youtube-ui.l.google.com` → two A records,
    /// with compression pointers as a real resolver writes them.
    pub(crate) fn youtube_response() -> Vec<u8> {
        let mut p = header(0x1234, 0x8180, 1, 3, 0);
        p.extend_from_slice(&name(&["WWW", "youtube", "com"]));
        p.extend_from_slice(&[0, 1, 0, 1]);
        // The question name sits at offset 12; "com" at 12 + 4 + 8 = 24.
        let mut target = name(&["youtube-ui", "l", "google"]);
        target.pop();
        target.extend_from_slice(&[0xc0, 24]);
        let cname_rr = p.len();
        rr(&mut p, &[0xc0, 12], TYPE_CNAME, 300, &target);
        let target_at = (cname_rr + 2 + 10) as u8;
        rr(&mut p, &[0xc0, target_at], TYPE_A, 120, &[142, 250, 1, 1]);
        rr(&mut p, &[0xc0, target_at], TYPE_A, 60, &[142, 250, 1, 2]);
        p
    }

    #[test]
    fn dns_response_with_cname_and_addresses() {
        let m = parse_response(&youtube_response()).expect("parses");
        assert!(m.response);
        assert_eq!(m.rcode, 0);
        assert_eq!(m.qname.as_deref(), Some("www.youtube.com"));
        assert_eq!(m.qtype, 1);
        assert_eq!(
            m.answers,
            vec![
                Answer {
                    name: "www.youtube.com".into(),
                    ttl: 300,
                    data: RData::Cname("youtube-ui.l.google.com".into()),
                },
                Answer {
                    name: "youtube-ui.l.google.com".into(),
                    ttl: 120,
                    data: RData::Addr("142.250.1.1".parse().unwrap()),
                },
                Answer {
                    name: "youtube-ui.l.google.com".into(),
                    ttl: 60,
                    data: RData::Addr("142.250.1.2".parse().unwrap()),
                },
            ]
        );
    }

    #[test]
    fn dns_query_and_nxdomain_and_aaaa() {
        let mut q = header(1, 0x0100, 1, 0, 0);
        q.extend_from_slice(&name(&["example", "org"]));
        q.extend_from_slice(&[0, 28, 0, 1]);
        let m = parse_message(&q).expect("parses");
        assert!(!m.response);
        assert_eq!(parse_response(&q), None);
        assert_eq!(m.qname.as_deref(), Some("example.org"));
        assert_eq!(m.qtype, 28);

        let mut r = header(1, 0x8583, 1, 1, 0);
        r.extend_from_slice(&name(&["example", "org"]));
        r.extend_from_slice(&[0, 28, 0, 1]);
        rr(&mut r, &[0xc0, 12], TYPE_AAAA, 7, &[0; 16]);
        let m = parse_response(&r).expect("parses");
        assert_eq!(m.rcode, 3);
        assert!(m.authoritative);
        assert_eq!(m.authority_count, 0);
        assert_eq!(
            m.answers.first().map(|a| &a.data),
            Some(&RData::Addr("::".parse().unwrap()))
        );
    }

    #[test]
    fn dns_damage_keeps_what_was_read() {
        let full = youtube_response();
        // Cut inside the last A record: the CNAME and first A survive.
        let m = parse_response(&full[..full.len() - 2]).expect("header");
        assert_eq!(m.answers.len(), 2);
        // A wrong-sized A rdata is skipped, not misread.
        let mut p = header(1, 0x8180, 0, 2, 0);
        rr(&mut p, &name(&["a"]), TYPE_A, 1, &[1, 2, 3]);
        rr(&mut p, &name(&["a"]), TYPE_A, 1, &[1, 2, 3, 4]);
        let m = parse_response(&p).expect("header");
        assert_eq!(m.answers.len(), 1);
        // A CNAME whose target runs past its rdata is dropped.
        let mut p = header(1, 0x8180, 0, 1, 0);
        let t = name(&["x", "y"]);
        rr(&mut p, &name(&["a"]), TYPE_CNAME, 1, &t[..2]);
        p.extend_from_slice(&t[2..]);
        assert!(parse_response(&p).expect("header").answers.is_empty());
        // A pointer loop in the owner stops the walk.
        let mut p = header(1, 0x8180, 0, 1, 0);
        rr(&mut p, &[0xc0, 12], TYPE_A, 1, &[1, 2, 3, 4]);
        assert!(parse_response(&p).expect("header").answers.is_empty());
        assert_eq!(parse_message(&[0; 11]), None);
    }

    #[test]
    fn dns_answers_are_capped() {
        let mut p = header(1, 0x8180, 0, 100, 0);
        for i in 0..100u8 {
            rr(&mut p, &name(&["a"]), TYPE_A, 1, &[10, 0, 0, i]);
        }
        assert_eq!(
            parse_response(&p).expect("parses").answers.len(),
            MAX_ANSWERS
        );
    }
}
