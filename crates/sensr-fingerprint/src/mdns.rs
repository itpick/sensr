//! mDNS / DNS-SD response parsing: advertised service types, model and name.

/// What an mDNS response tells us about the sender.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdnsInfo {
    /// Service types such as `_googlecast._tcp`, lowercased, without `.local`.
    pub services: Vec<String>,
    /// First non-empty TXT `model=`, `md=` or `am=` value.
    pub model: Option<String>,
    /// Instance label of the first SRV/TXT owner, e.g. `Living Room`.
    pub instance: Option<String>,
}

/// Parse an mDNS response. Queries (QR = 0) and short headers give `None`.
///
/// Records are read from the answer, authority and additional sections. A
/// malformed record stops the walk and returns what was read before it.
pub fn parse(udp_payload: &[u8]) -> Option<MdnsInfo> {
    let p = udp_payload;
    let flags = u16_at(p, 2)?;
    if flags & 0x8000 == 0 {
        return None;
    }
    let questions = u16_at(p, 4)?;
    let records = [6, 8, 10]
        .iter()
        .map(|&at| u16_at(p, at).map(usize::from))
        .sum::<Option<usize>>()?;
    let mut info = MdnsInfo::default();
    let _ = walk(p, questions, records, &mut info);
    Some(info)
}

const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_SRV: u16 = 33;
/// Pointer hops allowed while reading one name.
const MAX_HOPS: usize = 16;
/// RFC 1035 limits.
const MAX_LABEL: usize = 63;
const MAX_NAME: usize = 255;

fn u16_at(p: &[u8], at: usize) -> Option<u16> {
    let b = p.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
}

/// Reads every record; `None` means the walk hit damage and stopped.
fn walk(p: &[u8], questions: u16, records: usize, info: &mut MdnsInfo) -> Option<()> {
    let mut pos = 12usize;
    for _ in 0..questions {
        let (_, next) = read_name(p, pos)?;
        pos = next.checked_add(4)?; // QTYPE, QCLASS
    }
    for _ in 0..records {
        let (owner, next) = read_name(p, pos)?;
        let rtype = u16_at(p, next)?;
        let rdlen = usize::from(u16_at(p, next.checked_add(8)?)?);
        let start = next.checked_add(10)?;
        let end = start.checked_add(rdlen)?;
        let rdata = p.get(start..end)?;
        pos = end;
        match rtype {
            TYPE_PTR => {
                let service = if is_services_meta(&owner) {
                    read_name(p, start).and_then(|(target, _)| service_type(&target))
                } else {
                    service_type(&owner)
                };
                if let Some(s) = service
                    && !info.services.contains(&s)
                {
                    info.services.push(s);
                }
            }
            TYPE_TXT | TYPE_SRV => {
                if info.instance.is_none() {
                    info.instance = instance(&owner);
                }
                if rtype == TYPE_TXT && info.model.is_none() {
                    info.model = txt_model(rdata);
                }
            }
            _ => {}
        }
    }
    Some(())
}

/// Read a possibly compressed name at `pos`; returns its labels and the
/// offset just past it in the record stream. Loops, over-long labels and
/// reserved label types give `None`.
fn read_name(p: &[u8], pos: usize) -> Option<(Vec<String>, usize)> {
    let mut labels = Vec::new();
    let mut at = pos;
    let mut after = None;
    let mut hops = 0;
    let mut total = 0usize;
    loop {
        let len = *p.get(at)?;
        match len & 0xc0 {
            0x00 if len == 0 => return Some((labels, after.unwrap_or(at + 1))),
            0x00 => {
                let n = usize::from(len);
                if n > MAX_LABEL {
                    return None;
                }
                total += n + 1;
                if total > MAX_NAME {
                    return None;
                }
                let raw = p.get(at + 1..at + 1 + n)?;
                labels.push(String::from_utf8_lossy(raw).into_owned());
                at += 1 + n;
            }
            0xc0 => {
                let lo = *p.get(at + 1)?;
                after.get_or_insert(at + 2);
                hops += 1;
                if hops > MAX_HOPS {
                    return None;
                }
                at = (usize::from(len & 0x3f) << 8) | usize::from(lo);
            }
            // 0x40 / 0x80: extended or reserved label types (or a length
            // byte over 63); not valid in mDNS.
            _ => return None,
        }
    }
}

fn eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn is_services_meta(labels: &[String]) -> bool {
    let want = ["_services", "_dns-sd", "_udp", "local"];
    labels.len() == want.len() && labels.iter().zip(want).all(|(l, w)| eq(l, w))
}

/// `[.., "_x", "_tcp"|"_udp", "local"]` → `"_x._tcp"` (lowercased).
fn service_type(labels: &[String]) -> Option<String> {
    let [.., svc, proto, local] = labels else {
        return None;
    };
    let ok = eq(local, "local")
        && (eq(proto, "_tcp") || eq(proto, "_udp"))
        && svc.len() > 1
        && svc.starts_with('_');
    let s = format!("{svc}.{proto}").to_ascii_lowercase();
    (ok && s != "_dns-sd._udp").then_some(s)
}

/// `["Living Room", "_x", "_tcp", "local"]` → `"Living Room"`.
fn instance(labels: &[String]) -> Option<String> {
    let [inst, rest @ ..] = labels else {
        return None;
    };
    (rest.len() == 3 && service_type(rest).is_some() && !inst.is_empty()).then(|| inst.clone())
}

/// First non-empty `model=`, `md=` or `am=` value in TXT rdata.
fn txt_model(rdata: &[u8]) -> Option<String> {
    let mut at = 0usize;
    while let Some(&len) = rdata.get(at) {
        let entry = rdata.get(at + 1..at + 1 + usize::from(len))?;
        at += 1 + usize::from(len);
        let entry = String::from_utf8_lossy(entry);
        let Some((key, value)) = entry.split_once('=') else {
            continue;
        };
        if ["model", "md", "am"].iter().any(|k| eq(key, k)) && !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn name(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for l in labels {
            out.push(l.len() as u8);
            out.extend_from_slice(l.as_bytes());
        }
        out.push(0);
        out
    }

    fn record(out: &mut Vec<u8>, owner: &[u8], rtype: u16, rdata: &[u8]) {
        out.extend_from_slice(owner);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&0x8001u16.to_be_bytes()); // cache-flush, IN
        out.extend_from_slice(&120u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }

    fn txt(entries: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in entries {
            out.push(e.len() as u8);
            out.extend_from_slice(e.as_bytes());
        }
        out
    }

    fn header(flags: u16, qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
        let mut h = Vec::new();
        for v in [0u16, flags, qd, an, ns, ar] {
            h.extend_from_slice(&v.to_be_bytes());
        }
        h
    }

    /// A Chromecast-style response using name compression throughout.
    pub(crate) fn chromecast_response() -> Vec<u8> {
        let mut p = header(0x8400, 0, 3, 0, 1);
        // Answer 1 at offset 12: PTR _services._dns-sd._udp.local -> _googlecast._tcp.local
        let owner = name(&["_services", "_dns-sd", "_udp", "local"]);
        // "local" label sits at 12 + 1+9 + 1+7 + 1+4 = 35.
        let local_ptr = [0xc0, 35];
        let mut target = vec![11];
        target.extend_from_slice(b"_googlecast");
        target.push(4);
        target.extend_from_slice(b"_tcp");
        target.extend_from_slice(&local_ptr);
        let services_rr_start = p.len();
        record(&mut p, &owner, 12, &target);
        // Offset of the target name inside the rdata: after owner + 10 bytes.
        let gc_off = (services_rr_start + owner.len() + 10) as u8;
        // Answer 2: PTR _googlecast._tcp.local (compressed) -> Living Room._googlecast._tcp.local
        let mut inst = vec![11];
        inst.extend_from_slice(b"Living Room");
        inst.extend_from_slice(&[0xc0, gc_off]);
        let inst_rr_start = p.len();
        record(&mut p, &[0xc0, gc_off], 12, &inst);
        let inst_off = (inst_rr_start + 2 + 10) as u8;
        // Answer 3: TXT on the instance (compressed owner)
        record(
            &mut p,
            &[0xc0, inst_off],
            16,
            &txt(&["id=abc", "MD=", "md=Chromecast", "model=Later"]),
        );
        // Additional: SRV on the instance
        let mut srv = vec![0, 0, 0, 0, 0x1f, 0x49];
        srv.extend_from_slice(&name(&["cc-1234", "local"]));
        record(&mut p, &[0xc0, inst_off], 33, &srv);
        p
    }

    #[test]
    fn mdns_response_parses() {
        let i = parse(&chromecast_response()).expect("parses");
        assert_eq!(i.services, vec!["_googlecast._tcp".to_string()]);
        assert_eq!(i.model.as_deref(), Some("Chromecast"));
        assert_eq!(i.instance.as_deref(), Some("Living Room"));
    }

    #[test]
    fn mdns_query_is_ignored() {
        let mut p = chromecast_response();
        p[2] &= 0x7f; // clear QR
        assert_eq!(parse(&p), None);
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[0; 11]), None);
    }

    #[test]
    fn mdns_skips_questions_and_reads_authority() {
        let mut p = header(0x8400, 1, 0, 1, 0);
        p.extend_from_slice(&name(&["_ipp", "_tcp", "local"]));
        p.extend_from_slice(&[0, 12, 0, 1]);
        record(
            &mut p,
            &name(&["_ipp", "_tcp", "local"]),
            12,
            &name(&["Office", "_ipp", "_tcp", "local"]),
        );
        let i = parse(&p).expect("parses");
        assert_eq!(i.services, vec!["_ipp._tcp".to_string()]);
    }

    #[test]
    fn mdns_txt_model_keys_are_case_insensitive() {
        let mut p = header(0x8400, 0, 1, 0, 0);
        record(
            &mut p,
            &name(&["Lucas MacBook", "_device-info", "_tcp", "local"]),
            16,
            &txt(&["Model=MacBookPro18,1", "osxvers=23"]),
        );
        let i = parse(&p).expect("parses");
        assert_eq!(i.model.as_deref(), Some("MacBookPro18,1"));
        assert_eq!(i.instance.as_deref(), Some("Lucas MacBook"));
        assert!(i.services.is_empty());
    }

    #[test]
    fn mdns_pointer_loop_is_rejected() {
        // Answer owner is a pointer to itself.
        let mut p = header(0x8400, 0, 1, 0, 0);
        record(&mut p, &[0xc0, 12], 12, &name(&["_ipp", "_tcp", "local"]));
        let i = parse(&p).expect("header is fine");
        assert!(i.services.is_empty());
        // Two pointers pointing at each other in rdata.
        let mut p = header(0x8400, 0, 2, 0, 0);
        record(
            &mut p,
            &name(&["_services", "_dns-sd", "_udp", "local"]),
            12,
            &[0xc0, 0x00],
        );
        let at = p.len() - 2;
        p[at + 1] = at as u8; // rdata pointer points to itself
        record(&mut p, &name(&["_hap", "_tcp", "local"]), 12, &[0xc0, 12]);
        let i = parse(&p).expect("header is fine");
        assert!(!i.services.iter().any(|s| s.contains("dns-sd")));
    }

    #[test]
    fn mdns_label_over_63_bytes_is_rejected() {
        let long = "a".repeat(64);
        let mut p = header(0x8400, 0, 1, 0, 0);
        let mut owner = vec![64];
        owner.extend_from_slice(long.as_bytes());
        owner.extend_from_slice(&name(&["_ipp", "_tcp", "local"]));
        record(&mut p, &owner, 16, &txt(&["model=X"]));
        let i = parse(&p).expect("header is fine");
        assert_eq!(i.model, None);
        assert_eq!(i.instance, None);
    }

    #[test]
    fn mdns_duplicate_services_are_reported_once() {
        let mut p = header(0x8400, 0, 3, 0, 0);
        let svc = name(&["_services", "_dns-sd", "_udp", "local"]);
        record(&mut p, &svc, 12, &name(&["_hap", "_tcp", "local"]));
        record(&mut p, &svc, 12, &name(&["_HAP", "_tcp", "local"]));
        record(&mut p, &svc, 12, &name(&["_raop", "_tcp", "local"]));
        let i = parse(&p).expect("parses");
        assert_eq!(
            i.services,
            vec!["_hap._tcp".to_string(), "_raop._tcp".into()]
        );
    }
}
