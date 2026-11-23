//! Unbound's dnstap feed: Frame Streams framing, the dnstap protobuf and the
//! DNS messages inside it, all decoded by hand (no protobuf crate).
//!
//! **Frame Streams** (fstrm, the bidirectional mode Unbound uses on a Unix
//! socket): every frame is a 4-byte big-endian length and that many bytes. A
//! length of 0 escapes a control frame: a 4-byte control length, a 4-byte
//! control type, then optional `CONTENT_TYPE` fields (type 1, a 4-byte
//! length, the bytes). The writer sends READY with the content types it
//! offers; the reader answers ACCEPT with the one it takes; the writer sends
//! START, data frames, then STOP, which the reader answers with FINISH.
//!
//! **dnstap.proto** field numbers, checked against upstream
//! <https://github.com/dnstap/dnstap.pb/blob/master/dnstap.proto>:
//! `Dnstap { type = 15 (MESSAGE = 1), message = 14 }`;
//! `Message { type = 1 (CLIENT_QUERY = 5, CLIENT_RESPONSE = 6),
//! socket_family = 2 (INET = 1, INET6 = 2), query_address = 4,
//! query_time_sec = 8, query_message = 10, response_time_sec = 12,
//! response_message = 14 }`.
//!
//! Nothing here panics on input: every read is bounds-checked, every length
//! is capped, and a damaged frame is dropped while the stream carries on.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sensr_fingerprint::dns::{self, RData};

/// The only content type we accept.
pub const CONTENT_TYPE: &[u8] = b"protobuf:dnstap.Dnstap";
/// Largest data frame delivered; bigger ones are skipped.
pub const MAX_FRAME: usize = 128 * 1024;
/// Largest frame we skip over. A longer length is not something a writer
/// produces, so the stream is treated as lost (the caller closes it and the
/// writer reconnects at a frame boundary).
pub const MAX_SKIP: usize = 16 * 1024 * 1024;
/// fstrm's control frame limit.
const MAX_CONTROL: usize = 512;
/// Fields allowed in one control frame.
const MAX_CONTENT_TYPES: usize = 8;

const ACCEPT: u32 = 0x01;
const START: u32 = 0x02;
const STOP: u32 = 0x03;
const READY: u32 = 0x04;
const FINISH: u32 = 0x05;
const FIELD_CONTENT_TYPE: u32 = 0x01;

/// What [`FrameReader::push`] hands out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// One data frame's payload (a serialized `Dnstap`).
    Data(Vec<u8>),
    /// The writer sent STOP: send [`FrameReader::reply`] (FINISH) and close.
    Stop,
}

/// Incremental Frame Streams reader for one connection.
///
/// It buffers at most one partial frame (≤ [`MAX_FRAME`] + 8 bytes).
#[derive(Debug, Default)]
pub struct FrameReader {
    buf: Vec<u8>,
    /// Bytes of an oversized frame still to discard.
    skip: usize,
    /// Control replies waiting to be written back.
    out: Vec<u8>,
    /// A START with our content type (or none) was seen, and no STOP yet.
    started: bool,
    /// STOP seen, or the stream is lost: nothing more is delivered.
    done: bool,
    dropped: u64,
}

impl FrameReader {
    /// Feed bytes read from the socket; returns the frames they complete.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Frame> {
        let mut frames = Vec::new();
        if self.done {
            return frames;
        }
        let mut input = bytes;
        if self.skip > 0 {
            let n = self.skip.min(input.len());
            self.skip -= n;
            input = input.get(n..).unwrap_or_default();
        }
        self.buf.extend_from_slice(input);
        let mut at = 0usize;
        while !self.done {
            if self.skip > 0 {
                let n = self.skip.min(self.buf.len().saturating_sub(at));
                self.skip -= n;
                at += n;
                if self.skip > 0 {
                    break;
                }
            }
            let Some(len) = be32(&self.buf, at) else {
                break;
            };
            if len != 0 {
                if len > MAX_FRAME {
                    self.oversize(len);
                    at += 4;
                    continue;
                }
                let Some(payload) = slice(&self.buf, at + 4, len) else {
                    break;
                };
                if self.started {
                    frames.push(Frame::Data(payload.to_vec()));
                } else {
                    self.dropped += 1;
                }
                at += 4 + len;
                continue;
            }
            let Some(clen) = be32(&self.buf, at + 4) else {
                break;
            };
            if !(4..=MAX_CONTROL).contains(&clen) {
                self.oversize(clen);
                at += 8;
                continue;
            }
            let Some(body) = slice(&self.buf, at + 8, clen) else {
                break;
            };
            let control = parse_control(body);
            at += 8 + clen;
            match control {
                Some(c) => self.control(c, &mut frames),
                None => self.dropped += 1,
            }
        }
        if self.done {
            self.buf = Vec::new();
        } else {
            self.buf.drain(..at.min(self.buf.len()));
        }
        frames
    }

    /// Bytes to write back to the writer (ACCEPT, FINISH), once.
    pub fn reply(&mut self) -> Option<Vec<u8>> {
        (!self.out.is_empty()).then(|| std::mem::take(&mut self.out))
    }

    /// STOP was received or the stream is lost: write any reply and close.
    pub fn finished(&self) -> bool {
        self.done
    }

    /// Bytes held for a partial frame.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Frames dropped: oversized, malformed control, or data out of turn.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    fn oversize(&mut self, len: usize) {
        self.dropped += 1;
        if len > MAX_SKIP {
            self.done = true;
        } else {
            self.skip = len;
        }
    }

    fn control(&mut self, c: Control, frames: &mut Vec<Frame>) {
        match c.ctype {
            READY => {
                let offer: &[&[u8]] = if c.ours { &[CONTENT_TYPE] } else { &[] };
                self.out.extend(encode_control(ACCEPT, offer));
                // nothing we can read is offered: answer, then close
                self.done |= !c.ours;
            }
            // a START naming another content type: the writer did not take
            // ours, so the stream is useless
            START if c.typed && !c.ours => self.done = true,
            START => self.started = true,
            STOP => {
                self.out.extend(encode_control(FINISH, &[]));
                self.started = false;
                self.done = true;
                frames.push(Frame::Stop);
            }
            _ => self.dropped += 1,
        }
    }
}

fn be32(p: &[u8], at: usize) -> Option<usize> {
    let b = p.get(at..at.checked_add(4)?)?;
    usize::try_from(u32::from_be_bytes(b.try_into().ok()?)).ok()
}

fn slice(p: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    p.get(at..at.checked_add(len)?)
}

/// A parsed control frame.
struct Control {
    ctype: u32,
    /// Any `CONTENT_TYPE` field present.
    typed: bool,
    /// One of them is [`CONTENT_TYPE`].
    ours: bool,
}

/// Parse a control frame body. Malformed gives `None`.
fn parse_control(body: &[u8]) -> Option<Control> {
    let ctype = u32::try_from(be32(body, 0)?).ok()?;
    let mut c = Control {
        ctype,
        typed: false,
        ours: false,
    };
    let mut at = 4usize;
    let mut fields = 0usize;
    while at < body.len() {
        let ftype = u32::try_from(be32(body, at)?).ok()?;
        let flen = be32(body, at.checked_add(4)?)?;
        let value = slice(body, at.checked_add(8)?, flen)?;
        at = at.checked_add(8)?.checked_add(flen)?;
        fields += 1;
        if fields > MAX_CONTENT_TYPES {
            return None;
        }
        if ftype == FIELD_CONTENT_TYPE {
            c.typed = true;
            c.ours |= value == CONTENT_TYPE;
        }
    }
    Some(c)
}

fn encode_control(ctype: u32, content_types: &[&[u8]]) -> Vec<u8> {
    let mut body = ctype.to_be_bytes().to_vec();
    for ct in content_types {
        body.extend_from_slice(&FIELD_CONTENT_TYPE.to_be_bytes());
        body.extend_from_slice(&u32::try_from(ct.len()).unwrap_or(0).to_be_bytes());
        body.extend_from_slice(ct);
    }
    let mut f = vec![0, 0, 0, 0];
    f.extend_from_slice(&u32::try_from(body.len()).unwrap_or(0).to_be_bytes());
    f.extend_from_slice(&body);
    f
}

// ---- protobuf ----------------------------------------------------------

/// A protobuf field value (the two wire types we use; fixed-width fields are
/// skipped).
#[derive(Clone, Copy)]
enum Val<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed,
}

fn read_varint(p: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..10u32 {
        let b = *p.get(*at)?;
        *at += 1;
        // The 10th byte holds bit 63 only.
        if i == 9 && b > 1 {
            return None;
        }
        v |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// Calls `f` for every field of a message; `None` on any damage.
fn each_field<'a>(p: &'a [u8], mut f: impl FnMut(u32, Val<'a>)) -> Option<()> {
    let mut at = 0usize;
    while at < p.len() {
        let key = read_varint(p, &mut at)?;
        let field = u32::try_from(key >> 3).ok().filter(|&n| n != 0)?;
        let val = match key & 7 {
            0 => Val::Varint(read_varint(p, &mut at)?),
            1 => {
                at = at.checked_add(8).filter(|&e| e <= p.len())?;
                Val::Fixed
            }
            2 => {
                let len = usize::try_from(read_varint(p, &mut at)?).ok()?;
                let b = slice(p, at, len)?;
                at += len;
                Val::Bytes(b)
            }
            5 => {
                at = at.checked_add(4).filter(|&e| e <= p.len())?;
                Val::Fixed
            }
            // 3/4: deprecated groups; 6/7: undefined.
            _ => return None,
        };
        f(field, val);
    }
    Some(())
}

// ---- dnstap ------------------------------------------------------------

/// Which side of a client lookup the event is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    ClientQuery,
    ClientResponse,
}

/// One client query or response from Unbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnstapEvent {
    pub kind: EventKind,
    /// The client that asked (`query_address`).
    pub client: IpAddr,
    /// Unix seconds: the response time for a response, else the query time.
    pub time: i64,
    /// Question name, lowercased, no trailing dot.
    pub qname: String,
    pub qtype: u16,
    /// RCODE (responses; 0 for queries).
    pub rcode: u8,
    /// Authority records in the response (NSCOUNT). Distinguishes a local
    /// `always_nxdomain` answer (none) from an upstream one (the SOA).
    pub authority_count: u16,
    /// A/AAAA answers with their TTLs.
    pub answers: Vec<(IpAddr, u32)>,
    /// CNAME targets in the answer section, in order.
    pub cnames: Vec<String>,
}

const DNSTAP_TYPE_MESSAGE: u64 = 1;
const MESSAGE_CLIENT_QUERY: u64 = 5;
const MESSAGE_CLIENT_RESPONSE: u64 = 6;
const FAMILY_INET: u64 = 1;
const FAMILY_INET6: u64 = 2;

/// Decode one data frame. Anything but a well-formed `CLIENT_QUERY` or
/// `CLIENT_RESPONSE` with a client address and a question gives `None`.
pub fn decode(frame: &[u8]) -> Option<DnstapEvent> {
    let mut dtype = None;
    let mut message = None;
    each_field(frame, |n, v| match (n, v) {
        (15, Val::Varint(t)) => dtype = Some(t),
        (14, Val::Bytes(b)) => message = Some(b),
        _ => {}
    })?;
    if dtype != Some(DNSTAP_TYPE_MESSAGE) {
        return None;
    }
    decode_message(message?)
}

fn decode_message(p: &[u8]) -> Option<DnstapEvent> {
    let (mut mtype, mut family, mut addr) = (None, None, None);
    let (mut qtime, mut qmsg, mut rtime, mut rmsg) = (None, None, None, None);
    each_field(p, |n, v| match (n, v) {
        (1, Val::Varint(t)) => mtype = Some(t),
        (2, Val::Varint(f)) => family = Some(f),
        (4, Val::Bytes(b)) => addr = Some(b),
        (8, Val::Varint(t)) => qtime = Some(t),
        (10, Val::Bytes(b)) => qmsg = Some(b),
        (12, Val::Varint(t)) => rtime = Some(t),
        (14, Val::Bytes(b)) => rmsg = Some(b),
        _ => {}
    })?;
    let client = match (family, addr?.len()) {
        (Some(FAMILY_INET) | None, 4) => {
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(addr?).ok()?))
        }
        (Some(FAMILY_INET6) | None, 16) => {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(addr?).ok()?))
        }
        _ => return None,
    };
    let (kind, msg, time) = match mtype? {
        MESSAGE_CLIENT_QUERY => (EventKind::ClientQuery, dns::parse_message(qmsg?)?, qtime?),
        MESSAGE_CLIENT_RESPONSE => (
            EventKind::ClientResponse,
            dns::parse_response(rmsg?)?,
            rtime.or(qtime)?,
        ),
        _ => return None,
    };
    let mut ev = DnstapEvent {
        kind,
        client,
        time: i64::try_from(time).ok()?,
        qname: msg.qname?,
        qtype: msg.qtype,
        rcode: if kind == EventKind::ClientResponse {
            msg.rcode
        } else {
            0
        },
        authority_count: msg.authority_count,
        answers: Vec::new(),
        cnames: Vec::new(),
    };
    if kind == EventKind::ClientResponse {
        for a in msg.answers {
            match a.data {
                RData::Addr(ip) => ev.answers.push((ip, a.ttl)),
                RData::Cname(t) => ev.cnames.push(t),
            }
        }
    }
    Some(ev)
}

const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;

/// Was this response produced by a sensr-dns blocklist zone?
///
/// sensr-dns renders blocked names as `always_null` (A `0.0.0.0`, AAAA `::`)
/// or `always_nxdomain` local zones (sensr-dns `compile::zone_lines`).
/// Unbound answers a local zone without an SOA with a bare NXDOMAIN, while an
/// upstream NXDOMAIN carries the zone's SOA in the authority section, so
/// NXDOMAIN counts as blocked only with no authority records and no CNAME
/// chain. A blocklist with a custom redirect address is not detected here.
pub fn is_blocked(ev: &DnstapEvent) -> bool {
    if ev.kind != EventKind::ClientResponse {
        return false;
    }
    match ev.rcode {
        RCODE_NOERROR => ev.answers.iter().any(|(ip, _)| ip.is_unspecified()),
        RCODE_NXDOMAIN => ev.authority_count == 0 && ev.cnames.is_empty(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- builders ----------------------------------------------------------

    fn varint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push((v as u8) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    fn pb_varint(out: &mut Vec<u8>, field: u32, v: u64) {
        varint(out, u64::from(field) << 3);
        varint(out, v);
    }

    fn pb_bytes(out: &mut Vec<u8>, field: u32, b: &[u8]) {
        varint(out, (u64::from(field) << 3) | 2);
        varint(out, b.len() as u64);
        out.extend_from_slice(b);
    }

    /// A `Dnstap { type: MESSAGE, message }` around `Message` fields.
    fn dnstap(kind: u64, client: &[u8], time: u64, dns: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        pb_varint(&mut m, 1, kind);
        pb_varint(&mut m, 2, if client.len() == 4 { 1 } else { 2 });
        pb_varint(&mut m, 3, 1); // UDP
        pb_bytes(&mut m, 4, client);
        pb_varint(&mut m, 6, 53_000);
        pb_varint(&mut m, 8, time - 1);
        m.extend_from_slice(&[(9 << 3) | 5, 1, 2, 3, 4]); // query_time_nsec, fixed32
        if kind == 5 {
            pb_bytes(&mut m, 10, dns);
        } else {
            pb_varint(&mut m, 12, time);
            pb_bytes(&mut m, 14, dns);
        }
        let mut d = Vec::new();
        pb_bytes(&mut d, 1, b"unbound");
        pb_bytes(&mut d, 14, &m);
        pb_varint(&mut d, 15, 1);
        d
    }

    fn name(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for l in labels {
            out.push(l.len() as u8);
            out.extend_from_slice(l.as_bytes());
        }
        out.push(0);
        out
    }

    fn dns_header(flags: u16, qd: u16, an: u16, ns: u16) -> Vec<u8> {
        let mut h = Vec::new();
        for v in [0x4242, flags, qd, an, ns, 0] {
            h.extend_from_slice(&u16::to_be_bytes(v));
        }
        h
    }

    fn rr(out: &mut Vec<u8>, owner: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) {
        out.extend_from_slice(owner);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }

    fn question(out: &mut Vec<u8>, labels: &[&str], qtype: u16) {
        out.extend_from_slice(&name(labels));
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
    }

    /// `www.youtube.com` CNAME `youtube-ui.l.google.com`, two A records.
    fn youtube_response() -> Vec<u8> {
        let mut p = dns_header(0x8180, 1, 3, 0);
        question(&mut p, &["www", "youtube", "com"], 1);
        let cname_at = p.len();
        rr(
            &mut p,
            &[0xc0, 12],
            5,
            300,
            &name(&["youtube-ui", "l", "google", "com"]),
        );
        let target = [0xc0, (cname_at + 2 + 10) as u8];
        rr(&mut p, &target, 1, 120, &[142, 250, 74, 46]);
        rr(&mut p, &target, 1, 45, &[142, 250, 74, 78]);
        p
    }

    fn youtube_query() -> Vec<u8> {
        let mut p = dns_header(0x0100, 1, 0, 0);
        question(&mut p, &["www", "youtube", "com"], 1);
        p
    }

    fn control(ctype: u32, content_types: &[&[u8]]) -> Vec<u8> {
        let mut body = ctype.to_be_bytes().to_vec();
        for ct in content_types {
            body.extend_from_slice(&1u32.to_be_bytes());
            body.extend_from_slice(&(ct.len() as u32).to_be_bytes());
            body.extend_from_slice(ct);
        }
        let mut f = vec![0, 0, 0, 0];
        f.extend_from_slice(&(body.len() as u32).to_be_bytes());
        f.extend_from_slice(&body);
        f
    }

    fn data(payload: &[u8]) -> Vec<u8> {
        let mut f = (payload.len() as u32).to_be_bytes().to_vec();
        f.extend_from_slice(payload);
        f
    }

    fn datas(frames: Vec<Frame>) -> Vec<Vec<u8>> {
        frames
            .into_iter()
            .filter_map(|f| match f {
                Frame::Data(d) => Some(d),
                Frame::Stop => None,
            })
            .collect()
    }

    /// A reader past the handshake.
    fn started() -> FrameReader {
        let mut r = FrameReader::default();
        r.push(&control(READY, &[CONTENT_TYPE]));
        r.push(&control(START, &[CONTENT_TYPE]));
        let _ = r.reply();
        r
    }

    // ---- Frame Streams -----------------------------------------------------

    #[test]
    fn frame_stream_handshake_and_data() {
        let mut r = FrameReader::default();
        assert_eq!(r.reply(), None);
        // READY offering two content types, the second ours.
        assert!(
            r.push(&control(READY, &[b"other", CONTENT_TYPE]))
                .is_empty()
        );
        assert_eq!(r.reply(), Some(control(ACCEPT, &[CONTENT_TYPE])));
        assert_eq!(r.reply(), None, "a reply is handed out once");
        // START, then two data frames delivered one byte at a time.
        let mut stream = control(START, &[CONTENT_TYPE]);
        stream.extend(data(b"first"));
        stream.extend(data(b"second frame"));
        let mut got = Vec::new();
        for b in &stream {
            got.extend(datas(r.push(std::slice::from_ref(b))));
        }
        assert_eq!(got, vec![b"first".to_vec(), b"second frame".to_vec()]);
        // STOP: a Stop frame comes out and FINISH is queued.
        assert!(!r.finished());
        let out = r.push(&control(STOP, &[]));
        assert!(matches!(out.as_slice(), [Frame::Stop]));
        assert_eq!(r.reply(), Some(control(FINISH, &[])));
        assert!(r.finished());
        // Nothing is delivered after STOP.
        assert!(r.push(&data(b"late")).is_empty());
    }

    #[test]
    fn frame_stream_data_needs_a_matching_start() {
        let mut r = FrameReader::default();
        assert!(r.push(&data(b"early")).is_empty(), "data before START");
        // A START with no content type (unidirectional writers) is accepted.
        r.push(&control(START, &[]));
        assert_eq!(datas(r.push(&data(b"ok"))), vec![b"ok".to_vec()]);
        // A START naming another content type ends the stream.
        let mut r = FrameReader::default();
        r.push(&control(START, &[b"protobuf:other"]));
        assert!(r.finished());
        assert!(r.push(&data(b"wrong type")).is_empty());
        // READY without our content type gets an ACCEPT that names none,
        // and the reader is finished (the caller writes it and closes).
        let mut r = FrameReader::default();
        r.push(&control(READY, &[b"protobuf:other"]));
        assert_eq!(r.reply(), Some(control(ACCEPT, &[])));
        assert!(r.finished());
    }

    #[test]
    fn frame_stream_oversize_frames_are_skipped() {
        let mut r = started();
        // A frame one byte over the limit, then a normal one.
        let big = vec![7u8; MAX_FRAME + 1];
        let mut stream = data(&big);
        stream.extend(data(b"after"));
        let mut got = Vec::new();
        for chunk in stream.chunks(4096) {
            got.extend(datas(r.push(chunk)));
            assert!(r.buffered() <= MAX_FRAME + 8);
        }
        assert_eq!(got, vec![b"after".to_vec()]);
        assert_eq!(r.dropped(), 1);
        // A length no writer produces means the stream is lost: the reader
        // gives up so the caller closes and the writer reconnects at a frame
        // boundary.
        let mut r = started();
        assert!(r.push(&u32::MAX.to_be_bytes()).is_empty());
        assert!(r.finished());
        assert!(r.push(&data(b"x")).is_empty());
    }

    // ---- dnstap ------------------------------------------------------------

    #[test]
    fn decode_client_response_with_answers() {
        let ev = decode(&dnstap(
            6,
            &[192, 168, 1, 23],
            1_700_000_000,
            &youtube_response(),
        ))
        .expect("decodes");
        assert_eq!(ev.kind, EventKind::ClientResponse);
        assert_eq!(ev.client, "192.168.1.23".parse::<IpAddr>().unwrap());
        assert_eq!(ev.time, 1_700_000_000);
        assert_eq!(ev.qname, "www.youtube.com");
        assert_eq!(ev.qtype, 1);
        assert_eq!(ev.rcode, 0);
        assert_eq!(
            ev.answers,
            vec![
                ("142.250.74.46".parse().unwrap(), 120),
                ("142.250.74.78".parse().unwrap(), 45),
            ]
        );
        assert_eq!(ev.cnames, vec!["youtube-ui.l.google.com".to_string()]);
        assert!(!is_blocked(&ev));
    }

    #[test]
    fn decode_client_query_v6() {
        let client: Ipv6Addr = "fd00::1234".parse().unwrap();
        let ev = decode(&dnstap(
            5,
            &client.octets(),
            1_700_000_100,
            &youtube_query(),
        ))
        .expect("decodes");
        assert_eq!(ev.kind, EventKind::ClientQuery);
        assert_eq!(ev.client, IpAddr::V6(client));
        assert_eq!(ev.time, 1_700_000_099, "a query carries query_time_sec");
        assert_eq!(ev.qname, "www.youtube.com");
        assert!(ev.answers.is_empty() && ev.cnames.is_empty());
        assert!(!is_blocked(&ev));
    }

    #[test]
    fn decode_ignores_other_message_types() {
        // RESOLVER_RESPONSE (4) and a Dnstap.type other than MESSAGE.
        assert_eq!(
            decode(&dnstap(4, &[10, 0, 0, 1], 5, &youtube_response())),
            None
        );
        let mut d = dnstap(6, &[10, 0, 0, 1], 5, &youtube_response());
        *d.last_mut().unwrap() = 2;
        assert_eq!(decode(&d), None);
        // A client address of the wrong length.
        assert_eq!(
            decode(&dnstap(6, &[10, 0, 0], 5, &youtube_response())),
            None
        );
    }

    #[test]
    fn blocked_answers_detected() {
        let client = [10, 0, 0, 9];
        // always_null: A 0.0.0.0.
        let mut p = dns_header(0x8580, 1, 1, 0);
        question(&mut p, &["ads", "example", "com"], 1);
        rr(&mut p, &[0xc0, 12], 1, 3600, &[0, 0, 0, 0]);
        let ev = decode(&dnstap(6, &client, 9, &p)).expect("decodes");
        assert!(is_blocked(&ev));
        // always_null: AAAA ::.
        let mut p = dns_header(0x8580, 1, 1, 0);
        question(&mut p, &["ads", "example", "com"], 28);
        rr(&mut p, &[0xc0, 12], 28, 3600, &[0; 16]);
        let ev = decode(&dnstap(6, &client, 9, &p)).expect("decodes");
        assert!(is_blocked(&ev));
        // always_nxdomain: NXDOMAIN with no SOA in the authority section.
        let mut p = dns_header(0x8583, 1, 0, 0);
        question(&mut p, &["tracker", "example", "net"], 1);
        let ev = decode(&dnstap(6, &client, 9, &p)).expect("decodes");
        assert_eq!(ev.rcode, 3);
        assert!(is_blocked(&ev));
        // A real NXDOMAIN from upstream carries the zone's SOA: not blocked.
        let mut p = dns_header(0x8183, 1, 0, 1);
        question(&mut p, &["typo", "example", "net"], 1);
        rr(&mut p, &[0xc0, 18], 6, 900, &[0; 22]);
        let ev = decode(&dnstap(6, &client, 9, &p)).expect("decodes");
        assert_eq!(ev.rcode, 3);
        assert!(!is_blocked(&ev));
        // A query is never "blocked".
        let ev = decode(&dnstap(5, &client, 9, &youtube_query())).expect("decodes");
        assert!(!is_blocked(&ev));
    }

    // ---- Review Focus 3 ----------------------------------------------------

    #[test]
    fn decoders_survive_garbage() {
        let mut state: u64 = 0x0d45_7a95_eed0_0003;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u32
        };
        let valid = dnstap(6, &[192, 168, 1, 23], 1_700_000_000, &youtube_response());
        let mut r = started();
        for _ in 0..10_000 {
            // Random bytes.
            let len = (next() % 700) as usize;
            let buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = decode(&buf);
            let _ = r.push(&buf);
            assert!(r.buffered() <= MAX_FRAME + 8);
            let _ = r.reply();
            // A valid frame with one byte changed, then truncated.
            let mut m = valid.clone();
            let at = next() as usize % m.len();
            m[at] = next() as u8;
            let cut = next() as usize % (m.len() + 1);
            if let Some(ev) = decode(&m[..cut]) {
                let _ = is_blocked(&ev);
            }
            if r.finished() {
                r = started();
            }
        }
        for cut in 0..=valid.len() {
            let _ = decode(&valid[..cut]);
        }

        // A valid stream (handshake, frames, STOP) with bytes flipped and
        // fed in random chunks: never a panic, the buffer stays bounded,
        // and an undamaged copy still decodes afterwards.
        let mut stream = control(READY, &[CONTENT_TYPE]);
        stream.extend(control(START, &[CONTENT_TYPE]));
        for _ in 0..8 {
            stream.extend(data(&valid));
        }
        stream.extend(control(STOP, &[]));
        for _ in 0..2_000 {
            let mut m = stream.clone();
            for _ in 0..=(next() % 4) {
                let at = next() as usize % m.len();
                m[at] = next() as u8;
            }
            let mut r = FrameReader::default();
            let mut rest = &m[..];
            while !rest.is_empty() && !r.finished() {
                let n = 1 + next() as usize % 97;
                let (chunk, tail) = rest.split_at(n.min(rest.len()));
                rest = tail;
                for f in r.push(chunk) {
                    if let Frame::Data(d) = f {
                        let _ = decode(&d);
                    }
                }
                let _ = r.reply();
                assert!(r.buffered() <= MAX_FRAME + 8);
            }
        }
        let mut r = FrameReader::default();
        let got = datas(r.push(&stream));
        assert_eq!(got.len(), 8);
        assert!(got.iter().all(|d| decode(d).is_some()));
        assert!(r.finished());

        // Protobuf damage.
        let overflow = [
            0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ];
        assert_eq!(decode(&overflow), None, "varint over 64 bits");
        assert_eq!(decode(&[0x08, 0xff, 0xff]), None, "truncated varint");
        assert_eq!(decode(&[0x72, 0x05, 0x08]), None, "length past the end");
        assert_eq!(decode(&[0x00, 0x01]), None, "field number 0");
        assert_eq!(decode(&[0x0b, 0x0c]), None, "group wire type");
        assert_eq!(decode(&[0x0f]), None, "wire type 7");
        assert_eq!(decode(&[]), None);

        // A compressed-name loop in the DNS payload's answer.
        let mut p = dns_header(0x8180, 1, 1, 0);
        question(&mut p, &["loop", "example"], 1);
        let at = p.len() as u8;
        rr(&mut p, &[0xc0, at], 1, 60, &[1, 2, 3, 4]);
        let ev = decode(&dnstap(6, &[10, 0, 0, 1], 5, &p)).expect("question survives");
        assert_eq!(ev.qname, "loop.example");
        assert!(ev.answers.is_empty());
        // ... and in the question: there is nothing to report.
        let mut p = dns_header(0x8180, 1, 0, 0);
        p.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        assert_eq!(decode(&dnstap(6, &[10, 0, 0, 1], 5, &p)), None);

        // Bad control frames are dropped and the next frame still comes out.
        let mut r = started();
        let mut bad = vec![0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0]; // control len 3
        bad.extend(vec![0, 0, 0, 0, 0, 0, 2, 1]); // control len 513 ...
        bad.extend(vec![0u8; 513]);
        bad.extend(control(0x77, &[])); // unknown control type
        let mut lying = control(READY, &[CONTENT_TYPE]);
        lying[16] = 0xff; // content-type field length past the frame
        bad.extend(lying);
        bad.extend(data(b"resynced"));
        assert_eq!(datas(r.push(&bad)), vec![b"resynced".to_vec()]);
        assert_eq!(r.reply(), None, "a malformed READY is not answered");
        assert!(!r.finished());
    }
}
