//! ICMP and ICMPv6 echo encoding and decoding.
//!
//! Pure functions over byte slices: decoding never panics and rejects
//! anything that is not a well-formed echo reply.

use std::net::{IpAddr, Ipv4Addr};

use crate::Family;

const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const IPPROTO_ICMP: u8 = 1;
/// ICMP echo header: type, code, checksum, identifier, sequence.
pub const ECHO_HEADER_LEN: usize = 8;

/// A decoded echo reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoReply {
    /// Echo identifier.
    pub ident: u16,
    /// Echo sequence number.
    pub seq: u16,
    /// Sender, when the packet carried an IPv4 header.
    pub source: Option<IpAddr>,
}

/// RFC 1071 Internet checksum.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // A u32 cannot overflow here: a datagram has at most 32768 words.
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        sum += u32::from(u16::from_be_bytes(*w));
    }
    if let [last] = rest {
        sum += u32::from(*last) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds an echo request. For IPv4 the checksum is filled in; for ICMPv6 it
/// is left zero because the kernel computes it over the pseudo header (it is
/// mandatory on ICMPv6 sockets).
pub fn echo_request(family: Family, ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let ty = match family {
        Family::Inet => ICMP_ECHO_REQUEST,
        Family::Inet6 => ICMPV6_ECHO_REQUEST,
    };
    let mut pkt = Vec::with_capacity(ECHO_HEADER_LEN + payload.len());
    pkt.extend_from_slice(&[ty, 0, 0, 0]);
    pkt.extend_from_slice(&ident.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(payload);
    if family == Family::Inet {
        let sum = checksum(&pkt);
        pkt[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    pkt
}

/// Decodes an echo reply as received from an ICMP socket of `family`.
///
/// IPv4 raw sockets (and macOS ping sockets) deliver the IP header in front
/// of the ICMP message, Linux ping sockets and every ICMPv6 socket do not.
/// The two are told apart by the first nibble: an IPv4 header starts with
/// version 4, an echo reply with type 0. `truncated` skips the IPv4
/// checksum check when the read may have cut the payload short.
pub fn parse_echo_reply(family: Family, buf: &[u8], truncated: bool) -> Option<EchoReply> {
    match family {
        Family::Inet => {
            let (icmp, source) = match buf.first() {
                Some(b) if b >> 4 == 4 => {
                    let ihl = usize::from(b & 0x0f) * 4;
                    if ihl < 20 || buf.len() < ihl || buf.get(9) != Some(&IPPROTO_ICMP) {
                        return None;
                    }
                    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
                    (&buf[ihl..], Some(IpAddr::V4(src)))
                }
                _ => (buf, None),
            };
            if icmp.len() < ECHO_HEADER_LEN || icmp[0] != ICMP_ECHO_REPLY || icmp[1] != 0 {
                return None;
            }
            if !truncated && checksum(icmp) != 0 {
                return None;
            }
            Some(EchoReply {
                ident: u16::from_be_bytes([icmp[4], icmp[5]]),
                seq: u16::from_be_bytes([icmp[6], icmp[7]]),
                source,
            })
        }
        Family::Inet6 => {
            if buf.len() < ECHO_HEADER_LEN || buf[0] != ICMPV6_ECHO_REPLY || buf[1] != 0 {
                return None;
            }
            Some(EchoReply {
                ident: u16::from_be_bytes([buf[4], buf[5]]),
                seq: u16::from_be_bytes([buf[6], buf[7]]),
                source: None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Turns a request into the reply a peer would send.
    fn reply_of(mut req: Vec<u8>, family: Family) -> Vec<u8> {
        req[0] = match family {
            Family::Inet => ICMP_ECHO_REPLY,
            Family::Inet6 => ICMPV6_ECHO_REPLY,
        };
        if family == Family::Inet {
            req[2] = 0;
            req[3] = 0;
            let sum = checksum(&req);
            req[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        req
    }

    fn ipv4_header(payload_len: usize) -> Vec<u8> {
        let mut h = vec![
            0x45,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            64,
            IPPROTO_ICMP,
            0,
            0,
            10,
            0,
            0,
            1,
            10,
            0,
            0,
            2,
        ];
        let total = (20 + payload_len) as u16;
        h[2..4].copy_from_slice(&total.to_be_bytes());
        h
    }

    #[test]
    fn request_checksum_verifies() {
        let pkt = echo_request(Family::Inet, 0x1234, 7, &[0xab; 5]);
        assert_eq!(pkt.len(), 13);
        assert_eq!(pkt[0], 8);
        assert_eq!(checksum(&pkt), 0);
    }

    #[test]
    fn known_checksum() {
        // Echo request id 1 seq 1, no payload: 0x0800 + 0x0001 + 0x0001 =
        // 0x0802 → !0x0802 = 0xf7fd.
        let pkt = echo_request(Family::Inet, 1, 1, &[]);
        assert_eq!(&pkt[2..4], &[0xf7, 0xfd]);
    }

    #[test]
    fn parses_bare_and_ip_framed_v4_replies() {
        let reply = reply_of(echo_request(Family::Inet, 42, 9, b"x"), Family::Inet);
        let bare = parse_echo_reply(Family::Inet, &reply, false).expect("bare");
        assert_eq!((bare.ident, bare.seq, bare.source), (42, 9, None));

        let mut framed = ipv4_header(reply.len());
        framed.extend_from_slice(&reply);
        let got = parse_echo_reply(Family::Inet, &framed, false).expect("framed");
        assert_eq!((got.ident, got.seq), (42, 9));
        assert_eq!(got.source, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn rejects_non_replies() {
        let req = echo_request(Family::Inet, 1, 1, &[]);
        assert_eq!(parse_echo_reply(Family::Inet, &req, false), None, "request");
        let mut bad = reply_of(req, Family::Inet);
        bad[7] ^= 1;
        assert_eq!(
            parse_echo_reply(Family::Inet, &bad, false),
            None,
            "checksum"
        );
        assert!(
            parse_echo_reply(Family::Inet, &bad, true).is_some(),
            "truncated skips checksum"
        );
        let unreachable = [3u8, 1, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_echo_reply(Family::Inet, &unreachable, true), None);
        let v6req = echo_request(Family::Inet6, 1, 1, &[]);
        assert_eq!(parse_echo_reply(Family::Inet6, &v6req, false), None);
        assert_eq!(parse_echo_reply(Family::Inet6, &[], false), None);
        assert_eq!(
            parse_echo_reply(Family::Inet, &[0x45, 0, 0], false),
            None,
            "short header"
        );
    }

    #[test]
    fn parses_v6_reply() {
        let reply = reply_of(
            echo_request(Family::Inet6, 0xbeef, 3, &[0; 16]),
            Family::Inet6,
        );
        let got = parse_echo_reply(Family::Inet6, &reply, false).expect("v6");
        assert_eq!((got.ident, got.seq), (0xbeef, 3));
    }

    proptest! {
        #[test]
        fn never_panics(buf in proptest::collection::vec(any::<u8>(), 0..128), truncated: bool) {
            let _ = parse_echo_reply(Family::Inet, &buf, truncated);
            let _ = parse_echo_reply(Family::Inet6, &buf, truncated);
        }

        #[test]
        fn roundtrip(ident: u16, seq: u16, payload in proptest::collection::vec(any::<u8>(), 0..64)) {
            for family in [Family::Inet, Family::Inet6] {
                let reply = reply_of(echo_request(family, ident, seq, &payload), family);
                let got = parse_echo_reply(family, &reply, false).expect("reply");
                prop_assert_eq!((got.ident, got.seq), (ident, seq));
            }
        }
    }
}
