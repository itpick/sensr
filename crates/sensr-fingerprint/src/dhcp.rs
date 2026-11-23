//! DHCP (BOOTP) request parsing: the client fields that hint at the device.

/// What a DHCP client message tells us about the sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpInfo {
    /// Client hardware address.
    pub chaddr: [u8; 6],
    /// Option 53, DHCP message type (1 = DISCOVER, 3 = REQUEST, ...).
    pub msg_type: Option<u8>,
    /// Option 12, host name.
    pub hostname: Option<String>,
    /// Option 60, vendor class identifier.
    pub vendor_class: Option<String>,
    /// Option 55, parameter request list as comma-joined decimal codes.
    pub prl: Option<String>,
}

/// Parse a BOOTP request (`op` 1, Ethernet `htype`/`hlen`, DHCP cookie).
///
/// Returns `None` when the fixed header or cookie is wrong. A malformed
/// option area yields the options read before the damage.
pub fn parse_bootp(udp_payload: &[u8]) -> Option<DhcpInfo> {
    let p = udp_payload;
    if p.first() != Some(&1) || p.get(1) != Some(&1) || p.get(2) != Some(&6) {
        return None;
    }
    if p.get(236..240)? != MAGIC_COOKIE {
        return None;
    }
    let chaddr: [u8; 6] = p.get(28..34)?.try_into().ok()?;
    let mut info = DhcpInfo {
        chaddr,
        msg_type: None,
        hostname: None,
        vendor_class: None,
        prl: None,
    };
    let mut i = 240usize;
    while let Some(&code) = p.get(i) {
        match code {
            OPT_PAD => {
                i += 1;
                continue;
            }
            OPT_END => break,
            _ => {}
        }
        let Some(&len) = p.get(i + 1) else { break };
        let start = i + 2;
        let Some(data) = p.get(start..start + usize::from(len)) else {
            break;
        };
        i = start + usize::from(len);
        match code {
            OPT_MSG_TYPE if info.msg_type.is_none() => info.msg_type = data.first().copied(),
            OPT_HOSTNAME if info.hostname.is_none() => info.hostname = text(data),
            OPT_VENDOR_CLASS if info.vendor_class.is_none() => info.vendor_class = text(data),
            OPT_PRL if info.prl.is_none() && !data.is_empty() => {
                let codes: Vec<String> = data.iter().map(u8::to_string).collect();
                info.prl = Some(codes.join(","));
            }
            _ => {}
        }
    }
    Some(info)
}

const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const OPT_PAD: u8 = 0;
const OPT_HOSTNAME: u8 = 12;
const OPT_MSG_TYPE: u8 = 53;
const OPT_PRL: u8 = 55;
const OPT_VENDOR_CLASS: u8 = 60;
const OPT_END: u8 = 255;

/// Lossy UTF-8 with trailing NULs removed; empty gives `None`.
fn text(data: &[u8]) -> Option<String> {
    let end = data.iter().rposition(|&b| b != 0).map_or(0, |n| n + 1);
    let s = String::from_utf8_lossy(data.get(..end)?).into_owned();
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A DHCP request header with `chaddr` and the cookie, no options.
    pub(crate) fn header(chaddr: [u8; 6]) -> Vec<u8> {
        let mut p = vec![0u8; 240];
        p[0] = 1; // op BOOTREQUEST
        p[1] = 1; // htype Ethernet
        p[2] = 6; // hlen
        p[4..8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        p[28..34].copy_from_slice(&chaddr);
        p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        p
    }

    fn opt(p: &mut Vec<u8>, code: u8, data: &[u8]) {
        p.push(code);
        p.push(data.len() as u8);
        p.extend_from_slice(data);
    }

    pub(crate) fn discover() -> Vec<u8> {
        let mut p = header([0x02, 0xcf, 0x67, 0xc6, 0x7b, 0x71]);
        opt(&mut p, 53, &[1]);
        p.push(0); // pad
        opt(&mut p, 12, b"iPhone");
        opt(&mut p, 55, &[1, 3, 6, 15, 119, 252]);
        opt(&mut p, 60, b"android-dhcp-14");
        p.push(255);
        opt(&mut p, 12, b"after-end");
        p
    }

    #[test]
    fn dhcp_discover_parses() {
        let i = parse_bootp(&discover()).expect("parses");
        assert_eq!(i.chaddr, [0x02, 0xcf, 0x67, 0xc6, 0x7b, 0x71]);
        assert_eq!(i.msg_type, Some(1));
        assert_eq!(i.hostname.as_deref(), Some("iPhone"));
        assert_eq!(i.prl.as_deref(), Some("1,3,6,15,119,252"));
        assert_eq!(i.vendor_class.as_deref(), Some("android-dhcp-14"));
    }

    #[test]
    fn dhcp_rejects_wrong_header() {
        let good = discover();
        for (at, val) in [(0usize, 2u8), (1, 6), (2, 8), (236, 0x64)] {
            let mut p = good.clone();
            p[at] = val;
            assert_eq!(parse_bootp(&p), None, "byte {at} = {val}");
        }
        assert_eq!(parse_bootp(&good[..239]), None);
        assert_eq!(parse_bootp(&[]), None);
    }

    #[test]
    fn dhcp_option_length_past_end_keeps_earlier_options() {
        let mut p = header([0xb8, 0x27, 0xeb, 1, 2, 3]);
        opt(&mut p, 53, &[3]);
        p.extend_from_slice(&[12, 40, b'p', b'i']); // claims 40 bytes, has 2
        let i = parse_bootp(&p).expect("header is fine");
        assert_eq!(i.msg_type, Some(3));
        assert_eq!(i.hostname, None);
    }

    #[test]
    fn dhcp_truncated_option_code_and_length() {
        let mut p = header([0xb8, 0x27, 0xeb, 1, 2, 3]);
        p.push(12); // code with no length byte
        let i = parse_bootp(&p).expect("header is fine");
        assert_eq!(i.hostname, None);
        // Zero-length option and empty PRL are not reported as values.
        let mut p = header([0xb8, 0x27, 0xeb, 1, 2, 3]);
        opt(&mut p, 12, b"");
        opt(&mut p, 55, b"");
        p.push(255);
        let i = parse_bootp(&p).expect("header is fine");
        assert_eq!(i.hostname, None);
        assert_eq!(i.prl, None);
    }

    #[test]
    fn dhcp_hostname_is_lossy_and_nul_trimmed() {
        let mut p = header([0xb8, 0x27, 0xeb, 1, 2, 3]);
        opt(&mut p, 12, b"pi\xff\0");
        let i = parse_bootp(&p).expect("parses");
        assert_eq!(i.hostname.as_deref(), Some("pi\u{fffd}"));
    }
}
