//! Host discovery and neighbour (ARP) lookups.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

/// Parse `/proc/net/arp` text into IP -> lowercase MAC. Incomplete rows
/// (flags 0x0 or an all-zero MAC) and anything malformed are skipped.
pub fn neighbours(proc_arp: &str) -> HashMap<IpAddr, String> {
    let mut out = HashMap::new();
    for line in proc_arp.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let Ok(ip) = f[0].parse::<Ipv4Addr>() else {
            continue;
        };
        let flags = f[2]
            .strip_prefix("0x")
            .and_then(|h| u32::from_str_radix(h, 16).ok());
        if flags.is_none_or(|v| v == 0) {
            continue;
        }
        let mac = f[3].to_ascii_lowercase();
        let valid = mac.split(':').count() == 6
            && mac
                .split(':')
                .all(|o| o.len() == 2 && o.bytes().all(|b| b.is_ascii_hexdigit()));
        if !valid || mac == "00:00:00:00:00:00" {
            continue;
        }
        out.insert(IpAddr::V4(ip), mac);
    }
    out
}

/// MAC address recorded for `ip`, if any.
pub fn mac_for(ip: IpAddr, neigh: &HashMap<IpAddr, String>) -> Option<String> {
    neigh.get(&ip).cloned()
}

/// IPv4 address recorded for `mac` (case-insensitive), if any.
pub fn ip_for(mac: &str, neigh: &HashMap<IpAddr, String>) -> Option<Ipv4Addr> {
    neigh.iter().find_map(|(ip, m)| match ip {
        IpAddr::V4(v4) if m.eq_ignore_ascii_case(mac) => Some(*v4),
        _ => None,
    })
}

#[cfg(feature = "daemon")]
pub use live::alive;

#[cfg(feature = "daemon")]
mod live {
    use std::collections::HashMap;
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::time::{Duration, Instant};

    use socket2::{Domain, Protocol, Socket, Type};
    use tokio::task::JoinSet;

    const TCP_PORTS: [u16; 5] = [22, 80, 443, 445, 8080];
    const TCP_TIMEOUT: Duration = Duration::from_millis(500);
    const ICMP_TIMEOUT: Duration = Duration::from_secs(1);

    /// Is the host up? A neighbour entry, an ICMP echo reply (unprivileged
    /// ping socket) or any TCP accept/refuse on a common port says yes.
    pub async fn alive(ip: IpAddr, neigh: &HashMap<IpAddr, String>) -> bool {
        if neigh.contains_key(&ip) {
            return true;
        }
        let mut set = JoinSet::new();
        set.spawn(async move {
            tokio::task::spawn_blocking(move || icmp_echo(ip))
                .await
                .unwrap_or(false)
        });
        for port in TCP_PORTS {
            set.spawn(async move { tcp_up(SocketAddr::new(ip, port)).await });
        }
        while let Some(r) = set.join_next().await {
            if r.unwrap_or(false) {
                return true;
            }
        }
        false
    }

    async fn tcp_up(addr: SocketAddr) -> bool {
        match tokio::time::timeout(TCP_TIMEOUT, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => e.kind() == io::ErrorKind::ConnectionRefused,
            Err(_) => false,
        }
    }

    fn next_id() -> u16 {
        use std::sync::atomic::{AtomicU16, Ordering};
        static N: AtomicU16 = AtomicU16::new(1);
        (std::process::id() as u16).wrapping_add(N.fetch_add(1, Ordering::Relaxed))
    }

    fn checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        for c in data.chunks(2) {
            sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// One echo request, wait up to 1 s for a reply. Any failure to open the
    /// socket (no ping_group_range, sandbox) is just "no answer".
    fn icmp_echo(ip: IpAddr) -> bool {
        let (domain, proto, req_type, reply_type) = match ip {
            IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4, 8u8, 0u8),
            IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6, 128u8, 129u8),
        };
        let Ok(sock) = Socket::new(domain, Type::DGRAM, Some(proto)).map(std::net::UdpSocket::from)
        else {
            return false;
        };
        let id = next_id().to_be_bytes();
        let mut pkt = [
            req_type, 0, 0, 0, id[0], id[1], 0, 1, b's', b'e', b'n', b's', b'r', 0, 0, 0,
        ];
        if ip.is_ipv4() {
            let c = checksum(&pkt).to_be_bytes();
            pkt[2] = c[0];
            pkt[3] = c[1];
        }
        let dest = SocketAddr::new(ip, 0);
        if sock.send_to(&pkt, dest).is_err() {
            return false;
        }
        let deadline = Instant::now() + ICMP_TIMEOUT;
        let mut buf = [0u8; 256];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || sock.set_read_timeout(Some(left)).is_err() {
                return false;
            }
            let Ok(n) = sock.recv(&mut buf) else {
                return false;
            };
            let b = &buf[..n];
            // macOS hands back the IPv4 header on datagram ICMP sockets.
            let off = if ip.is_ipv4() && b.first().is_some_and(|v| v >> 4 == 4) {
                usize::from(b[0] & 0xf) * 4
            } else {
                0
            };
            // Where the kernel keeps our id (macOS) other sockets' replies
            // arrive here too, so check it; Linux rewrites it and filters.
            let id_ok = off == 0 || b.get(off + 4..off + 6) == Some(&id[..]);
            if b.get(off) == Some(&reply_type) && id_ok {
                return true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARP: &str = "IP address       HW type     Flags       HW address            Mask     Device\n\
192.168.1.10     0x1         0x2         AA:BB:CC:DD:EE:FF     *        eth0\n\
192.168.1.11     0x1         0x0         00:00:00:00:00:00     *        eth0\n\
garbage\n\
192.168.1.12     0x1         0x2         zz:bb     *        eth0\n";

    #[test]
    fn parses_complete_rows_lowercased() {
        let n = neighbours(ARP);
        assert_eq!(n.len(), 1);
        assert_eq!(
            n[&"192.168.1.10".parse::<IpAddr>().unwrap()],
            "aa:bb:cc:dd:ee:ff"
        );
    }

    #[test]
    fn empty_and_malformed_do_not_panic() {
        assert!(neighbours("").is_empty());
        assert!(neighbours("hdr\n\u{0}\u{1}\n1.2.3.4").is_empty());
    }

    #[test]
    fn skips_zero_mac_with_nonzero_flags() {
        let t = "h\n10.0.0.1 0x1 0x2 00:00:00:00:00:00 * e\n";
        assert!(neighbours(t).is_empty());
    }

    #[test]
    fn lookups() {
        let n = neighbours(ARP);
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        assert_eq!(mac_for(ip, &n).as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(
            ip_for("AA:bb:CC:dd:EE:ff", &n),
            Some(Ipv4Addr::new(192, 168, 1, 10))
        );
        assert_eq!(ip_for("11:22:33:44:55:66", &n), None);
        assert_eq!(mac_for("10.9.9.9".parse().unwrap(), &n), None);
    }

    #[cfg(feature = "daemon")]
    mod live {
        use super::*;
        use std::time::{Duration, Instant};

        #[tokio::test]
        async fn loopback_is_alive() {
            assert!(alive("127.0.0.1".parse().unwrap(), &HashMap::new()).await);
        }

        #[tokio::test]
        async fn neighbour_entry_is_alive() {
            let mut n = HashMap::new();
            n.insert(
                "192.0.2.1".parse().unwrap(),
                "aa:bb:cc:dd:ee:ff".to_string(),
            );
            assert!(alive("192.0.2.1".parse().unwrap(), &n).await);
        }

        #[tokio::test]
        async fn test_net_is_dead_quickly() {
            let t = Instant::now();
            assert!(!alive("192.0.2.1".parse().unwrap(), &HashMap::new()).await);
            assert!(t.elapsed() < Duration::from_secs(3));
        }
    }
}
