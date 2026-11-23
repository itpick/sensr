//! Pure host fingerprinting: no I/O, no clocks, no sockets.

pub mod classify;
pub mod dhcp;
pub mod mdns;
pub mod oui;

pub use classify::{Confidence, Evidence, Label, classify};

#[cfg(test)]
mod garbage {
    /// Review focus 3: hostile bytes never panic.
    #[test]
    fn parsers_survive_garbage() {
        let mut state: u64 = 0x5eed_5e45_f1e6_e7a1;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u32
        };
        let dhcp = crate::dhcp::tests::discover();
        let mdns = crate::mdns::tests::chromecast_response();
        for round in 0..10_000 {
            let len = (next() % 600) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = crate::dhcp::parse_bootp(&buf);
            let _ = crate::mdns::parse(&buf);
            // Valid headers with a random tail reach the option/record code.
            if round % 2 == 0 && buf.len() > 240 {
                buf[..240].copy_from_slice(&dhcp[..240]);
                let _ = crate::dhcp::parse_bootp(&buf);
            }
            if buf.len() > 12 {
                buf[..12].copy_from_slice(&mdns[..12]);
                let _ = crate::mdns::parse(&buf);
            }
            // Mutate a valid packet: flip a byte, then truncate.
            for valid in [&dhcp, &mdns] {
                let mut m = valid.clone();
                let at = next() as usize % m.len();
                m[at] = next() as u8;
                let cut = next() as usize % (m.len() + 1);
                let _ = crate::dhcp::parse_bootp(&m[..cut]);
                let _ = crate::mdns::parse(&m[..cut]);
            }
        }
        // Every prefix of the valid packets.
        for valid in [&dhcp, &mdns] {
            for cut in 0..=valid.len() {
                let _ = crate::dhcp::parse_bootp(&valid[..cut]);
                let _ = crate::mdns::parse(&valid[..cut]);
            }
        }
        assert_eq!(crate::dhcp::parse_bootp(&[]), None);
        assert_eq!(crate::mdns::parse(&[]), None);
    }
}
