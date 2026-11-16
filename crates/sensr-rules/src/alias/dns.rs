//! Host names in host aliases (`AsyncDNSResolver`): A and AAAA for every
//! name, CNAMEs followed, failures (NXDOMAIN, timeouts) tolerated and
//! reported. The resolver is a trait so tests and the agent choose the
//! transport.

use std::collections::BTreeSet;
use std::net::IpAddr;

/// One answer record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// an address (A or AAAA)
    Addr(IpAddr),
    /// a CNAME target
    Cname(String),
}

/// Record type asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordType {
    /// IPv4 address
    A,
    /// IPv6 address
    Aaaa,
}

/// A lookup failure; never fatal for the alias.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    /// the name does not exist
    #[error("NXDOMAIN {0}")]
    NxDomain(String),
    /// no answer in time
    #[error("timeout resolving {0}")]
    Timeout(String),
    /// anything else
    #[error("{0}")]
    Other(String),
}

/// Something that answers DNS queries.
pub trait Resolver {
    /// Records for `name` of type `rtype` (CNAMEs included as such).
    fn query(&self, name: &str, rtype: RecordType) -> Result<Vec<Record>, DnsError>;
}

/// CNAME chains longer than this are cut (loops, misconfiguration).
const MAX_CNAME_DEPTH: usize = 8;

/// Resolves every name once; returns the addresses and the distinct errors.
pub fn collect(names: &[String], r: &dyn Resolver) -> (BTreeSet<IpAddr>, Vec<DnsError>) {
    let mut addrs = BTreeSet::new();
    let mut errors: Vec<DnsError> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut queue: Vec<(String, usize)> = names.iter().map(|n| (n.clone(), 0)).collect();
    while let Some((name, depth)) = queue.pop() {
        if !seen.insert(name.clone()) || depth > MAX_CNAME_DEPTH {
            continue;
        }
        for rt in [RecordType::A, RecordType::Aaaa] {
            match r.query(&name, rt) {
                Ok(records) => {
                    for rec in records {
                        match rec {
                            Record::Addr(a) => {
                                addrs.insert(a);
                            }
                            Record::Cname(t) => queue.push((t, depth + 1)),
                        }
                    }
                }
                Err(e) => {
                    if !errors.contains(&e) {
                        errors.push(e);
                    }
                }
            }
        }
    }
    (addrs, errors)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Answers from a fixed table.
    #[derive(Default)]
    pub struct MockResolver(pub BTreeMap<(String, bool), Vec<Record>>);

    impl MockResolver {
        pub fn a(mut self, name: &str, ips: &[&str]) -> Self {
            for ip in ips {
                let ip: IpAddr = ip.parse().unwrap();
                self.0
                    .entry((name.into(), ip.is_ipv6()))
                    .or_default()
                    .push(Record::Addr(ip));
            }
            self
        }
        pub fn cname(mut self, name: &str, target: &str) -> Self {
            for v6 in [false, true] {
                self.0
                    .entry((name.into(), v6))
                    .or_default()
                    .push(Record::Cname(target.into()));
            }
            self
        }
    }

    impl Resolver for MockResolver {
        fn query(&self, name: &str, rt: RecordType) -> Result<Vec<Record>, DnsError> {
            let key = (name.to_owned(), rt == RecordType::Aaaa);
            match self.0.get(&key) {
                Some(v) => Ok(v.clone()),
                None if self.0.keys().any(|(n, _)| n == name) => Ok(Vec::new()),
                None => Err(DnsError::NxDomain(name.into())),
            }
        }
    }

    #[test]
    fn hostname_deferred_then_resolved_t0331() {
        let r = MockResolver::default()
            .cname("pkg.example.org", "cdn.example.net")
            .a("cdn.example.net", &["192.0.2.10", "2001:db8::10"])
            .a("mirror.example.org", &["192.0.2.11"]);
        let (addrs, errors) = collect(
            &[
                "pkg.example.org".into(),
                "mirror.example.org".into(),
                "gone.example.org".into(),
            ],
            &r,
        );
        let got: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
        assert_eq!(got, ["192.0.2.10", "192.0.2.11", "2001:db8::10"]);
        assert_eq!(errors, [DnsError::NxDomain("gone.example.org".into())]);
    }

    #[test]
    fn cname_loops_terminate() {
        let r = MockResolver::default().cname("a", "b").cname("b", "a");
        let (addrs, _) = collect(&["a".into()], &r);
        assert!(addrs.is_empty());
    }
}
