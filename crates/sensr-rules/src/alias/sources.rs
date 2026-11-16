//! Data the resolvers read, behind traits so resolution is hermetic in
//! tests and the agent decides how (and when) to fetch.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::ir::{IfAddr, IpFamily};

/// A fetch failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("fetch {url}: {reason}")]
pub struct FetchError {
    /// the URL
    pub url: String,
    /// why
    pub reason: String,
}

/// HTTP(S) authentication for URL aliases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Auth {
    /// none
    None,
    /// HTTP Basic
    Basic {
        /// user name
        user: String,
        /// password
        password: String,
    },
    /// `Authorization: Bearer …`
    Bearer(String),
    /// a custom header
    Header {
        /// header name
        name: String,
        /// header value
        value: String,
    },
}

/// Everything resolution may need from the outside world.
pub trait Sources {
    /// Body of `url` (status 200 only).
    fn fetch(&self, url: &str, auth: &Auth) -> Result<String, FetchError>;
    /// DNS.
    fn resolver(&self) -> &dyn super::dns::Resolver;
    /// Networks of a country (ISO 3166 alpha-2, or `EU`).
    fn geoip(&self, country: &str, fam: IpFamily) -> Vec<IpNet>;
    /// Networks announced by an AS.
    fn asn(&self, asn: u32) -> Vec<IpNet>;
    /// The neighbour (ARP/NDP) table: `(mac, address)` pairs.
    fn neighbours(&self) -> Vec<(String, IpAddr)>;
    /// Current addresses of a logical interface.
    fn interface_addrs(&self, iface: &str) -> Vec<IfAddr>;
    /// Run-time contents of an external alias.
    fn external(&self, name: &str) -> Vec<IpNet>;
}
