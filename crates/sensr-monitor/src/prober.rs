//! The probe transport abstraction.

use std::future::Future;
use std::io;
use std::net::IpAddr;

/// Everything needed to open a probe socket for one gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeSpec {
    /// Gateway name, for logs.
    pub gateway: String,
    /// Address to probe (monitor address or the gateway itself).
    pub target: IpAddr,
    /// Interface to bind to (Linux `SO_BINDTODEVICE`), e.g. `eth0`.
    pub device: Option<String>,
    /// Source address to bind to (dpinger `-B`).
    pub source: Option<IpAddr>,
    /// IPv6 scope (interface index) for a link-local target. On Linux it is
    /// looked up from `device` when left `None`.
    pub scope_id: Option<u32>,
    /// Echo payload size in bytes.
    pub data_length: usize,
    /// Echo identifier, unique per prober within this process.
    pub ident: u16,
}

/// An echo reply as seen by the probe loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    /// Sequence number of the answered request.
    pub seq: u16,
    /// When it arrived, taken right after the read.
    pub received: tokio::time::Instant,
}

/// Sends echo requests to one target and yields the replies.
///
/// Both methods take `&self` so the probe loop can wait for a reply while
/// sending the next request. `recv` must be cancel safe: the loop drops it
/// whenever another event wins the race.
pub trait Prober: Send + Sync + 'static {
    /// Sends the echo request with sequence number `seq`.
    fn send(&self, seq: u16) -> impl Future<Output = io::Result<()>> + Send;
    /// Waits for the next echo reply that belongs to this prober.
    fn recv(&self) -> impl Future<Output = io::Result<Reply>> + Send;
}

/// Opens [`Prober`]s; the [`crate::Monitor`] calls it once per gateway and
/// again whenever the target changes.
pub trait ProberFactory: Send + Sync + 'static {
    /// The prober type.
    type Prober: Prober;
    /// Opens a prober for `spec`.
    fn open(&self, spec: &ProbeSpec) -> io::Result<Self::Prober>;
}
