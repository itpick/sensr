//! The JSON-lines protocol on the daemon's unix socket: one [`Request`] per
//! line in, one [`Reply`] per line out.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// A request to the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Queue a scan.
    Start(StartReq),
    /// Stop a running or queued job.
    Cancel {
        /// The job to stop.
        job_id: u64,
    },
    /// What is running and queued.
    Status,
    /// The devices currently known (for auto-scan of new ones).
    Known {
        /// MAC and address of each.
        macs: Vec<KnownDevice>,
    },
}

/// Parameters of a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartReq {
    /// Address, network or range, as [`crate::target::parse`] reads it.
    pub target: String,
    /// What the target is.
    pub kind: JobKind,
    /// Started by auto-scan rather than a person.
    pub auto: bool,
    /// The device's MAC, when scanning a device.
    pub mac: Option<String>,
    /// Allow non-local targets.
    pub public_ok: bool,
    /// The person confirmed a large range.
    pub confirm: bool,
    /// Scan even if the target is on the exclude list.
    pub include_excluded: bool,
}

/// What a job scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    /// One device.
    Device,
    /// A range of addresses.
    Range,
}

/// A device the daemon is told about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownDevice {
    /// Hardware address.
    pub mac: String,
    /// Its IPv4 address.
    pub ipv4: Ipv4Addr,
}

/// The daemon's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Reply {
    /// The scan was queued.
    Started {
        /// Its id.
        job_id: u64,
    },
    /// The scan was not accepted.
    Refused {
        /// Why.
        reason: Refusal,
    },
    /// Done.
    Ok,
    /// Answer to [`Request::Status`].
    Status(StatusView),
}

/// Why a scan was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// Target is not local and `public_ok` was not set.
    Public,
    /// Range exceeds the configured maximum.
    TooLarge {
        /// Addresses in the range.
        addresses: u64,
        /// The configured maximum.
        max: u32,
    },
    /// Target is on the exclude list.
    Excluded,
    /// Target could not be understood.
    Invalid(String),
    /// Scanning is disabled.
    Disabled,
}

/// Daemon state for the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusView {
    /// The job being scanned, if any.
    pub running: Option<JobProgress>,
    /// Jobs waiting.
    pub queue: Vec<QueuedJob>,
}

/// Progress of the running job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobProgress {
    /// Job id.
    pub job_id: u64,
    /// What it scans.
    pub kind: JobKind,
    /// The target as given.
    pub target: String,
    /// Live hosts found (`None` until host discovery finishes).
    pub alive: Option<u32>,
    /// Address being scanned (1-based).
    pub address_n: u32,
    /// Addresses to scan.
    pub address_total: u32,
    /// TCP probes finished.
    pub tcp_done: u32,
    /// UDP probes finished.
    pub udp_done: u32,
}

/// A waiting job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedJob {
    /// Job id.
    pub job_id: u64,
    /// What it scans.
    pub kind: JobKind,
    /// The target as given.
    pub target: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start() -> Request {
        Request::Start(StartReq {
            target: "192.168.1.5".into(),
            kind: JobKind::Device,
            auto: false,
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            public_ok: false,
            confirm: false,
            include_excluded: false,
        })
    }

    #[test]
    fn start_is_one_line_with_op() {
        let line = serde_json::to_string(&start()).unwrap();
        assert!(!line.contains('\n'));
        assert!(line.contains(r#""op":"start""#));
        assert_eq!(serde_json::from_str::<Request>(&line).unwrap(), start());
    }

    #[test]
    fn simple_requests_round_trip() {
        for r in [
            Request::Status,
            Request::Cancel { job_id: 7 },
            Request::Known {
                macs: vec![KnownDevice {
                    mac: "aa:bb:cc:dd:ee:ff".into(),
                    ipv4: "192.168.1.5".parse().unwrap(),
                }],
            },
        ] {
            let line = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<Request>(&line).unwrap(), r);
        }
        assert_eq!(
            serde_json::to_string(&Request::Status).unwrap(),
            r#"{"op":"status"}"#
        );
    }

    #[test]
    fn replies_round_trip() {
        for r in [
            Reply::Started { job_id: 1 },
            Reply::Ok,
            Reply::Refused {
                reason: Refusal::TooLarge {
                    addresses: 8192,
                    max: 4096,
                },
            },
            Reply::Refused {
                reason: Refusal::Invalid("nope".into()),
            },
            Reply::Refused {
                reason: Refusal::Public,
            },
            Reply::Status(StatusView {
                running: Some(JobProgress {
                    job_id: 2,
                    kind: JobKind::Range,
                    target: "192.168.1.0/24".into(),
                    alive: None,
                    address_n: 3,
                    address_total: 254,
                    tcp_done: 10,
                    udp_done: 4,
                }),
                queue: vec![QueuedJob {
                    job_id: 3,
                    kind: JobKind::Device,
                    target: "192.168.1.9".into(),
                }],
            }),
        ] {
            let line = serde_json::to_string(&r).unwrap();
            assert!(!line.contains('\n'));
            assert_eq!(serde_json::from_str::<Reply>(&line).unwrap(), r);
        }
    }
}
