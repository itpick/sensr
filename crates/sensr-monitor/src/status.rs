//! Gateway status and its derivation from a [`Sample`].

use serde::Serialize;

use crate::{MonitorSettings, Sample};

/// Health of a gateway as the rest of sensr sees it.
///
/// Mirrors OPNsense's status strings (see [`Status::opnsense_str`]); the
/// extra [`Status::Pending`] separates "monitored but no data yet" from a
/// measured outage, which upstream both report as `down`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Monitored, but no probe has been answered or timed out yet: the
    /// target address is unknown (dynamic gateway before DHCP/RA), the socket
    /// could not be opened, or the first probe is still in flight.
    Pending,
    /// Within all thresholds, or not monitored (upstream `none`).
    Online,
    /// Average latency above the low threshold (`delay`).
    Delay,
    /// Loss above the low threshold (`loss`).
    Loss,
    /// Both of the above (`delay+loss`).
    DelayLoss,
    /// Latency or loss above the high threshold (`down`).
    Down,
    /// Marked down by the administrator (`force_down`).
    ForceDown,
}

impl Status {
    /// The status string OPNsense's API and gateway watcher use. `Pending`
    /// maps to `down`, which is what upstream reports for a monitored
    /// gateway without data.
    pub fn opnsense_str(self) -> &'static str {
        match self {
            Self::Online => "none",
            Self::Delay => "delay",
            Self::Loss => "loss",
            Self::DelayLoss => "delay+loss",
            Self::Down | Self::Pending => "down",
            Self::ForceDown => "force_down",
        }
    }

    /// True for the states upstream matches with "contains `down`": a
    /// default gateway switch skips these gateways.
    pub fn is_down(self) -> bool {
        matches!(self, Self::Down | Self::ForceDown | Self::Pending)
    }
}

/// Maps a sample onto a status with OPNsense's rules
/// (`StaticRoute::getMonitorStatus`): every comparison is a strict
/// "greater than", high thresholds win, and delay and loss combine.
///
/// | condition                                         | status       |
/// |---------------------------------------------------|--------------|
/// | no sample                                         | `Pending`    |
/// | latency > latency_high **or** loss > loss_high    | `Down`       |
/// | latency > latency_low **and** loss > loss_low     | `DelayLoss`  |
/// | latency > latency_low                             | `Delay`      |
/// | loss > loss_low                                   | `Loss`       |
/// | otherwise                                         | `Online`     |
///
/// `force_down` is not a sample property; the [`crate::Monitor`] applies it
/// on top.
pub fn evaluate(sample: Option<&Sample>, settings: &MonitorSettings) -> Status {
    let Some(s) = sample else {
        return Status::Pending;
    };
    let delay_high = s.latency_avg > settings.latency_high;
    let delay_low = s.latency_avg > settings.latency_low;
    let loss_high = s.loss_pct > f64::from(settings.loss_high);
    let loss_low = s.loss_pct > f64::from(settings.loss_low);
    if delay_high || loss_high {
        Status::Down
    } else if delay_low && loss_low {
        Status::DelayLoss
    } else if delay_low {
        Status::Delay
    } else if loss_low {
        Status::Loss
    } else {
        Status::Online
    }
}

/// Covers: SYS-GW-001, SYS-GW-002
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample(latency_ms: u64, loss_pct: f64) -> Sample {
        Sample {
            latency_avg: Duration::from_millis(latency_ms),
            latency_stddev: Duration::ZERO,
            loss_pct,
            received: 1,
            lost: 0,
        }
    }

    #[test]
    fn status_mapping_with_upstream_defaults() {
        let s = MonitorSettings::default();
        // (latency ms, loss %, status): thresholds 200/500 ms, 10/20 %.
        let cases = [
            (5, 0.0, Status::Online),
            (200, 10.0, Status::Online), // equal is not above
            (201, 0.0, Status::Delay),
            (500, 0.0, Status::Delay),
            (501, 0.0, Status::Down),
            (5, 10.5, Status::Loss),
            (5, 20.0, Status::Loss),
            (5, 20.1, Status::Down),
            (201, 11.0, Status::DelayLoss),
            (499, 19.0, Status::DelayLoss),
            (501, 11.0, Status::Down),
            (0, 100.0, Status::Down),
            (600, 100.0, Status::Down),
        ];
        for (lat, loss, want) in cases {
            assert_eq!(
                evaluate(Some(&sample(lat, loss)), &s),
                want,
                "{lat} ms {loss} %"
            );
        }
        assert_eq!(evaluate(None, &s), Status::Pending);
    }

    #[test]
    fn opnsense_strings() {
        let table = [
            (Status::Online, "none"),
            (Status::Delay, "delay"),
            (Status::Loss, "loss"),
            (Status::DelayLoss, "delay+loss"),
            (Status::Down, "down"),
            (Status::Pending, "down"),
            (Status::ForceDown, "force_down"),
        ];
        for (status, want) in table {
            assert_eq!(status.opnsense_str(), want);
            assert_eq!(status.is_down(), want.contains("down"), "{status:?}");
        }
    }

    #[test]
    fn serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&Status::DelayLoss).expect("json"),
            "\"delay_loss\""
        );
        assert_eq!(
            serde_json::to_string(&Status::ForceDown).expect("json"),
            "\"force_down\""
        );
    }
}
