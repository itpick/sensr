//! Probe timing and alarm thresholds of one gateway.

use std::time::Duration;

/// Largest echo payload accepted: fits an ICMP and an ICMPv6 echo in one
/// unfragmented-by-us datagram of either family.
pub const MAX_DATA_LENGTH: usize = 65_000;

/// How one gateway is probed and when it counts as degraded or down.
///
/// The defaults are OPNsense's (`GatewayField::getDpingerDefaults`), which
/// apply whenever a gateway leaves a field empty. The alert interval is not
/// configurable upstream: dpinger runs with its built-in one second and the
/// gateway watcher polls once a second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorSettings {
    /// Average latency above this is `delay` (OPNsense `latencylow`, 200 ms).
    pub latency_low: Duration,
    /// Average latency above this is `down` (`latencyhigh`, 500 ms).
    pub latency_high: Duration,
    /// Loss above this percentage is `loss` (`losslow`, 10).
    pub loss_low: u8,
    /// Loss above this percentage is `down` (`losshigh`, 20).
    pub loss_high: u8,
    /// Time between two echo requests (`interval`, 1 s; dpinger `-s`).
    pub interval: Duration,
    /// A request unanswered for this long is lost (`loss_interval`, 4 s;
    /// dpinger `-l`).
    pub loss_interval: Duration,
    /// Statistics cover the probes sent within this window (`time_period`,
    /// 60 s; dpinger `-t`).
    pub time_period: Duration,
    /// Echo payload size in bytes (`data_length`, 1; dpinger `-d`).
    pub data_length: usize,
    /// How often the status is re-evaluated (dpinger `-A`, 1 s).
    pub alert_interval: Duration,
}

impl Default for MonitorSettings {
    fn default() -> Self {
        Self {
            latency_low: Duration::from_millis(200),
            latency_high: Duration::from_millis(500),
            loss_low: 10,
            loss_high: 20,
            interval: Duration::from_secs(1),
            loss_interval: Duration::from_secs(4),
            time_period: Duration::from_secs(60),
            data_length: 1,
            alert_interval: Duration::from_secs(1),
        }
    }
}

/// A [`MonitorSettings`] combination OPNsense would reject (plus the zero
/// durations it cannot express, since its fields are whole seconds >= 1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettingsError {
    /// `latency_low` must be below `latency_high`.
    #[error("the low latency threshold needs to be lower than the high latency threshold")]
    LatencyOrder,
    /// `loss_low` must be below `loss_high`.
    #[error("the low packet loss threshold needs to be lower than the high packet loss threshold")]
    LossOrder,
    /// `loss_low` is 1..=99 and `loss_high` 1..=100.
    #[error("packet loss thresholds must be between 1 and 100 percent")]
    LossRange,
    /// A duration is zero.
    #[error("{0} must be greater than zero")]
    Zero(&'static str),
    /// `time_period` must be at least `2 * (interval + loss_interval)`.
    #[error(
        "the time period needs to be at least 2 times the sum of the probe interval and the loss interval"
    )]
    TimePeriodTooShort,
    /// The payload does not fit a single echo.
    #[error("data length must be at most {MAX_DATA_LENGTH} bytes")]
    DataLength,
}

impl MonitorSettings {
    /// Checks the constraints OPNsense enforces in `Gateways.xml` and
    /// `Gateways::performValidation`.
    pub fn validate(&self) -> Result<(), SettingsError> {
        for (name, d) in [
            ("latency_low", self.latency_low),
            ("interval", self.interval),
            ("loss_interval", self.loss_interval),
            ("time_period", self.time_period),
            ("alert_interval", self.alert_interval),
        ] {
            if d.is_zero() {
                return Err(SettingsError::Zero(name));
            }
        }
        if self.latency_low >= self.latency_high {
            return Err(SettingsError::LatencyOrder);
        }
        if !(1..=99).contains(&self.loss_low) || !(1..=100).contains(&self.loss_high) {
            return Err(SettingsError::LossRange);
        }
        if self.loss_low >= self.loss_high {
            return Err(SettingsError::LossOrder);
        }
        if self.time_period < (self.interval + self.loss_interval) * 2 {
            return Err(SettingsError::TimePeriodTooShort);
        }
        if self.data_length > MAX_DATA_LENGTH {
            return Err(SettingsError::DataLength);
        }
        Ok(())
    }
}

/// Covers: SYS-GW-001
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_opnsense() {
        let s = MonitorSettings::default();
        assert_eq!(s.latency_low, Duration::from_millis(200));
        assert_eq!(s.latency_high, Duration::from_millis(500));
        assert_eq!((s.loss_low, s.loss_high), (10, 20));
        assert_eq!(s.interval, Duration::from_secs(1));
        assert_eq!(s.loss_interval, Duration::from_secs(4));
        assert_eq!(s.time_period, Duration::from_secs(60));
        assert_eq!(s.data_length, 1);
        assert_eq!(s.validate(), Ok(()));
    }

    #[test]
    fn validation_table() {
        let ok = MonitorSettings::default();
        let cases: Vec<(MonitorSettings, Result<(), SettingsError>)> = vec![
            (
                MonitorSettings {
                    latency_low: Duration::from_millis(500),
                    ..ok
                },
                Err(SettingsError::LatencyOrder),
            ),
            (
                MonitorSettings { loss_low: 20, ..ok },
                Err(SettingsError::LossOrder),
            ),
            (
                MonitorSettings {
                    loss_high: 101,
                    ..ok
                },
                Err(SettingsError::LossRange),
            ),
            (
                MonitorSettings { loss_low: 0, ..ok },
                Err(SettingsError::LossRange),
            ),
            // 2 * (1 + 4) = 10 s is the minimum time period.
            (
                MonitorSettings {
                    time_period: Duration::from_secs(9),
                    ..ok
                },
                Err(SettingsError::TimePeriodTooShort),
            ),
            (
                MonitorSettings {
                    time_period: Duration::from_secs(10),
                    ..ok
                },
                Ok(()),
            ),
            (
                MonitorSettings {
                    interval: Duration::ZERO,
                    ..ok
                },
                Err(SettingsError::Zero("interval")),
            ),
            (
                MonitorSettings {
                    data_length: MAX_DATA_LENGTH + 1,
                    ..ok
                },
                Err(SettingsError::DataLength),
            ),
            (
                MonitorSettings {
                    data_length: 0,
                    ..ok
                },
                Ok(()),
            ),
        ];
        for (settings, want) in cases {
            assert_eq!(settings.validate(), want, "{settings:?}");
        }
    }
}
