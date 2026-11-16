//! Probe history of one target and its reduction to latency/loss figures.
//!
//! The window is clock-free: every call takes the instant it happens at, so
//! tests replay arbitrary timelines without sleeping.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::MonitorSettings;

/// Upper bound on remembered probes, whatever the settings say: a 1 ms
/// interval over an hour must not grow without limit.
const MAX_PROBES: usize = 1 << 16;

#[derive(Debug, Clone, Copy)]
struct Probe {
    seq: u16,
    sent: Instant,
    rtt: Option<Duration>,
}

/// Latency and loss of a target over the time period, the figures dpinger
/// reports on its status socket.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    /// Mean round trip time of the answered probes (zero if none).
    pub latency_avg: Duration,
    /// Population standard deviation of those round trip times.
    pub latency_stddev: Duration,
    /// Lost probes as a percentage of the counted ones, 0.0..=100.0.
    pub loss_pct: f64,
    /// Probes answered within the loss interval.
    pub received: u32,
    /// Probes unanswered for longer than the loss interval, or answered too
    /// late.
    pub lost: u32,
}

/// Ring of the probes sent to one target within the time period.
#[derive(Debug, Clone)]
pub struct ProbeWindow {
    probes: VecDeque<Probe>,
    max_len: usize,
}

impl ProbeWindow {
    /// An empty window sized for `settings`.
    pub fn new(settings: &MonitorSettings) -> Self {
        let per_period = if settings.interval.is_zero() {
            MAX_PROBES
        } else {
            let n = settings.time_period.as_nanos() / settings.interval.as_nanos();
            usize::try_from(n).unwrap_or(MAX_PROBES).saturating_add(2)
        };
        let max_len = per_period.clamp(2, MAX_PROBES);
        Self {
            probes: VecDeque::with_capacity(max_len.min(1024)),
            max_len,
        }
    }

    /// Records an echo request with sequence number `seq` sent at `at`.
    pub fn record_sent(&mut self, seq: u16, at: Instant) {
        if self.probes.len() == self.max_len {
            self.probes.pop_front();
        }
        self.probes.push_back(Probe {
            seq,
            sent: at,
            rtt: None,
        });
    }

    /// Records an echo reply for `seq` received at `at`. Returns the round
    /// trip time, or `None` for a reply that matches no outstanding probe
    /// (duplicate, stale, or not ours).
    pub fn record_reply(&mut self, seq: u16, at: Instant) -> Option<Duration> {
        // The newest probe with this number: sequence numbers wrap, and the
        // window is far shorter than 65536 probes in any sane setting.
        let probe = self
            .probes
            .iter_mut()
            .rev()
            .find(|p| p.seq == seq && p.rtt.is_none() && p.sent <= at)?;
        let rtt = at.duration_since(probe.sent);
        probe.rtt = Some(rtt);
        Some(rtt)
    }

    /// Drops probes sent longer than the time period before `now` and
    /// reduces the rest. Probes still within the loss interval and unanswered
    /// are pending and not counted, like dpinger. `None` means there is no
    /// counted probe yet (dpinger's `0 0 0`).
    pub fn sample(&mut self, now: Instant, settings: &MonitorSettings) -> Option<Sample> {
        while let Some(front) = self.probes.front() {
            if now.saturating_duration_since(front.sent) > settings.time_period {
                self.probes.pop_front();
            } else {
                break;
            }
        }

        let mut received = 0u32;
        let mut lost = 0u32;
        let mut sum_us = 0f64;
        let mut rtts_us = Vec::with_capacity(self.probes.len());
        for p in &self.probes {
            match p.rtt {
                Some(rtt) if rtt <= settings.loss_interval => {
                    let us = rtt.as_secs_f64() * 1e6;
                    sum_us += us;
                    rtts_us.push(us);
                    received += 1;
                }
                Some(_) => lost += 1,
                None if now.saturating_duration_since(p.sent) > settings.loss_interval => lost += 1,
                None => {}
            }
        }

        let counted = received + lost;
        if counted == 0 {
            return None;
        }
        let (avg_us, stddev_us) = if received == 0 {
            (0.0, 0.0)
        } else {
            let avg = sum_us / f64::from(received);
            let var = rtts_us.iter().map(|x| (x - avg).powi(2)).sum::<f64>() / f64::from(received);
            (avg, var.sqrt())
        };
        Some(Sample {
            latency_avg: Duration::from_secs_f64(avg_us / 1e6),
            latency_stddev: Duration::from_secs_f64(stddev_us / 1e6),
            loss_pct: f64::from(lost) * 100.0 / f64::from(counted),
            received,
            lost,
        })
    }

    /// Number of probes currently remembered.
    pub fn len(&self) -> usize {
        self.probes.len()
    }

    /// True if no probe is remembered.
    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }
}

/// Covers: SYS-GW-001
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// Sends one probe per second for `n` seconds; `rtt(i)` is the reply
    /// delay of probe `i` or `None` for no reply.
    fn run(n: u16, rtt: impl Fn(u16) -> Option<u64>) -> (ProbeWindow, Instant) {
        let s = MonitorSettings::default();
        let t0 = Instant::now();
        let mut w = ProbeWindow::new(&s);
        let end = t0 + Duration::from_secs(u64::from(n));
        for i in 0..n {
            let sent = t0 + Duration::from_secs(u64::from(i));
            w.record_sent(i, sent);
            if let Some(r) = rtt(i) {
                let at = sent + ms(r);
                if at <= end {
                    w.record_reply(i, at);
                }
            }
        }
        (w, end)
    }

    #[test]
    fn empty_window_has_no_sample() {
        let s = MonitorSettings::default();
        let mut w = ProbeWindow::new(&s);
        assert_eq!(w.sample(Instant::now(), &s), None);
    }

    #[test]
    fn unanswered_probe_is_pending_until_loss_interval() {
        let s = MonitorSettings::default();
        let t0 = Instant::now();
        let mut w = ProbeWindow::new(&s);
        w.record_sent(1, t0);
        assert_eq!(
            w.sample(t0 + ms(4000), &s),
            None,
            "exactly at the loss interval: pending"
        );
        let lost = w.sample(t0 + ms(4001), &s).expect("counted");
        assert_eq!((lost.received, lost.lost, lost.loss_pct), (0, 1, 100.0));
    }

    #[test]
    fn statistics_table() {
        struct Case {
            name: &'static str,
            rtts: fn(u16) -> Option<u64>,
            avg_ms: f64,
            stddev_ms: f64,
            loss: f64,
        }
        let cases = [
            Case {
                name: "steady 10 ms",
                rtts: |_| Some(10),
                avg_ms: 10.0,
                stddev_ms: 0.0,
                loss: 0.0,
            },
            Case {
                name: "alternating 10/30 ms",
                rtts: |i| Some(if i % 2 == 0 { 10 } else { 30 }),
                avg_ms: 20.0,
                stddev_ms: 10.0,
                loss: 0.0,
            },
            Case {
                // Answered probes count whatever their age; of 30, every 5th
                // (0,5,..,25 => 6) is unanswered and older than 4 s.
                name: "every fifth lost",
                rtts: |i| if i % 5 == 0 { None } else { Some(10) },
                avg_ms: 10.0,
                stddev_ms: 0.0,
                loss: 6.0 * 100.0 / 30.0,
            },
            Case {
                name: "reply after the loss interval counts as loss",
                // Odd probes 1..=25 answered after 4.5 s (13 lost); 27 and 29
                // are still pending; 15 even probes answered.
                rtts: |i| Some(if i % 2 == 0 { 10 } else { 4500 }),
                avg_ms: 10.0,
                stddev_ms: 0.0,
                loss: 13.0 * 100.0 / 28.0,
            },
            Case {
                name: "all lost",
                rtts: |_| None,
                avg_ms: 0.0,
                stddev_ms: 0.0,
                loss: 100.0,
            },
        ];
        let s = MonitorSettings::default();
        for c in cases {
            let (mut w, now) = run(30, c.rtts);
            let got = w.sample(now, &s).expect(c.name);
            let avg = got.latency_avg.as_secs_f64() * 1e3;
            let sd = got.latency_stddev.as_secs_f64() * 1e3;
            assert!((avg - c.avg_ms).abs() < 1e-6, "{}: avg {avg}", c.name);
            assert!((sd - c.stddev_ms).abs() < 1e-6, "{}: stddev {sd}", c.name);
            assert!(
                (got.loss_pct - c.loss).abs() < 1e-9,
                "{}: loss {}",
                c.name,
                got.loss_pct
            );
        }
    }

    #[test]
    fn probes_older_than_time_period_are_dropped() {
        let s = MonitorSettings::default();
        // 60 lost probes, then 60 good ones: after two periods only the good
        // ones remain.
        let (mut w, now) = run(120, |i| if i < 60 { None } else { Some(5) });
        let got = w.sample(now, &s).expect("sample");
        assert_eq!(got.lost, 0);
        assert!(w.len() <= 62);
    }

    #[test]
    fn duplicate_and_unknown_replies_are_ignored() {
        let s = MonitorSettings::default();
        let t0 = Instant::now();
        let mut w = ProbeWindow::new(&s);
        w.record_sent(7, t0);
        assert_eq!(w.record_reply(7, t0 + ms(3)), Some(ms(3)));
        assert_eq!(w.record_reply(7, t0 + ms(9)), None, "duplicate");
        assert_eq!(w.record_reply(8, t0 + ms(9)), None, "never sent");
    }

    #[test]
    fn sequence_wraparound_matches_newest_probe() {
        let s = MonitorSettings::default();
        let t0 = Instant::now();
        let mut w = ProbeWindow::new(&s);
        w.record_sent(u16::MAX, t0);
        w.record_sent(0, t0 + ms(1000));
        assert_eq!(w.record_reply(0, t0 + ms(1002)), Some(ms(2)));
        assert_eq!(w.record_reply(u16::MAX, t0 + ms(1003)), Some(ms(1003)));
    }

    #[test]
    fn window_is_bounded() {
        let s = MonitorSettings {
            interval: ms(1),
            time_period: Duration::from_secs(3600),
            ..MonitorSettings::default()
        };
        let mut w = ProbeWindow::new(&s);
        let t0 = Instant::now();
        for i in 0..(MAX_PROBES + 10) {
            w.record_sent(i as u16, t0 + ms(i as u64));
        }
        assert_eq!(w.len(), MAX_PROBES);
    }

    proptest! {
        #[test]
        fn loss_is_a_percentage(events in proptest::collection::vec((0u64..3000, proptest::option::of(0u64..6000)), 0..200), at in 0u64..400_000) {
            let s = MonitorSettings::default();
            let t0 = Instant::now();
            let mut w = ProbeWindow::new(&s);
            let mut t = t0;
            for (i, (gap, rtt)) in events.iter().enumerate() {
                t += ms(*gap);
                w.record_sent(i as u16, t);
                if let Some(r) = rtt {
                    w.record_reply(i as u16, t + ms(*r));
                }
            }
            if let Some(sample) = w.sample(t0 + ms(at), &s) {
                prop_assert!((0.0..=100.0).contains(&sample.loss_pct));
                prop_assert!(sample.received + sample.lost > 0);
                prop_assert!(sample.latency_avg <= s.loss_interval);
            }
        }
    }
}
