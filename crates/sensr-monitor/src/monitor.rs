//! The tokio driver: one probe loop per gateway, a shared snapshot and a
//! stream of status changes.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Serialize, Serializer};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use crate::{
    Family, MonitorSettings, ProbeSpec, ProbeWindow, Prober, ProberFactory, Sample, Status,
    evaluate,
};

/// Delay before retrying a probe socket that could not be opened.
const OPEN_RETRY: Duration = Duration::from_secs(5);
/// Pause after a receive error so a broken socket cannot spin the loop.
const RECV_ERROR_PAUSE: Duration = Duration::from_millis(100);
/// Status change events buffered for slow subscribers.
const EVENT_BUFFER: usize = 256;

/// How the monitor should treat one gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConfig {
    /// Gateway name (unique key).
    pub name: String,
    /// Address family.
    pub family: Family,
    /// Interface device to bind the probe socket to.
    pub device: Option<String>,
    /// Source address for probes.
    pub source: Option<IpAddr>,
    /// Address to probe: the monitor address, else the gateway address.
    /// `None` while a dynamic gateway's address is unknown.
    pub target: Option<IpAddr>,
    /// Probe at all (inverse of OPNsense `monitor_disable`).
    pub monitor: bool,
    /// Administratively forced down.
    pub force_down: bool,
    /// Timing and thresholds.
    pub settings: MonitorSettings,
}

impl GatewayConfig {
    /// A monitored gateway with default settings.
    pub fn new(name: impl Into<String>, family: Family, target: Option<IpAddr>) -> Self {
        Self {
            name: name.into(),
            family,
            device: None,
            source: None,
            target,
            monitor: true,
            force_down: false,
            settings: MonitorSettings::default(),
        }
    }
}

/// Current state of one gateway.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GatewayState {
    /// Gateway name.
    pub name: String,
    /// Current status.
    pub status: Status,
    /// Whether the gateway is probed (`false`: status is `online` by
    /// definition, as upstream's `none`).
    pub monitored: bool,
    /// The address being probed.
    pub monitor_address: Option<IpAddr>,
    /// Average round trip time in milliseconds, 0.1 ms resolution.
    pub latency_ms: Option<f64>,
    /// Standard deviation of the round trip time in milliseconds.
    pub stddev_ms: Option<f64>,
    /// Packet loss in percent, 0.1 resolution.
    pub loss_pct: Option<f64>,
    /// When `status` last changed, as Unix seconds in JSON.
    #[serde(serialize_with = "unix_seconds")]
    pub last_change: SystemTime,
    /// Why probing is not working, if it is not.
    pub error: Option<String>,
    /// Bumped on every reconfiguration so a cancelled loop cannot overwrite
    /// the state of its successor.
    #[serde(skip)]
    generation: u64,
}

fn unix_seconds<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u64(t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()))
}

/// All gateway states, keyed by name.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Snapshot {
    /// Gateway states.
    pub gateways: BTreeMap<String, GatewayState>,
}

impl Snapshot {
    /// The state of `name`.
    pub fn get(&self, name: &str) -> Option<&GatewayState> {
        self.gateways.get(name)
    }

    /// The status of `name`.
    pub fn status(&self, name: &str) -> Option<Status> {
        self.get(name).map(|g| g.status)
    }
}

/// A gateway changed status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusChanged {
    /// Gateway name.
    pub gateway: String,
    /// Previous status.
    pub from: Status,
    /// New status.
    pub to: Status,
}

/// Errors of the [`Monitor`] control API.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MonitorError {
    /// No gateway with this name is configured.
    #[error("unknown gateway {0}")]
    UnknownGateway(String),
    /// The settings are invalid.
    #[error("gateway {0}: {1}")]
    Settings(String, crate::SettingsError),
}

struct Entry {
    config: GatewayConfig,
    generation: u64,
    force_down: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

struct Shared {
    snapshot: watch::Sender<Snapshot>,
    events: broadcast::Sender<StatusChanged>,
}

impl Shared {
    /// Applies `f` to the state of `name` if it is still at `generation`,
    /// stamps status changes and announces them.
    fn update(&self, name: &str, generation: u64, f: impl FnOnce(&mut GatewayState)) {
        let mut change = None;
        self.snapshot.send_if_modified(|snap| {
            let Some(state) = snap.gateways.get_mut(name) else {
                return false;
            };
            if state.generation != generation {
                return false;
            }
            let before = state.clone();
            f(state);
            if state.status != before.status {
                state.last_change = SystemTime::now();
                change = Some(StatusChanged {
                    gateway: name.to_string(),
                    from: before.status,
                    to: state.status,
                });
            }
            *state != before
        });
        if let Some(ev) = change {
            tracing::info!(gateway = %ev.gateway, from = ?ev.from, to = ?ev.to, "gateway status changed");
            // No subscriber is not an error.
            let _ = self.events.send(ev);
        }
    }
}

/// Runs the probe loops and owns the published state.
///
/// Methods take `&self` and must be called within a tokio runtime (they
/// spawn tasks). Dropping the monitor stops every probe loop.
pub struct Monitor<F: ProberFactory> {
    factory: Arc<F>,
    shared: Arc<Shared>,
    entries: Mutex<HashMap<String, Entry>>,
    next_generation: std::sync::atomic::AtomicU64,
}

#[cfg(unix)]
impl Monitor<crate::IcmpFactory> {
    /// A monitor that probes with ICMP / ICMPv6 echo.
    pub fn icmp() -> Self {
        Self::new(crate::IcmpFactory)
    }
}

impl<F: ProberFactory> Monitor<F> {
    /// A monitor using `factory` for its probe sockets.
    pub fn new(factory: F) -> Self {
        let (snapshot, _) = watch::channel(Snapshot::default());
        let (events, _) = broadcast::channel(EVENT_BUFFER);
        Self {
            factory: Arc::new(factory),
            shared: Arc::new(Shared { snapshot, events }),
            entries: Mutex::new(HashMap::new()),
            next_generation: std::sync::atomic::AtomicU64::new(1),
        }
    }

    fn entries(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        // A panic while holding the lock leaves the map consistent (every
        // mutation is a single insert/remove), so poisoning is ignored.
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The current state of every gateway.
    pub fn snapshot(&self) -> Snapshot {
        self.shared.snapshot.borrow().clone()
    }

    /// A receiver that sees every snapshot update.
    pub fn subscribe(&self) -> watch::Receiver<Snapshot> {
        self.shared.snapshot.subscribe()
    }

    /// A receiver of status change events from now on.
    pub fn events(&self) -> broadcast::Receiver<StatusChanged> {
        self.shared.events.subscribe()
    }

    /// Adds a gateway or replaces its configuration. Probing restarts with
    /// an empty history when anything relevant changed.
    pub fn upsert(&self, config: GatewayConfig) -> Result<(), MonitorError> {
        config
            .settings
            .validate()
            .map_err(|e| MonitorError::Settings(config.name.clone(), e))?;
        let mut entries = self.entries();
        if let Some(e) = entries.get(&config.name)
            && e.config == config
        {
            return Ok(());
        }
        let entry = self.start(config);
        entries.insert(entry.config.name.clone(), entry);
        Ok(())
    }

    /// Stops monitoring `name` and removes it from the snapshot.
    pub fn remove(&self, name: &str) -> Result<(), MonitorError> {
        let removed = self.entries().remove(name);
        if removed.is_none() {
            return Err(MonitorError::UnknownGateway(name.to_string()));
        }
        self.shared.snapshot.send_modify(|s| {
            s.gateways.remove(name);
        });
        Ok(())
    }

    /// Sets the probe target of `name`, e.g. once DHCP has supplied the
    /// gateway address, or clears it (`None`) when the lease is gone.
    pub fn set_target(&self, name: &str, target: Option<IpAddr>) -> Result<(), MonitorError> {
        let mut entries = self.entries();
        let entry = entries
            .get(name)
            .ok_or_else(|| MonitorError::UnknownGateway(name.to_string()))?;
        if entry.config.target == target {
            return Ok(());
        }
        let config = GatewayConfig {
            target,
            ..entry.config.clone()
        };
        let entry = self.start(config);
        entries.insert(name.to_string(), entry);
        Ok(())
    }

    /// Forces `name` down or releases it, without losing its history.
    pub fn set_force_down(&self, name: &str, force_down: bool) -> Result<(), MonitorError> {
        let mut entries = self.entries();
        let entry = entries
            .get_mut(name)
            .ok_or_else(|| MonitorError::UnknownGateway(name.to_string()))?;
        entry.config.force_down = force_down;
        entry.force_down.store(force_down, Ordering::Relaxed);
        let probing = entry.task.is_some();
        let idle = idle_status(&entry.config);
        self.shared.update(name, entry.generation, |s| {
            if force_down {
                s.status = Status::ForceDown;
            } else if !probing {
                s.status = idle;
            }
            // A probing gateway gets its measured status back on the next
            // evaluation, within one alert interval.
        });
        Ok(())
    }

    /// Builds the entry for `config`, publishes its initial state and spawns
    /// its probe loop when there is something to probe.
    fn start(&self, config: GatewayConfig) -> Entry {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let force_down = Arc::new(AtomicBool::new(config.force_down));
        let initial = GatewayState {
            name: config.name.clone(),
            status: idle_status(&config),
            monitored: config.monitor,
            monitor_address: config.target,
            latency_ms: None,
            stddev_ms: None,
            loss_pct: None,
            last_change: SystemTime::now(),
            error: None,
            generation,
        };
        let mut change = None;
        self.shared.snapshot.send_modify(|snap| {
            let previous = snap.gateways.insert(config.name.clone(), initial.clone());
            if let Some(prev) = previous {
                if prev.status != initial.status {
                    change = Some(StatusChanged {
                        gateway: config.name.clone(),
                        from: prev.status,
                        to: initial.status,
                    });
                } else if let Some(state) = snap.gateways.get_mut(&config.name) {
                    state.last_change = prev.last_change;
                }
            }
        });
        if let Some(ev) = change {
            let _ = self.shared.events.send(ev);
        }

        let task = match (config.monitor, config.target) {
            (true, Some(target)) => {
                let spec = ProbeSpec {
                    gateway: config.name.clone(),
                    target,
                    device: config.device.clone(),
                    source: config.source,
                    scope_id: None,
                    data_length: config.settings.data_length,
                    ident: next_ident(),
                };
                Some(tokio::spawn(probe_loop(
                    Arc::clone(&self.factory),
                    spec,
                    config.settings,
                    Arc::clone(&force_down),
                    Arc::clone(&self.shared),
                    generation,
                )))
            }
            _ => None,
        };
        Entry {
            config,
            generation,
            force_down,
            task,
        }
    }
}

/// Status of a gateway that is not (yet) being measured.
fn idle_status(config: &GatewayConfig) -> Status {
    if config.force_down {
        Status::ForceDown
    } else if config.monitor {
        Status::Pending
    } else {
        Status::Online
    }
}

#[cfg(unix)]
fn next_ident() -> u16 {
    crate::IcmpFactory::next_ident()
}

#[cfg(not(unix))]
fn next_ident() -> u16 {
    use std::sync::atomic::AtomicU16;
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

async fn probe_loop<F: ProberFactory>(
    factory: Arc<F>,
    spec: ProbeSpec,
    settings: MonitorSettings,
    force_down: Arc<AtomicBool>,
    shared: Arc<Shared>,
    generation: u64,
) {
    let name = spec.gateway.clone();
    let prober = loop {
        match factory.open(&spec) {
            Ok(p) => {
                shared.update(&name, generation, |s| s.error = None);
                break p;
            }
            Err(e) => {
                tracing::warn!(gateway = %name, target = %spec.target, error = %e, "cannot open probe socket");
                let msg = e.to_string();
                shared.update(&name, generation, |s| s.error = Some(msg));
                tokio::time::sleep(OPEN_RETRY).await;
            }
        }
    };

    let mut window = ProbeWindow::new(&settings);
    let mut send_tick = tokio::time::interval(settings.interval);
    send_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut alert_tick = tokio::time::interval(settings.alert_interval);
    alert_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut seq: u16 = 0;

    loop {
        tokio::select! {
            _ = send_tick.tick() => {
                seq = seq.wrapping_add(1);
                // Recorded before sending: a request that cannot be sent
                // (no route, interface down) counts as lost, as it should.
                window.record_sent(seq, Instant::now().into_std());
                if let Err(e) = prober.send(seq).await {
                    tracing::debug!(gateway = %name, error = %e, "echo request not sent");
                }
            }
            reply = prober.recv() => match reply {
                Ok(r) => {
                    window.record_reply(r.seq, r.received.into_std());
                }
                Err(e) => {
                    tracing::debug!(gateway = %name, error = %e, "echo receive failed");
                    tokio::time::sleep(RECV_ERROR_PAUSE).await;
                }
            },
            _ = alert_tick.tick() => {
                let sample = window.sample(Instant::now().into_std(), &settings);
                let status = if force_down.load(Ordering::Relaxed) {
                    Status::ForceDown
                } else {
                    evaluate(sample.as_ref(), &settings)
                };
                shared.update(&name, generation, |s| apply(s, status, sample.as_ref()));
            }
        }
    }
}

fn apply(state: &mut GatewayState, status: Status, sample: Option<&Sample>) {
    state.status = status;
    state.latency_ms = sample.map(|s| round1(ms(s.latency_avg)));
    state.stddev_ms = sample.map(|s| round1(ms(s.latency_stddev)));
    state.loss_pct = sample.map(|s| round1(s.loss_pct));
}
