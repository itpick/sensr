//! systemd integration: `sd_notify` readiness/reload/stop and the watchdog.
//!
//! Every call is a no-op outside systemd (`NOTIFY_SOCKET` unset), so the
//! agent runs the same under `cargo test`.

use std::future::Future;
use std::time::Duration;

use sd_notify::NotifyState;
use tokio::sync::watch;

fn send(states: &[NotifyState]) {
    if std::env::var_os("NOTIFY_SOCKET").is_none() {
        return;
    }
    if let Err(e) = sd_notify::notify(states) {
        tracing::warn!(error = %e, "sd_notify failed");
    }
}

/// `READY=1` with a status line.
pub fn ready(status: &str) {
    send(&[NotifyState::Ready, NotifyState::Status(status)]);
}

/// `RELOADING=1` (with `MONOTONIC_USEC`, as `Type=notify-reload` requires).
pub fn reloading() {
    match NotifyState::monotonic_usec_now() {
        Ok(now) => send(&[NotifyState::Reloading, now]),
        Err(_) => send(&[NotifyState::Reloading]),
    }
}

/// `STOPPING=1`.
pub fn stopping() {
    send(&[NotifyState::Stopping, NotifyState::Status("stopping")]);
}

/// A status line.
pub fn status(text: &str) {
    send(&[NotifyState::Status(text)]);
}

/// Pings the watchdog at half the configured interval, but only while
/// `healthy` completes within that half interval. A wedged agent (e.g. a
/// deadlocked store lock) stops pinging and systemd restarts it.
pub async fn watchdog<F, Fut>(healthy: F, mut shutdown: watch::Receiver<bool>)
where
    F: Fn() -> Fut,
    Fut: Future<Output = ()>,
{
    let Some(interval) = sd_notify::watchdog_enabled() else {
        return;
    };
    let half = (interval / 2).max(Duration::from_millis(100));
    let mut tick = tokio::time::interval(half);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if tokio::time::timeout(half, healthy()).await.is_ok() {
                    send(&[NotifyState::Watchdog]);
                } else {
                    tracing::error!("health check timed out; withholding watchdog ping");
                }
            }
            _ = async { let _ = shutdown.wait_for(|s| *s).await; } => return,
        }
    }
}
