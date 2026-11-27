//! The event pipeline: decode ring-buffer records, fold duplicates, cap the
//! rate and batch for the database. Everything here is pure (no I/O, no
//! clock of its own): callers pass `now`, so tests drive time by hand.
//!
//! Counters are kept apart on purpose: `dropped_kernel` is the ring buffer
//! overflowing (the loader's `ringbuf_dropped()`, set with
//! [`Pipeline::set_dropped_kernel`]); `dropped_rate` is this pipeline's own
//! userspace cap (new rows only); `dropped_blocked` counts denials lost to
//! the pending-memory bound.
//!
//! For the daemon (Task 7): call [`Pipeline::tick`] on a timer (at most 1 s)
//! and [`Pipeline::drain`] on shutdown; if `Store::write_batch` fails, hand
//! the batch back with [`Pipeline::requeue`] or it is lost.

use std::collections::HashMap;
use std::mem::{offset_of, size_of};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::maps::{GuardEvent, PATH_LEN};

/// Identical events within this window become one row with a count.
pub const DEDUPE_WINDOW: Duration = Duration::from_secs(10);
/// A blocked row closes its window after this, so denials reach the DB soon.
pub const BLOCKED_WINDOW: Duration = Duration::from_secs(1);
/// Batches are handed out at most this often.
pub const BATCH_INTERVAL: Duration = Duration::from_secs(5);
/// Events kept per second, globally; the rest are counted as dropped.
pub const RATE_CAP_PER_SEC: u32 = 100;
/// New rows one rule may add per second, on average (a token bucket per
/// rule slot), so one noisy rule cannot use up the global budget.
pub const RULE_RATE_PER_SEC: u32 = 20;
/// The most a rule's bucket holds: a burst it may add at once.
pub const RULE_BURST: u32 = 50;
/// `sock_type` of a listening TCP socket (`SOCK_STREAM`).
pub const SOCK_STREAM: u8 = 1;
/// `sock_type` of a UDP bind (`SOCK_DGRAM`).
pub const SOCK_DGRAM: u8 = 2;
/// The hook number of `listen`.
const LISTEN_HOOK: u8 = 2;
/// Hard bound on pending (not yet batched) rows.
pub const MAX_PENDING: usize = 4096;
/// Bytes kept of a text field.
pub const TEXT_CAP: usize = 256;

const HOOK_NAMES: [&str; 7] = [
    "exec",
    "connect",
    "listen",
    "file_write",
    "setuid",
    "module",
    "bpf",
];

/// The hook's name (`enum guard_hook`), if known.
pub fn hook_name(hook: u8) -> Option<&'static str> {
    HOOK_NAMES.get(usize::from(hook)).copied()
}

/// The action's name (`enum guard_action`), if known.
pub fn action_name(action: u8) -> Option<&'static str> {
    match action {
        0 => Some("alert"),
        1 => Some("block"),
        _ => None,
    }
}

/// Converts the BPF timestamp to wall time.
///
/// The BPF `ts` is `bpf_ktime_get_boot_ns()` (CLOCK_BOOTTIME, see
/// `bpf/guard/README.md`), which has no relation to the wall clock. The
/// offset (wall ms minus boot ms) is captured once at start, so a later
/// wall-clock step (NTP) does not shift events already seen. The offset is
/// always applied to the same clock the programs read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootClock {
    offset_ms: i64,
}

impl BootClock {
    /// From one simultaneous reading: wall time (unix ms) and boot time (ns).
    pub fn new(wall_unix_ms: i64, boot_ns: u64) -> Self {
        Self {
            offset_ms: wall_unix_ms - (boot_ns / 1_000_000) as i64,
        }
    }

    /// Unix ms of a BPF timestamp.
    pub fn unix_ms(&self, boot_ns: u64) -> i64 {
        self.offset_ms + (boot_ns / 1_000_000) as i64
    }
}

/// One decoded ring-buffer record, text sanitised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// BPF timestamp, CLOCK_BOOTTIME ns.
    pub ts_boot_ns: u64,
    /// Tgid.
    pub pid: u32,
    /// Parent tgid.
    pub ppid: u32,
    /// Uid.
    pub uid: u32,
    /// Rule slot.
    pub rule_id: u32,
    /// `enum guard_hook`.
    pub hook: u8,
    /// `enum guard_action`.
    pub action: u8,
    /// Whether the operation was denied.
    pub blocked: bool,
    /// Executable path.
    pub exe: String,
    /// Path, uid, bpf op, or `addr:port` for connect/listen.
    pub target: String,
    /// Leaf cgroup name.
    pub unit: String,
    /// Listen events: the socket type (`SOCK_STREAM` for a listen, the
    /// bind's type otherwise); 0 for other hooks and older packs.
    pub sock_type: u8,
}

impl Event {
    /// The target as the de-duplication key sees it: a bind of a socket
    /// that does not listen (UDP) is keyed without its port, so a client
    /// that binds a fresh random port for each request (a resolver's
    /// queries) is one row with a count, not a row per port.
    fn dedupe_target(&self) -> String {
        if self.hook == LISTEN_HOOK
            && self.sock_type != 0
            && self.sock_type != SOCK_STREAM
            && let Some((addr, _port)) = self.target.rsplit_once(':')
        {
            return format!("{addr}:*");
        }
        self.target.clone()
    }
}

/// Text of a NUL-terminated field: bytes up to the first NUL, lossy UTF-8,
/// control characters dropped, at most [`TEXT_CAP`] bytes (on a char boundary).
pub fn sanitise(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let mut out = String::new();
    for c in String::from_utf8_lossy(&bytes[..end]).chars() {
        if c.is_control() {
            continue;
        }
        if out.len() + c.len_utf8() > TEXT_CAP {
            break;
        }
        out.push(c);
    }
    out
}

fn net_target(family: u8, addr: &[u8], port: u16) -> String {
    match family {
        2 => format!(
            "{}:{port}",
            std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])
        ),
        10 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&addr[..16]);
            format!("[{}]:{port}", std::net::Ipv6Addr::from(a))
        }
        _ => String::new(),
    }
}

/// Decodes one record (`struct guard_event`, little-endian). `None` for a
/// short buffer or an unknown hook or action. Bytes past the struct are ignored.
pub fn decode(raw: &[u8]) -> Option<Event> {
    if raw.len() < size_of::<GuardEvent>() {
        return None;
    }
    let u32_at = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().unwrap());
    let hook = raw[offset_of!(GuardEvent, hook)];
    let action = raw[offset_of!(GuardEvent, action)];
    hook_name(hook)?;
    action_name(action)?;
    let o = offset_of!(GuardEvent, exe);
    let exe = sanitise(&raw[o..o + PATH_LEN]);
    let o = offset_of!(GuardEvent, target);
    let mut target = sanitise(&raw[o..o + PATH_LEN]);
    let family = raw[offset_of!(GuardEvent, family)];
    if target.is_empty() {
        let o = offset_of!(GuardEvent, addr);
        let p = offset_of!(GuardEvent, port);
        let port = u16::from_le_bytes([raw[p], raw[p + 1]]);
        target = net_target(family, &raw[o..o + 16], port);
    }
    let o = offset_of!(GuardEvent, unit);
    let unit = sanitise(&raw[o..o + crate::maps::UNIT_LEN]);
    Some(Event {
        ts_boot_ns: u64::from_le_bytes(raw[0..8].try_into().unwrap()),
        pid: u32_at(offset_of!(GuardEvent, pid)),
        ppid: u32_at(offset_of!(GuardEvent, ppid)),
        uid: u32_at(offset_of!(GuardEvent, uid)),
        rule_id: u32_at(offset_of!(GuardEvent, rule_id)),
        hook,
        action,
        blocked: raw[offset_of!(GuardEvent, blocked)] != 0,
        exe,
        target,
        unit,
        sock_type: raw[offset_of!(GuardEvent, sock_type)],
    })
}

/// A row to store: the first event of a de-duplicated run plus the run's count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
    /// Unix seconds of the first event.
    pub ts: i64,
    /// Millisecond part of the first event (0..999).
    pub ts_ms: u32,
    /// Hook name.
    pub hook: String,
    /// Action name.
    pub action: String,
    /// Whether the operation was denied.
    pub blocked: bool,
    /// Rule slot.
    pub rule_id: u32,
    /// Executable.
    pub exe: String,
    /// Target.
    pub target: String,
    /// Unit.
    pub unit: String,
    /// Pid of the first event.
    pub pid: u32,
    /// Uid of the first event.
    pub uid: u32,
    /// Events folded into this row.
    pub count: u32,
}

/// Rows to write in one transaction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Batch {
    /// The rows.
    pub rows: Vec<Row>,
}

type Key = (u8, u8, bool, u32, String, String, String);

/// De-duplicate, rate-limit and batch events.
///
/// A row is held until its 10 s window has closed and a batch is due, so
/// one run of identical events is one row, however many batches pass.
#[derive(Debug)]
pub struct Pipeline {
    clock: BootClock,
    /// Per rule slot: tokens left and when they were last topped up.
    buckets: HashMap<u32, (f64, Instant)>,
    pending: HashMap<Key, (Instant, Duration, Row)>,
    /// Rows whose run ended (window passed) before a batch took them.
    closed: Vec<Row>,
    last_batch: Instant,
    window_start: Instant,
    window_count: u32,
    dropped_rate: u64,
    dropped_kernel: u64,
    dropped_blocked: u64,
}

impl Pipeline {
    /// A pipeline started at `now`; the first batch is due 5 s later.
    pub fn new(clock: BootClock, now: Instant) -> Self {
        Self {
            clock,
            buckets: HashMap::new(),
            pending: HashMap::new(),
            closed: Vec::new(),
            last_batch: now,
            window_start: now,
            window_count: 0,
            dropped_rate: 0,
            dropped_kernel: 0,
            dropped_blocked: 0,
        }
    }

    /// Events dropped by the userspace cap (rate, or pending bound).
    pub fn dropped_rate(&self) -> u64 {
        self.dropped_rate
    }

    /// Blocked events lost to the pending-memory bound (never to the rate cap).
    pub fn dropped_blocked(&self) -> u64 {
        self.dropped_blocked
    }

    /// Events the kernel ring buffer dropped (as last set).
    pub fn dropped_kernel(&self) -> u64 {
        self.dropped_kernel
    }

    /// Records the loader's running `ringbuf_dropped()` total.
    pub fn set_dropped_kernel(&mut self, total: u64) {
        self.dropped_kernel = total;
    }

    /// Rows waiting for a batch.
    pub fn pending_len(&self) -> usize {
        self.pending.len() + self.closed.len()
    }

    /// Adds an event; returns a batch if one is due.
    ///
    /// Rate caps: 100 new rows per second globally, in fixed 1 s windows
    /// (so up to 200 can pass across a window boundary), and per rule a
    /// token bucket of [`RULE_BURST`] refilled at [`RULE_RATE_PER_SEC`]. A
    /// row passes only when both have room, and then takes from both. Only
    /// a NEW row costs a token; an event that folds into a pending row just
    /// bumps its count, so one noisy event cannot starve distinct ones.
    /// Blocked events are exempt from the caps (a denial must not vanish),
    /// but still dedupe and still obey the [`MAX_PENDING`] memory bound;
    /// those drops go to `dropped_blocked`.
    pub fn push(&mut self, e: Event, now: Instant) -> Option<Batch> {
        if now.saturating_duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.window_count = 0;
        }
        let key: Key = (
            e.hook,
            e.action,
            e.blocked,
            e.rule_id,
            e.exe.clone(),
            e.dedupe_target(),
            e.unit.clone(),
        );
        if let Some((first, window, row)) = self.pending.get_mut(&key) {
            if now.saturating_duration_since(*first) < *window {
                row.count = row.count.saturating_add(1);
                if row.target != e.target {
                    // folded across ports: say so
                    row.target.clone_from(&key.5);
                }
                return self.tick(now);
            }
            // The old run ended; keep its row for the next batch.
            if let Some((_, _, old)) = self.pending.remove(&key) {
                self.closed.push(old);
            }
        }
        if self.pending_len() >= MAX_PENDING {
            if e.blocked {
                self.dropped_blocked += 1;
            } else {
                self.dropped_rate += 1;
            }
            return self.tick(now);
        }
        if !e.blocked {
            let (tokens, last) = self
                .buckets
                .entry(e.rule_id)
                .or_insert((f64::from(RULE_BURST), now));
            let refill =
                now.saturating_duration_since(*last).as_secs_f64() * f64::from(RULE_RATE_PER_SEC);
            *tokens = (*tokens + refill).min(f64::from(RULE_BURST));
            *last = now;
            if self.window_count >= RATE_CAP_PER_SEC || *tokens < 1.0 {
                self.dropped_rate += 1;
                return self.tick(now);
            }
            *tokens -= 1.0;
            self.window_count += 1;
        }
        let ms = self.clock.unix_ms(e.ts_boot_ns);
        let row = Row {
            ts: ms.div_euclid(1000),
            ts_ms: ms.rem_euclid(1000) as u32,
            hook: hook_name(e.hook).unwrap_or("unknown").to_owned(),
            action: action_name(e.action).unwrap_or("unknown").to_owned(),
            blocked: e.blocked,
            rule_id: e.rule_id,
            exe: e.exe,
            target: e.target,
            unit: e.unit,
            pid: e.pid,
            uid: e.uid,
            count: 1,
        };
        let window = if row.blocked {
            BLOCKED_WINDOW
        } else {
            DEDUPE_WINDOW
        };
        let batch = self.tick(now);
        self.pending.insert(key, (now, window, row));
        batch
    }

    /// A batch of the rows whose window has closed, if 5 s have passed since
    /// the last one and there is something to write.
    ///
    /// Task 7 must call this on a timer (at most every second) as well as
    /// after each `push`, or rows wait for the next event. Latency from an
    /// event to its batch is 10-15 s for alerts (10 s window + up to 5 s to
    /// the next batch) and 1-6 s for blocked events.
    pub fn tick(&mut self, now: Instant) -> Option<Batch> {
        if now.saturating_duration_since(self.last_batch) < BATCH_INTERVAL {
            return None;
        }
        let rows = self.take(|first, window| now.saturating_duration_since(first) >= window);
        if rows.is_empty() {
            return None;
        }
        self.last_batch = now;
        Some(Batch { rows })
    }

    /// Puts a batch back after a failed `write_batch`, so it goes out with
    /// the next one. Rows beyond the [`MAX_PENDING`] bound are counted in
    /// `dropped_rate` (or `dropped_blocked`). Without this a failed write
    /// loses the batch.
    pub fn requeue(&mut self, batch: Batch) {
        for row in batch.rows {
            if self.pending_len() >= MAX_PENDING {
                if row.blocked {
                    self.dropped_blocked += u64::from(row.count);
                } else {
                    self.dropped_rate += u64::from(row.count);
                }
            } else {
                self.closed.push(row);
            }
        }
    }

    /// Everything pending, windows open or not. Task 7 calls this on shutdown.
    pub fn drain(&mut self) -> Option<Batch> {
        let rows = self.take(|_, _| true);
        (!rows.is_empty()).then_some(Batch { rows })
    }

    fn take(&mut self, ready: impl Fn(Instant, Duration) -> bool) -> Vec<Row> {
        let keys: Vec<Key> = self
            .pending
            .iter()
            .filter(|(_, (first, window, _))| ready(*first, *window))
            .map(|(k, _)| k.clone())
            .collect();
        let mut rows: Vec<Row> = std::mem::take(&mut self.closed);
        rows.extend(
            keys.iter()
                .filter_map(|k| self.pending.remove(k).map(|(_, _, r)| r)),
        );
        rows.sort_by_key(|r| (r.ts, r.ts_ms));
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(hook: u8, exe: &[u8], target: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; size_of::<GuardEvent>()];
        b[0..8].copy_from_slice(&5_000_000_000u64.to_le_bytes());
        b[offset_of!(GuardEvent, pid)..][..4].copy_from_slice(&42u32.to_le_bytes());
        b[offset_of!(GuardEvent, uid)..][..4].copy_from_slice(&1000u32.to_le_bytes());
        b[offset_of!(GuardEvent, rule_id)..][..4].copy_from_slice(&7u32.to_le_bytes());
        b[offset_of!(GuardEvent, hook)] = hook;
        b[offset_of!(GuardEvent, action)] = 1;
        b[offset_of!(GuardEvent, blocked)] = 1;
        b[offset_of!(GuardEvent, exe)..][..exe.len()].copy_from_slice(exe);
        b[offset_of!(GuardEvent, target)..][..target.len()].copy_from_slice(target);
        b
    }

    fn ev(target: &str) -> Event {
        Event {
            ts_boot_ns: 5_000_000_000,
            pid: 1,
            ppid: 0,
            uid: 0,
            rule_id: 3,
            hook: 0,
            action: 0,
            blocked: false,
            exe: "/bin/sh".into(),
            target: target.into(),
            unit: "u.service".into(),
            sock_type: 0,
        }
    }

    /// `ev(target)` of rule slot `rule`.
    fn ev_r(target: &str, rule: u32) -> Event {
        Event {
            rule_id: rule,
            ..ev(target)
        }
    }

    fn pipe(t0: Instant) -> Pipeline {
        Pipeline::new(BootClock::new(1_700_000_000_000, 5_000_000_000), t0)
    }

    #[test]
    fn decode_rejects_short_buffer() {
        assert!(decode(&[0; 623]).is_none());
        assert!(decode(&[]).is_none());
    }

    #[test]
    fn decode_reads_fields_at_contract_offsets() {
        let e = decode(&raw(3, b"/bin/sh\0junk", b"/etc/passwd\0")).unwrap();
        assert_eq!(
            (e.pid, e.uid, e.rule_id, e.hook, e.action, e.blocked),
            (42, 1000, 7, 3, 1, true)
        );
        assert_eq!(
            (e.exe.as_str(), e.target.as_str()),
            ("/bin/sh", "/etc/passwd")
        );
        assert_eq!(e.ts_boot_ns, 5_000_000_000);
    }

    #[test]
    fn decode_rejects_unknown_hook_and_action() {
        assert!(decode(&raw(7, b"", b"")).is_none());
        let mut b = raw(0, b"", b"");
        b[offset_of!(GuardEvent, action)] = 2;
        assert!(decode(&b).is_none());
    }

    #[test]
    fn decode_formats_net_target() {
        let mut b = raw(1, b"/bin/curl\0", b"");
        let o = offset_of!(GuardEvent, addr);
        b[o..o + 4].copy_from_slice(&[10, 0, 0, 9]);
        b[offset_of!(GuardEvent, port)..][..2].copy_from_slice(&443u16.to_le_bytes());
        b[offset_of!(GuardEvent, family)] = 2;
        assert_eq!(decode(&b).unwrap().target, "10.0.0.9:443");
        b[offset_of!(GuardEvent, family)] = 10;
        b[o..o + 16].copy_from_slice(&[0; 16]);
        assert_eq!(decode(&b).unwrap().target, "[::]:443");
    }

    #[test]
    fn text_is_taken_up_to_nul_and_sanitised() {
        assert_eq!(sanitise(b"abc\0def"), "abc");
        assert_eq!(sanitise(b"a\x1b[31mb\nc\td\x7f"), "a[31mbcd");
        assert_eq!(sanitise(b"ok\xffend"), "ok\u{fffd}end");
        assert_eq!(sanitise(b""), "");
        // No NUL at all: the whole field.
        assert_eq!(sanitise(b"abcd"), "abcd");
    }

    #[test]
    fn text_is_capped_on_a_char_boundary() {
        let s = "é".repeat(200); // 400 bytes
        let out = sanitise(s.as_bytes());
        assert_eq!(out.len(), 256);
        assert_eq!(out.chars().count(), 128);
        let odd = format!("a{}", "é".repeat(200));
        let out = sanitise(odd.as_bytes());
        assert_eq!(out.len(), 255); // 1 + 127 * 2; the next char would pass 256
        assert!(sanitise(&[b'x'; 300]).len() == 256);
    }

    #[test]
    fn boot_clock_converts_to_wall_time() {
        let c = BootClock::new(1_700_000_010_500, 10_000_000_000);
        assert_eq!(c.unix_ms(10_000_000_000), 1_700_000_010_500);
        assert_eq!(c.unix_ms(12_250_000_000), 1_700_000_012_750);
        let mut p = pipe(Instant::now());
        let t = Instant::now();
        p.push(ev("/x"), t);
        let b = p.drain().unwrap();
        assert_eq!((b.rows[0].ts, b.rows[0].ts_ms), (1_700_000_000, 0));
    }

    #[test]
    fn dedupes_within_10s() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        for s in 0..3 {
            assert!(p.push(ev("/x"), t0 + Duration::from_secs(s)).is_none());
        }
        let b = p.tick(t0 + Duration::from_secs(10)).unwrap();
        assert_eq!(b.rows.len(), 1);
        assert_eq!(b.rows[0].count, 3);
    }

    #[test]
    fn dedupe_key_covers_every_field() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        p.push(ev("/x"), t0);
        p.push(ev("/y"), t0);
        let mut e = ev("/x");
        e.hook = 3;
        p.push(e, t0);
        let mut e = ev("/x");
        e.unit = "other".into();
        p.push(e, t0);
        let mut e = ev("/x");
        e.exe = "/bin/bash".into();
        p.push(e, t0);
        let mut e = ev("/x");
        e.rule_id = 9;
        p.push(e, t0);
        assert_eq!(p.drain().unwrap().rows.len(), 6);
    }

    #[test]
    fn identical_event_after_the_window_is_a_new_row() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        p.push(ev("/x"), t0);
        let b = p.push(ev("/x"), t0 + Duration::from_secs(11)).unwrap();
        assert_eq!(b.rows.len(), 1);
        assert_eq!(b.rows[0].count, 1);
        let b = p.drain().unwrap();
        assert_eq!(b.rows.len(), 1);
        assert_eq!(b.rows[0].count, 1);
    }

    #[test]
    fn rate_cap_counts_dropped() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        // spread over 20 rules, so the per-rule cap is not what stops them
        for i in 0..10_000 {
            p.push(ev_r(&format!("/f{i}"), i % 20), t0);
            assert!(p.pending_len() <= MAX_PENDING);
        }
        assert_eq!(p.pending_len(), 100);
        assert_eq!(p.dropped_rate(), 9_900);
        assert_eq!(p.dropped_kernel(), 0);
        // The next second admits events again.
        p.push(ev_r("/next", 21), t0 + Duration::from_secs(1));
        assert_eq!(p.pending_len(), 101);
    }

    #[test]
    fn pending_is_bounded_across_seconds() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        // 100 distinct per second for 60 s inside one dedupe/batch cadence
        // that never closes (no tick passes the 10 s window): bound holds.
        for s in 0..60u64 {
            for i in 0..100 {
                p.push(
                    ev_r(&format!("/{s}/{i}"), i),
                    t0 + Duration::from_millis(s * 100),
                );
                assert!(p.pending_len() <= MAX_PENDING);
            }
        }
    }

    #[test]
    fn kernel_and_rate_drops_are_separate() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        p.set_dropped_kernel(12);
        for i in 0..101 {
            p.push(ev_r(&format!("/f{i}"), i), t0);
        }
        assert_eq!((p.dropped_kernel(), p.dropped_rate()), (12, 1));
    }

    fn blocked(target: &str) -> Event {
        Event {
            blocked: true,
            action: 1,
            ..ev(target)
        }
    }

    #[test]
    fn duplicates_do_not_starve_distinct_events() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        for _ in 0..5_000 {
            p.push(ev("/noisy"), t0);
        }
        p.push(ev("/other"), t0);
        assert_eq!(p.dropped_rate(), 0);
        let b = p.drain().unwrap();
        assert_eq!(b.rows.len(), 2);
        assert_eq!(b.rows.iter().map(|r| r.count).max(), Some(5_000));
    }

    #[test]
    fn blocked_never_folds_into_alert_row() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        p.push(ev("/x"), t0);
        p.push(blocked("/x"), t0);
        let b = p.drain().unwrap();
        assert_eq!(b.rows.len(), 2);
        assert_eq!(b.rows.iter().filter(|r| r.blocked).count(), 1);
    }

    #[test]
    fn blocked_is_exempt_from_rate_cap() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        for i in 0..300 {
            p.push(blocked(&format!("/b{i}")), t0);
        }
        assert_eq!((p.dropped_rate(), p.dropped_blocked()), (0, 0));
        assert_eq!(p.pending_len(), 300);
        // Alerts still hit the cap, and blocked ones did not use tokens.
        for i in 0..101 {
            p.push(ev_r(&format!("/a{i}"), i), t0);
        }
        assert_eq!(p.dropped_rate(), 1);
    }

    #[test]
    fn blocked_still_dedupes() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        for _ in 0..3 {
            p.push(blocked("/x"), t0);
        }
        let b = p.drain().unwrap();
        assert_eq!((b.rows.len(), b.rows[0].count), (1, 3));
    }

    #[test]
    fn blocked_over_memory_bound_counts_dropped_blocked() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        for i in 0..MAX_PENDING {
            p.push(blocked(&format!("/b{i}")), t0);
        }
        assert_eq!(p.pending_len(), MAX_PENDING);
        p.push(blocked("/over"), t0);
        p.push(ev("/alert-over"), t0);
        assert_eq!((p.dropped_blocked(), p.dropped_rate()), (1, 1));
        assert_eq!(p.pending_len(), MAX_PENDING);
    }

    #[test]
    fn blocked_row_closes_after_1s() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        p.push(blocked("/x"), t0);
        p.push(ev("/a"), t0);
        let b = p.tick(t0 + Duration::from_secs(5)).unwrap();
        assert_eq!(b.rows.len(), 1);
        assert!(b.rows[0].blocked);
        // The alert row waits for its 10 s window.
        assert!(p.tick(t0 + Duration::from_secs(9)).is_none());
        assert_eq!(p.tick(t0 + Duration::from_secs(10)).unwrap().rows.len(), 1);
    }

    #[test]
    fn requeue_returns_a_failed_batch() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        p.push(ev("/a"), t0);
        let b = p.drain().unwrap();
        p.requeue(b);
        assert_eq!(p.pending_len(), 1);
        assert_eq!(p.drain().unwrap().rows[0].target, "/a");
    }

    #[test]
    fn requeue_is_bounded() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        let row = Row {
            ts: 0,
            ts_ms: 0,
            hook: "exec".into(),
            action: "alert".into(),
            blocked: false,
            rule_id: 0,
            exe: String::new(),
            target: String::new(),
            unit: String::new(),
            pid: 0,
            uid: 0,
            count: 2,
        };
        p.requeue(Batch {
            rows: vec![row; MAX_PENDING + 3],
        });
        assert_eq!(p.pending_len(), MAX_PENDING);
        assert_eq!(p.dropped_rate(), 6);
    }

    #[test]
    fn batch_at_most_every_5s() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        // Window-closed rows exist from t=10 s; batches come at most 5 s apart.
        p.push(ev("/a"), t0);
        assert!(p.tick(t0 + Duration::from_secs(4)).is_none());
        let b = p.tick(t0 + Duration::from_secs(10)).unwrap();
        assert_eq!(b.rows.len(), 1);
        p.push(ev("/b"), t0 + Duration::from_secs(11));
        assert!(p.tick(t0 + Duration::from_secs(14)).is_none());
        assert!(p.tick(t0 + Duration::from_secs(20)).is_none());
        let b = p.tick(t0 + Duration::from_secs(21)).unwrap();
        assert_eq!(b.rows[0].target, "/b");
        assert!(p.tick(t0 + Duration::from_secs(40)).is_none());
    }

    #[test]
    fn push_returns_the_due_batch() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        assert!(p.push(ev("/a"), t0).is_none());
        let b = p.push(ev("/b"), t0 + Duration::from_secs(12)).unwrap();
        assert_eq!(b.rows.len(), 1);
        assert_eq!(b.rows[0].target, "/a");
        assert_eq!(p.pending_len(), 1);
    }

    #[test]
    fn one_noisy_rule_does_not_eat_the_global_budget() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        for i in 0..1_000 {
            p.push(ev_r(&format!("/noisy{i}"), 1), t0);
        }
        assert_eq!(p.pending_len(), RULE_BURST as usize);
        assert_eq!(p.dropped_rate(), 1_000 - u64::from(RULE_BURST));
        // other rules still get the rest of the global second
        for i in 0..10 {
            p.push(ev_r(&format!("/quiet{i}"), 2 + i), t0);
        }
        assert_eq!(p.pending_len(), RULE_BURST as usize + 10);
    }

    #[test]
    fn a_rule_bucket_refills_at_its_rate() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        for i in 0..RULE_BURST {
            p.push(ev_r(&format!("/a{i}"), 1), t0);
        }
        p.push(ev_r("/over", 1), t0);
        assert_eq!(p.dropped_rate(), 1);
        // half a second: RULE_RATE_PER_SEC / 2 new tokens
        let t = t0 + Duration::from_millis(500);
        for i in 0..RULE_RATE_PER_SEC {
            p.push(ev_r(&format!("/b{i}"), 1), t);
        }
        assert_eq!(p.dropped_rate(), 1 + u64::from(RULE_RATE_PER_SEC / 2));
        // the bucket never holds more than the burst
        let t = t0 + Duration::from_secs(3600);
        for i in 0..RULE_BURST + 5 {
            p.push(
                ev_r(&format!("/c{i}"), 1),
                t + Duration::from_secs(u64::from(i / 90)),
            );
        }
        assert_eq!(p.dropped_rate(), 1 + u64::from(RULE_RATE_PER_SEC / 2) + 5);
    }

    #[test]
    fn blocked_events_do_not_use_rule_tokens() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        for i in 0..200 {
            p.push(
                Event {
                    rule_id: 1,
                    ..blocked(&format!("/b{i}"))
                },
                t0,
            );
        }
        assert_eq!(p.dropped_rate(), 0);
        p.push(ev_r("/a", 1), t0);
        assert_eq!((p.pending_len(), p.dropped_rate()), (201, 0));
    }

    fn udp_bind(target: &str) -> Event {
        Event {
            hook: 2,
            sock_type: SOCK_DGRAM,
            ..ev(target)
        }
    }

    #[test]
    fn udp_binds_to_new_ports_fold_into_one_row() {
        // a resolver binds a new random port for every query
        let t0 = Instant::now();
        let mut p = pipe(t0);
        for port in 30_000..30_500 {
            p.push(udp_bind(&format!("0.0.0.0:{port}")), t0);
            p.push(udp_bind(&format!("[::]:{port}")), t0);
        }
        assert_eq!(p.dropped_rate(), 0);
        let b = p.drain().unwrap();
        assert_eq!(b.rows.len(), 2, "{:?}", b.rows);
        assert!(b.rows.iter().all(|r| r.count == 500));
        // the row says the port varied
        let mut t: Vec<_> = b.rows.iter().map(|r| r.target.as_str()).collect();
        t.sort_unstable();
        assert_eq!(t, ["0.0.0.0:*", "[::]:*"]);
    }

    #[test]
    fn tcp_listens_and_other_hooks_keep_the_port() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        for port in [22, 80, 443] {
            p.push(
                Event {
                    sock_type: SOCK_STREAM,
                    ..udp_bind(&format!("0.0.0.0:{port}"))
                },
                t0,
            );
            // old packs report no socket type: keep the port
            p.push(
                Event {
                    sock_type: 0,
                    ..udp_bind(&format!("10.0.0.1:{port}"))
                },
                t0,
            );
            // connect (hook 1) never folds ports
            p.push(
                Event {
                    hook: 1,
                    ..udp_bind(&format!("10.0.0.2:{port}"))
                },
                t0,
            );
        }
        assert_eq!(p.drain().unwrap().rows.len(), 9);
    }

    #[test]
    fn a_udp_row_seen_once_keeps_its_port() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        p.push(udp_bind("0.0.0.0:5353"), t0);
        let b = p.drain().unwrap();
        assert_eq!(b.rows[0].target, "0.0.0.0:5353");
    }

    #[test]
    fn decode_reads_the_socket_type() {
        let mut b = raw(2, b"/bin/unbound\0", b"");
        b[offset_of!(GuardEvent, sock_type)] = 2;
        assert_eq!(decode(&b).unwrap().sock_type, 2);
    }

    #[test]
    fn drain_flushes_open_windows() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        p.push(ev("/a"), t0);
        assert_eq!(p.drain().unwrap().rows.len(), 1);
        assert!(p.drain().is_none());
    }
}
