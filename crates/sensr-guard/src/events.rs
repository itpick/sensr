//! The event pipeline: decode ring-buffer records, fold duplicates, cap the
//! rate and batch for the database. Everything here is pure (no I/O, no
//! clock of its own): callers pass `now`, so tests drive time by hand.
//!
//! Counters are kept apart on purpose: `dropped_kernel` is the ring buffer
//! overflowing (the loader's `ringbuf_dropped()`, set with
//! [`Pipeline::set_dropped_kernel`]); `dropped_rate` is this pipeline's own
//! userspace cap.

use std::collections::HashMap;
use std::mem::{offset_of, size_of};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::maps::{GuardEvent, PATH_LEN};

/// Identical events within this window become one row with a count.
pub const DEDUPE_WINDOW: Duration = Duration::from_secs(10);
/// Batches are handed out at most this often.
pub const BATCH_INTERVAL: Duration = Duration::from_secs(5);
/// Events kept per second, globally; the rest are counted as dropped.
pub const RATE_CAP_PER_SEC: u32 = 100;
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

type Key = (u8, u32, String, String, String);

/// De-duplicate, rate-limit and batch events.
///
/// A row is held until its 10 s window has closed and a batch is due, so
/// one run of identical events is one row, however many batches pass.
#[derive(Debug)]
pub struct Pipeline {
    clock: BootClock,
    pending: HashMap<Key, (Instant, Row)>,
    /// Rows whose run ended (window passed) before a batch took them.
    closed: Vec<Row>,
    last_batch: Instant,
    window_start: Instant,
    window_count: u32,
    dropped_rate: u64,
    dropped_kernel: u64,
}

impl Pipeline {
    /// A pipeline started at `now`; the first batch is due 5 s later.
    pub fn new(clock: BootClock, now: Instant) -> Self {
        Self {
            clock,
            pending: HashMap::new(),
            closed: Vec::new(),
            last_batch: now,
            window_start: now,
            window_count: 0,
            dropped_rate: 0,
            dropped_kernel: 0,
        }
    }

    /// Events dropped by the userspace cap (rate, or pending bound).
    pub fn dropped_rate(&self) -> u64 {
        self.dropped_rate
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
    pub fn push(&mut self, e: Event, now: Instant) -> Option<Batch> {
        if now.saturating_duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.window_count = 0;
        }
        if self.window_count >= RATE_CAP_PER_SEC {
            self.dropped_rate += 1;
            return self.tick(now);
        }
        let key: Key = (
            e.hook,
            e.rule_id,
            e.exe.clone(),
            e.target.clone(),
            e.unit.clone(),
        );
        if let Some((first, row)) = self.pending.get_mut(&key) {
            if now.saturating_duration_since(*first) < DEDUPE_WINDOW {
                row.count = row.count.saturating_add(1);
                self.window_count += 1;
                return self.tick(now);
            }
            // The old run ended; keep its row for the next batch.
            if let Some((_, old)) = self.pending.remove(&key) {
                self.closed.push(old);
            }
        }
        if self.pending_len() >= MAX_PENDING {
            self.dropped_rate += 1;
            return self.tick(now);
        }
        self.window_count += 1;
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
        let batch = self.tick(now);
        self.pending.insert(key, (now, row));
        batch
    }

    /// A batch of the rows whose window has closed, if 5 s have passed since
    /// the last one and there is something to write.
    pub fn tick(&mut self, now: Instant) -> Option<Batch> {
        if now.saturating_duration_since(self.last_batch) < BATCH_INTERVAL {
            return None;
        }
        let rows = self.take(|first| now.saturating_duration_since(first) >= DEDUPE_WINDOW);
        if rows.is_empty() {
            return None;
        }
        self.last_batch = now;
        Some(Batch { rows })
    }

    /// Everything pending, windows open or not (shutdown).
    pub fn drain(&mut self) -> Option<Batch> {
        let rows = self.take(|_| true);
        (!rows.is_empty()).then_some(Batch { rows })
    }

    fn take(&mut self, ready: impl Fn(Instant) -> bool) -> Vec<Row> {
        let keys: Vec<Key> = self
            .pending
            .iter()
            .filter(|(_, (first, _))| ready(*first))
            .map(|(k, _)| k.clone())
            .collect();
        let mut rows: Vec<Row> = std::mem::take(&mut self.closed);
        rows.extend(
            keys.iter()
                .filter_map(|k| self.pending.remove(k).map(|(_, r)| r)),
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
        for i in 0..10_000 {
            p.push(ev(&format!("/f{i}")), t0);
            assert!(p.pending_len() <= MAX_PENDING);
        }
        assert_eq!(p.pending_len(), 100);
        assert_eq!(p.dropped_rate(), 9_900);
        assert_eq!(p.dropped_kernel(), 0);
        // The next second admits events again.
        p.push(ev("/next"), t0 + Duration::from_secs(1));
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
                    ev(&format!("/{s}/{i}")),
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
            p.push(ev(&format!("/f{i}")), t0);
        }
        assert_eq!((p.dropped_kernel(), p.dropped_rate()), (12, 1));
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
    fn drain_flushes_open_windows() {
        let t0 = Instant::now();
        let mut p = pipe(t0);
        p.push(ev("/a"), t0);
        assert_eq!(p.drain().unwrap().rows.len(), 1);
        assert!(p.drain().is_none());
    }
}
