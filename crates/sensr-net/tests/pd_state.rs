//! PD state machine and persistence, driven by a fake clock.
//!
//! Covers: IF-007 (Identity Association), RA-001 (advertised prefixes and
//! lifetimes), ISS-C-002 (one PD state machine, persisted, RFC 9096
//! deprecation), ISS-C-003 (same lease = no-op).

use ipnet::Ipv6Net;
use pretty_assertions::assert_eq;
use sensr_net::ipv6::pd::{
    AdvertisedPrefix, Consumer, INFINITE_LIFETIME, LoadIssue, ND_PREFERRED_LIMIT, ND_VALID_LIMIT,
    Observation, PdEvent, PdState, PdStore, StaleSignal,
};

const T0: u64 = 1_800_000_000;

fn net(s: &str) -> Ipv6Net {
    s.parse().unwrap()
}

fn obs(prefix: &str, preferred: u32, valid: u32) -> Option<Observation> {
    Some(Observation {
        prefix: net(prefix),
        preferred_lifetime: preferred,
        valid_lifetime: valid,
        iaid: Some(1),
    })
}

fn lans() -> Vec<Consumer> {
    vec![Consumer::new("lan", 0), Consumer::new("iot", 0x10)]
}

fn live(prefix: &str, preferred: u32, valid: u32) -> AdvertisedPrefix {
    AdvertisedPrefix {
        prefix: net(prefix),
        preferred_lifetime_secs: preferred,
        valid_lifetime_secs: valid,
        deprecated: false,
    }
}

fn dep(prefix: &str, valid: u32) -> AdvertisedPrefix {
    AdvertisedPrefix {
        prefix: net(prefix),
        preferred_lifetime_secs: 0,
        valid_lifetime_secs: valid,
        deprecated: true,
    }
}

const OLD: &str = "2001:db8:1234:ab00::/56";
const NEW: &str = "2001:db8:5678:cd00::/56";

#[test]
fn acquire_renew_change_expire() {
    let mut s = PdState::new();
    let e = s.observe(T0, obs(OLD, 1800, 3600));
    assert!(matches!(e.as_slice(), [PdEvent::Acquired(d)] if d.prefix == net(OLD)));
    assert!(s.is_confirmed());

    // Uncapped lifetimes below the RFC 9096 limits pass through.
    let adv = s.advertised(T0, &lans());
    assert_eq!(
        adv["lan"],
        vec![live("2001:db8:1234:ab00::/64", 1800, 3600)]
    );
    assert_eq!(
        adv["iot"],
        vec![live("2001:db8:1234:ab10::/64", 1800, 3600)]
    );

    // Polling the same lease (remaining lifetimes tick down) is a no-op.
    assert_eq!(s.observe(T0 + 10, obs(OLD, 1790, 3590)), vec![]);
    // ±1 s jitter from whole-second sampling is still the same lease.
    assert_eq!(s.observe(T0 + 20, obs(OLD, 1781, 3581)), vec![]);
    assert_eq!(
        s.advertised(T0 + 100, &lans())["lan"],
        vec![live("2001:db8:1234:ab00::/64", 1700, 3500)]
    );

    // T1 renewal: same prefix, fresh lifetimes, not a change.
    let e = s.observe(T0 + 900, obs(OLD, 1800, 3600));
    match e.as_slice() {
        [PdEvent::Renewed(d)] => {
            assert_eq!(d.prefix, net(OLD));
            assert_eq!(d.valid_until, T0 + 900 + 3600);
            assert_eq!(d.obtained_at, T0);
            assert_eq!(d.renewed_at, T0 + 900);
        }
        other => panic!("{other:?}"),
    }
    assert!(s.stale().is_empty());

    // The ISP hands out a new prefix.
    let tc = T0 + 1000;
    let e = s.observe(tc, obs(NEW, 1800, 3600));
    assert!(
        matches!(e.as_slice(), [PdEvent::Changed { old, new }] if *old == net(OLD) && new.prefix == net(NEW))
    );
    // Old prefix: preferred 0, valid = what is left of its lease (3500 s
    // here, under ND_VALID_LIMIT), counting down.
    let adv = s.advertised(tc, &lans());
    assert_eq!(
        adv["lan"],
        vec![
            live("2001:db8:5678:cd00::/64", 1800, 3600),
            dep("2001:db8:1234:ab00::/64", 3500),
        ]
    );
    assert_eq!(
        s.advertised(tc + 500, &lans())["iot"],
        vec![
            live("2001:db8:5678:cd10::/64", 1300, 3100),
            dep("2001:db8:1234:ab10::/64", 3000),
        ]
    );
    assert_eq!(s.next_deadline(), Some(tc + 1800));

    // Past the old deadline: dropped from the advertisement even before
    // the next observe, then reported Expired by it.
    let tx = tc + 3500;
    assert_eq!(
        s.advertised(tx, &lans())["lan"],
        vec![live("2001:db8:5678:cd00::/64", 0, 100)]
    );
    let e = s.observe(tx, obs(NEW, 0, 100));
    assert_eq!(e, vec![PdEvent::Expired(net(OLD))]);
    assert!(s.stale().is_empty());
}

#[test]
fn long_leases_are_capped_and_stale_window_is_nd_valid_limit() {
    let mut s = PdState::new();
    s.observe(T0, obs(OLD, 7 * 86400, 14 * 86400));
    assert_eq!(
        s.advertised(T0, &lans())["lan"],
        vec![live(
            "2001:db8:1234:ab00::/64",
            ND_PREFERRED_LIMIT,
            ND_VALID_LIMIT
        )]
    );
    s.observe(T0 + 60, obs(NEW, 7 * 86400, 14 * 86400));
    let stale = s.stale()[0];
    assert_eq!(stale.deprecate_until, T0 + 60 + u64::from(ND_VALID_LIMIT));
    assert_eq!(
        s.advertised(T0 + 60, &lans())["lan"][1],
        dep("2001:db8:1234:ab00::/64", ND_VALID_LIMIT)
    );
    assert_eq!(
        s.advertised(T0 + 60 + 5000, &lans())["lan"][1],
        dep("2001:db8:1234:ab00::/64", 400)
    );
    assert_eq!(s.advertised(T0 + 60 + 5400, &lans())["lan"].len(), 1);
}

#[test]
fn zero_signal_advertises_valid_zero() {
    let mut s = PdState::new().with_stale_signal(StaleSignal::Zero);
    s.observe(T0, obs(OLD, 1800, 3600));
    s.observe(T0 + 1, obs(NEW, 1800, 3600));
    assert_eq!(
        s.advertised(T0 + 1, &lans())["lan"][1],
        dep("2001:db8:1234:ab00::/64", 0)
    );
    // Still advertised (with 0) until the deadline.
    assert_eq!(s.advertised(T0 + 3000, &lans())["lan"].len(), 2);
}

#[test]
fn lost_prefix_is_held_until_valid_then_expires() {
    let mut s = PdState::new();
    s.observe(T0, obs(OLD, 1800, 3600));
    assert_eq!(s.observe(T0 + 10, None), vec![PdEvent::Lost(net(OLD))]);
    assert!(!s.is_confirmed());
    // A second empty poll says nothing new.
    assert_eq!(s.observe(T0 + 20, None), vec![]);
    // The lease is still valid; hosts keep using it.
    assert_eq!(
        s.advertised(T0 + 20, &lans())["lan"],
        vec![live("2001:db8:1234:ab00::/64", 1780, 3580)]
    );
    // Coming back is a renewal, not a change.
    let e = s.observe(T0 + 30, obs(OLD, 1770, 3570));
    assert!(matches!(e.as_slice(), [PdEvent::Renewed(_)]));
    // Lost again and never back: expires at valid_until.
    s.observe(T0 + 40, None);
    assert_eq!(s.observe(T0 + 3600, None), vec![PdEvent::Expired(net(OLD))]);
    assert!(s.current().is_none());
    assert!(s.advertised(T0 + 3600, &lans()).is_empty());
}

#[test]
fn zero_valid_lifetime_withdraws_and_deprecates() {
    let mut s = PdState::new();
    s.observe(T0, obs(OLD, 1800, 3600));
    assert_eq!(
        s.observe(T0 + 5, obs(OLD, 0, 0)),
        vec![PdEvent::Lost(net(OLD))]
    );
    assert!(s.current().is_none());
    assert_eq!(
        s.advertised(T0 + 5, &lans())["lan"],
        vec![dep("2001:db8:1234:ab00::/64", 3595)]
    );
}

#[test]
fn returning_stale_prefix_is_not_advertised_twice() {
    let mut s = PdState::new();
    s.observe(T0, obs(OLD, 1800, 3600));
    s.observe(T0 + 10, obs(NEW, 1800, 3600));
    let e = s.observe(T0 + 20, obs(OLD, 1800, 3600));
    assert!(
        matches!(e.as_slice(), [PdEvent::Changed { old, new }] if *old == net(NEW) && new.prefix == net(OLD))
    );
    assert_eq!(s.stale().len(), 1);
    assert_eq!(s.stale()[0].prefix, net(NEW));
    let lan = &s.advertised(T0 + 20, &lans())["lan"];
    assert_eq!(lan.iter().filter(|a| a.deprecated).count(), 1);
    assert_eq!(lan[0].prefix, net("2001:db8:1234:ab00::/64"));
}

#[test]
fn resized_delegation_keeps_live_subnet_live() {
    // /56 -> /60 from the same base: subnet 0 is the same /64 in both.
    let mut s = PdState::new();
    s.observe(T0, obs("2001:db8:1234:ab00::/56", 1800, 3600));
    s.observe(T0 + 1, obs("2001:db8:1234:ab00::/60", 1800, 3600));
    let adv = s.advertised(T0 + 1, &lans());
    assert_eq!(
        adv["lan"],
        vec![live("2001:db8:1234:ab00::/64", 1800, 3600)]
    );
    // ID 0x10 does not fit a /60: only the stale /56's subnet remains.
    assert_eq!(adv["iot"], vec![dep("2001:db8:1234:ab10::/64", 3599)]);
}

#[test]
fn infinite_lifetimes_are_capped_and_never_expire() {
    let mut s = PdState::new();
    s.observe(T0, obs(OLD, INFINITE_LIFETIME, INFINITE_LIFETIME));
    assert_eq!(s.current().unwrap().valid_until, u64::MAX);
    assert_eq!(s.next_deadline(), None);
    assert_eq!(
        s.advertised(T0 + 10 * 365 * 86400, &lans())["lan"],
        vec![live(
            "2001:db8:1234:ab00::/64",
            ND_PREFERRED_LIMIT,
            ND_VALID_LIMIT
        )]
    );
    // Stale window of an infinite lease is ND_VALID_LIMIT.
    s.observe(T0 + 5, obs(NEW, INFINITE_LIFETIME, INFINITE_LIFETIME));
    assert_eq!(
        s.stale()[0].deprecate_until,
        T0 + 5 + u64::from(ND_VALID_LIMIT)
    );
}

#[test]
fn preferred_never_exceeds_valid() {
    let mut s = PdState::new();
    s.observe(T0, obs(OLD, 9000, 600));
    assert_eq!(
        s.advertised(T0, &lans())["lan"],
        vec![live("2001:db8:1234:ab00::/64", 600, 600)]
    );
}

#[test]
fn clock_stepping_back_keeps_stale_prefix_deprecated() {
    let mut s = PdState::new();
    s.observe(T0, obs(OLD, 1800, 3600));
    s.observe(T0 + 100, obs(NEW, 1800, 3600));
    // Boot without RTC: clock reads a day earlier.
    let early = T0 - 86400;
    let e = s.observe(early, obs(NEW, 1800, 3600));
    assert_eq!(e, vec![]);
    assert_eq!(
        s.advertised(early, &lans())["lan"][1],
        dep("2001:db8:1234:ab00::/64", 3500)
    );
}

#[test]
fn reboot_with_same_prefix_renews() {
    let dir = tempfile::tempdir().unwrap();
    let store = PdStore::new(dir.path().join("state/pd/wan.json"));
    let mut s = PdState::new();
    s.observe(T0, obs(OLD, 1800, 3600));
    store.save(&s).unwrap();

    let loaded = store.load();
    assert_eq!(loaded.issue, None);
    let mut s = loaded.state;
    assert!(!s.is_confirmed());
    assert_eq!(s.current().unwrap().prefix, net(OLD));
    // The lease is advertised from the persisted lifetimes before networkd
    // has re-acquired anything.
    assert_eq!(
        s.advertised(T0 + 120, &lans())["lan"],
        vec![live("2001:db8:1234:ab00::/64", 1680, 3480)]
    );
    let e = s.observe(T0 + 120, obs(OLD, 1680, 3480));
    assert!(matches!(e.as_slice(), [PdEvent::Renewed(d)] if d.obtained_at == T0));
    assert!(s.stale().is_empty());
}

#[test]
fn reboot_with_new_prefix_deprecates_the_persisted_one() {
    let dir = tempfile::tempdir().unwrap();
    let store = PdStore::new(dir.path().join("wan.json"));
    let mut s = PdState::new();
    s.observe(T0, obs(OLD, 1800, 3600));
    store.save(&s).unwrap();

    // Reboot 5 minutes later; the ISP gives a different prefix.
    let tb = T0 + 300;
    let mut s = store.load().state;
    let e = s.observe(tb, obs(NEW, 1800, 3600));
    assert!(matches!(e.as_slice(), [PdEvent::Changed { old, .. }] if *old == net(OLD)));
    assert_eq!(
        s.advertised(tb, &lans())["lan"],
        vec![
            live("2001:db8:5678:cd00::/64", 1800, 3600),
            dep("2001:db8:1234:ab00::/64", 3300),
        ]
    );
    store.save(&s).unwrap();

    // Another reboot inside the stale window keeps deprecating it.
    let mut s = store.load().state;
    assert_eq!(s.observe(tb + 60, obs(NEW, 1740, 3540)).len(), 1); // Renewed
    assert_eq!(
        s.advertised(tb + 60, &lans())["lan"][1],
        dep("2001:db8:1234:ab00::/64", 3240)
    );
    // And after the window it is gone.
    assert_eq!(
        s.observe(tb + 3300, obs(NEW, 0, 300)),
        vec![PdEvent::Expired(net(OLD))]
    );
}

#[test]
fn missing_and_corrupt_files_start_fresh() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wan.json");
    let store = PdStore::new(&path);
    let l = store.load();
    assert_eq!(l.issue, Some(LoadIssue::Missing));
    assert_eq!(l.state, PdState::new());

    std::fs::write(&path, b"{\"format\":1,\"state\":{\"current\":").unwrap();
    let l = store.load();
    match &l.issue {
        Some(LoadIssue::Corrupt { moved_to, .. }) => {
            let aside = moved_to.as_ref().unwrap();
            assert!(aside.ends_with("wan.json.corrupt"));
            assert!(aside.exists());
        }
        other => panic!("{other:?}"),
    }
    assert!(!path.exists());
    assert_eq!(l.state, PdState::new());
    // Saving afterwards works and round-trips.
    let mut s = l.state;
    s.observe(T0, obs(OLD, 1800, 3600));
    store.save(&s).unwrap();
    assert_eq!(store.load().state.current(), s.current());

    std::fs::write(&path, b"{\"format\":9,\"state\":{}}").unwrap();
    assert_eq!(store.load().issue, Some(LoadIssue::UnsupportedFormat(9)));
}

#[test]
fn save_leaves_no_temp_file_and_serialises_events() {
    let dir = tempfile::tempdir().unwrap();
    let store = PdStore::new(dir.path().join("wan.json"));
    let mut s = PdState::new();
    let e = s.observe(T0, obs(OLD, 1800, 3600));
    store.save(&s).unwrap();
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, vec!["wan.json".to_string()]);
    let ev = serde_json::to_value(e[0]).unwrap();
    assert_eq!(ev["event"], "acquired");
    assert_eq!(ev["data"]["prefix"], OLD);
    let adv = serde_json::to_value(s.advertised(T0, &lans())).unwrap();
    assert_eq!(adv["lan"][0]["prefix"], "2001:db8:1234:ab00::/64");
    assert_eq!(adv["lan"][0]["deprecated"], false);
}
