//! Phase 2 acceptance scenarios.

use avianlink_sim::{Profile, Report, Scenario};

fn assert_clean(r: &Report) {
    assert_eq!(r.delivered, r.messages, "incomplete delivery:\n{r}");
    assert_eq!(r.acked, r.messages, "incomplete acks:\n{r}");
    assert_eq!(r.bugs(), 0, "engine bug counters:\n{r}");
    let storage_errors: u64 = r.engines.iter().map(|s| s.storage_errors).sum();
    assert_eq!(storage_errors, 0, "{r}");
}

/// Done-criterion, part 1: 100% eventual delivery at a 64-byte MTU with
/// ~50% bursty loss and long outages.
#[test]
fn harsh_64_delivers_everything() {
    for seed in 1..=3 {
        let r = Scenario::harsh_64(seed).run();
        assert_clean(&r);
        assert!(r.downtime_ms > r.sim_duration_ms / 2, "{r}");
        let lost: u64 = r.channels.iter().map(|c| c.lost).sum();
        let sent: u64 = r.channels.iter().map(|c| c.sent - c.lost_outage).sum();
        assert!(
            lost * 100 / sent >= 40,
            "loss while up should be ~50%:\n{r}"
        );
    }
}

/// Done-criterion, part 2: nodes crash and restore from storage mid-run,
/// with nothing lost and nothing delivered twice (`assert_clean` checks
/// duplicates and integrity).
#[test]
fn crashes_lose_and_duplicate_nothing() {
    for seed in 1..=3 {
        let r = Scenario::harsh_64_crashy(seed).run();
        assert_clean(&r);
        assert!(r.crashes >= 10, "{r}");
    }
    // Also with a benign link, where crashes dominate.
    let mut sc = Scenario::new(Profile::Edge2g, 9);
    sc.crashes = Some(avianlink_sim::CrashModel {
        mean_interval_ms: 10 * 60_000,
        downtime_ms: 5_000,
    });
    let r = sc.run();
    assert_clean(&r);
    assert!(r.crashes >= 20, "{r}");
}

/// Adaptive timers and backoff must not regress Phase 1's bandwidth on the
/// outage-heavy profile (Phase 1: 17-32 wire bytes per payload byte).
#[test]
fn backoff_bounds_bandwidth_during_outages() {
    let r = Scenario::new(Profile::DisasterCellular, 1).run();
    assert_clean(&r);
    assert!(r.wire_per_payload() < 8.0, "{r}");
}

/// Storage stays bounded: it holds only undelivered messages, receive
/// windows and unpolled events.
#[test]
fn storage_footprint_is_bounded() {
    let r = Scenario::harsh_64(4).run();
    assert_clean(&r);
    assert!(r.max_storage_bytes < 256 * 1024, "{r}");
}
