//! Phase 5 acceptance scenarios.

use avianlink_sim::{Report, Scenario};

fn assert_clean(r: &Report) {
    assert_eq!(r.delivered, r.messages, "incomplete delivery:\n{r}");
    assert_eq!(r.acked, r.messages, "incomplete acks:\n{r}");
    assert_eq!(r.bugs(), 0, "engine bug counters:\n{r}");
}

/// Done-criterion: a peer offline for a simulated week converges, with
/// bounded bytes exchanged. Phase 4 spent ~3.4 MB per direction on probes
/// alone over such a week.
#[test]
fn week_offline_converges_with_bounded_bytes() {
    for seed in 1..=3 {
        let r = Scenario::week_offline(seed).run();
        assert_clean(&r);
        assert!(r.outage_wire_bytes < 128 * 1024, "{r}");
        let converge = r.converge_ms.unwrap();
        assert!(converge < 2 * 3_600_000, "{r}");
        // Bytes per delivered byte stay low: no resend-everything storm.
        assert!(r.wire_per_payload() < 3.0, "{r}");
        let syncs: u64 = r.engines.iter().map(|s| s.syncs_received).sum();
        assert!(syncs > 0, "{r}");
    }
}

/// A host that knows connectivity returned and calls `nudge()` converges
/// within minutes instead of waiting out the probe interval.
#[test]
fn nudge_on_reconnect_converges_fast() {
    for seed in 1..=3 {
        let mut sc = Scenario::week_offline(seed);
        sc.nudge_on_reconnect = true;
        let r = sc.run();
        assert_clean(&r);
        assert!(r.converge_ms.unwrap() < 10 * 60_000, "{r}");
    }
}
