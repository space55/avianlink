//! Phase 3 acceptance scenarios.

use avianlink_core::FecMode;
use avianlink_sim::{Adversary, Profile, Report, Scenario};

fn assert_clean(r: &Report) {
    assert_eq!(r.delivered, r.messages, "incomplete delivery:\n{r}");
    assert_eq!(r.acked, r.messages, "incomplete acks:\n{r}");
    assert_eq!(r.bugs(), 0, "engine bug counters:\n{r}");
}

fn sum(r: &Report, f: fn(&avianlink_core::Stats) -> u64) -> u64 {
    r.engines.iter().map(f).sum()
}

/// Done-criterion, part 1, under realistic traffic: an on-path attacker
/// replays, forges and tampers; nothing it does is accepted, nothing is
/// lost, nothing is delivered twice or altered (`bugs()` counts integrity
/// violations and duplicates).
#[test]
fn on_path_attacker_achieves_nothing() {
    for (profile, seed) in [(Profile::DisasterCellular, 1), (Profile::Edge2g, 2)] {
        let mut sc = Scenario::new(profile, seed);
        sc.messages = 300;
        sc.adversary = Some(Adversary {
            replay_prob: 0.2,
            forge_prob: 0.2,
            tamper_prob: 0.1,
        });
        let r = sc.run();
        assert_clean(&r);
        assert!(r.injected > 200, "{r}");
        assert!(sum(&r, |s| s.packets_dropped_replay) > 50, "{r}");
        assert!(sum(&r, |s| s.packets_dropped_unauthenticated) > 50, "{r}");
    }
    // And with crashes, where the replay window restarts from storage.
    let mut sc = Scenario::harsh_64_crashy(3);
    sc.messages = 300;
    sc.adversary = Some(Adversary {
        replay_prob: 0.3,
        forge_prob: 0.1,
        tamper_prob: 0.05,
    });
    assert_clean(&sc.run());
}

/// Done-criterion, part 2: Phase 2 metrics regress by no more than the
/// documented header overhead (`wire-format.md` §6: +12 bytes per packet,
/// and correspondingly smaller fragments at small MTUs). Phase 2 values
/// are seed-1 results recorded before the switch (commit 895c3ff), with the
/// workload of that time (`legacy_workload`). FEC (Phase 4) is off here:
/// this measures header overhead alone.
#[test]
fn regression_matches_documented_overhead() {
    // Hellos (D-044) are off too: they postdate Phase 3 and are measured
    // separately.
    let no_fec = |mut sc: Scenario| {
        sc.config.fec = FecMode::Off;
        sc.config.hello = avianlink_core::HelloMode::Off;
        sc
    };
    const PAYLOAD: f64 = 100_305.0; // seed-1 workload, identical across phases
    let tolerance = 1.02; // Phase 2 ratios were recorded to 2 decimals
    for (profile, p2_wire_per_payload, p2_pkts_per_msg) in [
        (Profile::Edge2g, 1.89, 2.60),
        (Profile::DisasterCellular, 4.99, 4.30),
    ] {
        let r = no_fec(Scenario::new(profile, 1).legacy_workload()).run();
        assert_clean(&r);
        assert_eq!(r.payload_bytes as f64, PAYLOAD);
        let p2_wire = p2_wire_per_payload * PAYLOAD;
        let p2_packets = p2_pkts_per_msg * r.messages as f64;
        let allowed = (p2_wire + 12.0 * p2_packets) * tolerance;
        assert!(
            (r.wire_bytes as f64) <= allowed,
            "{} > {allowed}\n{r}",
            r.wire_bytes
        );
    }
    // Small MTUs: packet count grows by at most the fragment-efficiency
    // ratio of the overhead table (51 B: 33 → 21; 64 B: 46 → 34).
    for (sc, p2_pkts_per_msg, ratio) in [
        (
            Scenario::new(Profile::LoraLike, 1).legacy_workload(),
            8.52,
            33.0 / 21.0,
        ),
        (Scenario::harsh_64(1).legacy_workload(), 11.69, 46.0 / 34.0),
    ] {
        let r = no_fec(sc).run();
        assert_clean(&r);
        let allowed = p2_pkts_per_msg * r.messages as f64 * ratio * tolerance;
        assert!(
            (r.packets as f64) <= allowed,
            "{} > {allowed}\n{r}",
            r.packets
        );
    }
}
