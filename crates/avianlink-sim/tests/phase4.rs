//! Phase 4 acceptance scenarios.

use avianlink_core::FecMode;
use avianlink_sim::{percentile, Profile, Report, Scenario};

fn assert_clean(r: &Report) {
    assert_eq!(r.delivered, r.messages, "incomplete delivery:\n{r}");
    assert_eq!(r.acked, r.messages, "incomplete acks:\n{r}");
    assert_eq!(r.bugs(), 0, "engine bug counters:\n{r}");
}

fn with_fec(mut sc: Scenario, fec: FecMode) -> Scenario {
    sc.config.fec = fec;
    sc
}

/// Done-criterion: FEC improves p95 time-to-delivery under bursty loss
/// against Phase 3 (no FEC), at a bounded, reported bandwidth cost.
#[test]
fn fec_improves_p95_under_bursty_loss() {
    let seeds = 1..=8u64;
    let run = |fec| -> Vec<Report> {
        seeds
            .clone()
            .map(|s| with_fec(Scenario::bursty_loss(s), fec).run())
            .collect()
    };
    let (off, xor) = (run(FecMode::Off), run(FecMode::Xor));
    off.iter().chain(&xor).for_each(assert_clean);
    let median = |rs: &[Report], f: fn(&Report) -> u64| {
        let mut v: Vec<u64> = rs.iter().map(f).collect();
        v.sort_unstable();
        percentile(&v, 50)
    };
    let p95_off = median(&off, |r| r.latency_p95_ms);
    let p95_xor = median(&xor, |r| r.latency_p95_ms);
    let wire = |rs: &[Report]| rs.iter().map(|r| r.wire_bytes).sum::<u64>() as f64;
    let cost = wire(&xor) / wire(&off);
    eprintln!("bursty_loss p95: off {p95_off} ms, xor {p95_xor} ms; bandwidth ×{cost:.2}");
    assert!(p95_xor * 100 <= p95_off * 85, "p95 {p95_xor} vs {p95_off}");
    assert!(cost < 1.5, "bandwidth ×{cost:.2}");
    assert!(xor
        .iter()
        .all(|r| r.engines.iter().map(|s| s.fec_recovered).sum::<u64>() > 50));
}

/// FEC must never compromise correctness: crashes, attackers and both
/// codes, on the scenarios where the D-037 fragment bug surfaced.
#[test]
fn fec_is_correct_under_crashes_and_attack() {
    for fec in [FecMode::Xor, FecMode::ReedSolomon] {
        for seed in [5, 8, 15] {
            assert_clean(&with_fec(Scenario::harsh_64_crashy(seed), fec).run());
        }
        let mut sc = with_fec(Scenario::disaster_hostile(2), fec);
        sc.messages = 300;
        assert_clean(&sc.run());
    }
}

/// On a duty-cycled link, FEC stays off rather than crowding out data.
#[test]
fn fec_stays_off_on_lora() {
    let mut sc = Scenario::new(Profile::LoraLike, 1);
    sc.messages = 200;
    let r = sc.run();
    assert_clean(&r);
    assert_eq!(r.engines.iter().map(|s| s.fec_repairs_sent).sum::<u64>(), 0);
}

/// Multi-fragment messages (~190 B at a 64-byte MTU, ~7 packets each):
/// windows often lose several packets, which only Reed-Solomon recovers.
#[test]
fn reed_solomon_beats_xor_on_multi_fragment_messages() {
    let p95 = |fec| {
        let mut v: Vec<u64> = (1..=6)
            .map(|seed| {
                let mut sc = with_fec(Scenario::bursty_loss(seed), fec);
                sc.link.mtu = 64;
                sc.messages = 400;
                sc.lengths = avianlink_sim::LengthMix {
                    short: 0.0,
                    medium: 1.0,
                };
                let r = sc.run();
                assert_clean(&r);
                r.latency_p95_ms
            })
            .collect();
        v.sort_unstable();
        percentile(&v, 50)
    };
    let (off, xor, rs) = (
        p95(FecMode::Off),
        p95(FecMode::Xor),
        p95(FecMode::ReedSolomon),
    );
    eprintln!("MTU 64, ~190 B: p95 off {off} xor {xor} rs {rs}");
    assert!(rs * 100 <= xor * 85, "rs {rs} vs xor {xor}");
    assert!(rs * 2 <= off, "rs {rs} vs off {off}");
}
