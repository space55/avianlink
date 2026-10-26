//! Phase 1 acceptance scenarios.

use avianlink_sim::{Profile, Report, Scenario};

fn assert_clean(r: &Report) {
    assert_eq!(r.delivered, r.messages, "incomplete delivery:\n{r}");
    assert_eq!(r.acked, r.messages, "incomplete acks:\n{r}");
    assert_eq!(r.bugs(), 0, "engine bug counters:\n{r}");
}

/// Phase 1 done-criterion: 1,000 messages over `disaster_cellular`, 100%
/// eventual delivery, on several seeds.
#[test]
fn disaster_cellular_1000_messages() {
    for seed in 1..=3 {
        let r = Scenario::new(Profile::DisasterCellular, seed).run();
        assert_clean(&r);
        assert!(r.downtime_ms > 0, "outages must actually occur");
        assert!(r.channels[0].corrupted + r.channels[1].corrupted > 0);
        assert!(r.channels[0].duplicated + r.channels[1].duplicated > 0);
    }
}

#[test]
fn every_profile_delivers_everything() {
    for p in Profile::ALL {
        let mut sc = Scenario::new(p, 7);
        sc.messages = 200;
        assert_clean(&sc.run());
    }
}

/// Offered load ~30x the duty-cycle capacity must drain, not collapse.
#[test]
fn overloaded_lora_drains() {
    let mut sc = Scenario::new(Profile::LoraLike, 3);
    sc.messages = 300;
    sc.mean_interval_ms = 30_000;
    assert_clean(&sc.run());
}

#[test]
fn runs_are_reproducible_from_seed() {
    let mut sc = Scenario::new(Profile::DisasterCellular, 42);
    sc.messages = 200;
    let a = sc.run().deterministic();
    let b = sc.run().deterministic();
    assert_eq!(a, b);
    sc.seed = 43;
    assert_ne!(a, sc.run().deterministic());
}
