//! D-044 acceptance scenarios: introductions by Hello.

use avianlink_sim::{Report, Scenario};

fn assert_clean(r: &Report) {
    assert_eq!(r.delivered, r.messages, "incomplete delivery:\n{r}");
    assert_eq!(r.acked, r.messages, "incomplete acks:\n{r}");
    assert_eq!(r.bugs(), 0, "engine bug counters:\n{r}");
}

/// B starts without A's key and auto-accepts A's contact request. Every
/// message gets through, both ways, at the base profile's cost.
#[test]
fn introduction_delivers_everything() {
    for seed in 1..=3 {
        let r = Scenario::introduction(seed).run();
        assert_clean(&r);
        let base = Scenario::named("disaster_cellular", seed).unwrap().run();
        assert!(
            r.wire_per_payload() < base.wire_per_payload() * 1.1,
            "{r}\nvs\n{base}"
        );
        let requests: u64 = r.engines[1].hellos_received;
        assert!(requests > 0, "{r}");
    }
}

/// The same at a 51-byte MTU and a 1% duty cycle: the 47-byte Hello fits.
#[test]
fn introduction_works_on_lora() {
    let mut sc = Scenario::introduction_lora(1);
    sc.messages = 200;
    assert_clean(&sc.run());
}
