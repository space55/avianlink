//! D-045 acceptance: A and B never online together; a relay carries
//! everything over impaired hops.

use avianlink_sim::{Profile, TurnsScenario};

#[test]
fn good_links_deliver_every_message_in_the_next_session() {
    for p in [Profile::Clean, Profile::Edge2g] {
        for seed in 1..=2 {
            let r = TurnsScenario::new(p, seed).run();
            assert_eq!(r.bugs(), 0, "{r}");
            assert_eq!((r.delivered, r.acked), (r.messages, r.messages), "{r}");
            assert_eq!(r.sessions_max, 1, "{r}");
            assert_eq!(r.unsettled_sessions, 0, "{r}");
        }
    }
}

/// On disaster-grade hops and LoRa, nothing is ever lost: whatever has not
/// arrived yet is still held by its sender, which keeps sending it.
#[test]
fn bad_links_never_lose_a_message() {
    for p in [Profile::DisasterCellular, Profile::LoraLike] {
        for seed in 1..=2 {
            let r = TurnsScenario::new(p, seed).run();
            assert_eq!(r.bugs(), 0, "{r}");
            assert_eq!(r.lost, 0, "{r}");
            assert_eq!(r.delivered + r.still_queued, r.messages, "{r}");
            assert!(r.delivered * 100 >= r.messages * 90, "{r}");
            assert!(r.sessions_p50 <= 1, "{r}");
        }
    }
}
