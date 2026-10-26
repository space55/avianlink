//! Named impairment profiles. `scripts/netem/` mirrors these (Phase 6).

use avianlink_core::AirtimeModel;

use crate::impair::{DelayModel, DutyLimit, GilbertElliott, Jitter, LinkProfile, OutageModel};
use crate::Profile;

const MIN: u64 = 60_000;
const HOUR: u64 = 60 * MIN;

impl Profile {
    /// Looks a profile up by its [`Profile::name`].
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }

    /// The impairment parameters for this profile.
    pub fn link(self) -> LinkProfile {
        match self {
            // Lab conditions: tests the engine's own overhead.
            Self::Clean => LinkProfile {
                mtu: 1200,
                delay: DelayModel {
                    base_ms: 5,
                    jitter: Jitter::None,
                },
                loss: GilbertElliott::NONE,
                bit_flip_prob: 0.0,
                duplicate_prob: 0.0,
                reorder_prob: 0.0,
                reorder_extra_ms: 0,
                rate_bytes_per_sec: None,
                duty: None,
                queue_limit_ms: 10_000,
                outage: None,
            },
            // GEO VSAT: ~550 ms RTT, 64 kbit/s, light loss, rain fade.
            Self::GeoSatellite => LinkProfile {
                mtu: 1200,
                delay: DelayModel {
                    base_ms: 275,
                    jitter: Jitter::Uniform { max_ms: 40 },
                },
                loss: GilbertElliott {
                    p_good_to_bad: 0.005,
                    p_bad_to_good: 0.3,
                    loss_good: 0.005,
                    loss_bad: 0.5,
                },
                bit_flip_prob: 0.001,
                duplicate_prob: 0.0,
                reorder_prob: 0.0,
                reorder_extra_ms: 0,
                rate_bytes_per_sec: Some(8_000),
                duty: None,
                queue_limit_ms: 5_000,
                outage: Some(OutageModel {
                    up_ms: 2 * HOUR,
                    down_ms: 2 * MIN,
                    randomize: true,
                }),
            },
            // 2G EDGE: slow, high and spiky latency, modest bursty loss.
            Self::Edge2g => LinkProfile {
                mtu: 512,
                delay: DelayModel {
                    base_ms: 300,
                    jitter: Jitter::Pareto {
                        scale_ms: 80.0,
                        alpha: 1.5,
                        cap_ms: 8_000,
                    },
                },
                loss: GilbertElliott {
                    p_good_to_bad: 0.02,
                    p_bad_to_good: 0.25,
                    loss_good: 0.01,
                    loss_bad: 0.4,
                },
                bit_flip_prob: 0.002,
                duplicate_prob: 0.005,
                reorder_prob: 0.01,
                reorder_extra_ms: 500,
                rate_bytes_per_sec: Some(4_000),
                duty: None,
                queue_limit_ms: 8_000,
                outage: Some(OutageModel {
                    up_ms: 20 * MIN,
                    down_ms: 30_000,
                    randomize: true,
                }),
            },
            // Overloaded, damaged cellular network after a disaster: ~35%
            // bursty loss, heavy-tailed delay up to 30 s, corruption,
            // duplication, reordering, and frequent multi-minute outages.
            Self::DisasterCellular => LinkProfile {
                mtu: 256,
                delay: DelayModel {
                    base_ms: 400,
                    jitter: Jitter::Pareto {
                        scale_ms: 200.0,
                        alpha: 1.2,
                        cap_ms: 30_000,
                    },
                },
                loss: GilbertElliott {
                    p_good_to_bad: 0.05,
                    p_bad_to_good: 0.1,
                    loss_good: 0.1,
                    loss_bad: 0.85,
                },
                bit_flip_prob: 0.02,
                duplicate_prob: 0.02,
                reorder_prob: 0.05,
                reorder_extra_ms: 3_000,
                rate_bytes_per_sec: Some(1_000),
                duty: None,
                queue_limit_ms: 10_000,
                outage: Some(OutageModel {
                    up_ms: 5 * MIN,
                    down_ms: 3 * MIN,
                    randomize: true,
                }),
            },
            // LoRa-like: 51-byte MTU (EU868 SF9-ish), ~0.37 s airtime per
            // full packet, 1% duty cycle per hour, ~10% bursty loss.
            Self::LoraLike => LinkProfile {
                mtu: 51,
                delay: DelayModel {
                    base_ms: 0,
                    jitter: Jitter::Uniform { max_ms: 50 },
                },
                loss: GilbertElliott {
                    p_good_to_bad: 0.03,
                    p_bad_to_good: 0.3,
                    loss_good: 0.05,
                    loss_bad: 0.6,
                },
                bit_flip_prob: 0.01,
                duplicate_prob: 0.0,
                reorder_prob: 0.0,
                reorder_extra_ms: 0,
                rate_bytes_per_sec: None,
                duty: Some(DutyLimit {
                    permille: 10,
                    window_ms: HOUR as u32,
                    airtime: AirtimeModel {
                        per_packet_us: 160_000,
                        per_byte_us: 4_100,
                    },
                }),
                queue_limit_ms: 60_000,
                outage: None,
            },
        }
    }
}
