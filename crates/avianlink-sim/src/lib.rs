//! Deterministic network simulator and test harness for avianlink.
//!
//! Virtual time and seeded RNG streams make every run reproducible from its
//! seed: a failing [`Scenario`] is replayed exactly by re-running it with the
//! same seed.
//!
//! ```no_run
//! use avianlink_sim::{Profile, Scenario};
//! let report = Scenario::new(Profile::DisasterCellular, 1).run();
//! println!("{report}");
//! ```

pub mod fuzz_harness;
pub mod impair;
mod metrics;
mod profiles;
mod sim;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

pub use metrics::{fmt_ms, percentile, Report};
pub use sim::{add_stats, total_channel_stats, CrashModel, LengthMix, Scenario, SIM_EPOCH_MS};

/// Named impairment profiles; parameters in [`Profile::link`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Profile {
    /// No impairments.
    Clean,
    /// Geostationary satellite: ~550 ms RTT, light loss, rain fade.
    GeoSatellite,
    /// 2G EDGE: low rate, high and variable delay.
    Edge2g,
    /// Degraded cellular in a disaster: bursty heavy loss, long outages.
    DisasterCellular,
    /// LoRa-like: tiny MTU, 1% duty cycle, slow.
    LoraLike,
}

impl Profile {
    /// All profiles, in a stable order.
    pub const ALL: [Self; 5] = [
        Self::Clean,
        Self::GeoSatellite,
        Self::Edge2g,
        Self::DisasterCellular,
        Self::LoraLike,
    ];

    /// The profile's stable name, as used in reports and netem scripts.
    pub fn name(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::GeoSatellite => "geo_satellite",
            Self::Edge2g => "edge_2g",
            Self::DisasterCellular => "disaster_cellular",
            Self::LoraLike => "lora_like",
        }
    }
}

/// Creates a deterministic RNG from a seed.
pub fn seeded_rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    #[test]
    fn same_seed_same_stream() {
        assert_eq!(seeded_rng(42).next_u64(), seeded_rng(42).next_u64());
        assert_ne!(seeded_rng(42).next_u64(), seeded_rng(43).next_u64());
    }

    #[test]
    fn profile_names_round_trip() {
        for p in Profile::ALL {
            assert_eq!(Profile::from_name(p.name()), Some(p));
        }
        assert_eq!(Profile::from_name("nope"), None);
    }
}
