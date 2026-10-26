//! Deterministic network simulator and test harness for avianlink.
//!
//! Virtual time and a single seeded RNG make every run reproducible from its
//! seed. Phase 1 adds the impairment models and the scenario runner.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// Named impairment profiles. Their parameters are defined in Phase 1 and
/// mirrored by `scripts/netem/` in Phase 6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Profile {
    /// No impairments.
    Clean,
    /// Geostationary satellite: ~600 ms RTT, light loss.
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

/// Creates the simulator's deterministic RNG from a seed.
pub fn seeded_rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use avianlink_core::{Config, Engine, MemoryStorage, Timestamp};
    use rand_core::RngCore;

    #[test]
    fn same_seed_same_stream() {
        assert_eq!(seeded_rng(42).next_u64(), seeded_rng(42).next_u64());
        assert_ne!(seeded_rng(42).next_u64(), seeded_rng(43).next_u64());
    }

    #[test]
    fn engine_accepts_sim_rng() {
        let mut e = Engine::new(Config::default(), MemoryStorage::new(), seeded_rng(7));
        assert_eq!(e.poll_transmit(Timestamp::ZERO), None);
    }

    #[test]
    fn profile_names_are_unique() {
        let mut names: Vec<_> = Profile::ALL.iter().map(|p| p.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Profile::ALL.len());
    }
}
