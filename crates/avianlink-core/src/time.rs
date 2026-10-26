/// A point in time, in milliseconds, supplied by the host.
///
/// Hosts should use Unix-epoch milliseconds, but the engine never relies on
/// that for correctness (see `docs/decisions.md` D-007). All arithmetic
/// saturates, so a clock that jumps backwards looks like "no time passed".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    /// The zero timestamp.
    pub const ZERO: Self = Self(0);

    /// Creates a timestamp from milliseconds.
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    /// Returns the timestamp as milliseconds.
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Returns `self + ms`, saturating at `u64::MAX`.
    pub const fn saturating_add_millis(self, ms: u64) -> Self {
        Self(self.0.saturating_add(ms))
    }

    /// Returns the milliseconds elapsed since `earlier`, or zero if `earlier`
    /// is in the future.
    pub const fn saturating_millis_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_saturates() {
        let t = Timestamp::from_millis(u64::MAX - 1);
        assert_eq!(t.saturating_add_millis(10).as_millis(), u64::MAX);
        let early = Timestamp::from_millis(5);
        assert_eq!(early.saturating_millis_since(t), 0);
        assert_eq!(t.saturating_millis_since(early), u64::MAX - 6);
    }
}
