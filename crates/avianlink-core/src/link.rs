use crate::Error;

/// Smallest link MTU the engine supports, in bytes.
pub const MIN_MTU: u16 = 48;

/// Host-chosen identifier for a link (a radio, a UDP socket, a modem...).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkId(pub u16);

/// How long a packet occupies the medium: `per_packet_us + per_byte_us * len`.
///
/// Captures the large fixed preamble cost of radios such as LoRa. The host's
/// link adapter picks the coefficients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AirtimeModel {
    /// Fixed airtime per packet, in microseconds.
    pub per_packet_us: u32,
    /// Additional airtime per payload byte, in microseconds.
    pub per_byte_us: u32,
}

impl AirtimeModel {
    /// Airtime of a `len`-byte packet, in microseconds.
    pub fn airtime_us(&self, len: usize) -> u64 {
        let len = u64::try_from(len).unwrap_or(u64::MAX);
        u64::from(self.per_packet_us)
            .saturating_add(u64::from(self.per_byte_us).saturating_mul(len))
    }
}

/// Transmission budget for a link. Often legally mandated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkBudget {
    /// No pacing beyond what the host imposes.
    Unlimited,
    /// Average byte rate limit.
    BytesPerSecond(u32),
    /// Fraction of time on air allowed within a sliding window.
    DutyCycle {
        /// Allowed airtime in parts per thousand (e.g. 10 = 1%).
        permille: u16,
        /// Length of the sliding window, in milliseconds.
        window_ms: u32,
        /// How to convert a packet length into airtime.
        airtime: AirtimeModel,
    },
}

/// Static properties of a link, supplied when the host registers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkConfig {
    /// Maximum packet size in bytes. Must be at least [`MIN_MTU`].
    pub mtu: u16,
    /// Rate or duty-cycle budget.
    pub budget: LinkBudget,
    /// Relative cost; when several links reach a peer, lower is preferred.
    pub cost: u16,
}

impl LinkConfig {
    /// Checks that the configuration is usable.
    pub fn validate(&self) -> Result<(), Error> {
        if self.mtu < MIN_MTU {
            return Err(Error::InvalidLinkConfig);
        }
        match self.budget {
            LinkBudget::Unlimited => Ok(()),
            LinkBudget::BytesPerSecond(0) => Err(Error::InvalidLinkConfig),
            LinkBudget::BytesPerSecond(_) => Ok(()),
            LinkBudget::DutyCycle {
                permille,
                window_ms,
                ..
            } => {
                if permille == 0 || permille > 1000 || window_ms == 0 {
                    Err(Error::InvalidLinkConfig)
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(mtu: u16, budget: LinkBudget) -> LinkConfig {
        LinkConfig {
            mtu,
            budget,
            cost: 1,
        }
    }

    #[test]
    fn validates_mtu_and_budget() {
        assert!(cfg(MIN_MTU, LinkBudget::Unlimited).validate().is_ok());
        assert!(cfg(MIN_MTU - 1, LinkBudget::Unlimited).validate().is_err());
        assert!(cfg(64, LinkBudget::BytesPerSecond(0)).validate().is_err());
        let duty = |permille, window_ms| LinkBudget::DutyCycle {
            permille,
            window_ms,
            airtime: AirtimeModel {
                per_packet_us: 30_000,
                per_byte_us: 1_600,
            },
        };
        assert!(cfg(222, duty(10, 3_600_000)).validate().is_ok());
        assert!(cfg(222, duty(0, 3_600_000)).validate().is_err());
        assert!(cfg(222, duty(1001, 3_600_000)).validate().is_err());
        assert!(cfg(222, duty(10, 0)).validate().is_err());
    }
}
