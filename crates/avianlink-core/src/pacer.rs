//! Per-link transmission budgets (`docs/decisions.md` D-015).
//!
//! A packet is admitted only if a worst-case (MTU-sized) packet would fit
//! the budget; the actual size is then charged.

use alloc::collections::VecDeque;

use crate::{AirtimeModel, LinkBudget, Timestamp};

#[derive(Debug)]
pub(crate) enum Pacer {
    Unlimited,
    Rate {
        /// Bytes per second; equivalently milli-bytes per millisecond.
        rate: u64,
        /// Milli-bytes currently available.
        tokens: u64,
        capacity: u64,
        last: Timestamp,
    },
    Duty {
        budget_us: u64,
        window_ms: u64,
        airtime: AirtimeModel,
        /// (send time, airtime µs), oldest first.
        log: VecDeque<(Timestamp, u64)>,
        used_us: u64,
        max_entries: usize,
    },
}

pub(crate) fn airtime_us(model: &AirtimeModel, len: usize) -> u64 {
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    u64::from(model.per_packet_us).saturating_add(u64::from(model.per_byte_us).saturating_mul(len))
}

impl Pacer {
    pub(crate) fn new(budget: LinkBudget, mtu: u16, max_entries: usize, now: Timestamp) -> Self {
        match budget {
            LinkBudget::Unlimited => Self::Unlimited,
            LinkBudget::BytesPerSecond(rate) => {
                let rate = u64::from(rate);
                let capacity = rate.max(u64::from(mtu)).saturating_mul(1000);
                Self::Rate {
                    rate,
                    tokens: capacity,
                    capacity,
                    last: now,
                }
            }
            LinkBudget::DutyCycle {
                permille,
                window_ms,
                airtime,
            } => Self::Duty {
                // window_ms * 1000 µs/ms * permille / 1000
                budget_us: u64::from(window_ms).saturating_mul(u64::from(permille)),
                window_ms: u64::from(window_ms),
                airtime,
                log: VecDeque::new(),
                used_us: 0,
                max_entries,
            },
        }
    }

    /// Whether a single MTU-sized packet can ever fit the budget.
    pub(crate) fn admits_mtu(budget: &LinkBudget, mtu: u16) -> bool {
        match budget {
            LinkBudget::DutyCycle {
                permille,
                window_ms,
                airtime,
            } => {
                airtime_us(airtime, usize::from(mtu))
                    <= u64::from(*window_ms).saturating_mul(u64::from(*permille))
            }
            _ => true,
        }
    }

    /// Earliest time at which an MTU-sized packet fits. Pure.
    pub(crate) fn ready_at(&self, now: Timestamp, mtu: u16) -> Timestamp {
        match self {
            Self::Unlimited => now,
            Self::Rate {
                rate,
                tokens,
                capacity,
                last,
            } => {
                let elapsed = now.saturating_millis_since(*last);
                let tokens = tokens
                    .saturating_add(elapsed.saturating_mul(*rate))
                    .min(*capacity);
                let need = u64::from(mtu).saturating_mul(1000);
                if tokens >= need {
                    now
                } else {
                    let missing = need.saturating_sub(tokens);
                    now.saturating_add_millis(missing.div_ceil((*rate).max(1)))
                }
            }
            Self::Duty {
                budget_us,
                window_ms,
                airtime,
                log,
                used_us,
                max_entries,
            } => {
                let need = airtime_us(airtime, usize::from(mtu));
                let mut used = *used_us;
                let mut entries = log.len();
                // Drop entries that have aged out by `now`, then keep
                // dropping until the packet fits; the last dropped entry's
                // expiry is the answer.
                let mut at = now;
                for &(t, a) in log {
                    let expires = t.saturating_add_millis(*window_ms);
                    let fits = used.saturating_add(need) <= *budget_us && entries < *max_entries;
                    if expires > now && fits {
                        break;
                    }
                    used = used.saturating_sub(a);
                    entries = entries.saturating_sub(1);
                    at = at.max(expires);
                }
                at
            }
        }
    }

    /// Charges a packet of `len` bytes sent at `now`. Call only when
    /// `ready_at(now, mtu) <= now`.
    pub(crate) fn consume(&mut self, now: Timestamp, len: usize) {
        match self {
            Self::Unlimited => {}
            Self::Rate {
                rate,
                tokens,
                capacity,
                last,
            } => {
                if now > *last {
                    let elapsed = now.saturating_millis_since(*last);
                    *tokens = tokens
                        .saturating_add(elapsed.saturating_mul(*rate))
                        .min(*capacity);
                    *last = now;
                }
                let cost = u64::try_from(len).unwrap_or(u64::MAX).saturating_mul(1000);
                *tokens = tokens.saturating_sub(cost);
            }
            Self::Duty {
                window_ms,
                airtime,
                log,
                used_us,
                ..
            } => {
                while let Some(&(t, a)) = log.front() {
                    if t.saturating_add_millis(*window_ms) > now {
                        break;
                    }
                    log.pop_front();
                    *used_us = used_us.saturating_sub(a);
                }
                let a = airtime_us(airtime, len);
                log.push_back((now, a));
                *used_us = used_us.saturating_add(a);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(ms: u64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    #[test]
    fn rate_limits_average() {
        let mut p = Pacer::new(LinkBudget::BytesPerSecond(100), 50, 0, t(0));
        // Capacity is one second of rate (100 bytes) = two 50-byte packets.
        assert_eq!(p.ready_at(t(0), 50), t(0));
        p.consume(t(0), 50);
        p.consume(t(0), 50);
        assert_eq!(p.ready_at(t(0), 50), t(500));
        assert_eq!(p.ready_at(t(500), 50), t(500));
    }

    #[test]
    fn duty_cycle_is_a_sliding_window() {
        // 10% of 1000 ms = 100 ms airtime; each packet costs 40 ms.
        let airtime = AirtimeModel {
            per_packet_us: 40_000,
            per_byte_us: 0,
        };
        let budget = LinkBudget::DutyCycle {
            permille: 100,
            window_ms: 1000,
            airtime,
        };
        let mut p = Pacer::new(budget, 50, 16, t(0));
        p.consume(t(0), 50);
        p.consume(t(10), 50);
        // 80 ms used; another 40 would exceed 100 ms until t=0 expires.
        assert_eq!(p.ready_at(t(20), 50), t(1000));
        assert_eq!(p.ready_at(t(1000), 50), t(1000));
        p.consume(t(1000), 50);
        assert_eq!(p.ready_at(t(1000), 50), t(1010));
    }

    #[test]
    fn duty_log_is_bounded() {
        let airtime = AirtimeModel {
            per_packet_us: 1,
            per_byte_us: 0,
        };
        let budget = LinkBudget::DutyCycle {
            permille: 1000,
            window_ms: 1000,
            airtime,
        };
        let mut p = Pacer::new(budget, 50, 2, t(0));
        p.consume(t(0), 1);
        p.consume(t(5), 1);
        assert_eq!(p.ready_at(t(6), 50), t(1000));
    }
}
