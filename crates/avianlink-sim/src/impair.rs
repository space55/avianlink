//! Per-link impairment models and the directional channel that applies them.

use avianlink_core::AirtimeModel;
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;

/// Uniform sample in `[0, 1)`.
pub(crate) fn unit(rng: &mut ChaCha20Rng) -> f64 {
    (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64
}

/// Uniform integer in `[0, n)`; 0 if `n == 0`.
pub(crate) fn below(rng: &mut ChaCha20Rng, n: u64) -> u64 {
    if n == 0 {
        0
    } else {
        rng.next_u64() % n
    }
}

fn chance(rng: &mut ChaCha20Rng, p: f64) -> bool {
    p > 0.0 && unit(rng) < p
}

/// Exponential sample with the given mean, at least 1 ms.
fn exponential(rng: &mut ChaCha20Rng, mean_ms: u64) -> u64 {
    let u = unit(rng).max(f64::MIN_POSITIVE);
    ((-u.ln()) * mean_ms as f64).round().max(1.0) as u64
}

/// Extra delay on top of the base propagation delay.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Jitter {
    /// No jitter.
    None,
    /// Uniform in `[0, max_ms]`.
    Uniform {
        /// Upper bound.
        max_ms: u64,
    },
    /// Pareto (heavy-tailed): `scale_ms * (U^(-1/alpha) - 1)`, capped.
    Pareto {
        /// Scale; the median is about `scale_ms * (2^(1/alpha) - 1)`.
        scale_ms: f64,
        /// Tail index; smaller is heavier. Below 2 the variance is infinite.
        alpha: f64,
        /// Hard cap.
        cap_ms: u64,
    },
}

impl Jitter {
    fn sample(&self, rng: &mut ChaCha20Rng) -> u64 {
        match *self {
            Self::None => 0,
            Self::Uniform { max_ms } => below(rng, max_ms.saturating_add(1)),
            Self::Pareto {
                scale_ms,
                alpha,
                cap_ms,
            } => {
                let u = unit(rng).max(f64::MIN_POSITIVE);
                let x = scale_ms * (u.powf(-1.0 / alpha) - 1.0);
                (x.round() as u64).min(cap_ms)
            }
        }
    }
}

/// One-way delay: base plus jitter.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DelayModel {
    /// Fixed propagation delay.
    pub base_ms: u64,
    /// Variable component.
    pub jitter: Jitter,
}

/// Two-state bursty loss model.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GilbertElliott {
    /// Per-packet probability of moving Good → Bad.
    pub p_good_to_bad: f64,
    /// Per-packet probability of moving Bad → Good.
    pub p_bad_to_good: f64,
    /// Loss probability in Good.
    pub loss_good: f64,
    /// Loss probability in Bad.
    pub loss_bad: f64,
}

impl GilbertElliott {
    /// No loss.
    pub const NONE: Self = Self {
        p_good_to_bad: 0.0,
        p_bad_to_good: 1.0,
        loss_good: 0.0,
        loss_bad: 0.0,
    };

    /// Long-run loss rate.
    pub fn mean_loss(&self) -> f64 {
        let denom = self.p_good_to_bad + self.p_bad_to_good;
        if denom == 0.0 {
            return self.loss_good;
        }
        let bad = self.p_good_to_bad / denom;
        (1.0 - bad) * self.loss_good + bad * self.loss_bad
    }
}

/// Alternating up/down periods shared by both directions of a link.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OutageModel {
    /// Mean (or exact, if not randomized) up period.
    pub up_ms: u64,
    /// Mean (or exact) down period.
    pub down_ms: u64,
    /// Exponentially distributed periods instead of fixed ones.
    pub randomize: bool,
}

/// Duty-cycle limit, mirrored into the engine's link budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DutyLimit {
    /// Allowed airtime in parts per thousand.
    pub permille: u16,
    /// Sliding window length.
    pub window_ms: u32,
    /// Airtime model (also the radio's serialization time).
    pub airtime: AirtimeModel,
}

/// All impairments of one link, applied independently in each direction
/// (outages are shared).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LinkProfile {
    /// Largest packet the link carries; larger packets are an engine bug.
    pub mtu: u16,
    /// One-way delay.
    pub delay: DelayModel,
    /// Bursty loss.
    pub loss: GilbertElliott,
    /// Probability a packet has 1–3 bits flipped.
    pub bit_flip_prob: f64,
    /// Probability a packet is delivered twice.
    pub duplicate_prob: f64,
    /// Probability a packet is held back by up to `reorder_extra_ms`.
    pub reorder_prob: f64,
    /// Maximum extra hold-back for reordered packets.
    pub reorder_extra_ms: u64,
    /// Serialization rate, if rate-limited.
    pub rate_bytes_per_sec: Option<u32>,
    /// Duty-cycle limit, if any.
    pub duty: Option<DutyLimit>,
    /// Packets that would wait longer than this in the transmit queue are
    /// tail-dropped.
    pub queue_limit_ms: u64,
    /// Scheduled outages.
    pub outage: Option<OutageModel>,
}

/// Counters for one direction of a link.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChannelStats {
    /// Packets handed to the channel.
    pub sent: u64,
    /// Bytes handed to the channel.
    pub sent_bytes: u64,
    /// Packets delivered (including duplicates).
    pub delivered: u64,
    /// Lost to Gilbert-Elliott loss.
    pub lost: u64,
    /// Lost to an outage.
    pub lost_outage: u64,
    /// Tail-dropped from the transmit queue.
    pub lost_queue: u64,
    /// Corrupted by bit flips (and still delivered).
    pub corrupted: u64,
    /// Extra copies delivered.
    pub duplicated: u64,
    /// Larger than the MTU (engine bug).
    pub oversize: u64,
    /// Sent while the duty-cycle window was already full (engine bug).
    pub duty_violations: u64,
}

/// Outage schedule, generated lazily and queryable at any time.
#[derive(Debug)]
pub(crate) struct Outages {
    model: Option<OutageModel>,
    rng: ChaCha20Rng,
    /// Sorted, non-overlapping [start, end) down intervals.
    down: Vec<(u64, u64)>,
    generated_until: u64,
}

impl Outages {
    pub(crate) fn new(model: Option<OutageModel>, rng: ChaCha20Rng, start: u64) -> Self {
        Self {
            model,
            rng,
            down: Vec::new(),
            generated_until: start,
        }
    }

    pub(crate) fn is_down(&mut self, t: u64) -> bool {
        let Some(m) = self.model else {
            return false;
        };
        while self.generated_until <= t {
            let (up, down) = if m.randomize {
                (
                    exponential(&mut self.rng, m.up_ms),
                    exponential(&mut self.rng, m.down_ms),
                )
            } else {
                (m.up_ms.max(1), m.down_ms)
            };
            let start = self.generated_until + up;
            self.down.push((start, start + down));
            self.generated_until = start + down;
        }
        let i = self.down.partition_point(|&(_, end)| end <= t);
        self.down.get(i).is_some_and(|&(s, _)| s <= t)
    }

    /// Total down time within `[from, to)`.
    pub(crate) fn downtime(&mut self, from: u64, to: u64) -> u64 {
        if self.model.is_none() {
            return 0;
        }
        self.is_down(to);
        self.down
            .iter()
            .map(|&(s, e)| e.min(to).saturating_sub(s.max(from)))
            .sum()
    }
}

/// One direction of a link.
#[derive(Debug)]
pub(crate) struct Channel {
    profile: LinkProfile,
    rng: ChaCha20Rng,
    bad: bool,
    tx_free_at: u64,
    duty_log: std::collections::VecDeque<(u64, u64)>,
    duty_used_us: u64,
    pub(crate) stats: ChannelStats,
}

impl Channel {
    pub(crate) fn new(profile: LinkProfile, rng: ChaCha20Rng) -> Self {
        Self {
            profile,
            rng,
            bad: false,
            tx_free_at: 0,
            duty_log: Default::default(),
            duty_used_us: 0,
            stats: ChannelStats::default(),
        }
    }

    /// Transmission time on the medium, in ms.
    fn tx_time_ms(&self, len: usize) -> u64 {
        if let Some(d) = self.profile.duty {
            d.airtime.airtime_us(len).div_ceil(1000)
        } else if let Some(rate) = self.profile.rate_bytes_per_sec {
            (len as u64 * 1000).div_ceil(u64::from(rate.max(1)))
        } else {
            0
        }
    }

    fn check_duty(&mut self, start: u64, len: usize) {
        let Some(d) = self.profile.duty else {
            return;
        };
        let window = u64::from(d.window_ms);
        while let Some(&(t, a)) = self.duty_log.front() {
            if t + window > start {
                break;
            }
            self.duty_log.pop_front();
            self.duty_used_us -= a;
        }
        let a = d.airtime.airtime_us(len);
        self.duty_log.push_back((start, a));
        self.duty_used_us += a;
        if self.duty_used_us > window * u64::from(d.permille) {
            self.stats.duty_violations += 1;
        }
    }

    /// Sends `bytes` at `now`; returns the (arrival time, bytes) of every
    /// copy that survives.
    pub(crate) fn send(
        &mut self,
        now: u64,
        bytes: Vec<u8>,
        outages: &mut Outages,
    ) -> Vec<(u64, Vec<u8>)> {
        self.stats.sent += 1;
        self.stats.sent_bytes += bytes.len() as u64;
        if bytes.len() > usize::from(self.profile.mtu) {
            self.stats.oversize += 1;
            return Vec::new();
        }
        let start = now.max(self.tx_free_at);
        if start - now > self.profile.queue_limit_ms {
            self.stats.lost_queue += 1;
            return Vec::new();
        }
        let done = start + self.tx_time_ms(bytes.len());
        self.tx_free_at = done;
        self.check_duty(start, bytes.len());
        if outages.is_down(start) {
            self.stats.lost_outage += 1;
            return Vec::new();
        }
        let ge = self.profile.loss;
        let flip = if self.bad {
            ge.p_bad_to_good
        } else {
            ge.p_good_to_bad
        };
        if chance(&mut self.rng, flip) {
            self.bad = !self.bad;
        }
        let loss = if self.bad { ge.loss_bad } else { ge.loss_good };
        if chance(&mut self.rng, loss) {
            self.stats.lost += 1;
            return Vec::new();
        }
        let mut bytes = bytes;
        if chance(&mut self.rng, self.profile.bit_flip_prob) && !bytes.is_empty() {
            self.stats.corrupted += 1;
            for _ in 0..=below(&mut self.rng, 3) {
                let bit = below(&mut self.rng, bytes.len() as u64 * 8);
                bytes[(bit / 8) as usize] ^= 1 << (bit % 8);
            }
        }
        let mut out = Vec::with_capacity(2);
        let copies = if chance(&mut self.rng, self.profile.duplicate_prob) {
            self.stats.duplicated += 1;
            2
        } else {
            1
        };
        for _ in 0..copies {
            let mut delay =
                self.profile.delay.base_ms + self.profile.delay.jitter.sample(&mut self.rng);
            if chance(&mut self.rng, self.profile.reorder_prob) {
                delay += below(&mut self.rng, self.profile.reorder_extra_ms + 1);
            }
            out.push((done + delay, bytes.clone()));
        }
        self.stats.delivered += out.len() as u64;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seeded_rng;

    #[test]
    fn gilbert_elliott_matches_mean() {
        let ge = GilbertElliott {
            p_good_to_bad: 0.05,
            p_bad_to_good: 0.1,
            loss_good: 0.1,
            loss_bad: 0.85,
        };
        let profile = LinkProfile {
            mtu: 100,
            delay: DelayModel {
                base_ms: 1,
                jitter: Jitter::None,
            },
            loss: ge,
            bit_flip_prob: 0.0,
            duplicate_prob: 0.0,
            reorder_prob: 0.0,
            reorder_extra_ms: 0,
            rate_bytes_per_sec: None,
            duty: None,
            queue_limit_ms: 0,
            outage: None,
        };
        let mut ch = Channel::new(profile, seeded_rng(1));
        let mut out = Outages::new(None, seeded_rng(2), 0);
        let n = 200_000;
        for i in 0..n {
            ch.send(i, vec![0; 10], &mut out);
        }
        let observed = ch.stats.lost as f64 / n as f64;
        assert!((observed - ge.mean_loss()).abs() < 0.01, "{observed}");
    }

    #[test]
    fn outages_alternate() {
        let m = OutageModel {
            up_ms: 100,
            down_ms: 50,
            randomize: false,
        };
        let mut o = Outages::new(Some(m), seeded_rng(1), 0);
        assert!(!o.is_down(99));
        assert!(o.is_down(100) && o.is_down(149));
        assert!(!o.is_down(150));
        assert!(o.is_down(250));
        assert!(!o.is_down(10)); // queries need not be monotonic
        assert_eq!(o.downtime(0, 300), 100);
    }

    #[test]
    fn pareto_is_heavy_tailed_and_capped() {
        let j = Jitter::Pareto {
            scale_ms: 100.0,
            alpha: 1.2,
            cap_ms: 30_000,
        };
        let mut rng = seeded_rng(3);
        let mut v: Vec<u64> = (0..100_000).map(|_| j.sample(&mut rng)).collect();
        v.sort_unstable();
        let median = v[v.len() / 2];
        let p999 = v[v.len() * 999 / 1000];
        assert!(median < 100, "{median}");
        assert!(p999 > 20 * median.max(1), "{p999}");
        assert!(*v.last().unwrap() <= 30_000);
    }
}
