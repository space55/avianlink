//! A simulated link: one direction of packets between two engines.
//!
//! The impairment *parameters* come from `avianlink-sim`'s named profiles,
//! which are tuned and shared with `scripts/netem/`. The impairment *engine*
//! is reimplemented here because the simulator's `Channel` is `pub(crate)`
//! and its `Scenario` runs a whole batch over virtual time, which is the
//! wrong shape for a GUI advancing in real time (api-requests AR-009).
//!
//! Reusing the numbers and not the code is the right half to duplicate: the
//! numbers are the part that was tuned against real links, and the ~150 lines
//! of "roll a die, drop or delay the packet" are the part that is obvious.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use avianlink_sim::impair::{Jitter, LinkProfile, OutageModel};
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;

/// How many recent packets the loss estimate looks back over.
///
/// Short enough that a burst shows up while it is happening, long enough that
/// one lost packet does not read as 100% loss.
const LOSS_WINDOW: usize = 64;

/// Draws a uniform value in `[0, 1)`.
fn unit(rng: &mut ChaCha20Rng) -> f64 {
    // 53 bits is the mantissa of an f64; taking the top 53 of a u64 gives a
    // uniform value with no rounding bias.
    (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64
}

/// Returns whether an event of probability `p` happens.
fn chance(rng: &mut ChaCha20Rng, p: f64) -> bool {
    p > 0.0 && unit(rng) < p
}

/// Draws a uniform integer in `[0, bound)`.
fn below(rng: &mut ChaCha20Rng, bound: u64) -> u64 {
    if bound == 0 {
        0
    } else {
        rng.next_u64() % bound
    }
}

/// Draws a jitter sample.
///
/// Reimplemented rather than called: `Jitter::sample` is private in
/// `avianlink-sim` even though the variants and their fields are public
/// (api-requests AR-009). The formulas are the simulator's.
fn sample_jitter(jitter: Jitter, rng: &mut ChaCha20Rng) -> u64 {
    match jitter {
        Jitter::None => 0,
        Jitter::Uniform { max_ms } => below(rng, max_ms.saturating_add(1)),
        Jitter::Pareto {
            scale_ms,
            alpha,
            cap_ms,
        } => {
            let u = unit(rng).max(f64::MIN_POSITIVE);
            let x = scale_ms * (u.powf(-1.0 / alpha) - 1.0);
            (x.round().max(0.0) as u64).min(cap_ms)
        }
    }
}

/// Draws an exponential sample with mean `mean_ms`, at least 1 ms.
fn exponential(rng: &mut ChaCha20Rng, mean_ms: u64) -> u64 {
    let u = unit(rng).max(f64::MIN_POSITIVE);
    ((-u.ln()) * mean_ms as f64).round().max(1.0) as u64
}

/// A packet waiting for its arrival time.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pending {
    at: u64,
    /// Tiebreak, so two packets due at the same millisecond keep a stable
    /// order and the simulation stays reproducible from its seed.
    id: u64,
    bytes: Vec<u8>,
}

impl Ord for Pending {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.at.cmp(&other.at).then(self.id.cmp(&other.id))
    }
}

impl PartialOrd for Pending {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Alternating up and down periods, generated as time advances.
#[derive(Debug)]
pub struct Outages {
    model: Option<OutageModel>,
    rng: ChaCha20Rng,
    /// When the current period ends.
    until: u64,
    /// Whether the link is currently down.
    down: bool,
}

impl Outages {
    /// Starts an outage schedule, up, at `start`.
    pub fn new(model: Option<OutageModel>, mut rng: ChaCha20Rng, start: u64) -> Self {
        let until = match model {
            Some(m) => start.saturating_add(Self::period(&mut rng, m.up_ms, m.randomize)),
            None => u64::MAX,
        };
        Self {
            model,
            rng,
            until,
            down: false,
        }
    }

    fn period(rng: &mut ChaCha20Rng, mean_ms: u64, randomize: bool) -> u64 {
        if randomize {
            exponential(rng, mean_ms.max(1))
        } else {
            mean_ms.max(1)
        }
    }

    /// Advances to `now` and reports whether the link is down.
    pub fn is_down(&mut self, now: u64) -> bool {
        let Some(model) = self.model else {
            return false;
        };
        while now >= self.until {
            self.down = !self.down;
            let mean = if self.down {
                model.down_ms
            } else {
                model.up_ms
            };
            let next = Self::period(&mut self.rng, mean, model.randomize);
            self.until = self.until.saturating_add(next.max(1));
        }
        self.down
    }

    /// When the up/down state will next flip.
    pub fn next_change(&self) -> Option<u64> {
        self.model.map(|_| self.until)
    }
}

/// Counters for one direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChannelCounters {
    /// Packets handed to the channel.
    pub sent: u64,
    /// Bytes handed to the channel.
    pub sent_bytes: u64,
    /// Packets delivered, including duplicates.
    pub delivered: u64,
    /// Bytes delivered.
    pub delivered_bytes: u64,
    /// Dropped by the loss model.
    pub lost: u64,
    /// Dropped because the link was down.
    pub lost_outage: u64,
    /// Delivered with bits flipped.
    pub corrupted: u64,
    /// Extra copies delivered.
    pub duplicated: u64,
}

/// One direction of a simulated link.
#[derive(Debug)]
pub struct Channel {
    profile: LinkProfile,
    rng: ChaCha20Rng,
    /// Gilbert-Elliott state: `true` while in the bad state.
    bad: bool,
    queue: BinaryHeap<Reverse<Pending>>,
    next_id: u64,
    /// Recent outcomes, `true` for delivered. Fixed capacity.
    recent: std::collections::VecDeque<bool>,
    counters: ChannelCounters,
}

impl Channel {
    /// Creates a channel with the given impairments.
    pub fn new(profile: LinkProfile, rng: ChaCha20Rng) -> Self {
        Self {
            profile,
            rng,
            bad: false,
            queue: BinaryHeap::new(),
            next_id: 0,
            recent: std::collections::VecDeque::with_capacity(LOSS_WINDOW),
            counters: ChannelCounters::default(),
        }
    }

    /// Replaces the impairment profile, keeping packets already in flight.
    pub fn set_profile(&mut self, profile: LinkProfile) {
        self.profile = profile;
    }

    /// The counters so far.
    pub fn counters(&self) -> ChannelCounters {
        self.counters
    }

    /// Loss over the last [`LOSS_WINDOW`] packets, in parts per thousand.
    ///
    /// `None` until enough packets have been sent for the number to mean
    /// anything. The UI renders `None` as "not measured", never as zero: a
    /// link that has carried four packets has not demonstrated anything.
    pub fn recent_loss_permille(&self) -> Option<u16> {
        const MINIMUM: usize = 8;
        if self.recent.len() < MINIMUM {
            return None;
        }
        let lost = self.recent.iter().filter(|delivered| !**delivered).count();
        Some(((lost * 1000) / self.recent.len()) as u16)
    }

    fn record(&mut self, delivered: bool) {
        if self.recent.len() == LOSS_WINDOW {
            self.recent.pop_front();
        }
        self.recent.push_back(delivered);
    }

    /// Advances the Gilbert-Elliott state and returns whether this packet is
    /// lost to it.
    ///
    /// The state flips *before* the draw, so a burst starts with a loss
    /// rather than one packet later. That matters for the UI: it is what
    /// makes loss arrive in visible clumps instead of as a uniform drizzle.
    fn lost_to_burst(&mut self) -> bool {
        let model = self.profile.loss;
        let flip = if self.bad {
            model.p_bad_to_good
        } else {
            model.p_good_to_bad
        };
        if chance(&mut self.rng, flip) {
            self.bad = !self.bad;
        }
        let p = if self.bad {
            model.loss_bad
        } else {
            model.loss_good
        };
        chance(&mut self.rng, p)
    }

    /// Hands a packet to the link at `now`.
    ///
    /// The packet is dropped, delayed, corrupted, duplicated or reordered
    /// according to the profile. Nothing is returned: surviving copies appear
    /// from [`Self::take_due`] when their time comes.
    pub fn send(&mut self, now: u64, bytes: &[u8], link_down: bool) {
        self.counters.sent = self.counters.sent.saturating_add(1);
        self.counters.sent_bytes = self.counters.sent_bytes.saturating_add(bytes.len() as u64);

        if bytes.len() > usize::from(self.profile.mtu) {
            // The engine fragmented to the smallest registered MTU, so this
            // would be an engine bug. Drop it rather than silently widening
            // the link; a test asserts it never happens.
            self.record(false);
            return;
        }
        if link_down {
            self.counters.lost_outage = self.counters.lost_outage.saturating_add(1);
            self.record(false);
            return;
        }
        if self.lost_to_burst() {
            self.counters.lost = self.counters.lost.saturating_add(1);
            self.record(false);
            return;
        }

        let mut delay = self
            .profile
            .delay
            .base_ms
            .saturating_add(sample_jitter(self.profile.delay.jitter, &mut self.rng));
        if chance(&mut self.rng, self.profile.reorder_prob) {
            delay = delay.saturating_add(below(&mut self.rng, self.profile.reorder_extra_ms + 1));
        }

        let mut payload = bytes.to_vec();
        if chance(&mut self.rng, self.profile.bit_flip_prob) {
            self.counters.corrupted = self.counters.corrupted.saturating_add(1);
            let flips = 1 + below(&mut self.rng, 3);
            for _ in 0..flips {
                let byte = below(&mut self.rng, payload.len() as u64) as usize;
                let bit = below(&mut self.rng, 8) as u8;
                if let Some(target) = payload.get_mut(byte) {
                    *target ^= 1 << bit;
                }
            }
        }

        let duplicate = chance(&mut self.rng, self.profile.duplicate_prob);
        self.push(now.saturating_add(delay), payload.clone());
        if duplicate {
            self.counters.duplicated = self.counters.duplicated.saturating_add(1);
            let extra = below(&mut self.rng, 200) + 1;
            self.push(now.saturating_add(delay).saturating_add(extra), payload);
        }
        self.record(true);
    }

    fn push(&mut self, at: u64, bytes: Vec<u8>) {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.queue.push(Reverse(Pending { at, id, bytes }));
    }

    /// When the next packet is due, if any.
    pub fn next_arrival(&self) -> Option<u64> {
        self.queue.peek().map(|Reverse(p)| p.at)
    }

    /// Takes every packet due at or before `now`, in arrival order.
    pub fn take_due(&mut self, now: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while self.queue.peek().is_some_and(|Reverse(p)| p.at <= now) {
            if let Some(Reverse(p)) = self.queue.pop() {
                self.counters.delivered = self.counters.delivered.saturating_add(1);
                self.counters.delivered_bytes = self
                    .counters
                    .delivered_bytes
                    .saturating_add(p.bytes.len() as u64);
                out.push(p.bytes);
            }
        }
        out
    }

    /// Packets still in flight.
    pub fn in_flight(&self) -> usize {
        self.queue.len()
    }
}
