//! Per-contact state: outbox, receive window, timers (`docs/reliability.md`).

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use super::persist::ContactRecord;
use crate::wire::{FragmentPlan, PairTag};
use crate::{LinkId, MessageId, PublicKey, Timestamp};

/// Clock granularity term in the RTO (RFC 6298's `G`).
const RTO_GRANULARITY_MS: u64 = 100;
/// Backoff exponent cap; the interval is capped by `max_rto_ms` long before.
const MAX_BACKOFF: u32 = 20;

/// One fragment's retransmission state.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct FragState {
    pub(super) last_sent: Option<Timestamp>,
    pub(super) sends: u32,
    /// Random extra delay for this fragment's next retransmission.
    pub(super) jitter_ms: u64,
    /// When the peer reported holding it (FRAG_ACK); soft.
    pub(super) held_at: Option<Timestamp>,
}

/// An undelivered outgoing message.
#[derive(Debug)]
pub(super) struct OutMsg {
    pub(super) id: MessageId,
    pub(super) record: Vec<u8>,
    pub(super) queued_at: Timestamp,
    /// Set on first transmission (D-017).
    pub(super) plan: Option<Planned>,
}

#[derive(Debug)]
pub(super) struct Planned {
    pub(super) plan: FragmentPlan,
    /// Frame space the plan was made for.
    pub(super) space: usize,
    pub(super) frags: Vec<FragState>,
}

/// The timer parameters a due-time computation needs.
#[derive(Debug, Clone, Copy)]
pub(super) struct Timers {
    pub(super) rto: u64,
    pub(super) max_rto: u64,
    /// Probes sent at the plain RTO before the interval starts doubling.
    pub(super) grace: u32,
    /// Lower bound on the probe interval from the link's budget.
    pub(super) probe_floor: u64,
}

impl OutMsg {
    /// When fragment `f` is next due in normal (non-backoff) mode.
    pub(super) fn frag_due(&self, f: &FragState, t: Timers) -> Timestamp {
        match (f.held_at, f.last_sent) {
            (Some(held), _) => held.saturating_add_millis(t.max_rto),
            (None, Some(sent)) => sent.saturating_add_millis(t.rto.saturating_add(f.jitter_ms)),
            (None, None) => self.queued_at,
        }
    }

    /// Earliest time any fragment is due in normal mode.
    pub(super) fn next_due(&self, t: Timers) -> Timestamp {
        match &self.plan {
            None => self.queued_at,
            Some(p) => p
                .frags
                .iter()
                .map(|f| self.frag_due(f, t))
                .min()
                .unwrap_or(self.queued_at),
        }
    }
}

/// What we have received from a peer: all seqs below `cum`, plus `above`.
#[derive(Debug, Default, Clone)]
pub(super) struct Inbox {
    pub(super) cum: u64,
    pub(super) above: BTreeSet<u64>,
}

impl Inbox {
    pub(super) fn contains(&self, seq: u64) -> bool {
        seq < self.cum || self.above.contains(&seq)
    }

    pub(super) fn insert(&mut self, seq: u64) {
        if seq < self.cum {
            return;
        }
        if seq != self.cum {
            self.above.insert(seq);
            return;
        }
        self.cum = self.cum.saturating_add(1);
        while self.above.remove(&self.cum) {
            self.cum = self.cum.saturating_add(1);
        }
    }

    /// Earlier seqs not yet received, for a `seq` not yet inserted.
    pub(super) fn missing_before(&self, seq: u64) -> u64 {
        if seq <= self.cum {
            return 0;
        }
        let have = u64::try_from(self.above.range(self.cum..seq).count()).unwrap_or(u64::MAX);
        seq.saturating_sub(self.cum).saturating_sub(have)
    }

    /// Bitmap for an ACK frame: bit `i` = seq `cum + 1 + i`. Trailing zero
    /// bytes trimmed.
    pub(super) fn bitmap(&self, max_bytes: usize) -> Vec<u8> {
        let mut out = alloc::vec![0u8; max_bytes];
        let base = self.cum.saturating_add(1);
        for &seq in &self.above {
            let Some(off) = seq.checked_sub(base).and_then(|o| usize::try_from(o).ok()) else {
                continue;
            };
            match out.get_mut(off / 8) {
                Some(byte) => *byte |= 1u8 << (off % 8),
                None => break,
            }
        }
        while out.last() == Some(&0) {
            out.pop();
        }
        out
    }
}

/// RFC 6298 estimator in integer milliseconds.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Rtt {
    srtt: Option<u64>,
    rttvar: u64,
}

impl Rtt {
    pub(super) fn sample(&mut self, r: u64) {
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(srtt) => {
                let err = srtt.abs_diff(r);
                self.rttvar = (self.rttvar / 4).saturating_mul(3).saturating_add(err / 4);
                self.srtt = Some((srtt / 8).saturating_mul(7).saturating_add(r / 8));
            }
        }
    }

    pub(super) fn rto(&self, initial: u64, min: u64, max: u64, var_mult: u64) -> u64 {
        match self.srtt {
            None => initial.clamp(min, max),
            Some(srtt) => srtt
                .saturating_add(RTO_GRANULARITY_MS.max(self.rttvar.saturating_mul(var_mult)))
                .clamp(min, max),
        }
    }
}

#[derive(Debug)]
pub(super) struct Contact {
    pub(super) key: PublicKey,
    /// Tag on packets we send to this contact.
    pub(super) tx_tag: PairTag,
    /// Link we last heard this contact on.
    pub(super) route: Option<LinkId>,
    pub(super) lamport: u64,
    pub(super) next_seq: u64,
    pub(super) tx_counter: u64,
    /// Counters below this are reserved in storage.
    pub(super) counter_reserved: u64,
    pub(super) outbox: BTreeMap<u64, OutMsg>,
    pub(super) inbox: Inbox,
    pub(super) ack_due: Option<Timestamp>,
    /// Partially received seqs whose progress we owe a FRAG_ACK for.
    pub(super) frag_ack_pending: BTreeSet<u64>,
    pub(super) rtt: Rtt,
    /// Largest counter already used for an RTT sample.
    pub(super) rtt_sampled: Option<u64>,
    /// Recent (counter, send time), oldest first.
    pub(super) sent_log: VecDeque<(u64, Timestamp)>,
    /// Largest counter received from the peer and when.
    pub(super) rx_largest: Option<(u64, Timestamp)>,
    /// Last authenticated packet from the peer.
    pub(super) last_heard: Option<Timestamp>,
    /// 0: normal. k > 0: peer unreachable, probing every `rto * 2^k`.
    pub(super) backoff: u32,
    pub(super) probe_due: Timestamp,
}

impl Contact {
    pub(super) fn new(key: PublicKey, tx_tag: PairTag) -> Self {
        Self {
            key,
            tx_tag,
            route: None,
            lamport: 0,
            next_seq: 0,
            tx_counter: 0,
            counter_reserved: 0,
            outbox: BTreeMap::new(),
            inbox: Inbox::default(),
            ack_due: None,
            frag_ack_pending: BTreeSet::new(),
            rtt: Rtt::default(),
            rtt_sampled: None,
            sent_log: VecDeque::new(),
            rx_largest: None,
            last_heard: None,
            backoff: 0,
            probe_due: Timestamp::ZERO,
        }
    }

    pub(super) fn from_record(r: &ContactRecord, tx_tag: PairTag) -> Self {
        let mut c = Self::new(r.key, tx_tag);
        c.next_seq = r.next_seq;
        c.lamport = r.lamport;
        // Skip everything that might have been used before the crash.
        c.tx_counter = r.counter_reserved;
        c.counter_reserved = r.counter_reserved;
        c
    }

    pub(super) fn record(&self) -> ContactRecord {
        ContactRecord {
            key: self.key,
            next_seq: self.next_seq,
            lamport: self.lamport,
            counter_reserved: self.counter_reserved,
        }
    }

    /// When outgoing data is next due, if there is any.
    pub(super) fn data_due(&self, t: Timers) -> Option<Timestamp> {
        if self.outbox.is_empty() {
            return None;
        }
        if self.backoff > 0 {
            return Some(self.probe_due);
        }
        self.outbox.values().map(|m| m.next_due(t)).min()
    }

    /// Earliest time this contact has something to send, if anything.
    pub(super) fn next_work(&self, t: Timers) -> Option<Timestamp> {
        match (self.data_due(t), self.ack_due) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Probe interval at the current backoff level.
    pub(super) fn probe_interval(&self, t: Timers) -> u64 {
        let shift = self.backoff.saturating_sub(t.grace).min(MAX_BACKOFF);
        t.rto
            .saturating_mul(1u64 << shift)
            .min(t.max_rto)
            .max(t.probe_floor)
    }

    pub(super) fn deepen_backoff(&mut self) {
        self.backoff = self.backoff.saturating_add(1).min(MAX_BACKOFF);
    }

    /// An authenticated packet with `counter` arrived from the peer.
    pub(super) fn heard(&mut self, now: Timestamp, counter: u64) {
        self.last_heard = Some(now);
        self.backoff = 0;
        if self.rx_largest.is_none_or(|(c, _)| counter > c) {
            self.rx_largest = Some((counter, now));
        }
    }

    pub(super) fn log_sent(&mut self, counter: u64, now: Timestamp, max: usize) {
        while self.sent_log.len() >= max {
            self.sent_log.pop_front();
        }
        self.sent_log.push_back((counter, now));
    }

    pub(super) fn sent_at(&self, counter: u64) -> Option<Timestamp> {
        let i = self
            .sent_log
            .binary_search_by_key(&counter, |&(c, _)| c)
            .ok()?;
        self.sent_log.get(i).map(|&(_, t)| t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbox_advances_cum_and_bitmaps() {
        let mut i = Inbox::default();
        i.insert(1);
        i.insert(3);
        i.insert(10);
        assert_eq!(i.cum, 0);
        assert_eq!(i.missing_before(4), 2);
        assert_eq!(i.missing_before(0), 0);
        assert_eq!(i.bitmap(4), [0b0000_0101, 0b0000_0010]);
        assert_eq!(i.bitmap(1), [0b0000_0101]);
        i.insert(0);
        assert_eq!(i.cum, 2);
        assert_eq!(i.bitmap(4), [0b1000_0001]);
        assert!(i.contains(1) && i.contains(10) && !i.contains(4));
        i.insert(2);
        assert_eq!(i.cum, 4);
    }

    #[test]
    fn rtt_estimator_converges_and_clamps() {
        let mut r = Rtt::default();
        assert_eq!(r.rto(3000, 1000, 60_000, 4), 3000);
        r.sample(500);
        // srtt 500, rttvar 250: 500 + max(100, 1000).
        assert_eq!(r.rto(3000, 1000, 60_000, 4), 1500);
        for _ in 0..50 {
            r.sample(2000);
        }
        let rto = r.rto(3000, 1000, 60_000, 4);
        assert!((2000..2600).contains(&rto), "{rto}");
        r.sample(10_000_000);
        assert_eq!(r.rto(3000, 1000, 60_000, 4), 60_000);
    }

    #[test]
    fn probe_interval_doubles_to_cap() {
        let mut c = Contact::new(PublicKey([0; 32]), [0; 3]);
        let t = Timers {
            rto: 1000,
            max_rto: 10_000,
            grace: 0,
            probe_floor: 0,
        };
        c.deepen_backoff();
        assert_eq!(c.probe_interval(t), 2000);
        c.deepen_backoff();
        assert_eq!(c.probe_interval(t), 4000);
        for _ in 0..30 {
            c.deepen_backoff();
        }
        assert_eq!(c.probe_interval(t), 10_000);
        let floored = Timers {
            probe_floor: 50_000,
            ..t
        };
        assert_eq!(c.probe_interval(floored), 50_000);
        c.heard(Timestamp::ZERO, 0);
        assert_eq!(c.backoff, 0);
    }
}
