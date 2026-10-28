//! Per-contact state: outbox, receive window, timers (`docs/reliability.md`).

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use super::persist::{BlockDigest, ContactRecord, RecvDigest};
use crate::crypto::PairKeys;
use crate::wire::{ChainRole, FragmentPlan, ReceiptHash, HELLO_LEN};
use crate::{LinkId, MessageId, PublicKey, Timestamp};

fn id8(id: &crate::MessageId) -> [u8; 8] {
    let mut h = [0u8; 8];
    h.iter_mut().zip(id.0).for_each(|(o, b)| *o = b);
    h
}

/// Clock granularity term in the RTO (RFC 6298's `G`).
const RTO_GRANULARITY_MS: u64 = 100;
/// Backoff exponent cap; the interval is capped by `max_rto_ms` long before.
const MAX_BACKOFF: u32 = 20;
/// In long silences the probe interval is this fraction of the silence.
const PROBE_SILENCE_DIVISOR: u64 = 64;

/// One fragment's retransmission state.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct FragState {
    pub(super) last_sent: Option<Timestamp>,
    pub(super) sends: u32,
    /// Random extra delay for this fragment's next retransmission.
    pub(super) jitter_ms: u64,
    /// When the peer reported holding it (FRAG_ACK); soft.
    pub(super) held_at: Option<Timestamp>,
    /// When a relay receipted a packet carrying it (`relay.md` §6); soft.
    pub(super) stored_at: Option<Timestamp>,
}

/// An undelivered outgoing message.
#[derive(Debug)]
pub(super) struct OutMsg {
    pub(super) id: MessageId,
    pub(super) record: Vec<u8>,
    pub(super) queued_at: Timestamp,
    /// Set on first transmission (D-017).
    pub(super) plan: Option<Planned>,
    /// `MessageTransmitted` already reported in this incarnation.
    pub(super) announced: bool,
    /// `MessageStored` already reported in this incarnation.
    pub(super) stored_announced: bool,
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
    /// Upper bound on the probe interval (`max_probe_interval`).
    pub(super) probe_cap: u64,
    /// How long the current backoff has lasted (0 when not in backoff).
    pub(super) silence: u64,
    /// Whether the silence has reached `deep_backoff_after_ms`: probes then
    /// carry only a SYNC.
    pub(super) deep: bool,
    /// Traffic goes through a relay (`relay.md` §6).
    pub(super) relay: bool,
    /// On a relay: how long a stored fragment waits before it is resent
    /// (half the relay's retention).
    pub(super) resend: u64,
}

impl OutMsg {
    /// When fragment `f` is next due in normal (non-backoff) mode. On a
    /// relay: at the RTO until receipted, then every `resend`.
    pub(super) fn frag_due(&self, f: &FragState, t: Timers) -> Timestamp {
        if t.relay {
            return match (f.held_at.max(f.stored_at), f.last_sent) {
                (Some(kept), _) => kept.saturating_add_millis(t.resend),
                (None, Some(sent)) => sent.saturating_add_millis(t.rto.saturating_add(f.jitter_ms)),
                (None, None) => self.queued_at,
            };
        }
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

    pub(super) fn srtt(&self) -> Option<u64> {
        self.srtt
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

/// Replay window size in packets (`security.md` §6).
pub(super) const REPLAY_WINDOW: u64 = 512;
const REPLAY_WORDS: usize = 8;

/// Highest accepted counter plus a 512-packet bitmap below it. Bit `k` set:
/// counter `high - k` was accepted.
#[derive(Debug, Clone, Default)]
pub(super) struct Replay {
    high: Option<u64>,
    bits: [u64; REPLAY_WORDS],
}

impl Replay {
    /// A window that rejects everything at or below `floor` (after restore).
    pub(super) fn with_floor(floor: Option<u64>) -> Self {
        Self {
            high: floor,
            bits: [u64::MAX; REPLAY_WORDS],
        }
    }

    pub(super) fn high(&self) -> Option<u64> {
        self.high
    }

    /// Whether `counter` would be accepted. Does not change the window.
    pub(super) fn fresh(&self, counter: u64) -> bool {
        let Some(high) = self.high else {
            return true;
        };
        if counter > high {
            return true;
        }
        let k = high.saturating_sub(counter);
        if k >= REPLAY_WINDOW {
            return false;
        }
        let (w, b) = (k / 64, k % 64);
        usize::try_from(w)
            .ok()
            .and_then(|w| self.bits.get(w))
            .is_some_and(|word| word & (1u64 << b) == 0)
    }

    /// Fraction of counters missing among those aged 32..288 below the
    /// highest, in permille; `None` until 32 such counters exist.
    pub(super) fn loss_permille(&self) -> Option<u64> {
        let high = self.high?;
        let last = high.min(287);
        if last < 63 {
            return None;
        }
        let (mut seen, mut total) = (0u64, 0u64);
        for k in 32..=last {
            total = total.saturating_add(1);
            let hit = usize::try_from(k / 64)
                .ok()
                .and_then(|w| self.bits.get(w))
                .is_some_and(|word| word & (1u64 << (k % 64)) != 0);
            if hit {
                seen = seen.saturating_add(1);
            }
        }
        total
            .saturating_sub(seen)
            .saturating_mul(1000)
            .checked_div(total)
    }

    /// Records `counter` as accepted. Call only after authentication.
    pub(super) fn mark(&mut self, counter: u64) {
        match self.high {
            Some(high) if counter <= high => {
                let k = high.saturating_sub(counter);
                if let Some(word) = usize::try_from(k / 64)
                    .ok()
                    .and_then(|w| self.bits.get_mut(w))
                {
                    *word |= 1u64 << (k % 64);
                }
            }
            prev => {
                let shift = prev.map_or(REPLAY_WINDOW, |h| counter.saturating_sub(h));
                self.shift(shift);
                self.high = Some(counter);
                if let Some(w0) = self.bits.first_mut() {
                    *w0 |= 1;
                }
            }
        }
    }

    /// Ages every entry by `d` packets.
    fn shift(&mut self, d: u64) {
        if d >= REPLAY_WINDOW {
            self.bits = [0; REPLAY_WORDS];
            return;
        }
        let words = usize::try_from(d / 64).unwrap_or(REPLAY_WORDS);
        let bits = u32::try_from(d % 64).unwrap_or(0);
        let old = self.bits;
        for (i, slot) in self.bits.iter_mut().enumerate() {
            let src = i.checked_sub(words);
            let hi = src.and_then(|s| old.get(s)).copied().unwrap_or(0);
            let lo = src
                .and_then(|s| s.checked_sub(1))
                .and_then(|s| old.get(s))
                .copied()
                .unwrap_or(0);
            *slot = if bits == 0 {
                hi
            } else {
                hi.wrapping_shl(bits) | lo.wrapping_shr(64u32.saturating_sub(bits))
            };
        }
    }
}

/// A repair waiting to be sent.
#[derive(Debug, Clone)]
pub(super) struct RepairOut {
    pub(super) base: u64,
    pub(super) mask: u64,
    pub(super) shape: u8,
    pub(super) data: Vec<u8>,
}

/// Sender side of FEC for one contact.
#[derive(Debug, Default)]
pub(super) struct FecTx {
    /// Current window: (counter, plaintext), in counter order.
    pub(super) sources: Vec<(u64, Vec<u8>)>,
    /// When the window's first source was sent.
    pub(super) opened: Timestamp,
    /// Repairs of closed windows, oldest first.
    pub(super) pending: VecDeque<RepairOut>,
    /// Fractional repairs owed, in thousandths, carried across windows.
    pub(super) credit: u64,
}

#[derive(Debug)]
pub(super) struct Contact {
    pub(super) key: PublicKey,
    /// Directional keys and routing tags.
    pub(super) keys: PairKeys,
    pub(super) replay: Replay,
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
    /// Last packet from the peer with a new highest counter.
    pub(super) last_fresh: Option<Timestamp>,
    /// 0: normal. k > 0: peer unreachable, probing every `rto * 2^k`.
    pub(super) backoff: u32,
    pub(super) probe_due: Timestamp,
    pub(super) fec_tx: FecTx,
    /// Loss the peer reports on our packets (LOSS frames), permille.
    pub(super) peer_loss: Option<u64>,
    /// Actual arrivals from the peer (before FEC recovery), for LOSS.
    pub(super) arrivals: Replay,
    /// Last loss we reported, and packets received since.
    pub(super) loss_reported: Option<u64>,
    pub(super) rx_since_report: u32,
    /// When the current backoff began (deep backoff, `reliability.md` §3).
    pub(super) backoff_since: Option<Timestamp>,
    /// A SYNC frame should ride on the next packet to this contact.
    pub(super) sync_due: bool,
    /// Digests of our last sent blocks (persisted in the contact record).
    pub(super) sent_digests: Vec<BlockDigest>,
    /// Digests of the peer's last received blocks (persisted with the inbox).
    pub(super) recv_digests: Vec<RecvDigest>,
    /// Blocks already reported as diverged.
    pub(super) diverged: Vec<u64>,
    /// An authenticated packet from the contact has been accepted, so it
    /// knows our key (persisted; `reliability.md` §3).
    pub(super) confirmed: bool,
    /// Unconfirmed and Hellos are on: probe from the start, Hello first.
    pub(super) introducing: bool,
    /// Our Hello to this contact (the same bytes every time).
    pub(super) hello: Option<[u8; HELLO_LEN]>,
    /// The probe round (its `probe_due`) a Hello has already gone out for.
    pub(super) hello_round: Option<Timestamp>,
    /// When we last answered a Hello from this contact with a SYNC.
    pub(super) hello_reply_at: Option<Timestamp>,
    /// The next SYNC asks for a reply.
    pub(super) sync_reply: bool,
    /// On a relay: packets awaiting a receipt, oldest first.
    pub(super) relay_log: VecDeque<RelaySent>,
    /// On a relay: when the latest ACK-carrying packet went out, if no
    /// receipt has confirmed it yet, and when to resend it.
    pub(super) ack_sent_at: Option<Timestamp>,
    pub(super) ack_retry_at: Option<Timestamp>,
    /// On a relay: our Hello's last upload, and its receipt.
    pub(super) hello_sent_at: Option<Timestamp>,
    pub(super) hello_stored_at: Option<Timestamp>,
    /// Mailbox proofs used, per (role, epoch) (persisted; `relay.md` §2.1).
    pub(super) chain_used: BTreeMap<(ChainRole, u64), u32>,
}

/// A packet uploaded to a relay, until its receipt.
#[derive(Debug, Clone)]
pub(super) struct RelaySent {
    pub(super) hash: ReceiptHash,
    pub(super) sent_at: Timestamp,
    /// (seq, fragment index) carried.
    pub(super) frags: Vec<(u64, u64)>,
    pub(super) ack: bool,
    pub(super) hello: bool,
}

impl Contact {
    pub(super) fn new(key: PublicKey, keys: PairKeys) -> Self {
        Self {
            key,
            keys,
            replay: Replay::default(),
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
            last_fresh: None,
            backoff: 0,
            probe_due: Timestamp::ZERO,
            fec_tx: FecTx::default(),
            peer_loss: None,
            arrivals: Replay::default(),
            loss_reported: None,
            rx_since_report: 0,
            backoff_since: None,
            sync_due: false,
            sent_digests: Vec::new(),
            recv_digests: Vec::new(),
            diverged: Vec::new(),
            confirmed: false,
            introducing: false,
            hello: None,
            hello_round: None,
            hello_reply_at: None,
            sync_reply: false,
            relay_log: VecDeque::new(),
            ack_sent_at: None,
            ack_retry_at: None,
            hello_sent_at: None,
            hello_stored_at: None,
            chain_used: BTreeMap::new(),
        }
    }

    pub(super) fn from_record(r: &ContactRecord, keys: PairKeys) -> Self {
        let mut c = Self::new(r.key, keys);
        c.next_seq = r.next_seq;
        c.lamport = r.lamport;
        // Skip everything that might have been used before the crash.
        c.tx_counter = r.counter_reserved;
        c.counter_reserved = r.counter_reserved;
        c.sent_digests = r.sent_digests.clone();
        c.confirmed = r.confirmed;
        c.chain_used = r.chain_used.clone();
        // Announce the restored floor and next.
        c.sync_due = true;
        c
    }

    pub(super) fn record(&self) -> ContactRecord {
        ContactRecord {
            key: self.key,
            next_seq: self.next_seq,
            lamport: self.lamport,
            counter_reserved: self.counter_reserved,
            sent_digests: self.sent_digests.clone(),
            confirmed: self.confirmed,
            chain_used: self.chain_used.clone(),
        }
    }

    /// Folds message `id` with `seq` into our sent-block digests.
    pub(super) fn fold_sent(ds: &mut Vec<BlockDigest>, seq: u64, id: &crate::MessageId) {
        let block = seq / crate::wire::SYNC_BLOCK;
        let h = id8(id);
        match ds.iter_mut().find(|d| d.0 == block) {
            Some(d) => d.1.iter_mut().zip(h).for_each(|(a, b)| *a ^= b),
            None => ds.push((block, h)),
        }
        while ds.len() > crate::wire::MAX_SYNC_DIGESTS {
            ds.remove(0);
        }
    }

    /// Folds a received message into the received-block digests.
    pub(super) fn fold_recv(ds: &mut Vec<RecvDigest>, seq: u64, id: &crate::MessageId) {
        let block = seq / crate::wire::SYNC_BLOCK;
        let h = id8(id);
        match ds.iter_mut().find(|d| d.0 == block) {
            Some(d) => {
                d.1.iter_mut().zip(h).for_each(|(a, b)| *a ^= b);
                d.2 = d.2.saturating_add(1);
            }
            None => ds.push((block, h, 1)),
        }
        ds.sort_unstable_by_key(|d| d.0);
        while ds.len() > crate::wire::MAX_SYNC_DIGESTS {
            ds.remove(0);
        }
    }

    /// Sent-block digests the peer can compare: the two most recent
    /// completed blocks.
    pub(super) fn sync_digests(&self) -> Vec<BlockDigest> {
        let done = self.next_seq / crate::wire::SYNC_BLOCK;
        let mut ds: Vec<BlockDigest> = self
            .sent_digests
            .iter()
            .filter(|d| d.0 < done)
            .copied()
            .collect();
        let excess = ds.len().saturating_sub(2);
        ds.drain(..excess);
        ds
    }

    /// Lowest seq we can still deliver to the peer.
    pub(super) fn floor(&self) -> u64 {
        self.outbox.keys().next().copied().unwrap_or(self.next_seq)
    }

    /// Whether traffic goes out as one probe per interval: the peer looks
    /// unreachable, or hasn't confirmed it knows us. Never on a relay,
    /// where silence is normal.
    pub(super) fn probing(&self, t: Timers) -> bool {
        !t.relay && (self.backoff > 0 || self.introducing)
    }

    /// When outgoing data is next due, if there is any. An introduction
    /// probes even with nothing queued (except on a relay).
    pub(super) fn data_due(&self, t: Timers) -> Option<Timestamp> {
        if self.outbox.is_empty() && (!self.introducing || t.relay) {
            return None;
        }
        if self.probing(t) {
            return Some(self.probe_due);
        }
        self.outbox.values().map(|m| m.next_due(t)).min()
    }

    /// When an ACK is due: one is owed, or (on a relay) the last one's
    /// upload was never receipted.
    pub(super) fn ack_due_at(&self, t: Timers) -> Option<Timestamp> {
        let retry = self.ack_retry_at.filter(|_| t.relay);
        match (self.ack_due, retry) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Earliest time this contact has something to send, if anything.
    pub(super) fn next_work(&self, t: Timers) -> Option<Timestamp> {
        match (self.data_due(t), self.ack_due_at(t)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Probe interval at the current backoff level: the short-term doubling
    /// (capped at `max_rto`), or 1/64 of the silence so far once that is
    /// longer, at most `max_probe_interval` (`reliability.md` §3, D-040).
    pub(super) fn probe_interval(&self, t: Timers) -> u64 {
        let shift = self.backoff.saturating_sub(t.grace).min(MAX_BACKOFF);
        let short = t.rto.saturating_mul(1u64 << shift).min(t.max_rto);
        let long = t.silence / PROBE_SILENCE_DIVISOR;
        short.max(long).min(t.probe_cap).max(t.probe_floor)
    }

    pub(super) fn deepen_backoff(&mut self, now: Timestamp) {
        if self.backoff == 0 {
            self.backoff_since = Some(now);
        }
        self.backoff = self.backoff.saturating_add(1).min(MAX_BACKOFF);
    }

    /// An authenticated packet with `counter` arrived from the peer.
    /// Only a packet with a new highest counter is evidence that the
    /// peer is sending *now*. An older one (a late reordered packet, or an
    /// attacker replaying a packet whose original was lost) still
    /// authenticates, but must not pull us out of backoff (security.md §9).
    pub(super) fn heard(&mut self, now: Timestamp, counter: u64) {
        self.last_heard = Some(now);
        if self.rx_largest.is_none_or(|(c, _)| counter > c) {
            self.rx_largest = Some((counter, now));
            self.last_fresh = Some(now);
            self.backoff = 0;
            self.backoff_since = None;
        }
    }

    /// Our loss estimate, if it is worth (re)reporting to the peer.
    pub(super) fn loss_report_due(&self) -> Option<u64> {
        let est = self.arrivals.loss_permille()?;
        match self.loss_reported {
            Some(last) if est.abs_diff(last) < 20 && self.rx_since_report < 64 => None,
            _ => Some(est),
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
    fn replay_window_rejects_repeats_and_ancient_counters() {
        let mut r = Replay::default();
        assert!(r.fresh(5));
        r.mark(5);
        assert!(!r.fresh(5));
        assert!(r.fresh(4) && r.fresh(6));
        r.mark(3);
        assert!(!r.fresh(3) && r.fresh(4));
        r.mark(600);
        assert!(!r.fresh(5) && !r.fresh(3), "5 and 3 fell out of the window");
        assert!(r.fresh(100), "100 is inside the window and unseen");
        r.mark(100);
        assert!(!r.fresh(100) && !r.fresh(600) && r.fresh(599));
        // Shifts that cross word boundaries keep earlier marks.
        r.mark(670);
        assert!(!r.fresh(600) && r.fresh(601) && !r.fresh(670));
        assert!(!r.fresh(158), "below the window");
        let f = Replay::with_floor(Some(1000));
        assert!(!f.fresh(1000) && !f.fresh(999) && f.fresh(1001));
        assert!(Replay::with_floor(None).fresh(0));
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
        let mut rng =
            <rand_chacha::ChaCha20Rng as rand_chacha::rand_core::SeedableRng>::seed_from_u64(3);
        let (a, b) = (
            crate::Identity::generate(&mut rng),
            crate::Identity::generate(&mut rng),
        );
        let keys = PairKeys::derive(&a, &b.public_key()).unwrap();
        let mut c = Contact::new(b.public_key(), keys);
        let t = Timers {
            rto: 1000,
            max_rto: 10_000,
            grace: 0,
            probe_floor: 0,
            probe_cap: 3_600_000,
            silence: 0,
            deep: false,
            relay: false,
            resend: 0,
        };
        c.deepen_backoff(Timestamp::ZERO);
        assert_eq!(c.probe_interval(t), 2000);
        c.deepen_backoff(Timestamp::ZERO);
        assert_eq!(c.probe_interval(t), 4000);
        for _ in 0..30 {
            c.deepen_backoff(Timestamp::ZERO);
        }
        assert_eq!(c.probe_interval(t), 10_000);
        // A long silence stretches the interval to 1/64 of it, up to the cap.
        let long = Timers {
            silence: 128 * 60_000,
            ..t
        };
        assert_eq!(c.probe_interval(long), 120_000);
        let longer = Timers {
            silence: 7 * 24 * 3_600_000,
            ..t
        };
        assert_eq!(c.probe_interval(longer), 3_600_000);
        let floored = Timers {
            probe_floor: 50_000,
            ..t
        };
        assert_eq!(c.probe_interval(floored), 50_000);
        c.heard(Timestamp::ZERO, 0);
        assert_eq!(c.backoff, 0);
    }
}
