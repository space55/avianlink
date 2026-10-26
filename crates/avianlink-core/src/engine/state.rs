//! Per-contact state: outbox, receive window, counters.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::wire::{FragmentPlan, PairTag};
use crate::{LinkId, MessageId, PublicKey, Timestamp};

/// One fragment's retransmission state.
#[derive(Debug, Clone, Copy)]
pub(super) struct FragState {
    pub(super) next_send: Timestamp,
    pub(super) sends: u32,
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

impl OutMsg {
    /// Earliest time any fragment is due.
    pub(super) fn next_due(&self) -> Timestamp {
        match &self.plan {
            None => self.queued_at,
            Some(p) => p
                .frags
                .iter()
                .map(|f| f.next_send)
                .min()
                .unwrap_or(self.queued_at),
        }
    }
}

/// What we have received from a peer: all seqs below `cum`, plus `above`.
#[derive(Debug, Default)]
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
    pub(super) outbox: BTreeMap<u64, OutMsg>,
    pub(super) inbox: Inbox,
    pub(super) ack_due: Option<Timestamp>,
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
            outbox: BTreeMap::new(),
            inbox: Inbox::default(),
            ack_due: None,
        }
    }

    /// Earliest time this contact has something to send, if anything.
    pub(super) fn next_work(&self) -> Option<Timestamp> {
        let data = self.outbox.values().map(OutMsg::next_due).min();
        match (data, self.ack_due) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
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
        assert_eq!(i.bitmap(4), [0b0000_0101, 0b0000_0010]);
        assert_eq!(i.bitmap(1), [0b0000_0101]);
        i.insert(0);
        assert_eq!(i.cum, 2);
        assert_eq!(i.bitmap(4), [0b1000_0001]);
        assert!(i.contains(1) && i.contains(10) && !i.contains(4));
        i.insert(2);
        assert_eq!(i.cum, 4);
    }
}
