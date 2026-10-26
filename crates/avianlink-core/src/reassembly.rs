//! Bounded fragment reassembly (`docs/wire-format.md` §3.1).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::ConversationId;

/// Accounting overhead charged per stored fragment, on top of its bytes.
const FRAGMENT_OVERHEAD: usize = 32;

#[derive(Debug)]
struct Partial {
    count: u64,
    frags: BTreeMap<u64, Vec<u8>>,
    bytes: usize,
    data_bytes: usize,
    touched: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Insert {
    /// Fragment stored (or was a duplicate); message incomplete.
    Incomplete,
    /// All fragments present; the reassembled record.
    Complete(Vec<u8>),
    /// Fragment rejected: invalid fields or oversized message.
    Invalid,
    /// Fragment rejected: no room even after eviction.
    NoRoom,
}

#[derive(Debug)]
pub(crate) struct Reassembly {
    partials: BTreeMap<(ConversationId, u64), Partial>,
    total_bytes: usize,
    limit_bytes: usize,
    max_fragments: u64,
    max_record_len: usize,
    clock: u64,
}

impl Reassembly {
    pub(crate) fn new(limit_bytes: usize, max_fragments: u64, max_record_len: usize) -> Self {
        Self {
            partials: BTreeMap::new(),
            total_bytes: 0,
            limit_bytes,
            max_fragments,
            max_record_len,
            clock: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub(crate) fn insert(
        &mut self,
        conv: ConversationId,
        seq: u64,
        count: u64,
        index: u64,
        data: &[u8],
    ) -> Insert {
        if count == 0 || index >= count || count > self.max_fragments {
            return Insert::Invalid;
        }
        if count == 1 {
            return if data.len() <= self.max_record_len {
                Insert::Complete(data.to_vec())
            } else {
                Insert::Invalid
            };
        }
        let key = (conv, seq);
        if self.partials.get(&key).is_some_and(|p| p.count != count) {
            // Sender re-fragmented; restart.
            self.remove(&key);
        }
        if self
            .partials
            .get(&key)
            .is_some_and(|p| p.frags.contains_key(&index))
        {
            return Insert::Incomplete;
        }
        let cost = data.len().saturating_add(FRAGMENT_OVERHEAD);
        if cost > self.limit_bytes {
            return Insert::NoRoom;
        }
        let data_after = self
            .partials
            .get(&key)
            .map_or(0, |p| p.data_bytes)
            .saturating_add(data.len());
        if data_after > self.max_record_len {
            self.remove(&key);
            return Insert::Invalid;
        }
        if !self.make_room(cost, &key) {
            return Insert::NoRoom;
        }
        self.clock = self.clock.saturating_add(1);
        let partial = self.partials.entry(key).or_insert_with(|| Partial {
            count,
            frags: BTreeMap::new(),
            bytes: 0,
            data_bytes: 0,
            touched: 0,
        });
        partial.frags.insert(index, data.to_vec());
        partial.bytes = partial.bytes.saturating_add(cost);
        partial.data_bytes = data_after;
        partial.touched = self.clock;
        self.total_bytes = self.total_bytes.saturating_add(cost);

        let complete = u64::try_from(partial.frags.len()).is_ok_and(|n| n == count);
        if !complete {
            return Insert::Incomplete;
        }
        match self.remove(&key) {
            Some(p) => {
                let mut record = Vec::with_capacity(p.data_bytes);
                p.frags.values().for_each(|f| record.extend_from_slice(f));
                Insert::Complete(record)
            }
            None => Insert::Invalid,
        }
    }

    /// Fragments held for `(conv, seq)`: the fragment count and a bitmap
    /// (bit `i` = fragment `i`), for a FRAG_ACK.
    pub(crate) fn held(&self, conv: ConversationId, seq: u64) -> Option<(u64, Vec<u8>)> {
        let p = self.partials.get(&(conv, seq))?;
        let bytes = usize::try_from(p.count.div_ceil(8)).ok()?;
        let mut bitmap = alloc::vec![0u8; bytes];
        for &i in p.frags.keys() {
            let i = usize::try_from(i).ok()?;
            if let Some(b) = bitmap.get_mut(i / 8) {
                *b |= 1u8 << (i % 8);
            }
        }
        Some((p.count, bitmap))
    }

    fn remove(&mut self, key: &(ConversationId, u64)) -> Option<Partial> {
        let p = self.partials.remove(key)?;
        self.total_bytes = self.total_bytes.saturating_sub(p.bytes);
        Some(p)
    }

    /// Evicts least recently updated partials other than `keep` until `cost`
    /// more bytes fit. Returns whether they do.
    fn make_room(&mut self, cost: usize, keep: &(ConversationId, u64)) -> bool {
        while self.total_bytes.saturating_add(cost) > self.limit_bytes {
            let victim = self
                .partials
                .iter()
                .filter(|(k, _)| *k != keep)
                .min_by_key(|(_, p)| p.touched)
                .map(|(k, _)| *k);
            match victim {
                Some(k) => {
                    self.remove(&k);
                }
                None => return false,
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const C: ConversationId = ConversationId([1; 16]);

    #[test]
    fn reassembles_out_of_order_with_duplicates() {
        let mut r = Reassembly::new(10_000, 16, 1000);
        assert_eq!(r.insert(C, 0, 3, 2, b"ef"), Insert::Incomplete);
        assert_eq!(r.insert(C, 0, 3, 0, b"ab"), Insert::Incomplete);
        assert_eq!(r.held(C, 0), Some((3, vec![0b101])));
        assert_eq!(r.insert(C, 0, 3, 0, b"ab"), Insert::Incomplete);
        assert_eq!(
            r.insert(C, 0, 3, 1, b"cd"),
            Insert::Complete(b"abcdef".to_vec())
        );
        assert_eq!(r.total_bytes(), 0);
        assert_eq!(r.held(C, 0), None);
    }

    #[test]
    fn rejects_invalid() {
        let mut r = Reassembly::new(10_000, 16, 4);
        assert_eq!(r.insert(C, 0, 0, 0, b"a"), Insert::Invalid);
        assert_eq!(r.insert(C, 0, 2, 2, b"a"), Insert::Invalid);
        assert_eq!(r.insert(C, 0, 17, 0, b"a"), Insert::Invalid);
        assert_eq!(r.insert(C, 0, 1, 0, b"abcde"), Insert::Invalid);
        assert_eq!(r.insert(C, 1, 2, 0, b"abc"), Insert::Incomplete);
        assert_eq!(r.insert(C, 1, 2, 1, b"de"), Insert::Invalid);
        assert_eq!(r.total_bytes(), 0);
    }

    #[test]
    fn refragmentation_restarts() {
        let mut r = Reassembly::new(10_000, 16, 1000);
        assert_eq!(r.insert(C, 0, 3, 0, b"ab"), Insert::Incomplete);
        assert_eq!(r.insert(C, 0, 2, 1, b"def"), Insert::Incomplete);
        assert_eq!(
            r.insert(C, 0, 2, 0, b"abc"),
            Insert::Complete(b"abcdef".to_vec())
        );
    }

    #[test]
    fn evicts_lru_when_full() {
        let mut r = Reassembly::new(2 * (FRAGMENT_OVERHEAD + 2), 16, 1000);
        assert_eq!(r.insert(C, 0, 2, 0, b"aa"), Insert::Incomplete);
        assert_eq!(r.insert(C, 1, 2, 0, b"bb"), Insert::Incomplete);
        // Seq 2 evicts seq 0 (oldest).
        assert_eq!(r.insert(C, 2, 2, 0, b"cc"), Insert::Incomplete);
        assert_eq!(r.insert(C, 0, 2, 1, b"aa"), Insert::Incomplete);
        assert!(r.total_bytes() <= 2 * (FRAGMENT_OVERHEAD + 2));
        // Larger than the whole table: dropped.
        assert_eq!(r.insert(C, 3, 2, 0, &[0; 200]), Insert::NoRoom);
    }
}
