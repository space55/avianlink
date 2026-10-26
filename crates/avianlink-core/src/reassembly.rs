//! Bounded, offset-based fragment reassembly (`docs/wire-format.md` §3.1).
//!
//! Fragments are placed by byte offset, so fragments from different
//! fragmentation plans of the same record combine correctly (D-037).

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::wire::Part;
use crate::ConversationId;

/// Accounting overhead charged per partial, on top of its buffer.
const PARTIAL_OVERHEAD: usize = 64;

#[derive(Debug)]
struct Partial {
    /// Bytes so far; grows to the furthest fragment end seen.
    buf: Vec<u8>,
    /// Record length, once the final fragment has arrived.
    total: Option<usize>,
    /// Covered byte ranges: start → end, disjoint and non-adjacent.
    covered: BTreeMap<usize, usize>,
    /// Length of the most recent non-final fragment (FRAG_ACK block size).
    unit: usize,
    cost: usize,
    touched: u64,
}

impl Partial {
    /// Known length, or the bytes seen so far.
    fn extent(&self) -> usize {
        self.total.unwrap_or(self.buf.len())
    }

    fn cover(&mut self, a: usize, b: usize) {
        let (mut start, mut end) = (a, b);
        if let Some((&s, &e)) = self.covered.range(..=a).next_back() {
            if e >= a {
                start = s;
                end = end.max(e);
                self.covered.remove(&s);
            }
        }
        while let Some((&s, &e)) = self.covered.range(start..).next() {
            if s > end {
                break;
            }
            end = end.max(e);
            self.covered.remove(&s);
        }
        self.covered.insert(start, end);
    }

    fn holds(&self, a: usize, b: usize) -> bool {
        self.covered
            .range(..=a)
            .next_back()
            .is_some_and(|(_, &e)| e >= b)
    }

    fn complete(&self) -> bool {
        self.total.is_some_and(|t| self.holds(0, t))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Insert {
    /// Fragment stored (or was a duplicate); message incomplete.
    Incomplete,
    /// The whole record.
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
    max_record_len: usize,
    clock: u64,
}

impl Reassembly {
    pub(crate) fn new(limit_bytes: usize, max_record_len: usize) -> Self {
        Self {
            partials: BTreeMap::new(),
            total_bytes: 0,
            limit_bytes,
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
        part: Option<Part>,
        data: &[u8],
    ) -> Insert {
        let Some(part) = part else {
            return if data.len() <= self.max_record_len {
                Insert::Complete(data.to_vec())
            } else {
                Insert::Invalid
            };
        };
        let Ok(offset) = usize::try_from(part.offset) else {
            return Insert::Invalid;
        };
        let Some(end) = offset.checked_add(data.len()) else {
            return Insert::Invalid;
        };
        if data.is_empty() || end > self.max_record_len {
            return Insert::Invalid;
        }
        let key = (conv, seq);
        if let Some(p) = self.partials.get(&key) {
            // The record length is fixed by the final fragment; nothing may
            // contradict it.
            let ok = match (part.last, p.total) {
                (true, Some(t)) => t == end,
                (true, None) => p.buf.len() <= end,
                (false, Some(t)) => end < t,
                (false, None) => true,
            };
            if !ok {
                return Insert::Invalid;
            }
        }
        let grow = self
            .partials
            .get(&key)
            .map_or(end, |p| end.saturating_sub(p.buf.len()));
        let fresh = !self.partials.contains_key(&key);
        let cost = grow.saturating_add(if fresh { PARTIAL_OVERHEAD } else { 0 });
        if cost > 0 && !self.make_room(cost, &key) {
            return Insert::NoRoom;
        }
        self.clock = self.clock.saturating_add(1);
        let p = self.partials.entry(key).or_insert_with(|| Partial {
            buf: Vec::new(),
            total: None,
            covered: BTreeMap::new(),
            unit: 0,
            cost: 0,
            touched: 0,
        });
        p.cost = p.cost.saturating_add(cost);
        self.total_bytes = self.total_bytes.saturating_add(cost);
        if p.buf.len() < end {
            p.buf.resize(end, 0);
        }
        if let Some(dst) = p.buf.get_mut(offset..end) {
            dst.copy_from_slice(data);
        }
        p.cover(offset, end);
        if part.last {
            p.total = Some(end);
        } else {
            p.unit = data.len();
        }
        p.touched = self.clock;
        if !p.complete() {
            return Insert::Incomplete;
        }
        match self.remove(&key) {
            Some(p) => Insert::Complete(p.buf),
            None => Insert::Invalid,
        }
    }

    /// Coverage of `(conv, seq)` for a FRAG_ACK: the block size and a
    /// bitmap of fully held blocks. `None` without a partial or before any
    /// non-final fragment arrived.
    pub(crate) fn held(&self, conv: ConversationId, seq: u64) -> Option<(u64, Vec<u8>)> {
        let p = self.partials.get(&(conv, seq))?;
        if p.unit == 0 {
            return None;
        }
        let blocks = p.extent().div_ceil(p.unit);
        let mut bitmap = vec![0u8; blocks.div_ceil(8)];
        for k in 0..blocks {
            let a = k.saturating_mul(p.unit);
            let b = a.saturating_add(p.unit).min(p.extent());
            if p.holds(a, b) {
                if let Some(byte) = bitmap.get_mut(k / 8) {
                    *byte |= 1u8 << (k % 8);
                }
            }
        }
        while bitmap.last() == Some(&0) {
            bitmap.pop();
        }
        Some((u64::try_from(p.unit).unwrap_or(u64::MAX), bitmap))
    }

    /// Drops partials of `conv` below `seq` (the peer will never complete
    /// them).
    pub(crate) fn discard_below(&mut self, conv: ConversationId, seq: u64) {
        let keys: Vec<_> = self
            .partials
            .range((conv, 0)..(conv, seq))
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            self.remove(&k);
        }
    }

    /// Drops every partial of `conv` (contact removed).
    pub(crate) fn discard_conversation(&mut self, conv: ConversationId) {
        let keys: Vec<_> = self
            .partials
            .range((conv, 0)..=(conv, u64::MAX))
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            self.remove(&k);
        }
    }

    fn remove(&mut self, key: &(ConversationId, u64)) -> Option<Partial> {
        let p = self.partials.remove(key)?;
        self.total_bytes = self.total_bytes.saturating_sub(p.cost);
        Some(p)
    }

    /// Evicts least recently updated partials other than `keep` until `cost`
    /// more bytes fit. Returns whether they do.
    fn make_room(&mut self, cost: usize, keep: &(ConversationId, u64)) -> bool {
        if cost > self.limit_bytes {
            return false;
        }
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

    const C: ConversationId = ConversationId([1; 16]);

    fn mid(offset: u64) -> Option<Part> {
        Some(Part {
            offset,
            last: false,
        })
    }

    fn fin(offset: u64) -> Option<Part> {
        Some(Part { offset, last: true })
    }

    #[test]
    fn reassembles_out_of_order_with_duplicates() {
        let mut r = Reassembly::new(10_000, 1000);
        assert_eq!(r.insert(C, 0, fin(4), b"ef"), Insert::Incomplete);
        assert_eq!(r.insert(C, 0, mid(0), b"ab"), Insert::Incomplete);
        assert_eq!(r.held(C, 0), Some((2, vec![0b101])));
        assert_eq!(r.insert(C, 0, mid(0), b"ab"), Insert::Incomplete);
        assert_eq!(
            r.insert(C, 0, mid(2), b"cd"),
            Insert::Complete(b"abcdef".to_vec())
        );
        assert_eq!(r.total_bytes(), 0);
        assert_eq!(r.held(C, 0), None);
    }

    /// The D-037 bug: two plans with equal fragment counts but different
    /// sizes (30 bytes as 19+11 and as 29+1) must not splice into garbage.
    #[test]
    fn fragments_from_different_plans_combine_correctly() {
        let record: Vec<u8> = (0..30u8).collect();
        let mut r = Reassembly::new(10_000, 1000);
        assert_eq!(r.insert(C, 7, fin(19), &record[19..]), Insert::Incomplete);
        assert_eq!(
            r.insert(C, 7, mid(0), &record[..29]),
            Insert::Complete(record.clone())
        );
        // Overlapping plans of any shape.
        assert_eq!(r.insert(C, 8, mid(10), &record[10..25]), Insert::Incomplete);
        assert_eq!(r.insert(C, 8, fin(20), &record[20..]), Insert::Incomplete);
        assert_eq!(
            r.insert(C, 8, mid(0), &record[..12]),
            Insert::Complete(record)
        );
    }

    #[test]
    fn rejects_invalid() {
        let mut r = Reassembly::new(10_000, 10);
        assert_eq!(r.insert(C, 0, mid(0), b""), Insert::Invalid);
        assert_eq!(
            r.insert(C, 0, mid(10), b"a"),
            Insert::Invalid,
            "beyond limit"
        );
        assert_eq!(r.insert(C, 0, mid(u64::MAX), b"a"), Insert::Invalid);
        assert_eq!(r.insert(C, 0, None, &[0; 11]), Insert::Invalid);
        assert_eq!(r.insert(C, 1, mid(0), b"abc"), Insert::Incomplete);
        assert_eq!(
            r.insert(C, 1, fin(1), b"x"),
            Insert::Invalid,
            "ends before held data"
        );
        assert_eq!(
            r.insert(C, 1, fin(3), b"de"),
            Insert::Complete(b"abcde".to_vec())
        );
        assert_eq!(r.insert(C, 2, fin(3), b"de"), Insert::Incomplete);
        assert_eq!(
            r.insert(C, 2, fin(2), b"de"),
            Insert::Invalid,
            "second, different end"
        );
        assert_eq!(
            r.insert(C, 2, mid(3), b"de"),
            Insert::Invalid,
            "middle reaching the end"
        );
    }

    #[test]
    fn evicts_lru_when_full() {
        let cost = 10 + PARTIAL_OVERHEAD;
        let mut r = Reassembly::new(2 * cost, 1000);
        assert_eq!(r.insert(C, 0, mid(0), &[1; 10]), Insert::Incomplete);
        assert_eq!(r.insert(C, 1, mid(0), &[2; 10]), Insert::Incomplete);
        // Seq 2 evicts seq 0 (oldest).
        assert_eq!(r.insert(C, 2, mid(0), &[3; 10]), Insert::Incomplete);
        assert_eq!(r.insert(C, 0, mid(0), &[1; 10]), Insert::Incomplete);
        assert!(r.total_bytes() <= 2 * cost);
        // Larger than the whole table: dropped.
        assert_eq!(r.insert(C, 3, mid(0), &[0; 900]), Insert::NoRoom);
    }
}
