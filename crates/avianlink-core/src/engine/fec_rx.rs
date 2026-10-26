//! Receiver side of FEC: recent source plaintexts and pending repairs
//! (`docs/reliability.md` §6). Bounded in bytes and in repair count.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::fec;
use crate::wire::RepairFrame;
use crate::ConversationId;

/// Accounting overhead per stored symbol, on top of its bytes.
const ENTRY_OVERHEAD: usize = 48;

/// A window's identity: first counter, source mask, repair count.
pub(super) type Window = (u64, u64, usize);

#[derive(Debug)]
struct PendingRepair {
    conv: ConversationId,
    window: Window,
    j: usize,
    data: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct FecRx {
    /// (conversation, counter) → (insertion order, plaintext).
    symbols: BTreeMap<(ConversationId, u64), (u64, Vec<u8>)>,
    order: u64,
    bytes: usize,
    limit: usize,
    repairs: VecDeque<PendingRepair>,
    max_repairs: usize,
}

fn covers(window: &Window, counter: u64) -> bool {
    let (base, mask, _) = *window;
    counter
        .checked_sub(base)
        .filter(|&d| d < 32)
        .is_some_and(|d| mask & (1u64 << d) != 0)
}

fn sources(window: &Window) -> Vec<u64> {
    let (base, mask, _) = *window;
    (0..32u64)
        .filter(|i| mask & (1u64 << i) != 0)
        .filter_map(|i| base.checked_add(i))
        .collect()
}

impl FecRx {
    pub(super) fn new(limit: usize, max_repairs: usize) -> Self {
        Self {
            symbols: BTreeMap::new(),
            order: 0,
            bytes: 0,
            limit,
            repairs: VecDeque::new(),
            max_repairs,
        }
    }

    /// Remembers a received (or recovered) source, evicting the oldest
    /// symbols beyond the byte limit.
    pub(super) fn store(&mut self, conv: ConversationId, counter: u64, plain: &[u8]) {
        let cost = plain.len().saturating_add(ENTRY_OVERHEAD);
        if cost > self.limit {
            return;
        }
        self.remove_symbol(&(conv, counter));
        self.order = self.order.saturating_add(1);
        self.symbols
            .insert((conv, counter), (self.order, plain.to_vec()));
        self.bytes = self.bytes.saturating_add(cost);
        while self.bytes > self.limit {
            let oldest = self
                .symbols
                .iter()
                .min_by_key(|(_, (order, _))| *order)
                .map(|(k, _)| *k);
            match oldest {
                Some(k) => self.remove_symbol(&k),
                None => break,
            }
        }
    }

    fn remove_symbol(&mut self, key: &(ConversationId, u64)) {
        if let Some((_, v)) = self.symbols.remove(key) {
            self.bytes = self
                .bytes
                .saturating_sub(v.len().saturating_add(ENTRY_OVERHEAD));
        }
    }

    /// Queues a repair; returns its window, or `None` if the frame is
    /// invalid.
    pub(super) fn add_repair(
        &mut self,
        conv: ConversationId,
        r: &RepairFrame<'_>,
    ) -> Option<Window> {
        r.sources()?;
        let (m, j) = r.m_j();
        let window = (r.base, r.mask, m);
        let dup = self
            .repairs
            .iter()
            .any(|p| p.conv == conv && p.window == window && p.j == j);
        if !dup {
            self.repairs.push_back(PendingRepair {
                conv,
                window,
                j,
                data: r.data.to_vec(),
            });
            while self.repairs.len() > self.max_repairs {
                self.repairs.pop_front();
            }
        }
        Some(window)
    }

    /// Windows with pending repairs that include `counter`.
    pub(super) fn windows_with(&self, conv: ConversationId, counter: u64) -> Vec<Window> {
        let mut out: Vec<Window> = Vec::new();
        for p in &self.repairs {
            if p.conv == conv && covers(&p.window, counter) && !out.contains(&p.window) {
                out.push(p.window);
            }
        }
        out
    }

    /// Decodes `window` if enough repairs are in. Returns the recovered
    /// `(counter, plaintext)` pairs (zero-padded). Repairs of a window that
    /// decodes, or turns out to need nothing, are dropped.
    pub(super) fn try_window(
        &mut self,
        conv: ConversationId,
        window: Window,
    ) -> Vec<(u64, Vec<u8>)> {
        let (_, _, m) = window;
        let counters = sources(&window);
        let missing: Vec<usize> = (0..counters.len())
            .filter(|&i| {
                counters
                    .get(i)
                    .is_some_and(|c| !self.symbols.contains_key(&(conv, *c)))
            })
            .collect();
        let have = self
            .repairs
            .iter()
            .filter(|p| p.conv == conv && p.window == window)
            .count();
        if have == 0 || missing.len() > have {
            return Vec::new();
        }
        let mut recovered = Vec::new();
        if !missing.is_empty() {
            let known: Vec<(usize, &[u8])> = counters
                .iter()
                .enumerate()
                .filter_map(|(i, c)| self.symbols.get(&(conv, *c)).map(|(_, s)| (i, &s[..])))
                .collect();
            let reps: Vec<(usize, &[u8])> = self
                .repairs
                .iter()
                .filter(|p| p.conv == conv && p.window == window)
                .map(|p| (p.j, &p.data[..]))
                .collect();
            if let Some(syms) = fec::decode(m, &known, &reps, &missing) {
                recovered = missing
                    .iter()
                    .zip(syms)
                    .filter_map(|(&i, s)| counters.get(i).map(|&c| (c, s)))
                    .collect();
            }
        }
        self.repairs
            .retain(|p| !(p.conv == conv && p.window == window));
        recovered
    }

    pub(super) fn discard_conversation(&mut self, conv: ConversationId) {
        let keys: Vec<_> = self
            .symbols
            .range((conv, 0)..=(conv, u64::MAX))
            .map(|(k, _)| *k)
            .collect();
        keys.iter().for_each(|k| self.remove_symbol(k));
        self.repairs.retain(|p| p.conv != conv);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: ConversationId = ConversationId([9; 16]);

    #[test]
    fn recovers_a_missing_source_from_xor_repair() {
        let mut rx = FecRx::new(10_000, 8);
        let srcs: [&[u8]; 3] = [b"one", b"two!", b"3"];
        let rep = fec::encode(&srcs, 1).remove(0);
        rx.store(C, 10, srcs[0]);
        rx.store(C, 12, srcs[2]);
        let frame = RepairFrame {
            base: 10,
            mask: 0b111,
            shape: 0,
            data: &rep,
        };
        let w = rx.add_repair(C, &frame).unwrap();
        assert_eq!(rx.windows_with(C, 11), [w]);
        let got = rx.try_window(C, w);
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].0, &got[0].1[..4]), (11, &b"two!"[..]));
        assert!(rx.windows_with(C, 11).is_empty(), "repairs consumed");
    }

    #[test]
    fn waits_for_enough_repairs_and_bounds_memory() {
        let mut rx = FecRx::new(200, 2);
        let srcs: [&[u8]; 2] = [b"aa", b"bb"];
        let rep = fec::encode(&srcs, 1).remove(0);
        let frame = RepairFrame {
            base: 0,
            mask: 0b11,
            shape: 0,
            data: &rep,
        };
        let w = rx.add_repair(C, &frame).unwrap();
        assert!(rx.try_window(C, w).is_empty(), "two missing, one repair");
        for i in 0..20 {
            rx.store(C, 100 + i, &[0u8; 40]);
        }
        assert!(rx.bytes <= 200);
        for b in 0..5 {
            rx.add_repair(
                C,
                &RepairFrame {
                    base: 50 + b,
                    ..frame
                },
            );
        }
        assert!(rx.repairs.len() <= 2);
        rx.discard_conversation(C);
        assert_eq!((rx.symbols.len(), rx.repairs.len(), rx.bytes), (0, 0, 0));
    }
}
