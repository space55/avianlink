use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Durable key-value storage implemented by the host.
///
/// The engine groups every set of related writes in a batch:
/// `begin`, then `store`/`remove` calls, then `commit`. On any error inside
/// a batch it calls `rollback`. Batches do not nest. The engine never reads
/// inside a batch.
///
/// **Contract.** After `commit` returns `Ok`, all writes of the batch are
/// durable together. After a crash, or after `rollback`, none of them are
/// visible. "Sent" in avianlink means "committed here"
/// (`docs/reliability.md` §4).
pub trait Storage {
    /// Host-specific failure type.
    type Error: core::fmt::Debug;

    /// Returns the committed value under `key`, if any.
    fn load(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Calls `f(key, value)` for every committed key starting with
    /// `prefix`, in ascending key order.
    fn scan_prefix(
        &mut self,
        prefix: &[u8],
        f: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), Self::Error>;

    /// Starts a batch.
    fn begin(&mut self) -> Result<(), Self::Error>;

    /// Stores `value` under `key` within the current batch.
    fn store(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;

    /// Removes `key` within the current batch. Removing a missing key is
    /// not an error.
    fn remove(&mut self, key: &[u8]) -> Result<(), Self::Error>;

    /// Makes the batch durable, atomically.
    fn commit(&mut self) -> Result<(), Self::Error>;

    /// Discards the batch.
    fn rollback(&mut self);
}

/// Writes staged by an open batch: `Some(value)` stores, `None` removes.
type Batch = Vec<(Vec<u8>, Option<Vec<u8>>)>;

/// In-memory [`Storage`] for tests and the simulator. Batches are atomic.
/// Durability lasts as long as the value does: clone it to snapshot the
/// state a crash would leave behind.
#[derive(Clone, Debug, Default)]
pub struct MemoryStorage {
    committed: BTreeMap<Vec<u8>, Vec<u8>>,
    pending: Option<Batch>,
    /// Fail the operation after this many more successful writes/commits.
    fail_after: Option<u32>,
    commits: u64,
}

/// Error from [`MemoryStorage`]: an injected fault or a misuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryStorageError {
    /// Injected by [`MemoryStorage::fail_after`].
    Injected,
    /// `store`/`remove`/`commit` outside a batch, or nested `begin`.
    NotInBatch,
}

impl MemoryStorage {
    /// Creates empty storage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of committed entries.
    pub fn len(&self) -> usize {
        self.committed.len()
    }

    /// Whether no entries are committed.
    pub fn is_empty(&self) -> bool {
        self.committed.is_empty()
    }

    /// Total committed key and value bytes.
    pub fn bytes(&self) -> usize {
        self.committed.iter().fold(0usize, |n, (k, v)| {
            n.saturating_add(k.len()).saturating_add(v.len())
        })
    }

    /// Batches committed so far.
    pub fn commits(&self) -> u64 {
        self.commits
    }

    /// Makes the write or commit after the next `n` successful ones fail,
    /// once. `None` clears it.
    pub fn fail_after(&mut self, n: Option<u32>) {
        self.fail_after = n;
    }

    /// What a crash right now would leave behind: committed state only.
    pub fn crash_snapshot(&self) -> Self {
        Self {
            committed: self.committed.clone(),
            pending: None,
            fail_after: None,
            commits: self.commits,
        }
    }

    fn tick(&mut self) -> Result<(), MemoryStorageError> {
        match self.fail_after {
            Some(0) => {
                self.fail_after = None;
                Err(MemoryStorageError::Injected)
            }
            Some(n) => {
                self.fail_after = Some(n.saturating_sub(1));
                Ok(())
            }
            None => Ok(()),
        }
    }

    fn push(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<(), MemoryStorageError> {
        self.tick()?;
        self.pending
            .as_mut()
            .ok_or(MemoryStorageError::NotInBatch)?
            .push((key.to_vec(), value.map(<[u8]>::to_vec)));
        Ok(())
    }
}

impl Storage for MemoryStorage {
    type Error = MemoryStorageError;

    fn load(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.committed.get(key).cloned())
    }

    fn scan_prefix(
        &mut self,
        prefix: &[u8],
        f: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), Self::Error> {
        self.committed
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .for_each(|(k, v)| f(k, v));
        Ok(())
    }

    fn begin(&mut self) -> Result<(), Self::Error> {
        if self.pending.is_some() {
            return Err(MemoryStorageError::NotInBatch);
        }
        self.pending = Some(Vec::new());
        Ok(())
    }

    fn store(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.push(key, Some(value))
    }

    fn remove(&mut self, key: &[u8]) -> Result<(), Self::Error> {
        self.push(key, None)
    }

    fn commit(&mut self) -> Result<(), Self::Error> {
        self.tick()?;
        let ops = self.pending.take().ok_or(MemoryStorageError::NotInBatch)?;
        for (k, v) in ops {
            match v {
                Some(v) => {
                    self.committed.insert(k, v);
                }
                None => {
                    self.committed.remove(&k);
                }
            }
        }
        self.commits = self.commits.saturating_add(1);
        Ok(())
    }

    fn rollback(&mut self) {
        self.pending = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(s: &mut MemoryStorage, prefix: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        s.scan_prefix(prefix, &mut |k, _| out.push(k.to_vec()))
            .unwrap();
        out
    }

    #[test]
    fn batches_are_atomic() {
        let mut s = MemoryStorage::new();
        s.begin().unwrap();
        s.store(b"a1", b"x").unwrap();
        s.store(b"a2", b"y").unwrap();
        assert_eq!(s.load(b"a1").unwrap(), None);
        assert!(s.crash_snapshot().is_empty());
        s.commit().unwrap();
        assert_eq!(keys(&mut s, b"a"), [b"a1".to_vec(), b"a2".to_vec()]);

        s.begin().unwrap();
        s.remove(b"a1").unwrap();
        s.rollback();
        assert_eq!(s.load(b"a1").unwrap().as_deref(), Some(&b"x"[..]));
    }

    #[test]
    fn injected_failure_and_misuse() {
        let mut s = MemoryStorage::new();
        assert_eq!(s.store(b"k", b"v"), Err(MemoryStorageError::NotInBatch));
        s.fail_after(Some(1));
        s.begin().unwrap();
        s.store(b"k", b"v").unwrap();
        assert_eq!(s.commit(), Err(MemoryStorageError::Injected));
        s.rollback();
        assert!(s.is_empty());
    }

    #[test]
    fn prefix_scan_is_bounded_and_ordered() {
        let mut s = MemoryStorage::new();
        s.begin().unwrap();
        for k in [&b"b"[..], b"ab", b"a", b"aa", b"ba"] {
            s.store(k, b"").unwrap();
        }
        s.commit().unwrap();
        assert_eq!(
            keys(&mut s, b"a"),
            [b"a".to_vec(), b"aa".to_vec(), b"ab".to_vec()]
        );
        assert_eq!(keys(&mut s, b"").len(), 5);
    }
}
