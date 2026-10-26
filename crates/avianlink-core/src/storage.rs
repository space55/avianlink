use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::convert::Infallible;

/// Durable key-value storage implemented by the host.
///
/// The engine persists its outbox and counters here. A `store` that returns
/// `Ok` must be durable: "sent" in avianlink means "durably queued".
///
/// The interface is provisional; Phase 2 will add prefix iteration and
/// decide on atomic batches.
pub trait Storage {
    /// Host-specific failure type.
    type Error: core::fmt::Debug;

    /// Returns the value stored under `key`, if any.
    fn load(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Durably stores `value` under `key`, replacing any previous value.
    fn store(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;

    /// Removes `key`. Removing a missing key is not an error.
    fn remove(&mut self, key: &[u8]) -> Result<(), Self::Error>;
}

/// In-memory [`Storage`] for tests and the simulator. Not durable.
#[derive(Clone, Debug, Default)]
pub struct MemoryStorage {
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl MemoryStorage {
    /// Creates empty storage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether storage is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Storage for MemoryStorage {
    type Error = Infallible;

    fn load(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.entries.get(key).cloned())
    }

    fn store(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.entries.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn remove(&mut self, key: &[u8]) -> Result<(), Self::Error> {
        self.entries.remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_storage_round_trip() {
        let mut s = MemoryStorage::new();
        assert_eq!(s.load(b"k").unwrap(), None);
        s.store(b"k", b"v").unwrap();
        assert_eq!(s.load(b"k").unwrap().as_deref(), Some(&b"v"[..]));
        s.remove(b"k").unwrap();
        s.remove(b"k").unwrap();
        assert!(s.is_empty());
    }
}
