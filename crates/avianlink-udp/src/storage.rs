//! `FileStorage`: a write-ahead log in one file (`docs/hosting.md` §2).

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use avianlink_core::wire::{put_varint, Reader};
use avianlink_core::Storage;
use sha2::{Digest, Sha256};

const LOG: &str = "state.log";
const TMP: &str = "state.log.tmp";
const HEADER: usize = 4 + 8;
/// Sanity bound on one record; a larger length is corruption.
const MAX_RECORD: usize = 64 << 20;

type Op = (Vec<u8>, Option<Vec<u8>>);

/// Durable, atomic [`Storage`] backed by an append-only log file.
#[derive(Debug)]
pub struct FileStorage {
    dir: PathBuf,
    file: File,
    map: BTreeMap<Vec<u8>, Vec<u8>>,
    pending: Option<Vec<Op>>,
    log_len: u64,
}

/// Error from [`FileStorage`].
#[derive(Debug)]
pub enum FileStorageError {
    /// The file system failed.
    Io(io::Error),
    /// `store`/`remove`/`commit` outside a batch, or a nested `begin`.
    NotInBatch,
}

impl From<io::Error> for FileStorageError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

fn check(payload: &[u8]) -> [u8; 8] {
    let d = Sha256::digest(payload);
    let mut c = [0u8; 8];
    c.copy_from_slice(&d[..8]);
    c
}

fn encode_record(ops: &[Op]) -> Vec<u8> {
    let mut payload = Vec::new();
    for (k, v) in ops {
        match v {
            Some(v) => {
                payload.push(1);
                put_varint(&mut payload, k.len() as u64);
                payload.extend_from_slice(k);
                put_varint(&mut payload, v.len() as u64);
                payload.extend_from_slice(v);
            }
            None => {
                payload.push(2);
                put_varint(&mut payload, k.len() as u64);
                payload.extend_from_slice(k);
            }
        }
    }
    let mut rec = Vec::with_capacity(HEADER + payload.len());
    rec.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    rec.extend_from_slice(&check(&payload));
    rec.extend_from_slice(&payload);
    rec
}

fn decode_ops(payload: &[u8]) -> Option<Vec<Op>> {
    let mut r = Reader::new(payload);
    let mut ops = Vec::new();
    while !r.is_empty() {
        let op = r.u8().ok()?;
        let klen = r.varint_usize().ok()?;
        let k = r.bytes(klen).ok()?.to_vec();
        match op {
            1 => {
                let vlen = r.varint_usize().ok()?;
                ops.push((k, Some(r.bytes(vlen).ok()?.to_vec())));
            }
            2 => ops.push((k, None)),
            _ => return None,
        }
    }
    Some(ops)
}

/// Replays complete, valid records; returns the map and the length of the
/// valid prefix.
fn replay(bytes: &[u8]) -> (BTreeMap<Vec<u8>, Vec<u8>>, u64) {
    let mut map = BTreeMap::new();
    let mut pos = 0usize;
    while let Some(header) = bytes.get(pos..pos + HEADER) {
        let len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        if len > MAX_RECORD {
            break;
        }
        let Some(payload) = bytes.get(pos + HEADER..pos + HEADER + len) else {
            break;
        };
        if check(payload) != header[4..12] {
            break;
        }
        let Some(ops) = decode_ops(payload) else {
            break;
        };
        for (k, v) in ops {
            match v {
                Some(v) => map.insert(k, v),
                None => map.remove(&k),
            };
        }
        pos += HEADER + len;
    }
    (map, pos as u64)
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

impl FileStorage {
    /// Opens (creating if needed) the storage in `dir`. A torn final record
    /// from a crash is discarded.
    pub fn open(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        // A leftover temp file means a crash during compaction, before the
        // rename: the old log is still authoritative.
        let _ = fs::remove_file(dir.join(TMP));
        let path = dir.join(LOG);
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let (map, valid) = replay(&bytes);
        if valid < bytes.len() as u64 {
            file.set_len(valid)?;
            file.sync_all()?;
        }
        Ok(Self {
            dir,
            file,
            map,
            pending: None,
            log_len: valid,
        })
    }

    /// Bytes of live keys and values.
    pub fn live_bytes(&self) -> u64 {
        self.map
            .iter()
            .map(|(k, v)| (k.len() + v.len()) as u64)
            .sum()
    }

    /// Size of the log file.
    pub fn log_bytes(&self) -> u64 {
        self.log_len
    }

    /// Rewrites the log as one record holding the live state.
    pub fn compact(&mut self) -> io::Result<()> {
        let ops: Vec<Op> = self
            .map
            .iter()
            .map(|(k, v)| (k.clone(), Some(v.clone())))
            .collect();
        let rec = encode_record(&ops);
        let tmp = self.dir.join(TMP);
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&rec)?;
        f.sync_all()?;
        fs::rename(&tmp, self.dir.join(LOG))?;
        sync_dir(&self.dir)?;
        self.file = OpenOptions::new().append(true).open(self.dir.join(LOG))?;
        self.log_len = rec.len() as u64;
        Ok(())
    }
}

impl Storage for FileStorage {
    type Error = FileStorageError;

    fn load(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.map.get(key).cloned())
    }

    fn scan_prefix(
        &mut self,
        prefix: &[u8],
        f: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), Self::Error> {
        self.map
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .for_each(|(k, v)| f(k, v));
        Ok(())
    }

    fn begin(&mut self) -> Result<(), Self::Error> {
        if self.pending.is_some() {
            return Err(FileStorageError::NotInBatch);
        }
        self.pending = Some(Vec::new());
        Ok(())
    }

    fn store(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.pending
            .as_mut()
            .ok_or(FileStorageError::NotInBatch)?
            .push((key.to_vec(), Some(value.to_vec())));
        Ok(())
    }

    fn remove(&mut self, key: &[u8]) -> Result<(), Self::Error> {
        self.pending
            .as_mut()
            .ok_or(FileStorageError::NotInBatch)?
            .push((key.to_vec(), None));
        Ok(())
    }

    fn commit(&mut self) -> Result<(), Self::Error> {
        let ops = self.pending.take().ok_or(FileStorageError::NotInBatch)?;
        let rec = encode_record(&ops);
        self.file.write_all(&rec)?;
        self.file.sync_data()?;
        self.log_len += rec.len() as u64;
        for (k, v) in ops {
            match v {
                Some(v) => self.map.insert(k, v),
                None => self.map.remove(&k),
            };
        }
        if self.log_len > 4 * self.live_bytes() + 64 * 1024 {
            self.compact()?;
        }
        Ok(())
    }

    fn rollback(&mut self) {
        self.pending = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("avianlink-fs-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn batch(s: &mut FileStorage, ops: &[(&[u8], Option<&[u8]>)]) {
        s.begin().unwrap();
        for (k, v) in ops {
            match v {
                Some(v) => s.store(k, v).unwrap(),
                None => s.remove(k).unwrap(),
            }
        }
        s.commit().unwrap();
    }

    #[test]
    fn persists_across_reopen() {
        let d = tmpdir("reopen");
        let mut s = FileStorage::open(&d).unwrap();
        batch(&mut s, &[(b"a", Some(b"1")), (b"b", Some(b"2"))]);
        batch(&mut s, &[(b"a", None), (b"c", Some(b"3"))]);
        s.begin().unwrap();
        s.store(b"never", b"x").unwrap();
        s.rollback();
        drop(s);
        let mut s = FileStorage::open(&d).unwrap();
        assert_eq!(s.load(b"a").unwrap(), None);
        assert_eq!(s.load(b"b").unwrap(), Some(b"2".to_vec()));
        assert_eq!(s.load(b"c").unwrap(), Some(b"3".to_vec()));
        assert_eq!(s.load(b"never").unwrap(), None);
        let _ = fs::remove_dir_all(&d);
    }

    /// A crash mid-append leaves a torn record: every truncation point of
    /// the last batch must reopen to the state before that batch, or after.
    #[test]
    fn torn_tail_is_atomic() {
        let d = tmpdir("torn");
        let mut s = FileStorage::open(&d).unwrap();
        batch(&mut s, &[(b"k1", Some(b"before"))]);
        let before = s.log_bytes();
        batch(&mut s, &[(b"k1", Some(b"after")), (b"k2", Some(b"after"))]);
        let after = s.log_bytes();
        drop(s);
        let full = fs::read(d.join(LOG)).unwrap();
        for cut in before..=after {
            fs::write(d.join(LOG), &full[..cut as usize]).unwrap();
            let mut s = FileStorage::open(&d).unwrap();
            let k1 = s.load(b"k1").unwrap();
            let k2 = s.load(b"k2").unwrap();
            if cut == after {
                assert_eq!(
                    (k1.as_deref(), k2.as_deref()),
                    (Some(&b"after"[..]), Some(&b"after"[..]))
                );
            } else {
                assert_eq!(
                    (k1.as_deref(), k2),
                    (Some(&b"before"[..]), None),
                    "cut {cut}"
                );
                assert_eq!(s.log_bytes(), before, "tail truncated");
            }
        }
        // A flipped byte inside the last record also discards it.
        let mut bad = full.clone();
        bad[(after - 1) as usize] ^= 1;
        fs::write(d.join(LOG), &bad).unwrap();
        let mut s = FileStorage::open(&d).unwrap();
        assert_eq!(s.load(b"k2").unwrap(), None);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn compaction_preserves_state_and_bounds_the_log() {
        let d = tmpdir("compact");
        let mut s = FileStorage::open(&d).unwrap();
        for i in 0..1_000u32 {
            batch(
                &mut s,
                &[
                    (b"counter", Some(&i.to_le_bytes())),
                    (b"big", Some(&[7u8; 100])),
                ],
            );
        }
        assert!(s.log_bytes() < 4 * s.live_bytes() + 64 * 1024 + 1024);
        drop(s);
        // A stale temp file from a crash mid-compaction is ignored.
        fs::write(d.join(TMP), b"garbage").unwrap();
        let mut s = FileStorage::open(&d).unwrap();
        assert_eq!(
            s.load(b"counter").unwrap(),
            Some(999u32.to_le_bytes().to_vec())
        );
        assert!(!d.join(TMP).exists());
        let _ = fs::remove_dir_all(&d);
    }
}
