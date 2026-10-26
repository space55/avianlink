use alloc::vec::Vec;

use super::{put_varint, varint_len, DecodeError, Reader};

/// Flag bit 0: a timestamp follows the Lamport value.
pub const FLAG_TIMESTAMP: u64 = 1 << 0;
/// Flag bit 1: an extension block follows.
pub const FLAG_EXTENSIONS: u64 = 1 << 1;
/// Timestamp epoch: 2025-01-01T00:00:00Z, in Unix seconds.
pub const TIMESTAMP_EPOCH_UNIX_SECS: u64 = 1_735_689_600;

/// A decoded message record (the plaintext of a message).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    /// Per-conversation Lamport clock value.
    pub lamport: u64,
    /// Sender wall clock, seconds since [`TIMESTAMP_EPOCH_UNIX_SECS`].
    pub timestamp: Option<u64>,
    /// Message body.
    pub text: &'a str,
}

/// Encoded length of `rec`.
pub fn record_len(rec: &Record<'_>) -> usize {
    let ts = rec.timestamp.map_or(0, varint_len);
    1usize
        .saturating_add(varint_len(rec.lamport))
        .saturating_add(ts)
        .saturating_add(rec.text.len())
}

/// Appends the encoding of `rec`. Never writes extensions.
pub fn encode_record(out: &mut Vec<u8>, rec: &Record<'_>) {
    let flags = if rec.timestamp.is_some() {
        FLAG_TIMESTAMP
    } else {
        0
    };
    put_varint(out, flags);
    put_varint(out, rec.lamport);
    if let Some(ts) = rec.timestamp {
        put_varint(out, ts);
    }
    out.extend_from_slice(rec.text.as_bytes());
}

/// Decodes a record, skipping any extension block. Reserved flag bits are
/// ignored.
pub fn decode_record(bytes: &[u8], max_text_len: usize) -> Result<Record<'_>, DecodeError> {
    let mut r = Reader::new(bytes);
    let flags = r.varint()?;
    let lamport = r.varint()?;
    let timestamp = if flags & FLAG_TIMESTAMP != 0 {
        Some(r.varint()?)
    } else {
        None
    };
    if flags & FLAG_EXTENSIONS != 0 {
        let len = r.varint_usize()?;
        r.bytes(len)?;
    }
    let text = r.rest();
    if text.len() > max_text_len {
        return Err(DecodeError::TextTooLong);
    }
    let text = core::str::from_utf8(text).map_err(|_| DecodeError::InvalidUtf8)?;
    Ok(Record {
        lamport,
        timestamp,
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_extensions_skipped() {
        let rec = Record {
            lamport: 300,
            timestamp: Some(57_000_000),
            text: "héllo",
        };
        let mut out = Vec::new();
        encode_record(&mut out, &rec);
        assert_eq!(out.len(), record_len(&rec));
        assert_eq!(decode_record(&out, 100), Ok(rec));
        assert_eq!(decode_record(&out, 3), Err(DecodeError::TextTooLong));

        // A future sender with an extension block and a reserved flag bit.
        let mut fut = Vec::new();
        put_varint(&mut fut, FLAG_EXTENSIONS | (1 << 5));
        put_varint(&mut fut, 1);
        put_varint(&mut fut, 3);
        fut.extend_from_slice(&[1, 1, 0xaa]);
        fut.extend_from_slice(b"hi");
        let dec = decode_record(&fut, 100).unwrap();
        assert_eq!((dec.lamport, dec.timestamp, dec.text), (1, None, "hi"));
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_eq!(
            decode_record(&[0, 0, 0xff], 10),
            Err(DecodeError::InvalidUtf8)
        );
    }
}
