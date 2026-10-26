use alloc::vec::Vec;

use super::{DecodeError, Reader};

/// Longest valid varint encoding.
pub const MAX_VARINT_LEN: usize = 10;

const SHIFTS: [u32; MAX_VARINT_LEN] = [0, 7, 14, 21, 28, 35, 42, 49, 56, 63];

/// Encoded length of `v`, in bytes (1..=10).
pub fn varint_len(v: u64) -> usize {
    let bits = u64::BITS.saturating_sub(v.leading_zeros());
    match bits.div_ceil(7) {
        0 => 1,
        // At most 10, so the conversion cannot fail.
        n => usize::try_from(n).unwrap_or(MAX_VARINT_LEN),
    }
}

/// Appends the canonical LEB128 encoding of `v`.
pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let low = (v & 0x7f) as u8;
        v = v.wrapping_shr(7);
        if v == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

impl Reader<'_> {
    /// Reads a canonical varint.
    pub fn varint(&mut self) -> Result<u64, DecodeError> {
        let mut value = 0u64;
        for (i, &shift) in SHIFTS.iter().enumerate() {
            let b = self.u8()?;
            if i == MAX_VARINT_LEN - 1 && b > 1 {
                return Err(DecodeError::VarintOverflow);
            }
            value |= u64::from(b & 0x7f).wrapping_shl(shift);
            if b & 0x80 == 0 {
                if b == 0 && i != 0 {
                    return Err(DecodeError::VarintNonCanonical);
                }
                return Ok(value);
            }
        }
        Err(DecodeError::VarintOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint(&mut out, v);
        out
    }

    #[test]
    fn known_encodings() {
        assert_eq!(enc(0), [0x00]);
        assert_eq!(enc(127), [0x7f]);
        assert_eq!(enc(128), [0x80, 0x01]);
        assert_eq!(enc(300), [0xac, 0x02]);
        assert_eq!(enc(u64::MAX).len(), 10);
        for v in [0, 1, 127, 128, 16383, 16384, u64::MAX] {
            assert_eq!(enc(v).len(), varint_len(v));
        }
    }

    #[test]
    fn rejects_bad_encodings() {
        let dec = |b: &[u8]| Reader::new(b).varint();
        assert_eq!(dec(&[0x80, 0x00]), Err(DecodeError::VarintNonCanonical));
        assert_eq!(dec(&[0x80]), Err(DecodeError::Truncated));
        assert_eq!(dec(&[]), Err(DecodeError::Truncated));
        let mut too_big = [0xffu8; 10];
        too_big[9] = 0x02;
        assert_eq!(dec(&too_big), Err(DecodeError::VarintOverflow));
        assert_eq!(dec(&[0xff; 11]), Err(DecodeError::VarintOverflow));
        let mut max = [0xffu8; 10];
        max[9] = 0x01;
        assert_eq!(dec(&max), Ok(u64::MAX));
    }
}
