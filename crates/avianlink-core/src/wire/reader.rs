use super::DecodeError;

/// Bounds-checked cursor over untrusted bytes. Every accessor fails instead
/// of panicking when the input runs out.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Wraps `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len()
    }

    /// Whether all input has been consumed.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Reads one byte.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        let (&b, rest) = self.buf.split_first().ok_or(DecodeError::Truncated)?;
        self.buf = rest;
        Ok(b)
    }

    /// Reads exactly `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let (head, rest) = self.buf.split_at_checked(n).ok_or(DecodeError::Truncated)?;
        self.buf = rest;
        Ok(head)
    }

    /// Reads a fixed-size array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)
    }

    /// Consumes and returns everything left.
    pub fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.buf)
    }

    /// Reads a varint that must fit in `usize`.
    pub fn varint_usize(&mut self) -> Result<usize, DecodeError> {
        usize::try_from(self.varint()?).map_err(|_| DecodeError::TooLarge)
    }
}
