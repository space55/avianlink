use alloc::vec::Vec;

use super::{put_varint, varint_len, DecodeError, Reader};

/// PADDING frame type; body ignored.
pub const FRAME_PADDING: u64 = 0x00;
/// MSG frame type: a message fragment.
pub const FRAME_MSG: u64 = 0x01;
/// ACK frame type: selective acknowledgement.
pub const FRAME_ACK: u64 = 0x02;

/// A message fragment. Semantic validity (`count >= 1`, `index < count`) is
/// the caller's to check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsgFrame<'a> {
    /// Sender's per-conversation sequence number.
    pub seq: u64,
    /// Total fragments.
    pub count: u64,
    /// This fragment's index (0 when `count == 1`).
    pub index: u64,
    /// Fragment bytes.
    pub data: &'a [u8],
}

/// A selective acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckFrame<'a> {
    /// Every seq below this has been received.
    pub cum: u64,
    /// Bit `i` set: seq `cum + 1 + i` received.
    pub bitmap: &'a [u8],
}

impl AckFrame<'_> {
    /// Whether this ACK covers `seq`.
    pub fn covers(&self, seq: u64) -> bool {
        if seq < self.cum {
            return true;
        }
        let Some(offset) = seq.checked_sub(self.cum).and_then(|d| d.checked_sub(1)) else {
            return false;
        };
        let Ok(offset) = usize::try_from(offset) else {
            return false;
        };
        self.bitmap
            .get(offset / 8)
            .is_some_and(|byte| byte & (1u8 << (offset % 8)) != 0)
    }

    /// One past the highest seq the bitmap can describe.
    pub fn horizon(&self) -> u64 {
        let bits = u64::try_from(self.bitmap.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(8);
        self.cum.saturating_add(1).saturating_add(bits)
    }
}

/// A decoded frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    /// Ignored filler.
    Padding,
    /// Message fragment.
    Msg(MsgFrame<'a>),
    /// Acknowledgement.
    Ack(AckFrame<'a>),
    /// A frame type this version does not know; skipped.
    Unknown {
        /// The unknown type.
        frame_type: u64,
    },
}

/// Iterator over the frames of a packet. Yields an error at most once, then
/// stops.
#[derive(Clone, Debug)]
pub struct Frames<'a> {
    r: Reader<'a>,
    failed: bool,
}

impl<'a> Frames<'a> {
    /// Iterates over the frames in `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            r: Reader::new(buf),
            failed: false,
        }
    }

    fn next_frame(&mut self) -> Result<Frame<'a>, DecodeError> {
        let frame_type = self.r.varint()?;
        let len = self.r.varint_usize()?;
        let body = self.r.bytes(len)?;
        let mut b = Reader::new(body);
        Ok(match frame_type {
            FRAME_PADDING => Frame::Padding,
            FRAME_MSG => {
                let seq = b.varint()?;
                let count = b.varint()?;
                let index = if count > 1 { b.varint()? } else { 0 };
                Frame::Msg(MsgFrame {
                    seq,
                    count,
                    index,
                    data: b.rest(),
                })
            }
            FRAME_ACK => {
                let cum = b.varint()?;
                Frame::Ack(AckFrame {
                    cum,
                    bitmap: b.rest(),
                })
            }
            frame_type => Frame::Unknown { frame_type },
        })
    }
}

impl<'a> Iterator for Frames<'a> {
    type Item = Result<Frame<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.r.is_empty() {
            return None;
        }
        let item = self.next_frame();
        self.failed = item.is_err();
        Some(item)
    }
}

/// Checks that every frame in `buf` is structurally valid.
pub fn validate_frames(buf: &[u8]) -> Result<(), DecodeError> {
    Frames::new(buf).try_for_each(|f| f.map(|_| ()))
}

fn frame_len(frame_type: u64, body_len: usize) -> usize {
    let len_len = varint_len(u64::try_from(body_len).unwrap_or(u64::MAX));
    varint_len(frame_type)
        .saturating_add(len_len)
        .saturating_add(body_len)
}

fn msg_body_len(seq: u64, count: u64, index: u64, data_len: usize) -> usize {
    let index_len = if count > 1 { varint_len(index) } else { 0 };
    varint_len(seq)
        .saturating_add(varint_len(count))
        .saturating_add(index_len)
        .saturating_add(data_len)
}

/// Encoded length of a MSG frame.
pub fn msg_frame_len(seq: u64, count: u64, index: u64, data_len: usize) -> usize {
    frame_len(FRAME_MSG, msg_body_len(seq, count, index, data_len))
}

/// Appends a MSG frame.
pub fn put_msg_frame(out: &mut Vec<u8>, seq: u64, count: u64, index: u64, data: &[u8]) {
    let body = msg_body_len(seq, count, index, data.len());
    put_varint(out, FRAME_MSG);
    put_varint(out, u64::try_from(body).unwrap_or(u64::MAX));
    put_varint(out, seq);
    put_varint(out, count);
    if count > 1 {
        put_varint(out, index);
    }
    out.extend_from_slice(data);
}

/// Encoded length of an ACK frame.
pub fn ack_frame_len(cum: u64, bitmap_len: usize) -> usize {
    frame_len(FRAME_ACK, varint_len(cum).saturating_add(bitmap_len))
}

/// Appends an ACK frame.
pub fn put_ack_frame(out: &mut Vec<u8>, cum: u64, bitmap: &[u8]) {
    let body = varint_len(cum).saturating_add(bitmap.len());
    put_varint(out, FRAME_ACK);
    put_varint(out, u64::try_from(body).unwrap_or(u64::MAX));
    put_varint(out, cum);
    out.extend_from_slice(bitmap);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_covers() {
        let ack = AckFrame {
            cum: 10,
            bitmap: &[0b0000_0101, 0b1000_0000],
        };
        assert!(ack.covers(0) && ack.covers(9));
        assert!(!ack.covers(10));
        assert!(ack.covers(11) && !ack.covers(12) && ack.covers(13));
        assert!(ack.covers(26) && !ack.covers(27));
        assert!(!ack.covers(u64::MAX));
        assert_eq!(ack.horizon(), 27);
    }

    #[test]
    fn frames_round_trip_and_unknown_skipped() {
        let mut out = Vec::new();
        put_msg_frame(&mut out, 5, 3, 2, b"abc");
        put_varint(&mut out, 0x7e); // unknown type
        put_varint(&mut out, 2);
        out.extend_from_slice(&[9, 9]);
        put_ack_frame(&mut out, 7, &[1]);
        let frames: Vec<_> = Frames::new(&out).collect::<Result<_, _>>().unwrap();
        assert_eq!(
            frames,
            [
                Frame::Msg(MsgFrame {
                    seq: 5,
                    count: 3,
                    index: 2,
                    data: b"abc"
                }),
                Frame::Unknown { frame_type: 0x7e },
                Frame::Ack(AckFrame {
                    cum: 7,
                    bitmap: &[1]
                }),
            ]
        );
        assert_eq!(
            msg_frame_len(5, 3, 2, 3) + ack_frame_len(7, 1) + 4,
            out.len()
        );
    }

    #[test]
    fn truncated_frame_is_error() {
        let mut out = Vec::new();
        put_msg_frame(&mut out, 1, 1, 0, b"hello");
        out.pop();
        assert_eq!(validate_frames(&out), Err(DecodeError::Truncated));
    }
}
