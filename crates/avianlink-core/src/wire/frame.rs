use alloc::vec::Vec;

use super::{put_varint, varint_len, DecodeError, Reader};

/// PADDING frame type; body ignored.
pub const FRAME_PADDING: u64 = 0x00;
/// MSG frame type: a message fragment.
pub const FRAME_MSG: u64 = 0x01;
/// ACK frame type: selective acknowledgement.
pub const FRAME_ACK: u64 = 0x02;
/// REPAIR frame type: FEC repair symbol.
pub const FRAME_REPAIR: u64 = 0x03;
/// SYNC frame type: the sender's reconciliation summary.
pub const FRAME_SYNC: u64 = 0x04;
/// SYNC flag: the recipient should reply with its ACK and SYNC.
pub const SYNC_REPLY_WANTED: u64 = 1;
/// Seqs per SYNC digest block.
pub const SYNC_BLOCK: u64 = 64;
/// Most digests in one SYNC frame.
pub const MAX_SYNC_DIGESTS: usize = 4;
/// FRAG_ACK frame type: per-fragment acknowledgement.
pub const FRAME_FRAG_ACK: u64 = 0x05;
/// LOSS frame type: receiver's measured loss.
pub const FRAME_LOSS: u64 = 0x06;

/// Which part of a message record a MSG frame carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Part {
    /// Byte offset of this fragment within the record.
    pub offset: u64,
    /// Whether this is the final fragment (its end is the record length).
    pub last: bool,
}

/// A message fragment (wire §3.1). Semantic validity is the caller's to
/// check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsgFrame<'a> {
    /// Sender's per-conversation sequence number.
    pub seq: u64,
    /// `None`: the whole record; otherwise the fragment's place in it.
    pub part: Option<Part>,
    /// Fragment bytes.
    pub data: &'a [u8],
}

/// A selective acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckFrame<'a> {
    /// Every seq below this has been received.
    pub cum: u64,
    /// Largest packet counter received from the peer.
    pub largest: u64,
    /// Milliseconds between that packet's arrival and this ACK.
    pub ack_delay: u64,
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

/// Fragments held of a partially reassembled message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragAckFrame<'a> {
    /// The message.
    pub seq: u64,
    /// Block size in bytes (wire §3.3).
    pub unit: u64,
    /// Bit `i` set: block `i` held.
    pub bitmap: &'a [u8],
}

impl FragAckFrame<'_> {
    /// Whether block `index` is held.
    pub fn has(&self, index: u64) -> bool {
        let Ok(i) = usize::try_from(index) else {
            return false;
        };
        self.bitmap
            .get(i / 8)
            .is_some_and(|b| b & (1u8 << (i % 8)) != 0)
    }
}

/// An FEC repair symbol (wire §3.4). Field validity is the caller's to
/// check ([`RepairFrame::sources`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepairFrame<'a> {
    /// First source counter.
    pub base: u64,
    /// Bit `i`: counter `base + i` is a source.
    pub mask: u64,
    /// `(m − 1) << 4 | j`.
    pub shape: u8,
    /// Coded symbol.
    pub data: &'a [u8],
}

impl RepairFrame<'_> {
    /// Repairs in this window (`m`) and this one's index (`j`).
    pub fn m_j(&self) -> (usize, usize) {
        (
            usize::from(self.shape >> 4).saturating_add(1),
            usize::from(self.shape & 0x0f),
        )
    }

    /// Source counters in order, or `None` if the fields are invalid.
    pub fn sources(&self) -> Option<alloc::vec::Vec<u64>> {
        let (m, j) = self.m_j();
        let n = self.mask.count_ones();
        if self.mask & 1 == 0 || self.mask >> 32 != 0 || n > 16 || j >= m {
            return None;
        }
        (0..32u64)
            .filter(|i| self.mask & (1u64 << i) != 0)
            .map(|i| self.base.checked_add(i))
            .collect()
    }
}

/// The sender's reconciliation summary (wire §3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncFrame<'a> {
    /// Flag bits ([`SYNC_REPLY_WANTED`]).
    pub flags: u64,
    /// Lowest seq the sender can still deliver.
    pub floor: u64,
    /// Sender's next unused seq.
    pub next: u64,
    digests: &'a [u8],
}

impl SyncFrame<'_> {
    /// Whether the sender asked for a reply.
    pub fn reply_wanted(&self) -> bool {
        self.flags & SYNC_REPLY_WANTED != 0
    }

    /// The `(block, hash)` digests, at most [`MAX_SYNC_DIGESTS`]. Malformed
    /// trailing data ends the list.
    pub fn digests(&self) -> alloc::vec::Vec<(u64, [u8; 8])> {
        let mut r = Reader::new(self.digests);
        let n = r.varint().unwrap_or(0);
        let mut out = alloc::vec::Vec::new();
        for _ in 0..n.min(MAX_SYNC_DIGESTS as u64) {
            let (Ok(block), Ok(hash)) = (r.varint(), r.array::<8>()) else {
                break;
            };
            out.push((block, hash));
        }
        out
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
    /// Per-fragment acknowledgement.
    FragAck(FragAckFrame<'a>),
    /// FEC repair symbol.
    Repair(RepairFrame<'a>),
    /// Receiver's measured loss, in permille.
    Loss(u64),
    /// Reconciliation summary.
    Sync(SyncFrame<'a>),
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
                let part = match b.varint()? {
                    0 => None,
                    frag => {
                        let f = frag.saturating_sub(1);
                        Some(Part {
                            offset: f >> 1,
                            last: f & 1 == 1,
                        })
                    }
                };
                Frame::Msg(MsgFrame {
                    seq,
                    part,
                    data: b.rest(),
                })
            }
            FRAME_ACK => {
                let cum = b.varint()?;
                let largest = b.varint()?;
                let ack_delay = b.varint()?;
                Frame::Ack(AckFrame {
                    cum,
                    largest,
                    ack_delay,
                    bitmap: b.rest(),
                })
            }
            FRAME_REPAIR => {
                let base = b.varint()?;
                let mask = b.varint()?;
                let shape = b.u8()?;
                Frame::Repair(RepairFrame {
                    base,
                    mask,
                    shape,
                    data: b.rest(),
                })
            }
            FRAME_LOSS => Frame::Loss(b.varint()?),
            FRAME_SYNC => {
                let flags = b.varint()?;
                let floor = b.varint()?;
                let next = b.varint()?;
                Frame::Sync(SyncFrame {
                    flags,
                    floor,
                    next,
                    digests: b.rest(),
                })
            }
            FRAME_FRAG_ACK => {
                let seq = b.varint()?;
                let unit = b.varint()?;
                Frame::FragAck(FragAckFrame {
                    seq,
                    unit,
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
        // Trailing zero bytes are padding (wire §3).
        if self.failed || self.r.is_empty() || self.r.peek_rest().iter().all(|&b| b == 0) {
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

fn frag_field(part: Option<Part>) -> u64 {
    part.map_or(0, |p| {
        p.offset
            .saturating_mul(2)
            .saturating_add(u64::from(p.last))
            .saturating_add(1)
    })
}

fn msg_body_len(seq: u64, part: Option<Part>, data_len: usize) -> usize {
    let part_len = varint_len(frag_field(part));
    varint_len(seq)
        .saturating_add(part_len)
        .saturating_add(data_len)
}

/// Encoded length of a MSG frame.
pub fn msg_frame_len(seq: u64, part: Option<Part>, data_len: usize) -> usize {
    frame_len(FRAME_MSG, msg_body_len(seq, part, data_len))
}

/// Appends a MSG frame.
pub fn put_msg_frame(out: &mut Vec<u8>, seq: u64, part: Option<Part>, data: &[u8]) {
    let body = msg_body_len(seq, part, data.len());
    put_varint(out, FRAME_MSG);
    put_varint(out, u64::try_from(body).unwrap_or(u64::MAX));
    put_varint(out, seq);
    put_varint(out, frag_field(part));
    out.extend_from_slice(data);
}

/// Encoded length of an ACK frame.
pub fn ack_frame_len(cum: u64, largest: u64, ack_delay: u64, bitmap_len: usize) -> usize {
    let body = varint_len(cum)
        .saturating_add(varint_len(largest))
        .saturating_add(varint_len(ack_delay))
        .saturating_add(bitmap_len);
    frame_len(FRAME_ACK, body)
}

/// Appends an ACK frame.
pub fn put_ack_frame(out: &mut Vec<u8>, cum: u64, largest: u64, ack_delay: u64, bitmap: &[u8]) {
    let body = varint_len(cum)
        .saturating_add(varint_len(largest))
        .saturating_add(varint_len(ack_delay))
        .saturating_add(bitmap.len());
    put_varint(out, FRAME_ACK);
    put_varint(out, u64::try_from(body).unwrap_or(u64::MAX));
    put_varint(out, cum);
    put_varint(out, largest);
    put_varint(out, ack_delay);
    out.extend_from_slice(bitmap);
}

/// Encoded length of a REPAIR frame.
pub fn repair_frame_len(base: u64, mask: u64, data_len: usize) -> usize {
    let body = varint_len(base)
        .saturating_add(varint_len(mask))
        .saturating_add(1)
        .saturating_add(data_len);
    frame_len(FRAME_REPAIR, body)
}

/// Appends a REPAIR frame.
pub fn put_repair_frame(out: &mut Vec<u8>, base: u64, mask: u64, shape: u8, data: &[u8]) {
    let body = varint_len(base)
        .saturating_add(varint_len(mask))
        .saturating_add(1)
        .saturating_add(data.len());
    put_varint(out, FRAME_REPAIR);
    put_varint(out, u64::try_from(body).unwrap_or(u64::MAX));
    put_varint(out, base);
    put_varint(out, mask);
    out.push(shape);
    out.extend_from_slice(data);
}

fn sync_body(flags: u64, floor: u64, next: u64, digests: &[(u64, [u8; 8])]) -> Vec<u8> {
    let mut body = Vec::new();
    put_varint(&mut body, flags);
    put_varint(&mut body, floor);
    put_varint(&mut body, next);
    let n = digests.len().min(MAX_SYNC_DIGESTS);
    put_varint(&mut body, u64::try_from(n).unwrap_or(0));
    for (block, hash) in digests.iter().take(n) {
        put_varint(&mut body, *block);
        body.extend_from_slice(hash);
    }
    body
}

/// Encoded length of a SYNC frame.
pub fn sync_frame_len(flags: u64, floor: u64, next: u64, digests: &[(u64, [u8; 8])]) -> usize {
    frame_len(FRAME_SYNC, sync_body(flags, floor, next, digests).len())
}

/// Appends a SYNC frame.
pub fn put_sync_frame(
    out: &mut Vec<u8>,
    flags: u64,
    floor: u64,
    next: u64,
    digests: &[(u64, [u8; 8])],
) {
    let body = sync_body(flags, floor, next, digests);
    put_varint(out, FRAME_SYNC);
    put_varint(out, u64::try_from(body.len()).unwrap_or(u64::MAX));
    out.extend_from_slice(&body);
}

/// Encoded length of a LOSS frame.
pub fn loss_frame_len(permille: u64) -> usize {
    frame_len(FRAME_LOSS, varint_len(permille))
}

/// Appends a LOSS frame.
pub fn put_loss_frame(out: &mut Vec<u8>, permille: u64) {
    put_varint(out, FRAME_LOSS);
    put_varint(out, u64::try_from(varint_len(permille)).unwrap_or(u64::MAX));
    put_varint(out, permille);
}

/// Encoded length of a FRAG_ACK frame.
pub fn frag_ack_frame_len(seq: u64, unit: u64, bitmap_len: usize) -> usize {
    let body = varint_len(seq)
        .saturating_add(varint_len(unit))
        .saturating_add(bitmap_len);
    frame_len(FRAME_FRAG_ACK, body)
}

/// Appends a FRAG_ACK frame.
pub fn put_frag_ack_frame(out: &mut Vec<u8>, seq: u64, unit: u64, bitmap: &[u8]) {
    let body = varint_len(seq)
        .saturating_add(varint_len(unit))
        .saturating_add(bitmap.len());
    put_varint(out, FRAME_FRAG_ACK);
    put_varint(out, u64::try_from(body).unwrap_or(u64::MAX));
    put_varint(out, seq);
    put_varint(out, unit);
    out.extend_from_slice(bitmap);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn ack_covers() {
        let ack = AckFrame {
            cum: 10,
            largest: 0,
            ack_delay: 0,
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
        let part = Some(Part {
            offset: 6,
            last: true,
        });
        put_msg_frame(&mut out, 5, part, b"abc");
        put_varint(&mut out, 0x7e); // unknown type
        put_varint(&mut out, 2);
        out.extend_from_slice(&[9, 9]);
        put_ack_frame(&mut out, 7, 300, 5, &[1]);
        put_frag_ack_frame(&mut out, 9, 12, &[0b11, 0b1000]);
        let frames: Vec<_> = Frames::new(&out).collect::<Result<_, _>>().unwrap();
        assert_eq!(
            frames,
            [
                Frame::Msg(MsgFrame {
                    seq: 5,
                    part,
                    data: b"abc"
                }),
                Frame::Unknown { frame_type: 0x7e },
                Frame::Ack(AckFrame {
                    cum: 7,
                    largest: 300,
                    ack_delay: 5,
                    bitmap: &[1]
                }),
                Frame::FragAck(FragAckFrame {
                    seq: 9,
                    unit: 12,
                    bitmap: &[0b11, 0b1000]
                }),
            ]
        );
        assert_eq!(
            msg_frame_len(5, part, 3)
                + ack_frame_len(7, 300, 5, 1)
                + frag_ack_frame_len(9, 12, 2)
                + 4,
            out.len()
        );
        let Frame::FragAck(fa) = frames[3] else {
            panic!()
        };
        assert!(fa.has(0) && fa.has(1) && !fa.has(2) && fa.has(11) && !fa.has(12));
    }

    #[test]
    fn repair_and_loss_frames_and_zero_padding() {
        let mut out = Vec::new();
        put_repair_frame(&mut out, 300, 0b1011, 0x21, b"xyz");
        put_loss_frame(&mut out, 350);
        assert_eq!(
            out.len(),
            repair_frame_len(300, 0b1011, 3) + loss_frame_len(350)
        );
        out.extend_from_slice(&[0, 0, 0]); // padding, odd length
        let frames: Vec<_> = Frames::new(&out).collect::<Result<_, _>>().unwrap();
        let Frame::Repair(r) = frames[0] else {
            panic!("{frames:?}")
        };
        assert_eq!(
            (r.base, r.mask, r.data, r.m_j()),
            (300, 0b1011, &b"xyz"[..], (3, 1))
        );
        assert_eq!(r.sources(), Some(vec![300, 301, 303]));
        assert_eq!(frames[1], Frame::Loss(350));
        assert_eq!(frames.len(), 2);
        assert_eq!(validate_frames(&[0]), Ok(()));
        let bad = RepairFrame {
            base: 0,
            mask: 0b10,
            shape: 0,
            data: &[],
        };
        assert_eq!(bad.sources(), None, "bit 0 must be set");
        let bad = RepairFrame {
            mask: 1,
            shape: 0x05,
            ..bad
        };
        assert_eq!(bad.sources(), None, "j >= m");
    }

    #[test]
    fn sync_frame_round_trips() {
        let mut out = Vec::new();
        let digests = [(3u64, [1u8; 8]), (4, [2; 8])];
        put_sync_frame(&mut out, SYNC_REPLY_WANTED, 200, 300, &digests);
        assert_eq!(out.len(), sync_frame_len(1, 200, 300, &digests));
        let frames: Vec<_> = Frames::new(&out).collect::<Result<_, _>>().unwrap();
        let Frame::Sync(s) = frames[0] else {
            panic!("{frames:?}")
        };
        assert!(s.reply_wanted());
        assert_eq!((s.floor, s.next, s.digests()), (200, 300, digests.to_vec()));
        // Truncated digests end the list, they don't fail the frame.
        let short = SyncFrame {
            flags: 0,
            floor: 0,
            next: 0,
            digests: &[2, 7, 1, 2],
        };
        assert!(short.digests().is_empty());
    }

    #[test]
    fn truncated_frame_is_error() {
        let mut out = Vec::new();
        put_msg_frame(&mut out, 1, None, b"hello");
        out.pop();
        assert_eq!(validate_frames(&out), Err(DecodeError::Truncated));
    }
}
