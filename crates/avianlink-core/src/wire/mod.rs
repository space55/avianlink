//! Low-level codec for the format in `docs/wire-format.md`.
//!
//! Public for fuzzing, property tests and tooling. Not a stable API.

mod frame;
mod packet;
mod reader;
mod record;
mod sizing;
mod varint;

use core::fmt;

pub use frame::{
    ack_frame_len, frag_ack_frame_len, msg_frame_len, put_ack_frame, put_frag_ack_frame,
    put_msg_frame, validate_frames, AckFrame, FragAckFrame, Frame, Frames, MsgFrame, FRAME_ACK,
    FRAME_FRAG_ACK, FRAME_MSG, FRAME_PADDING,
};
pub use packet::{
    begin_packet, header_len, parse_header, peek_tag, PairTag, AEAD_TAG_LEN, MAX_HEADER_LEN,
    MIN_PACKET_LEN, SIZING_COUNTER_LEN, TAG_LEN, VERSION,
};
pub use reader::Reader;
pub use record::{
    decode_record, encode_record, record_len, Record, FLAG_EXTENSIONS, FLAG_TIMESTAMP,
    TIMESTAMP_EPOCH_UNIX_SECS,
};
pub use sizing::{frame_space, plan_fragments, FragmentPlan};
pub use varint::{put_varint, varint_len, MAX_VARINT_LEN};

/// Why a piece of wire data failed to decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended before a field was complete.
    Truncated,
    /// A varint was longer than 10 bytes or exceeded `u64::MAX`.
    VarintOverflow,
    /// A varint used a non-minimal encoding.
    VarintNonCanonical,
    /// A value does not fit the platform's `usize`.
    TooLarge,
    /// Packet is shorter than [`MIN_PACKET_LEN`].
    TooShort,
    /// Unknown version byte.
    UnknownVersion(u8),
    /// Text is not valid UTF-8.
    InvalidUtf8,
    /// Text is longer than the configured maximum.
    TextTooLong,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated"),
            Self::VarintOverflow => f.write_str("varint overflow"),
            Self::VarintNonCanonical => f.write_str("non-canonical varint"),
            Self::TooLarge => f.write_str("value too large"),
            Self::TooShort => f.write_str("packet too short"),
            Self::UnknownVersion(v) => write!(f, "unknown version {v:#04x}"),
            Self::InvalidUtf8 => f.write_str("invalid UTF-8"),
            Self::TextTooLong => f.write_str("text too long"),
        }
    }
}

impl core::error::Error for DecodeError {}
