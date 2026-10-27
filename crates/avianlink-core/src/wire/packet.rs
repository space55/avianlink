use alloc::vec::Vec;

use super::{put_varint, varint_len, DecodeError, Reader};

/// Packet kind of a v1 data packet (byte 0; `wire-format.md` §2).
pub const VERSION: u8 = 0x01;
/// Length of the routing tag.
pub const TAG_LEN: usize = 3;
/// Length of the trailing AEAD (Poly1305) tag.
pub const AEAD_TAG_LEN: usize = 16;
/// Counter length assumed when sizing fragments (counter < 2³⁵).
pub const SIZING_COUNTER_LEN: usize = 5;
/// Worst-case header length used for sizing.
pub const MAX_HEADER_LEN: usize = 1 + TAG_LEN + SIZING_COUNTER_LEN;
/// Smallest well-formed packet: header with 1-byte counter, no frames, AEAD
/// tag.
pub const MIN_PACKET_LEN: usize = 1 + TAG_LEN + 1 + AEAD_TAG_LEN;

/// Routing tag of one direction between two contacts.
pub type PairTag = [u8; TAG_LEN];

/// Actual header length for a given counter.
pub fn header_len(counter: u64) -> usize {
    (1 + TAG_LEN).saturating_add(varint_len(counter))
}

/// Checks length and kind, and returns the routing tag. Cheap: no
/// cryptography.
pub fn peek_tag(packet: &[u8]) -> Result<PairTag, DecodeError> {
    if packet.len() < MIN_PACKET_LEN {
        return Err(DecodeError::TooShort);
    }
    let mut r = Reader::new(packet);
    let version = r.u8()?;
    if version != VERSION {
        return Err(DecodeError::UnknownVersion(version));
    }
    r.array()
}

/// Parses the cleartext header: `(tag, counter, header length)`. The
/// remainder is ciphertext plus the AEAD tag.
pub fn parse_header(packet: &[u8]) -> Result<(PairTag, u64, usize), DecodeError> {
    let tag = peek_tag(packet)?;
    let mut r = Reader::new(packet.get(1 + TAG_LEN..).ok_or(DecodeError::TooShort)?);
    let counter = r.varint()?;
    let header = header_len(counter);
    if packet.len() < header.saturating_add(AEAD_TAG_LEN) {
        return Err(DecodeError::TooShort);
    }
    Ok((tag, counter, header))
}

/// Starts a packet: writes kind, tag and counter into `out`. Frames are
/// appended next, then sealed with `crypto::PairKeys::seal`.
pub fn begin_packet(out: &mut Vec<u8>, tag: PairTag, counter: u64) {
    out.push(VERSION);
    out.extend_from_slice(&tag);
    put_varint(out, counter);
}
