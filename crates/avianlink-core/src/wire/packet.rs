use alloc::vec::Vec;

use super::{put_varint, varint_len, DecodeError, Reader};
use crate::{hash, PublicKey};

/// Current wire version (first byte of every packet).
pub const VERSION: u8 = 0x01;
/// Length of the pair routing tag.
pub const TAG_LEN: usize = 3;
/// Length of the trailing check (becomes the AEAD tag in Phase 3).
pub const CHECK_LEN: usize = 4;
/// Counter length assumed when sizing fragments.
pub const SIZING_COUNTER_LEN: usize = 5;
/// Worst-case header length used for sizing.
pub const MAX_HEADER_LEN: usize = 1 + TAG_LEN + SIZING_COUNTER_LEN;
/// Smallest well-formed packet: header with 1-byte counter, no frames, check.
pub const MIN_PACKET_LEN: usize = 1 + TAG_LEN + 1 + CHECK_LEN;

/// Pair routing tag.
pub type PairTag = [u8; TAG_LEN];

/// Actual header length for a given counter.
pub fn header_len(counter: u64) -> usize {
    (1 + TAG_LEN).saturating_add(varint_len(counter))
}

/// Checks length and version, and returns the routing tag. Cheap; does not
/// verify the check.
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

fn split_check(packet: &[u8]) -> Option<(&[u8], &[u8])> {
    packet.split_at_checked(packet.len().checked_sub(CHECK_LEN)?)
}

/// Whether `packet`'s check verifies for `sender → recipient`.
pub fn verify_check(packet: &[u8], sender: &PublicKey, recipient: &PublicKey) -> bool {
    match split_check(packet) {
        Some((body, check)) => hash::packet_check(sender, recipient, body) == check,
        None => false,
    }
}

/// Parses the header of a packet whose check has already verified. Returns
/// the counter and the frame bytes.
pub fn split_verified(packet: &[u8]) -> Result<(u64, &[u8]), DecodeError> {
    let (body, _) = split_check(packet).ok_or(DecodeError::TooShort)?;
    let mut r = Reader::new(body);
    let _version = r.u8()?;
    let _tag: PairTag = r.array()?;
    let counter = r.varint()?;
    Ok((counter, r.rest()))
}

/// Starts a packet: writes version, tag and counter into `out`.
pub fn begin_packet(out: &mut Vec<u8>, tag: PairTag, counter: u64) {
    out.push(VERSION);
    out.extend_from_slice(&tag);
    put_varint(out, counter);
}

/// Finishes a packet by appending the check over everything in `out`.
pub fn seal_packet(out: &mut Vec<u8>, sender: &PublicKey, recipient: &PublicKey) {
    let check = hash::packet_check(sender, recipient, out);
    out.extend_from_slice(&check);
}
