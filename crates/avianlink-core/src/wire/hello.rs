//! The Hello packet (`docs/wire-format.md` §2.5): unencrypted, MAC-authenticated.

use super::{DecodeError, Reader};
use crate::PublicKey;

/// Packet kind of a Hello (byte 0).
pub const HELLO_KIND: u8 = 0x02;
/// Bytes of recipient hint.
pub const HELLO_HINT_LEN: usize = 2;
/// Bytes of truncated HMAC.
pub const HELLO_MAC_LEN: usize = 12;
/// Bytes covered by the MAC: kind, hint, sender key.
pub const HELLO_SIGNED_LEN: usize = 1 + HELLO_HINT_LEN + 32;
/// Total length of a Hello; every v1 Hello is exactly this long.
pub const HELLO_LEN: usize = HELLO_SIGNED_LEN + HELLO_MAC_LEN;

const _: () = assert!(HELLO_LEN <= crate::link::MIN_MTU as usize);

/// A structurally valid Hello, not yet authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hello<'a> {
    /// Recipient hint.
    pub hint: [u8; HELLO_HINT_LEN],
    /// The sender's claimed public key.
    pub sender: PublicKey,
    /// The bytes the MAC covers.
    pub signed: &'a [u8],
    /// The truncated MAC.
    pub mac: [u8; HELLO_MAC_LEN],
}

/// Parses a Hello. Only the length and kind are checked: authenticating it
/// is `crypto`'s job.
pub fn parse_hello(packet: &[u8]) -> Result<Hello<'_>, DecodeError> {
    if packet.len() != HELLO_LEN {
        return Err(DecodeError::TooShort);
    }
    let signed = packet
        .get(..HELLO_SIGNED_LEN)
        .ok_or(DecodeError::TooShort)?;
    let mut r = Reader::new(packet);
    let kind = r.u8()?;
    if kind != HELLO_KIND {
        return Err(DecodeError::UnknownVersion(kind));
    }
    Ok(Hello {
        hint: r.array()?,
        sender: PublicKey(r.array()?),
        signed,
        mac: r.array()?,
    })
}

/// The signed part of a Hello from `sender` to the holder of `hint`.
pub fn hello_signed(hint: [u8; HELLO_HINT_LEN], sender: &PublicKey) -> [u8; HELLO_SIGNED_LEN] {
    let mut out = [0u8; HELLO_SIGNED_LEN];
    let parts = core::iter::once(HELLO_KIND).chain(hint).chain(sender.0);
    out.iter_mut().zip(parts).for_each(|(o, b)| *o = b);
    out
}

/// A complete Hello from its signed part and MAC.
pub fn encode_hello(signed: &[u8; HELLO_SIGNED_LEN], mac: &[u8; HELLO_MAC_LEN]) -> [u8; HELLO_LEN] {
    let mut out = [0u8; HELLO_LEN];
    out.iter_mut()
        .zip(signed.iter().chain(mac))
        .for_each(|(o, b)| *o = *b);
    out
}
