use alloc::vec::Vec;

/// A peer's 32-byte public identity key.
///
/// Phase 1 treats it as opaque bytes; Phase 3 makes it an X25519/Ed25519 key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey(pub [u8; 32]);

/// Identifies a (pairwise) conversation: a hash of both participants' keys,
/// identical on both sides (`docs/wire-format.md` §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConversationId(pub [u8; 16]);

/// Content-addressed message identifier (truncated hash of the message).
///
/// Duplicates share an ID, so resends are idempotent. The on-wire
/// truncation length is specified in `docs/wire-format.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(pub [u8; 16]);

/// An encoded packet, never larger than the MTU of the link it is bound for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet(Vec<u8>);

impl Packet {
    /// Wraps already-encoded bytes.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The packet's bytes, ready to hand to the link.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the packet, returning its bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the packet is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
