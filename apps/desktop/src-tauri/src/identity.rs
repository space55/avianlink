//! Hex encoding of the engine's opaque identifiers, and the human-checkable
//! fingerprint.
//!
//! Everything that crosses IPC does so as a lowercase hex string
//! (`docs/ipc.md` § Conventions). Decoding is strict: exact length, lowercase
//! only. Strictness matters because these strings are pasted by hand from
//! another machine, and a silently-accepted near-miss would produce a
//! contact that can never receive anything, with no visible cause.

use avianlink_core::{ConversationId, MessageId, PublicKey};
use sha2::{Digest, Sha256};

use crate::error::{IpcError, IpcResult};

/// Domain-separation label for the fingerprint hash.
///
/// Fixed by desktop DA-009 so that `avianlink-core` can adopt the derivation
/// unchanged (api-requests AR-004).
const FINGERPRINT_LABEL: &[u8] = b"avianlink-fingerprint-v1";

/// Bytes of the fingerprint hash shown to the user: 80 bits.
const FINGERPRINT_BYTES: usize = 10;

/// Characters per group in the rendered fingerprint.
const FINGERPRINT_GROUP: usize = 4;

/// Encodes a fixed-size byte array as lowercase hex.
fn encode<const N: usize>(bytes: &[u8; N]) -> String {
    hex::encode(bytes)
}

/// Decodes exactly `N` bytes of lowercase hex, or explains why it could not.
fn decode<const N: usize>(what: &str, text: &str) -> IpcResult<[u8; N]> {
    let expected = N * 2;
    if text.len() != expected {
        return Err(IpcError::bad_request(format!(
            "{what} must be {expected} hex characters, got {}",
            text.len()
        )));
    }
    if text.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(IpcError::bad_request(format!(
            "{what} must be lowercase hex"
        )));
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(text, &mut out)
        .map_err(|_| IpcError::bad_request(format!("{what} is not valid hex")))?;
    Ok(out)
}

/// Renders a public key for display and copying.
pub fn encode_key(key: &PublicKey) -> String {
    encode(&key.0)
}

/// Parses a public key pasted by the user.
pub fn decode_key(text: &str) -> IpcResult<PublicKey> {
    Ok(PublicKey(decode("public key", text.trim())?))
}

/// Renders a conversation identifier.
pub fn encode_conversation(id: &ConversationId) -> String {
    encode(&id.0)
}

/// Parses a conversation identifier received from the frontend.
pub fn decode_conversation(text: &str) -> IpcResult<ConversationId> {
    Ok(ConversationId(decode("conversation id", text.trim())?))
}

/// Renders a message identifier.
pub fn encode_message_id(id: &MessageId) -> String {
    encode(&id.0)
}

/// Parses a message identifier received from the frontend.
pub fn decode_message_id(text: &str) -> IpcResult<MessageId> {
    Ok(MessageId(decode("message id", text.trim())?))
}

/// Derives the 80-bit fingerprint of a public key.
pub fn fingerprint_bytes(key: &PublicKey) -> [u8; FINGERPRINT_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_LABEL);
    hasher.update(key.0);
    let digest = hasher.finalize();
    let mut out = [0u8; FINGERPRINT_BYTES];
    out.copy_from_slice(&digest[..FINGERPRINT_BYTES]);
    out
}

/// Renders the fingerprint as five dash-separated groups of four lowercase
/// hex characters, e.g. `a1b2-c3d4-e5f6-7890-abcd`.
///
/// The grouping is the point: an ungrouped 20-character string does not get
/// compared character by character, and this is the app's only
/// authentication step.
pub fn fingerprint(key: &PublicKey) -> String {
    let hex = hex::encode(fingerprint_bytes(key));
    let groups: Vec<String> = hex
        .as_bytes()
        .chunks(FINGERPRINT_GROUP)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    groups.join("-")
}

/// The first group of the fingerprint, used as a fallback display name when
/// the user does not supply one.
pub fn short_fingerprint(key: &PublicKey) -> String {
    fingerprint(key)
        .split('-')
        .next()
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PublicKey {
        PublicKey([byte; 32])
    }

    #[test]
    fn key_round_trips() {
        let k = key(0xab);
        let text = encode_key(&k);
        assert_eq!(text.len(), 64);
        assert_eq!(decode_key(&text).unwrap(), k);
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        // Pasting from a QR reader or a chat window brings whitespace along.
        let k = key(1);
        let padded = format!("  {}\n", encode_key(&k));
        assert_eq!(decode_key(&padded).unwrap(), k);
    }

    #[test]
    fn decoding_rejects_wrong_length_uppercase_and_non_hex() {
        assert_eq!(
            decode_key("ab").unwrap_err().kind,
            crate::error::IpcErrorKind::BadRequest
        );
        let upper = encode_key(&key(0xab)).to_uppercase();
        assert!(decode_key(&upper).is_err());
        let not_hex: String = std::iter::repeat_n('z', 64).collect();
        assert!(decode_key(&not_hex).is_err());
    }

    #[test]
    fn conversation_and_message_ids_are_sixteen_bytes() {
        let c = ConversationId([7; 16]);
        assert_eq!(encode_conversation(&c).len(), 32);
        assert_eq!(decode_conversation(&encode_conversation(&c)).unwrap(), c);
        let m = MessageId([9; 16]);
        assert_eq!(decode_message_id(&encode_message_id(&m)).unwrap(), m);
        // A 32-byte key is not a valid 16-byte id.
        assert!(decode_conversation(&encode_key(&key(0))).is_err());
    }

    #[test]
    fn fingerprint_is_five_groups_of_four() {
        let fp = fingerprint(&key(0));
        let groups: Vec<&str> = fp.split('-').collect();
        assert_eq!(groups.len(), 5);
        assert!(groups.iter().all(|g| g.len() == 4));
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        assert_eq!(short_fingerprint(&key(0)), groups[0]);
    }

    #[test]
    fn fingerprint_is_stable_and_key_dependent() {
        // Pinned so a refactor cannot silently change what users compare.
        assert_eq!(fingerprint(&key(0)), "d033-9b2b-d44b-ab05-ec86");
        assert_ne!(fingerprint(&key(0)), fingerprint(&key(1)));
    }

    #[test]
    fn fingerprint_is_domain_separated() {
        // Must not be a bare hash of the key: that would collide with any
        // other protocol that fingerprints the same key material.
        let bare = hex::encode(&Sha256::digest(key(0).0)[..FINGERPRINT_BYTES]);
        assert_ne!(fingerprint(&key(0)).replace('-', ""), bare);
    }
}
