//! Domain-separated SHA-256 helpers (`docs/wire-format.md` §2, §5).

use sha2::{Digest, Sha256};

use crate::wire::put_varint;
use crate::{ConversationId, MessageId, PublicKey};

fn digest(label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn truncate<const N: usize>(d: [u8; 32]) -> [u8; N] {
    let mut out = [0u8; N];
    out.iter_mut().zip(d).for_each(|(o, b)| *o = b);
    out
}

/// The conversation between `a` and `b`; symmetric.
pub fn conversation_id(a: &PublicKey, b: &PublicKey) -> ConversationId {
    let (lo, hi) = if a.0 <= b.0 { (a, b) } else { (b, a) };
    ConversationId(truncate(digest(b"avianlink/v1/conv", &[&lo.0, &hi.0])))
}

/// Content-addressed ID of message `seq` with encoded `record`.
pub fn message_id(sender: &PublicKey, recipient: &PublicKey, seq: u64, record: &[u8]) -> MessageId {
    let mut seq_buf = alloc::vec::Vec::with_capacity(10);
    put_varint(&mut seq_buf, seq);
    MessageId(truncate(digest(
        b"avianlink/v1/msg",
        &[&sender.0, &recipient.0, &seq_buf, record],
    )))
}
