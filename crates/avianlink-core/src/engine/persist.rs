//! Storage keys and record encodings (`docs/reliability.md` §4).
//!
//! Storage is the host's, so its contents are parsed as carefully as
//! network input: decoding fails rather than panics.

use alloc::string::ToString;
use alloc::vec::Vec;

use super::state::Inbox;
use crate::wire::{put_varint, DecodeError, Reader};
use crate::{ConversationId, Event, MessageId, PublicKey, ReceivedMessage, Timestamp};

/// Bumped on incompatible layout changes.
pub(super) const SCHEMA: u8 = 1;

pub(super) const KEY_VERSION: &[u8] = b"v";
pub(super) const PREFIX_CONTACT: &[u8] = b"c";
pub(super) const PREFIX_OUTBOX: &[u8] = b"o";
pub(super) const PREFIX_INBOX: &[u8] = b"i";
pub(super) const PREFIX_EVENT: &[u8] = b"e";

/// A pending write: `Some(value)` to store, `None` to remove.
pub(super) type Op = (Vec<u8>, Option<Vec<u8>>);

fn key(prefix: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut k = prefix.to_vec();
    parts.iter().for_each(|p| k.extend_from_slice(p));
    k
}

pub(super) fn contact_key(conv: &ConversationId) -> Vec<u8> {
    key(PREFIX_CONTACT, &[&conv.0])
}

pub(super) fn outbox_key(conv: &ConversationId, seq: u64) -> Vec<u8> {
    key(PREFIX_OUTBOX, &[&conv.0, &seq.to_be_bytes()])
}

pub(super) fn inbox_key(conv: &ConversationId) -> Vec<u8> {
    key(PREFIX_INBOX, &[&conv.0])
}

pub(super) fn event_key(n: u64) -> Vec<u8> {
    key(PREFIX_EVENT, &[&n.to_be_bytes()])
}

/// `"v"`: schema and the identity the state belongs to.
pub(super) fn version_record(local: &PublicKey) -> Vec<u8> {
    let mut v = alloc::vec![SCHEMA];
    v.extend_from_slice(&local.0);
    v
}

pub(super) fn decode_version(v: &[u8]) -> Result<(u8, PublicKey), DecodeError> {
    let mut r = Reader::new(v);
    Ok((r.u8()?, PublicKey(r.array()?)))
}

/// Durable per-contact fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ContactRecord {
    pub(super) key: PublicKey,
    pub(super) next_seq: u64,
    pub(super) lamport: u64,
    pub(super) counter_reserved: u64,
}

impl ContactRecord {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut v = self.key.0.to_vec();
        put_varint(&mut v, self.next_seq);
        put_varint(&mut v, self.lamport);
        put_varint(&mut v, self.counter_reserved);
        v
    }

    pub(super) fn decode(v: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(v);
        Ok(Self {
            key: PublicKey(r.array()?),
            next_seq: r.varint()?,
            lamport: r.varint()?,
            counter_reserved: r.varint()?,
        })
    }
}

pub(super) fn encode_outbox(queued_at: Timestamp, record: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(record.len().saturating_add(8));
    put_varint(&mut v, queued_at.as_millis());
    v.extend_from_slice(record);
    v
}

pub(super) fn decode_outbox(v: &[u8]) -> Result<(Timestamp, &[u8]), DecodeError> {
    let mut r = Reader::new(v);
    Ok((Timestamp::from_millis(r.varint()?), r.rest()))
}

/// Splits an outbox key into (conversation, seq).
pub(super) fn parse_outbox_key(k: &[u8]) -> Option<(ConversationId, u64)> {
    let mut r = Reader::new(k.get(PREFIX_OUTBOX.len()..)?);
    let conv = ConversationId(r.array().ok()?);
    let seq = u64::from_be_bytes(r.array().ok()?);
    r.is_empty().then_some((conv, seq))
}

/// Splits a one-conversation key (contact, inbox) after its prefix.
pub(super) fn parse_conv_key(prefix: &[u8], k: &[u8]) -> Option<ConversationId> {
    let mut r = Reader::new(k.get(prefix.len()..)?);
    let conv = ConversationId(r.array().ok()?);
    r.is_empty().then_some(conv)
}

pub(super) fn parse_event_key(k: &[u8]) -> Option<u64> {
    let mut r = Reader::new(k.get(PREFIX_EVENT.len()..)?);
    let n = u64::from_be_bytes(r.array().ok()?);
    r.is_empty().then_some(n)
}

pub(super) fn encode_inbox(inbox: &Inbox, window_bytes: usize) -> Vec<u8> {
    let mut v = Vec::new();
    put_varint(&mut v, inbox.cum);
    v.extend_from_slice(&inbox.bitmap(window_bytes));
    v
}

pub(super) fn decode_inbox(v: &[u8]) -> Result<Inbox, DecodeError> {
    let mut r = Reader::new(v);
    let cum = r.varint()?;
    let mut inbox = Inbox {
        cum,
        above: Default::default(),
    };
    let base = cum.checked_add(1).ok_or(DecodeError::TooLarge)?;
    for (byte_i, &byte) in (0u64..).zip(r.rest()) {
        for bit in 0..8u64 {
            if byte & (1u8 << bit) != 0 {
                let off = byte_i
                    .checked_mul(8)
                    .and_then(|o| o.checked_add(bit))
                    .and_then(|o| base.checked_add(o))
                    .ok_or(DecodeError::TooLarge)?;
                inbox.above.insert(off);
            }
        }
    }
    Ok(inbox)
}

const EVENT_RECEIVED: u8 = 1;
const EVENT_DELIVERED: u8 = 2;

pub(super) fn encode_event(ev: &Event) -> Vec<u8> {
    let mut v = Vec::new();
    match ev {
        Event::MessageReceived(m) => {
            v.push(EVENT_RECEIVED);
            v.extend_from_slice(&m.conversation.0);
            v.extend_from_slice(&m.id.0);
            put_varint(&mut v, m.seq);
            put_varint(&mut v, m.lamport);
            put_varint(&mut v, m.missing_before);
            put_varint(&mut v, m.received_at.as_millis());
            match m.sender_time {
                Some(t) => {
                    v.push(1);
                    put_varint(&mut v, t.as_millis());
                }
                None => v.push(0),
            }
            v.extend_from_slice(m.text.as_bytes());
        }
        Event::MessageDelivered { conversation, id } => {
            v.push(EVENT_DELIVERED);
            v.extend_from_slice(&conversation.0);
            v.extend_from_slice(&id.0);
        }
    }
    v
}

pub(super) fn decode_event(v: &[u8]) -> Result<Event, DecodeError> {
    let mut r = Reader::new(v);
    let kind = r.u8()?;
    let conversation = ConversationId(r.array()?);
    let id = MessageId(r.array()?);
    match kind {
        EVENT_RECEIVED => {
            let seq = r.varint()?;
            let lamport = r.varint()?;
            let missing_before = r.varint()?;
            let received_at = Timestamp::from_millis(r.varint()?);
            let sender_time = match r.u8()? {
                0 => None,
                _ => Some(Timestamp::from_millis(r.varint()?)),
            };
            let text = core::str::from_utf8(r.rest())
                .map_err(|_| DecodeError::InvalidUtf8)?
                .to_string();
            Ok(Event::MessageReceived(ReceivedMessage {
                conversation,
                id,
                seq,
                lamport,
                missing_before,
                sender_time,
                received_at,
                text,
            }))
        }
        EVENT_DELIVERED => Ok(Event::MessageDelivered { conversation, id }),
        _ => Err(DecodeError::TooLarge),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn records_round_trip() {
        let c = ContactRecord {
            key: PublicKey([7; 32]),
            next_seq: 300,
            lamport: 9,
            counter_reserved: 1 << 40,
        };
        assert_eq!(ContactRecord::decode(&c.encode()), Ok(c));

        let mut inbox = Inbox::default();
        for s in [0, 1, 2, 5, 9, 40] {
            inbox.insert(s);
        }
        let back = decode_inbox(&encode_inbox(&inbox, 512)).unwrap();
        assert_eq!((back.cum, &back.above), (inbox.cum, &inbox.above));

        let conv = ConversationId([3; 16]);
        assert_eq!(parse_outbox_key(&outbox_key(&conv, 77)), Some((conv, 77)));
        assert_eq!(parse_conv_key(PREFIX_INBOX, &inbox_key(&conv)), Some(conv));
        assert_eq!(parse_event_key(&event_key(5)), Some(5));
        assert_eq!(parse_outbox_key(b"o\x01"), None);

        for ev in [
            Event::MessageReceived(ReceivedMessage {
                conversation: conv,
                id: MessageId([4; 16]),
                seq: 3,
                lamport: 8,
                missing_before: 1,
                sender_time: Some(Timestamp::from_millis(1_000)),
                received_at: Timestamp::from_millis(2_000),
                text: String::from("héllo"),
            }),
            Event::MessageDelivered {
                conversation: conv,
                id: MessageId([5; 16]),
            },
        ] {
            assert_eq!(decode_event(&encode_event(&ev)), Ok(ev));
        }
        assert!(decode_event(&[9; 40]).is_err());
    }
}
