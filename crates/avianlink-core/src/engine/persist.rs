//! Storage keys and record encodings (`docs/reliability.md` §4).
//!
//! Storage is the host's, so its contents are parsed as carefully as
//! network input: decoding fails rather than panics.

use alloc::string::ToString;
use alloc::vec::Vec;

use super::state::Inbox;
use crate::wire::{put_varint, DecodeError, Reader};
use crate::{ConversationId, Event, LinkId, MessageId, PublicKey, ReceivedMessage, Timestamp};

/// Bumped on incompatible layout changes. Schema 3 is read too: it lacks
/// the confirmed flag (D-044).
pub(super) const SCHEMA: u8 = 4;
pub(super) const SCHEMA_V3: u8 = 3;

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

/// A digest of one 64-seq block of message IDs (`reliability.md` §7).
pub(super) type BlockDigest = (u64, [u8; 8]);

fn put_digests(v: &mut Vec<u8>, ds: &[BlockDigest]) {
    put_varint(v, u64::try_from(ds.len()).unwrap_or(0));
    for (block, hash) in ds {
        put_varint(v, *block);
        v.extend_from_slice(hash);
    }
}

/// Durable per-contact fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ContactRecord {
    pub(super) key: PublicKey,
    pub(super) next_seq: u64,
    pub(super) lamport: u64,
    pub(super) counter_reserved: u64,
    /// Digests of our most recent sent blocks.
    pub(super) sent_digests: Vec<BlockDigest>,
    /// An authenticated packet from the contact has been accepted.
    /// Absent in schema 3 records, which decode as confirmed.
    pub(super) confirmed: bool,
}

impl ContactRecord {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut v = self.key.0.to_vec();
        put_varint(&mut v, self.next_seq);
        put_varint(&mut v, self.lamport);
        put_varint(&mut v, self.counter_reserved);
        put_digests(&mut v, &self.sent_digests);
        v.push(u8::from(self.confirmed));
        v
    }

    pub(super) fn decode(v: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(v);
        let key = PublicKey(r.array()?);
        let next_seq = r.varint()?;
        let lamport = r.varint()?;
        let counter_reserved = r.varint()?;
        let n = r.varint()?;
        let mut sent_digests = Vec::new();
        for _ in 0..n.min(8) {
            sent_digests.push((r.varint()?, r.array()?));
        }
        let confirmed = r.is_empty() || r.u8()? != 0;
        Ok(Self {
            key,
            next_seq,
            lamport,
            counter_reserved,
            sent_digests,
            confirmed,
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

/// Received-block digest with the number of messages folded in.
pub(super) type RecvDigest = (u64, [u8; 8], u8);

/// Receive window, received-block digests and the replay floor (highest
/// accepted packet counter, stored +1 so 0 means none).
pub(super) fn encode_inbox(
    inbox: &Inbox,
    window_bytes: usize,
    replay_high: Option<u64>,
    digests: &[RecvDigest],
) -> Vec<u8> {
    let mut v = Vec::new();
    put_varint(&mut v, replay_high.map_or(0, |h| h.saturating_add(1)));
    put_varint(&mut v, u64::try_from(digests.len()).unwrap_or(0));
    for (block, hash, count) in digests {
        put_varint(&mut v, *block);
        v.extend_from_slice(hash);
        v.push(*count);
    }
    put_varint(&mut v, inbox.cum);
    v.extend_from_slice(&inbox.bitmap(window_bytes));
    v
}

pub(super) type DecodedInbox = (Inbox, Option<u64>, Vec<RecvDigest>);

pub(super) fn decode_inbox(v: &[u8]) -> Result<DecodedInbox, DecodeError> {
    let mut r = Reader::new(v);
    let replay_high = r.varint()?.checked_sub(1);
    let n = r.varint()?;
    let mut digests = Vec::new();
    for _ in 0..n.min(8) {
        digests.push((r.varint()?, r.array()?, r.u8()?));
    }
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
    Ok((inbox, replay_high, digests))
}

const EVENT_RECEIVED: u8 = 1;
const EVENT_DELIVERED: u8 = 2;
const EVENT_SKIPPED: u8 = 3;
const EVENT_DIVERGED: u8 = 4;
const EVENT_CONTACT_REQUEST: u8 = 5;

/// Encodes a durable event; `None` for transient ones (never persisted).
pub(super) fn encode_event(ev: &Event) -> Option<Vec<u8>> {
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
        Event::MessagesSkipped {
            conversation,
            first_seq,
            count,
        } => {
            v.push(EVENT_SKIPPED);
            v.extend_from_slice(&conversation.0);
            v.extend_from_slice(&[0; 16]);
            put_varint(&mut v, *first_seq);
            put_varint(&mut v, *count);
        }
        Event::SyncDiverged {
            conversation,
            first_seq,
            last_seq,
        } => {
            v.push(EVENT_DIVERGED);
            v.extend_from_slice(&conversation.0);
            v.extend_from_slice(&[0; 16]);
            put_varint(&mut v, *first_seq);
            put_varint(&mut v, *last_seq);
        }
        Event::ContactRequest {
            public_key,
            link,
            received_at,
        } => {
            v.push(EVENT_CONTACT_REQUEST);
            v.extend_from_slice(&[0; 32]);
            v.extend_from_slice(&public_key.0);
            put_varint(&mut v, u64::from(link.0));
            put_varint(&mut v, received_at.as_millis());
        }
        Event::MessageTransmitted { .. } => return None,
    }
    Some(v)
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
        EVENT_SKIPPED => Ok(Event::MessagesSkipped {
            conversation,
            first_seq: r.varint()?,
            count: r.varint()?,
        }),
        EVENT_DIVERGED => Ok(Event::SyncDiverged {
            conversation,
            first_seq: r.varint()?,
            last_seq: r.varint()?,
        }),
        EVENT_CONTACT_REQUEST => Ok(Event::ContactRequest {
            public_key: PublicKey(r.array()?),
            link: LinkId(u16::try_from(r.varint()?).map_err(|_| DecodeError::TooLarge)?),
            received_at: Timestamp::from_millis(r.varint()?),
        }),
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
            sent_digests: alloc::vec![(3, [5; 8]), (4, [6; 8])],
            confirmed: false,
        };
        assert_eq!(ContactRecord::decode(&c.encode()), Ok(c.clone()));
        // Schema 3 records have no flag and decode as confirmed.
        let mut v3 = c.encode();
        v3.pop();
        assert!(ContactRecord::decode(&v3).unwrap().confirmed);

        let mut inbox = Inbox::default();
        for s in [0, 1, 2, 5, 9, 40] {
            inbox.insert(s);
        }
        let ds = [(0u64, [9u8; 8], 64u8)];
        let (back, high, d) = decode_inbox(&encode_inbox(&inbox, 512, Some(77), &ds)).unwrap();
        assert_eq!(
            (back.cum, &back.above, high),
            (inbox.cum, &inbox.above, Some(77))
        );
        assert_eq!(d, ds);
        let (_, none, _) = decode_inbox(&encode_inbox(&inbox, 512, None, &[])).unwrap();
        assert_eq!(none, None);

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
            Event::MessagesSkipped {
                conversation: conv,
                first_seq: 3,
                count: 40,
            },
            Event::SyncDiverged {
                conversation: conv,
                first_seq: 64,
                last_seq: 127,
            },
            Event::ContactRequest {
                public_key: PublicKey([8; 32]),
                link: LinkId(3),
                received_at: Timestamp::from_millis(9_000),
            },
        ] {
            assert_eq!(decode_event(&encode_event(&ev).unwrap()), Ok(ev));
        }
        assert!(decode_event(&[9; 40]).is_err());
    }
}
