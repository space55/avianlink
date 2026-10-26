//! The app's own state: contacts, message history, read marks and settings.
//!
//! This is distinct from the engine's `Storage` trait. The engine persists
//! its outbox and counters; this store holds everything the *interface*
//! needs, which the engine neither has nor should have — display names,
//! verification marks, read state, and the full history of delivered
//! messages (the engine forgets a message once it is acknowledged).
//!
//! **Phase 0 scope: in memory.** Every method here is the method the SQLite
//! implementation will have in Phase 2; only the innards change. There is
//! deliberately no `trait AppStore`, because it would have exactly one
//! implementation in each phase and the second one can use an in-memory
//! SQLite database for tests.
//!
//! No method reads a clock. Callers pass `now`, which is what makes
//! out-of-order and late-arrival behaviour testable at all.

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;

use avianlink_core::{ConversationId, MessageId, PublicKey};

use crate::identity;
use crate::ipc::{
    order_key, Contact, ConversationSummary, Identity, Message, MessagePage, MessagePreview,
    MessageStatus, MessageStatusChanged, Settings, MAX_PAGE_LIMIT, PREVIEW_CHARS,
};

/// A contact, plus the state the engine does not keep.
#[derive(Clone, Debug)]
struct ContactRecord {
    key: PublicKey,
    display_name: String,
    verified: bool,
    added_at: u64,
    last_packet_at: Option<u64>,
    last_message_at: Option<u64>,
}

/// One conversation's history.
#[derive(Clone, Debug, Default)]
struct Thread {
    /// Messages keyed by `order_key`, so iteration is causal order.
    by_order: BTreeMap<String, Message>,
    /// Message id -> `order_key`, so status updates are a lookup not a scan.
    by_id: HashMap<String, String>,
    /// Highest `order_key` the user has seen.
    read_through: Option<String>,
    /// Incoming messages above `read_through`.
    unread: u32,
    /// Outgoing messages not yet delivered or failed.
    undelivered: u32,
}

/// Outcome of inserting a received message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inserted {
    /// The message is new and was stored.
    New(Message),
    /// We already had it. Retransmission makes this the common case, so it
    /// is an ordinary outcome and not an error.
    Duplicate,
}

/// The app's state.
#[derive(Debug, Default)]
pub struct AppStore {
    identity: Option<PublicKey>,
    contacts: BTreeMap<ConversationId, ContactRecord>,
    threads: BTreeMap<ConversationId, Thread>,
    settings: Settings,
}

impl AppStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    // -- identity ----------------------------------------------------------

    /// Records this machine's public identity key.
    pub fn set_identity(&mut self, key: PublicKey) {
        self.identity = Some(key);
    }

    /// This machine's identity, if one has been established.
    pub fn identity(&self) -> Option<Identity> {
        self.identity.map(|key| Identity {
            public_key: identity::encode_key(&key),
            fingerprint: identity::fingerprint(&key),
            display_name: self.settings.display_name.clone(),
        })
    }

    // -- contacts ----------------------------------------------------------

    /// Adds or replaces a contact. Returns the stored form.
    pub fn upsert_contact(
        &mut self,
        conversation: ConversationId,
        key: PublicKey,
        display_name: &str,
        verified: bool,
        now: u64,
    ) -> Contact {
        let name = if display_name.trim().is_empty() {
            identity::short_fingerprint(&key)
        } else {
            display_name.trim().to_string()
        };
        let entry = self
            .contacts
            .entry(conversation)
            .and_modify(|c| {
                c.display_name = name.clone();
                c.verified = verified;
            })
            .or_insert_with(|| ContactRecord {
                key,
                display_name: name,
                verified,
                added_at: now,
                last_packet_at: None,
                last_message_at: None,
            });
        let record = entry.clone();
        self.threads.entry(conversation).or_default();
        self.to_contact(conversation, &record)
    }

    /// Whether `conversation` is a known contact.
    pub fn has_contact(&self, conversation: &ConversationId) -> bool {
        self.contacts.contains_key(conversation)
    }

    /// A single contact.
    pub fn contact(&self, conversation: &ConversationId) -> Option<Contact> {
        self.contacts
            .get(conversation)
            .map(|c| self.to_contact(*conversation, c))
    }

    /// All contacts, sorted by display name, case-insensitively.
    pub fn contacts(&self) -> Vec<Contact> {
        let mut out: Vec<Contact> = self
            .contacts
            .iter()
            .map(|(id, c)| self.to_contact(*id, c))
            .collect();
        out.sort_by(|a, b| {
            a.display_name
                .to_lowercase()
                .cmp(&b.display_name.to_lowercase())
                .then_with(|| a.conversation_id.cmp(&b.conversation_id))
        });
        out
    }

    /// The public key behind a conversation, for re-registering with the
    /// engine at startup (api-requests AR-005).
    pub fn contact_key(&self, conversation: &ConversationId) -> Option<PublicKey> {
        self.contacts.get(conversation).map(|c| c.key)
    }

    /// Sets a contact's verification mark. `None` if there is no such contact.
    pub fn set_verified(
        &mut self,
        conversation: &ConversationId,
        verified: bool,
    ) -> Option<Contact> {
        let record = self.contacts.get_mut(conversation)?;
        record.verified = verified;
        let record = record.clone();
        Some(self.to_contact(*conversation, &record))
    }

    /// Notes that a packet attributed to this contact arrived.
    pub fn note_packet(&mut self, conversation: &ConversationId, now: u64) -> Option<Contact> {
        let record = self.contacts.get_mut(conversation)?;
        record.last_packet_at = Some(now);
        let record = record.clone();
        Some(self.to_contact(*conversation, &record))
    }

    fn to_contact(&self, conversation: ConversationId, record: &ContactRecord) -> Contact {
        Contact {
            conversation_id: identity::encode_conversation(&conversation),
            public_key: identity::encode_key(&record.key),
            fingerprint: identity::fingerprint(&record.key),
            display_name: record.display_name.clone(),
            verified: record.verified,
            added_at: record.added_at,
            last_packet_at: record.last_packet_at,
            last_message_at: record.last_message_at,
            unread_count: self
                .threads
                .get(&conversation)
                .map_or(0, |thread| thread.unread),
        }
    }

    // -- messages ----------------------------------------------------------

    /// Stores an outgoing message we have just queued.
    pub fn insert_outgoing(
        &mut self,
        conversation: ConversationId,
        id: MessageId,
        seq: u64,
        lamport: u64,
        text: &str,
        now: u64,
    ) -> Message {
        let id_hex = identity::encode_message_id(&id);
        let key = order_key(lamport, &id_hex);
        let message = Message {
            id: id_hex,
            conversation_id: identity::encode_conversation(&conversation),
            outgoing: true,
            text: text.to_string(),
            lamport,
            seq,
            order_key: key,
            sent_at: Some(now),
            received_at: None,
            status: Some(MessageStatus::Queued),
            delivered_at: None,
            attempts: Some(0),
            // Our own message is always at the head of our causal order, so
            // it can never be late. If it ever were, the engine's Lamport
            // clock would be broken.
            arrived_late: false,
        };
        let thread = self.threads.entry(conversation).or_default();
        thread.undelivered = thread.undelivered.saturating_add(1);
        Self::store(thread, message.clone());
        message
    }

    /// Stores a received message, or reports it as a duplicate.
    ///
    /// Sets `arrived_late` when a strictly greater `order_key` is already
    /// present: that is exactly "this appeared behind something you were
    /// already looking at". It is computed once and never recomputed, because
    /// it records a fact about history rather than about the current sort.
    #[expect(clippy::too_many_arguments, reason = "every field is independent")]
    pub fn insert_incoming(
        &mut self,
        conversation: ConversationId,
        id: MessageId,
        seq: u64,
        lamport: u64,
        text: &str,
        sent_at: Option<u64>,
        received_at: u64,
    ) -> Inserted {
        let id_hex = identity::encode_message_id(&id);
        let key = order_key(lamport, &id_hex);
        let thread = self.threads.entry(conversation).or_default();
        if thread.by_id.contains_key(&id_hex) {
            return Inserted::Duplicate;
        }
        let arrived_late = thread
            .by_order
            .range((Bound::Excluded(key.clone()), Bound::Unbounded))
            .next()
            .is_some();
        let message = Message {
            id: id_hex,
            conversation_id: identity::encode_conversation(&conversation),
            outgoing: false,
            text: text.to_string(),
            lamport,
            seq,
            order_key: key.clone(),
            sent_at,
            received_at: Some(received_at),
            status: None,
            delivered_at: None,
            attempts: None,
            arrived_late,
        };
        if thread.read_through.as_ref().is_none_or(|read| key > *read) {
            thread.unread = thread.unread.saturating_add(1);
        }
        Self::store(thread, message.clone());
        if let Some(record) = self.contacts.get_mut(&conversation) {
            record.last_message_at = Some(received_at);
            record.last_packet_at = Some(received_at);
        }
        Inserted::New(message)
    }

    fn store(thread: &mut Thread, message: Message) {
        thread
            .by_id
            .insert(message.id.clone(), message.order_key.clone());
        thread.by_order.insert(message.order_key.clone(), message);
    }

    /// Advances an outgoing message's status, keeping it monotonic.
    ///
    /// Returns the event to emit, or `None` when nothing changed — which is
    /// the common case under retransmission and is what keeps the event
    /// stream quiet.
    pub fn update_status(
        &mut self,
        conversation: &ConversationId,
        id: &MessageId,
        status: MessageStatus,
        at: u64,
    ) -> Option<MessageStatusChanged> {
        let id_hex = identity::encode_message_id(id);
        let thread = self.threads.get_mut(conversation)?;
        let key = thread.by_id.get(&id_hex)?.clone();
        let message = thread.by_order.get_mut(&key)?;
        let previous = message.status?;
        let next = previous.max(status);
        let attempts = message.attempts.unwrap_or(0);
        let bumped_attempt = status == MessageStatus::Sent;
        if bumped_attempt {
            message.attempts = Some(attempts.saturating_add(1));
        }
        if next == previous {
            return None;
        }
        message.status = Some(next);
        if next == MessageStatus::Delivered {
            message.delivered_at = Some(at);
        }
        if matches!(next, MessageStatus::Delivered | MessageStatus::Failed) {
            thread.undelivered = thread.undelivered.saturating_sub(1);
        }
        Some(MessageStatusChanged {
            conversation_id: identity::encode_conversation(conversation),
            message_id: id_hex,
            status: next,
            delivered_at: message.delivered_at,
            attempts: message.attempts.unwrap_or(0),
        })
    }

    /// Promotes every still-`queued` outgoing message in a conversation to
    /// `sent`, returning the changes to emit.
    ///
    /// This exists only for the api-requests AR-002 workaround: an engine
    /// that cannot say which messages a packet carried forces the driver to
    /// assume all of them. It over-reports by design, and is not used for
    /// engines that report transmissions themselves.
    pub fn promote_queued_to_sent(
        &mut self,
        conversation: &ConversationId,
        now: u64,
    ) -> Vec<MessageStatusChanged> {
        let Some(thread) = self.threads.get(conversation) else {
            return Vec::new();
        };
        let queued: Vec<MessageId> = thread
            .by_order
            .values()
            .filter(|m| m.status == Some(MessageStatus::Queued))
            .filter_map(|m| {
                let mut bytes = [0u8; 16];
                hex::decode_to_slice(&m.id, &mut bytes).ok()?;
                Some(MessageId(bytes))
            })
            .collect();
        queued
            .into_iter()
            .filter_map(|id| self.update_status(conversation, &id, MessageStatus::Sent, now))
            .collect()
    }

    /// A page of history, oldest first.
    ///
    /// Pagination is on `order_key` rather than an offset so that a message
    /// inserting into the middle of history cannot shift a page boundary and
    /// make the UI skip or duplicate a message while the user scrolls.
    pub fn messages(
        &self,
        conversation: &ConversationId,
        before: Option<&str>,
        limit: u32,
    ) -> Option<MessagePage> {
        let thread = self.threads.get(conversation)?;
        let limit = limit.clamp(1, MAX_PAGE_LIMIT) as usize;
        let upper = match before {
            Some(cursor) => Bound::Excluded(cursor.to_string()),
            None => Bound::Unbounded,
        };
        // Walk backwards from the cursor to collect the newest `limit`
        // messages below it, then reverse: the UI wants ascending order but
        // pages are taken from the bottom.
        let mut page: Vec<Message> = thread
            .by_order
            .range((Bound::Unbounded, upper))
            .rev()
            .take(limit)
            .map(|(_, m)| m.clone())
            .collect();
        page.reverse();
        let oldest = page.first().map(|m| m.order_key.clone());
        let has_more = match oldest.as_deref() {
            Some(first) => thread
                .by_order
                .range((Bound::Unbounded, Bound::Excluded(first.to_string())))
                .next_back()
                .is_some(),
            None => false,
        };
        Some(MessagePage {
            messages: page,
            has_more,
            oldest_order_key: oldest,
            total: thread.by_order.len() as u32,
        })
    }

    /// Clears unread state up to a point the user has actually seen.
    ///
    /// Takes an `order_key` rather than "all", so a late message that lands
    /// above the read point stays unread.
    pub fn mark_read(&mut self, conversation: &ConversationId, through: &str) -> Option<Contact> {
        let thread = self.threads.get_mut(conversation)?;
        let lower = match thread.read_through.clone() {
            Some(prev) if prev.as_str() >= through => return None,
            Some(prev) => Bound::Excluded(prev),
            None => Bound::Unbounded,
        };
        let newly_read = thread
            .by_order
            .range((lower, Bound::Included(through.to_string())))
            .filter(|(_, m)| !m.outgoing)
            .count();
        thread.unread = thread.unread.saturating_sub(newly_read as u32);
        thread.read_through = Some(through.to_string());
        let record = self.contacts.get(conversation)?.clone();
        Some(self.to_contact(*conversation, &record))
    }

    /// Sidebar rows: one per contact, including contacts with no messages, so
    /// a new contact appears immediately.
    pub fn conversations(&self) -> Vec<ConversationSummary> {
        let mut out: Vec<ConversationSummary> = self
            .contacts
            .iter()
            .map(|(id, record)| {
                let thread = self.threads.get(id);
                ConversationSummary {
                    conversation_id: identity::encode_conversation(id),
                    contact: self.to_contact(*id, record),
                    last_message: thread
                        .and_then(|t| t.by_order.values().next_back())
                        .map(preview),
                    unread_count: thread.map_or(0, |t| t.unread),
                    undelivered_count: thread.map_or(0, |t| t.undelivered),
                }
            })
            .collect();
        // Most recent conversation first; never-used ones last, by name.
        out.sort_by(|a, b| {
            match (
                a.last_message.as_ref().map(|m| m.at),
                b.last_message.as_ref().map(|m| m.at),
            ) {
                (Some(x), Some(y)) => y.cmp(&x),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a
                    .contact
                    .display_name
                    .to_lowercase()
                    .cmp(&b.contact.display_name.to_lowercase()),
            }
        });
        out
    }

    // -- settings ----------------------------------------------------------

    /// Current settings.
    pub fn settings(&self) -> Settings {
        self.settings.clone()
    }

    /// Replaces settings and returns the stored form.
    pub fn set_settings(&mut self, settings: Settings) -> Settings {
        self.settings = settings;
        self.settings.clone()
    }

    /// Deletes everything. The caller is responsible for also discarding the
    /// identity key from the keychain and rebuilding the engine.
    pub fn reset(&mut self) {
        self.identity = None;
        self.contacts.clear();
        self.threads.clear();
        self.settings = Settings::default();
    }
}

/// Truncates a message to a sidebar preview.
///
/// Truncation happens here so that listing conversations never carries full
/// message bodies across IPC.
fn preview(message: &Message) -> MessagePreview {
    let text: String = if message.text.chars().count() > PREVIEW_CHARS {
        message.text.chars().take(PREVIEW_CHARS).collect()
    } else {
        message.text.clone()
    };
    MessagePreview {
        text,
        outgoing: message.outgoing,
        at: message.sent_at.or(message.received_at).unwrap_or(0),
        status: message.status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_700_000_000_000;

    fn key(b: u8) -> PublicKey {
        PublicKey([b; 32])
    }

    fn conv(b: u8) -> ConversationId {
        ConversationId([b; 16])
    }

    fn msg(b: u8) -> MessageId {
        MessageId([b; 16])
    }

    fn store_with_contact() -> (AppStore, ConversationId) {
        let mut s = AppStore::new();
        s.set_identity(key(0));
        let c = conv(1);
        s.upsert_contact(c, key(2), "Rook", false, T0);
        (s, c)
    }

    #[test]
    fn identity_exposes_no_secret_and_derives_the_fingerprint() {
        let mut s = AppStore::new();
        assert!(s.identity().is_none());
        s.set_identity(key(7));
        let id = s.identity().unwrap();
        assert_eq!(id.public_key, identity::encode_key(&key(7)));
        assert_eq!(id.fingerprint, identity::fingerprint(&key(7)));
    }

    #[test]
    fn contact_without_a_name_falls_back_to_the_short_fingerprint() {
        let mut s = AppStore::new();
        let c = s.upsert_contact(conv(1), key(2), "   ", false, T0);
        assert_eq!(c.display_name, identity::short_fingerprint(&key(2)));
        assert!(!c.display_name.is_empty());
    }

    #[test]
    fn upsert_renames_without_losing_history_or_added_at() {
        let (mut s, c) = store_with_contact();
        s.insert_outgoing(c, msg(1), 0, 1, "hi", T0);
        let renamed = s.upsert_contact(c, key(2), "Rook (work)", true, T0 + 5_000);
        assert_eq!(renamed.display_name, "Rook (work)");
        assert!(renamed.verified);
        assert_eq!(renamed.added_at, T0, "added_at must not be rewritten");
        assert_eq!(s.messages(&c, None, 10).unwrap().total, 1);
    }

    #[test]
    fn contacts_sort_case_insensitively() {
        let mut s = AppStore::new();
        s.upsert_contact(conv(1), key(1), "zebra", false, T0);
        s.upsert_contact(conv(2), key(2), "Apple", false, T0);
        let names: Vec<String> = s.contacts().into_iter().map(|c| c.display_name).collect();
        assert_eq!(names, vec!["Apple", "zebra"]);
    }

    #[test]
    fn outgoing_messages_start_queued() {
        let (mut s, c) = store_with_contact();
        let m = s.insert_outgoing(c, msg(1), 0, 1, "hello", T0);
        assert_eq!(m.status, Some(MessageStatus::Queued));
        assert_eq!(m.sent_at, Some(T0));
        assert_eq!(m.received_at, None, "we did not receive our own message");
        assert_eq!(m.attempts, Some(0));
        assert!(!m.arrived_late);
        assert_eq!(s.conversations()[0].undelivered_count, 1);
    }

    #[test]
    fn status_advances_queued_sent_delivered_and_emits_once_each() {
        let (mut s, c) = store_with_contact();
        s.insert_outgoing(c, msg(1), 0, 1, "hello", T0);

        let sent = s
            .update_status(&c, &msg(1), MessageStatus::Sent, T0 + 1_000)
            .expect("queued -> sent is a change");
        assert_eq!(sent.status, MessageStatus::Sent);
        assert_eq!(sent.attempts, 1);
        assert_eq!(sent.delivered_at, None);

        // A retransmission bumps attempts but must not emit again.
        assert!(s
            .update_status(&c, &msg(1), MessageStatus::Sent, T0 + 2_000)
            .is_none());

        let delivered = s
            .update_status(&c, &msg(1), MessageStatus::Delivered, T0 + 3_600_000)
            .expect("sent -> delivered is a change");
        assert_eq!(delivered.status, MessageStatus::Delivered);
        assert_eq!(delivered.delivered_at, Some(T0 + 3_600_000));
        assert_eq!(delivered.attempts, 2, "the retransmission was counted");
        assert_eq!(s.conversations()[0].undelivered_count, 0);
    }

    #[test]
    fn status_never_goes_backwards() {
        // A `sent` for attempt 7 can arrive after the ack for attempt 3.
        let (mut s, c) = store_with_contact();
        s.insert_outgoing(c, msg(1), 0, 1, "hello", T0);
        s.update_status(&c, &msg(1), MessageStatus::Delivered, T0 + 10);
        assert!(s
            .update_status(&c, &msg(1), MessageStatus::Sent, T0 + 20)
            .is_none());
        let page = s.messages(&c, None, 10).unwrap();
        assert_eq!(page.messages[0].status, Some(MessageStatus::Delivered));
        assert_eq!(page.messages[0].delivered_at, Some(T0 + 10));
    }

    #[test]
    fn status_updates_for_unknown_messages_are_ignored() {
        let (mut s, c) = store_with_contact();
        assert!(s
            .update_status(&c, &msg(9), MessageStatus::Sent, T0)
            .is_none());
        assert!(s
            .update_status(&conv(9), &msg(1), MessageStatus::Sent, T0)
            .is_none());
    }

    #[test]
    fn retransmitted_incoming_messages_are_duplicates_not_errors() {
        let (mut s, c) = store_with_contact();
        let first = s.insert_incoming(c, msg(1), 0, 1, "hi", Some(T0), T0 + 100);
        assert!(matches!(first, Inserted::New(_)));
        let again = s.insert_incoming(c, msg(1), 0, 1, "hi", Some(T0), T0 + 90_000);
        assert_eq!(again, Inserted::Duplicate);
        assert_eq!(s.messages(&c, None, 10).unwrap().total, 1);
        assert_eq!(s.contact(&c).unwrap().unread_count, 1);
    }

    #[test]
    fn a_late_message_sorts_into_place_and_is_marked() {
        let (mut s, c) = store_with_contact();
        // lamport 1 and 3 arrive; 2 turns up an hour later.
        s.insert_incoming(c, msg(1), 0, 1, "first", Some(T0), T0);
        s.insert_incoming(c, msg(3), 2, 3, "third", Some(T0 + 2), T0 + 10);
        let late = s.insert_incoming(c, msg(2), 1, 2, "second", Some(T0 + 1), T0 + 3_600_000);
        let Inserted::New(late) = late else {
            panic!("expected a new message")
        };
        assert!(late.arrived_late, "it landed behind an existing message");

        let page = s.messages(&c, None, 10).unwrap();
        let texts: Vec<&str> = page.messages.iter().map(|m| m.text.as_str()).collect();
        assert_eq!(texts, vec!["first", "second", "third"], "causal order");
    }

    #[test]
    fn a_message_arriving_at_the_head_is_not_marked_late() {
        let (mut s, c) = store_with_contact();
        s.insert_incoming(c, msg(1), 0, 1, "first", Some(T0), T0);
        let Inserted::New(m) = s.insert_incoming(c, msg(2), 1, 2, "second", Some(T0), T0 + 5)
        else {
            panic!()
        };
        assert!(!m.arrived_late);
    }

    #[test]
    fn arrived_late_is_not_recomputed_by_later_arrivals() {
        // It records "this appeared out of order while you were watching",
        // which stops being true of the *sort* as soon as more arrive.
        let (mut s, c) = store_with_contact();
        s.insert_incoming(c, msg(3), 2, 3, "third", None, T0);
        s.insert_incoming(c, msg(1), 0, 1, "first", None, T0 + 10);
        s.insert_incoming(c, msg(5), 4, 5, "fifth", None, T0 + 20);
        let page = s.messages(&c, None, 10).unwrap();
        let late: Vec<bool> = page.messages.iter().map(|m| m.arrived_late).collect();
        assert_eq!(late, vec![true, false, false]);
    }

    #[test]
    fn pagination_is_stable_when_a_message_inserts_mid_history() {
        // The reason the cursor is an order_key and not an offset. Build 10
        // messages at even lamports, read the newest 4, then let an odd
        // lamport land inside the already-read range.
        let (mut s, c) = store_with_contact();
        for i in 1..=10u8 {
            s.insert_incoming(c, msg(i * 2), u64::from(i), u64::from(i) * 2, "m", None, T0);
        }
        let newest = s.messages(&c, None, 4).unwrap();
        assert_eq!(newest.messages.len(), 4);
        assert!(newest.has_more);
        let cursor = newest.oldest_order_key.clone().unwrap();

        // A late message lands at lamport 19, inside the page just read.
        s.insert_incoming(c, msg(19), 99, 19, "late", None, T0 + 3_600_000);

        let older = s.messages(&c, Some(&cursor), 4).unwrap();
        // Nothing from the first page reappears, and nothing was skipped.
        assert!(older.messages.iter().all(|m| m.order_key < cursor.clone()));
        let newest_keys: Vec<&String> = newest.messages.iter().map(|m| &m.order_key).collect();
        assert!(older
            .messages
            .iter()
            .all(|m| !newest_keys.contains(&&m.order_key)));
    }

    #[test]
    fn paging_walks_the_whole_history_exactly_once() {
        let (mut s, c) = store_with_contact();
        for i in 0..25u8 {
            s.insert_incoming(c, msg(i), u64::from(i), u64::from(i) + 1, "m", None, T0);
        }
        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = s.messages(&c, cursor.as_deref(), 7).unwrap();
            assert!(page
                .messages
                .windows(2)
                .all(|w| w[0].order_key < w[1].order_key));
            seen.extend(page.messages.iter().map(|m| m.order_key.clone()));
            if !page.has_more {
                break;
            }
            cursor = page.oldest_order_key;
        }
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 25);
    }

    #[test]
    fn empty_conversation_pages_cleanly() {
        let (s, c) = store_with_contact();
        let page = s.messages(&c, None, 50).unwrap();
        assert!(page.messages.is_empty());
        assert!(!page.has_more);
        assert_eq!(page.oldest_order_key, None);
        assert_eq!(page.total, 0);
        assert!(s.messages(&conv(9), None, 50).is_none());
    }

    #[test]
    fn page_limit_is_clamped() {
        let (mut s, c) = store_with_contact();
        for i in 0..5u8 {
            s.insert_incoming(c, msg(i), u64::from(i), u64::from(i) + 1, "m", None, T0);
        }
        assert_eq!(s.messages(&c, None, 0).unwrap().messages.len(), 1);
        assert_eq!(
            s.messages(&c, None, u32::MAX).unwrap().messages.len(),
            5,
            "clamped to MAX_PAGE_LIMIT, not rejected"
        );
    }

    #[test]
    fn reading_clears_unread_and_a_late_message_above_the_mark_stays_unread() {
        let (mut s, c) = store_with_contact();
        s.insert_incoming(c, msg(1), 0, 1, "a", None, T0);
        s.insert_incoming(c, msg(2), 1, 2, "b", None, T0 + 1);
        assert_eq!(s.contact(&c).unwrap().unread_count, 2);

        let through = order_key(2, &identity::encode_message_id(&msg(2)));
        s.mark_read(&c, &through);
        assert_eq!(s.contact(&c).unwrap().unread_count, 0);

        // Arrives below the read mark: already seen, stays read.
        s.insert_incoming(c, msg(9), 9, 1, "late-below", None, T0 + 10);
        assert_eq!(s.contact(&c).unwrap().unread_count, 0);

        // Arrives above it: genuinely unseen.
        s.insert_incoming(c, msg(4), 3, 4, "new", None, T0 + 20);
        assert_eq!(s.contact(&c).unwrap().unread_count, 1);
    }

    #[test]
    fn marking_read_is_idempotent_and_never_moves_backwards() {
        let (mut s, c) = store_with_contact();
        s.insert_incoming(c, msg(1), 0, 1, "a", None, T0);
        s.insert_incoming(c, msg(2), 1, 2, "b", None, T0);
        let early = order_key(1, &identity::encode_message_id(&msg(1)));
        let late = order_key(2, &identity::encode_message_id(&msg(2)));
        s.mark_read(&c, &late);
        assert_eq!(s.contact(&c).unwrap().unread_count, 0);
        // A stale "I read up to here" from an older scroll position.
        assert!(s.mark_read(&c, &early).is_none());
        assert_eq!(s.contact(&c).unwrap().unread_count, 0);
    }

    #[test]
    fn our_own_messages_are_never_unread() {
        let (mut s, c) = store_with_contact();
        s.insert_outgoing(c, msg(1), 0, 1, "mine", T0);
        assert_eq!(s.contact(&c).unwrap().unread_count, 0);
    }

    #[test]
    fn conversations_list_includes_contacts_with_no_messages() {
        let mut s = AppStore::new();
        s.upsert_contact(conv(1), key(1), "Empty", false, T0);
        let list = s.conversations();
        assert_eq!(list.len(), 1);
        assert!(list[0].last_message.is_none());
        assert_eq!(list[0].unread_count, 0);
    }

    #[test]
    fn conversations_sort_recent_first_then_unused_by_name() {
        let mut s = AppStore::new();
        s.upsert_contact(conv(1), key(1), "Old", false, T0);
        s.upsert_contact(conv(2), key(2), "Recent", false, T0);
        s.upsert_contact(conv(3), key(3), "zz-never", false, T0);
        s.upsert_contact(conv(4), key(4), "aa-never", false, T0);
        s.insert_incoming(conv(1), msg(1), 0, 1, "old", Some(T0), T0);
        s.insert_incoming(conv(2), msg(2), 0, 1, "new", Some(T0 + 1_000), T0 + 1_000);
        let names: Vec<String> = s
            .conversations()
            .into_iter()
            .map(|c| c.contact.display_name)
            .collect();
        assert_eq!(names, vec!["Recent", "Old", "aa-never", "zz-never"]);
    }

    #[test]
    fn preview_is_truncated_by_characters_not_bytes() {
        let (mut s, c) = store_with_contact();
        // Multi-byte characters: truncating by byte index would panic or
        // split a character.
        let long: String = std::iter::repeat_n('é', PREVIEW_CHARS + 50).collect();
        s.insert_incoming(c, msg(1), 0, 1, &long, None, T0);
        let preview = s.conversations()[0].last_message.clone().unwrap();
        assert_eq!(preview.text.chars().count(), PREVIEW_CHARS);
    }

    #[test]
    fn preview_uses_send_time_when_known_and_receive_time_otherwise() {
        let (mut s, c) = store_with_contact();
        s.insert_incoming(c, msg(1), 0, 1, "no clock", None, T0 + 500);
        assert_eq!(
            s.conversations()[0].last_message.as_ref().unwrap().at,
            T0 + 500
        );
        s.insert_incoming(c, msg(2), 1, 2, "clock", Some(T0 + 1), T0 + 600);
        assert_eq!(
            s.conversations()[0].last_message.as_ref().unwrap().at,
            T0 + 1
        );
    }

    #[test]
    fn noting_a_packet_updates_last_heard_from_without_a_message() {
        let (mut s, c) = store_with_contact();
        assert_eq!(s.contact(&c).unwrap().last_packet_at, None);
        let updated = s.note_packet(&c, T0 + 42).unwrap();
        assert_eq!(updated.last_packet_at, Some(T0 + 42));
        assert_eq!(updated.last_message_at, None);
        assert!(s.note_packet(&conv(9), T0).is_none());
    }

    #[test]
    fn verification_is_a_local_toggle() {
        let (mut s, c) = store_with_contact();
        assert!(!s.contact(&c).unwrap().verified);
        assert!(s.set_verified(&c, true).unwrap().verified);
        assert!(!s.set_verified(&c, false).unwrap().verified);
        assert!(s.set_verified(&conv(9), true).is_none());
    }

    #[test]
    fn reset_clears_everything() {
        let (mut s, c) = store_with_contact();
        s.insert_outgoing(c, msg(1), 0, 1, "hi", T0);
        s.set_settings(Settings {
            display_name: Some("me".into()),
            ..Settings::default()
        });
        s.reset();
        assert!(s.identity().is_none());
        assert!(s.contacts().is_empty());
        assert!(s.conversations().is_empty());
        assert!(s.messages(&c, None, 10).is_none());
        assert_eq!(s.settings().display_name, None);
    }

    #[test]
    fn settings_round_trip() {
        let mut s = AppStore::new();
        assert_eq!(
            s.settings().show_receive_time_threshold_ms,
            crate::ipc::DEFAULT_RECEIVE_TIME_THRESHOLD_MS
        );
        let stored = s.set_settings(Settings {
            display_name: Some("Kestrel".into()),
            show_receive_time_threshold_ms: 60_000,
            fake_engine: None,
        });
        assert_eq!(stored.display_name.as_deref(), Some("Kestrel"));
        assert_eq!(s.settings().show_receive_time_threshold_ms, 60_000);
    }

    #[test]
    fn display_name_flows_into_identity() {
        let mut s = AppStore::new();
        s.set_identity(key(1));
        s.set_settings(Settings {
            display_name: Some("Kestrel".into()),
            ..Settings::default()
        });
        assert_eq!(
            s.identity().unwrap().display_name.as_deref(),
            Some("Kestrel")
        );
    }

    #[test]
    fn has_contact_and_contact_key_support_startup_replay() {
        // At startup the app must re-register every contact with the engine,
        // because the engine cannot enumerate them (AR-005).
        let (s, c) = store_with_contact();
        assert!(s.has_contact(&c));
        assert!(!s.has_contact(&conv(9)));
        assert_eq!(s.contact_key(&c), Some(key(2)));
        assert_eq!(s.contact_key(&conv(9)), None);
    }
}
