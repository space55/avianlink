mod persist;
mod state;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::ToString;
use alloc::vec::Vec;
use rand_core::CryptoRngCore;

use crate::config::MAX_SEQ;
use crate::crypto::{Identity, PairKeys};
use crate::hash;
use crate::pacer::Pacer;
use crate::reassembly::{Insert, Reassembly};
use crate::wire::{
    self, ack_frame_len, begin_packet, decode_record, encode_record, frag_ack_frame_len,
    frame_space, header_len, msg_frame_len, plan_fragments, put_ack_frame, put_frag_ack_frame,
    put_msg_frame, AckFrame, DecodeError, FragAckFrame, Frame, Frames, MsgFrame, PairTag, Record,
    AEAD_TAG_LEN, TIMESTAMP_EPOCH_UNIX_SECS,
};
use crate::{
    Config, ConversationId, Error, Event, LinkConfig, LinkId, MessageId, Packet, PublicKey,
    ReceivedMessage, Storage, Timestamp,
};
use persist::{
    contact_key, decode_event, decode_inbox, decode_outbox, decode_version, encode_event,
    encode_inbox, encode_outbox, event_key, inbox_key, outbox_key, parse_conv_key, parse_event_key,
    parse_outbox_key, version_record, ContactRecord, Op, KEY_VERSION, PREFIX_CONTACT, PREFIX_EVENT,
    PREFIX_INBOX, PREFIX_OUTBOX, SCHEMA,
};
use state::{Contact, FragState, OutMsg, Planned, Replay, Timers};

/// A packet the host should send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    /// Link to send on.
    pub link: LinkId,
    /// The peer the packet is for. Point-to-point links use it to pick an
    /// address; broadcast links can ignore it.
    pub to: ConversationId,
    /// Encoded packet, no larger than the link's MTU.
    pub packet: Packet,
}

/// A durably queued outgoing message, as returned by
/// [`Engine::send_text`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Queued {
    /// Content-addressed ID; [`Event::MessageDelivered`] reports it.
    pub id: MessageId,
    /// Our sequence number in this conversation.
    pub seq: u64,
    /// Lamport value assigned: the causal sort key, comparable with
    /// [`ReceivedMessage::lamport`].
    pub lamport: u64,
}

/// Delivery progress of one undelivered outgoing message
/// ([`Engine::outgoing`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutgoingStatus {
    /// The message.
    pub id: MessageId,
    /// Its sequence number.
    pub seq: u64,
    /// When `send_text` queued it.
    pub queued_at: Timestamp,
    /// How many times it has been (re)transmitted in this incarnation: the
    /// most any one fragment was sent. 0 until first transmission.
    pub transmissions: u32,
    /// Fragments, once planned (0 before first transmission).
    pub fragments: u32,
    /// Fragments the peer reported holding (FRAG_ACK).
    pub fragments_held: u32,
}

/// Per-link counters ([`Engine::link_stats`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkStats {
    /// Packets handed to the host for this link.
    pub packets_sent: u64,
    /// Bytes handed to the host for this link.
    pub bytes_sent: u64,
    /// Packets received on this link.
    pub packets_received: u64,
    /// Bytes received on this link.
    pub bytes_received: u64,
    /// Received packets that were dropped (malformed, unauthenticated,
    /// replayed).
    pub packets_dropped: u64,
    /// If the link's rate or duty-cycle budget is exhausted: when an
    /// MTU-sized packet next fits. `None` when it fits now.
    pub budget_blocked_until: Option<Timestamp>,
}

/// What the engine knows about a contact's reachability
/// ([`Engine::contact_status`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContactStatus {
    /// Last authenticated packet from the contact (any kind, ACK-only
    /// included), in this incarnation.
    pub last_heard: Option<Timestamp>,
    /// Smoothed round-trip time, once measured.
    pub srtt_ms: Option<u64>,
    /// Current retransmission timeout.
    pub rto_ms: u64,
    /// Whether the engine currently believes the contact unreachable and is
    /// only probing (`docs/reliability.md` §3).
    pub unreachable: bool,
    /// Undelivered outgoing messages to this contact.
    pub outbox_len: usize,
}

/// Diagnostic counters. All counters saturate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Packets passed to [`Engine::handle_packet`].
    pub packets_received: u64,
    /// Dropped: arrived on an unregistered link.
    pub packets_dropped_unknown_link: u64,
    /// Dropped: unknown version byte.
    pub packets_dropped_version: u64,
    /// Dropped: too short, or structurally malformed after decryption.
    pub packets_dropped_malformed: u64,
    /// Dropped: no contact's routing tag matched, or decryption failed for
    /// every candidate (tampered, truncated, misrouted or forged).
    pub packets_dropped_unauthenticated: u64,
    /// Dropped: counter already seen or below the replay window
    /// (replays and network duplicates).
    pub packets_dropped_replay: u64,
    /// Frames of unknown type skipped.
    pub frames_unknown: u64,
    /// MSG frames with invalid fragment fields.
    pub frames_dropped_invalid: u64,
    /// MSG frames beyond the receive window.
    pub frames_dropped_window: u64,
    /// MSG frames dropped because the event queue was full.
    pub frames_dropped_backpressure: u64,
    /// Fragments dropped because reassembly memory was full.
    pub fragments_dropped_reassembly_full: u64,
    /// Reassembled records that failed to decode.
    pub records_malformed: u64,
    /// New messages delivered to the host.
    pub messages_received: u64,
    /// Already-received messages seen again.
    pub messages_duplicate: u64,
    /// Our messages confirmed delivered.
    pub messages_delivered: u64,
    /// Packets returned by [`Engine::poll_transmit`].
    pub packets_sent: u64,
    /// Bytes returned by [`Engine::poll_transmit`].
    pub bytes_sent: u64,
    /// MSG frames sent (first sends and retransmissions).
    pub fragments_sent: u64,
    /// MSG frames that were retransmissions.
    pub retransmissions: u64,
    /// Packets sent as backoff probes to an unreachable peer.
    pub probes_sent: u64,
    /// ACK frames sent.
    pub acks_sent: u64,
    /// FRAG_ACK frames sent.
    pub frag_acks_sent: u64,
    /// RTT samples taken.
    pub rtt_samples: u64,
    /// Storage operations that failed (the triggering input was dropped).
    pub storage_errors: u64,
}

fn bump(c: &mut u64) {
    *c = c.saturating_add(1);
}

fn usize_of(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

fn u64_of(v: usize) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

/// Probes to an unreachable peer may use at most 1/this of a link's budget.
const PROBE_BUDGET_INVERSE_SHARE: u8 = 10;

/// Writes `ops` as one atomic batch.
fn commit<S: Storage>(storage: &mut S, ops: Vec<Op>) -> Result<(), Error> {
    storage.begin().map_err(|_| Error::Storage)?;
    for (k, v) in &ops {
        let r = match v {
            Some(v) => storage.store(k, v),
            None => storage.remove(k),
        };
        if r.is_err() {
            storage.rollback();
            return Err(Error::Storage);
        }
    }
    storage.commit().map_err(|_| {
        storage.rollback();
        Error::Storage
    })
}

#[derive(Debug)]
struct LinkState {
    config: LinkConfig,
    pacer: Pacer,
    stats: LinkStats,
}

/// The sans-IO messaging engine.
///
/// `S` is the host's durable storage, `R` the host's cryptographically
/// secure RNG. See the crate docs for the driving loop and
/// `docs/reliability.md` for what is persisted.
pub struct Engine<S, R> {
    config: Config,
    identity: Identity,
    local: PublicKey,
    storage: S,
    rng: R,
    links: BTreeMap<LinkId, LinkState>,
    contacts: BTreeMap<ConversationId, Contact>,
    by_tag: BTreeMap<PairTag, Vec<ConversationId>>,
    reassembly: Reassembly,
    /// Pending events with their storage key number (`None`: transient).
    events: VecDeque<(Option<u64>, Event)>,
    next_event_key: u64,
    stats: Stats,
    /// Latest time seen from the host; never decreases.
    now: Timestamp,
    outbox_len: usize,
    /// Round-robin cursor: the contact that sent most recently.
    last_served: Option<ConversationId>,
}

impl<S: Storage, R: CryptoRngCore> Engine<S, R> {
    /// Creates an engine for `identity` on empty storage.
    ///
    /// Fails with [`Error::StorageNotEmpty`] if `storage` already holds an
    /// engine; use [`Engine::restore`] for that. The identity's secret is
    /// never written to storage.
    pub fn new(config: Config, identity: Identity, mut storage: S, rng: R) -> Result<Self, Error> {
        config.validate()?;
        let local = identity.public_key();
        if storage
            .load(KEY_VERSION)
            .map_err(|_| Error::Storage)?
            .is_some()
        {
            return Err(Error::StorageNotEmpty);
        }
        commit(
            &mut storage,
            alloc::vec![(KEY_VERSION.to_vec(), Some(version_record(&local)))],
        )?;
        Ok(Self::empty(config, identity, storage, rng))
    }

    /// Resumes an engine from `storage` after a restart or crash: contacts,
    /// undelivered outgoing messages, receive windows and unpolled events.
    /// Links are not persisted; register them again.
    pub fn restore(
        config: Config,
        identity: Identity,
        mut storage: S,
        rng: R,
    ) -> Result<Self, Error> {
        config.validate()?;
        let local = identity.public_key();
        let version = storage
            .load(KEY_VERSION)
            .map_err(|_| Error::Storage)?
            .ok_or(Error::CorruptStorage)?;
        let (schema, owner) = decode_version(&version).map_err(|_| Error::CorruptStorage)?;
        if schema != SCHEMA {
            return Err(Error::CorruptStorage);
        }
        if owner != local {
            return Err(Error::IdentityMismatch);
        }

        let mut bad = false;
        let mut contacts = Vec::new();
        storage
            .scan_prefix(PREFIX_CONTACT, &mut |k, v| match (
                parse_conv_key(PREFIX_CONTACT, k),
                ContactRecord::decode(v),
            ) {
                (Some(conv), Ok(rec)) => contacts.push((conv, rec)),
                _ => bad = true,
            })
            .map_err(|_| Error::Storage)?;
        let mut outbox = Vec::new();
        storage
            .scan_prefix(
                PREFIX_OUTBOX,
                &mut |k, v| match (parse_outbox_key(k), decode_outbox(v)) {
                    (Some((conv, seq)), Ok((queued_at, record))) => {
                        outbox.push((conv, seq, queued_at, record.to_vec()))
                    }
                    _ => bad = true,
                },
            )
            .map_err(|_| Error::Storage)?;
        let mut inboxes = Vec::new();
        storage
            .scan_prefix(PREFIX_INBOX, &mut |k, v| match (
                parse_conv_key(PREFIX_INBOX, k),
                decode_inbox(v),
            ) {
                (Some(conv), Ok(inbox)) => inboxes.push((conv, inbox)),
                _ => bad = true,
            })
            .map_err(|_| Error::Storage)?;
        let mut events = Vec::new();
        storage
            .scan_prefix(
                PREFIX_EVENT,
                &mut |k, v| match (parse_event_key(k), decode_event(v)) {
                    (Some(n), Ok(ev)) => events.push((n, ev)),
                    _ => bad = true,
                },
            )
            .map_err(|_| Error::Storage)?;
        if bad {
            return Err(Error::CorruptStorage);
        }

        let mut e = Self::empty(config, identity, storage, rng);
        for (conv, rec) in contacts {
            if conv != hash::conversation_id(&local, &rec.key) || rec.key == local {
                return Err(Error::CorruptStorage);
            }
            let keys = PairKeys::derive(&e.identity, &rec.key).ok_or(Error::CorruptStorage)?;
            e.insert_contact(conv, Contact::from_record(&rec, keys));
        }
        for (conv, seq, queued_at, record) in outbox {
            let contact = e.contacts.get_mut(&conv).ok_or(Error::CorruptStorage)?;
            if seq >= contact.next_seq {
                return Err(Error::CorruptStorage);
            }
            let id = hash::message_id(&local, &contact.key, seq, &record);
            contact.outbox.insert(
                seq,
                OutMsg {
                    id,
                    record,
                    queued_at,
                    plan: None,
                    announced: false,
                },
            );
            e.outbox_len = e.outbox_len.saturating_add(1);
        }
        for (conv, (inbox, replay_high)) in inboxes {
            let contact = e.contacts.get_mut(&conv).ok_or(Error::CorruptStorage)?;
            contact.inbox = inbox;
            contact.replay = Replay::with_floor(replay_high);
        }
        for (n, ev) in events {
            e.next_event_key = e.next_event_key.max(n.saturating_add(1));
            e.events.push_back((Some(n), ev));
        }
        Ok(e)
    }

    fn empty(config: Config, identity: Identity, storage: S, rng: R) -> Self {
        let local = identity.public_key();
        Self {
            identity,
            reassembly: Reassembly::new(
                usize_of(config.max_reassembly_bytes),
                u64::from(config.max_fragments),
                usize_of(config.max_record_len()),
            ),
            config,
            local,
            storage,
            rng,
            links: BTreeMap::new(),
            contacts: BTreeMap::new(),
            by_tag: BTreeMap::new(),
            events: VecDeque::new(),
            next_event_key: 0,
            stats: Stats::default(),
            now: Timestamp::ZERO,
            outbox_len: 0,
            last_served: None,
        }
    }

    fn insert_contact(&mut self, conv: ConversationId, contact: Contact) {
        let rx_tag = contact.keys.rx_tag;
        self.contacts.insert(conv, contact);
        self.by_tag.entry(rx_tag).or_default().push(conv);
    }

    /// Registers a link.
    pub fn add_link(&mut self, id: LinkId, link: LinkConfig) -> Result<(), Error> {
        link.validate()?;
        if !Pacer::admits_mtu(&link.budget, link.mtu) {
            return Err(Error::InvalidLinkConfig);
        }
        if self.links.contains_key(&id) {
            return Err(Error::LinkExists);
        }
        if self.links.len() >= usize::from(self.config.max_links) {
            return Err(Error::TooManyLinks);
        }
        let pacer = Pacer::new(
            link.budget,
            link.mtu,
            usize_of(self.config.max_duty_log_entries),
            self.now,
        );
        self.links.insert(
            id,
            LinkState {
                config: link,
                pacer,
                stats: LinkStats::default(),
            },
        );
        Ok(())
    }

    /// Unregisters a link. Traffic routed over it moves to the cheapest
    /// remaining link.
    pub fn remove_link(&mut self, id: LinkId) -> Result<(), Error> {
        self.links.remove(&id).map(|_| ()).ok_or(Error::UnknownLink)
    }

    /// Adds a contact by public key (obtained out of band) and returns the
    /// conversation with them. Persisted. Fails with
    /// [`Error::InvalidContact`] for our own key, a duplicate, or a key that
    /// is not a valid, non-weak Ed25519 point.
    pub fn add_contact(&mut self, key: PublicKey) -> Result<ConversationId, Error> {
        if key == self.local {
            return Err(Error::InvalidContact);
        }
        let keys = PairKeys::derive(&self.identity, &key).ok_or(Error::InvalidContact)?;
        let conv = hash::conversation_id(&self.local, &key);
        if self.contacts.contains_key(&conv) {
            return Err(Error::InvalidContact);
        }
        if self.contacts.len() >= usize_of(self.config.max_contacts) {
            return Err(Error::TooManyContacts);
        }
        let contact = Contact::new(key, keys);
        commit(
            &mut self.storage,
            alloc::vec![(contact_key(&conv), Some(contact.record().encode()))],
        )?;
        self.insert_contact(conv, contact);
        Ok(conv)
    }

    /// Known contacts and their conversations, in conversation order.
    pub fn contacts(&self) -> impl Iterator<Item = (ConversationId, PublicKey)> + '_ {
        self.contacts.iter().map(|(c, ct)| (*c, ct.key))
    }

    /// Queues a text message. On `Ok` the message is committed to storage
    /// ("sent"); delivery is reported later as [`Event::MessageDelivered`]
    /// with the returned ID. On `Err` nothing changed.
    pub fn send_text(
        &mut self,
        conversation: ConversationId,
        text: &str,
        now: Timestamp,
    ) -> Result<Queued, Error> {
        self.observe(now);
        if text.len() > usize_of(self.config.max_text_len) {
            return Err(Error::TextTooLong);
        }
        let timestamp = self
            .config
            .wall_clock
            .then(|| (self.now.as_millis() / 1000).saturating_sub(TIMESTAMP_EPOCH_UNIX_SECS));
        let local = self.local;
        let now = self.now;
        let contact = self
            .contacts
            .get_mut(&conversation)
            .ok_or(Error::UnknownConversation)?;
        if self.outbox_len >= usize_of(self.config.max_outbox_messages) {
            return Err(Error::OutboxFull);
        }
        let seq = contact.next_seq;
        if seq > MAX_SEQ {
            return Err(Error::Exhausted);
        }
        let next_seq = seq.checked_add(1).ok_or(Error::Exhausted)?;
        let lamport = contact.lamport.checked_add(1).ok_or(Error::Exhausted)?;
        let mut record = Vec::new();
        encode_record(
            &mut record,
            &Record {
                lamport,
                timestamp,
                text,
            },
        );
        let id = hash::message_id(&local, &contact.key, seq, &record);
        let mut rec = contact.record();
        rec.next_seq = next_seq;
        rec.lamport = lamport;
        commit(
            &mut self.storage,
            alloc::vec![
                (
                    outbox_key(&conversation, seq),
                    Some(encode_outbox(now, &record))
                ),
                (contact_key(&conversation), Some(rec.encode())),
            ],
        )?;
        contact.next_seq = next_seq;
        contact.lamport = lamport;
        contact.outbox.insert(
            seq,
            OutMsg {
                id,
                record,
                queued_at: now,
                plan: None,
                announced: false,
            },
        );
        self.outbox_len = self.outbox_len.saturating_add(1);
        Ok(Queued { id, seq, lamport })
    }

    /// Feeds a packet received on `link`. Malformed or unauthenticated
    /// packets are dropped and counted in [`Stats`]; this never fails or
    /// panics.
    pub fn handle_packet(&mut self, link: LinkId, bytes: &[u8], now: Timestamp) {
        self.observe(now);
        bump(&mut self.stats.packets_received);
        let Some(l) = self.links.get_mut(&link) else {
            bump(&mut self.stats.packets_dropped_unknown_link);
            return;
        };
        bump(&mut l.stats.packets_received);
        l.stats.bytes_received = l.stats.bytes_received.saturating_add(u64_of(bytes.len()));
        if !self.process_packet(link, bytes) {
            if let Some(l) = self.links.get_mut(&link) {
                bump(&mut l.stats.packets_dropped);
            }
        }
    }

    /// Authenticates and applies one packet. Returns whether it was
    /// accepted.
    fn process_packet(&mut self, link: LinkId, bytes: &[u8]) -> bool {
        let tag = match wire::peek_tag(bytes) {
            Ok(tag) => tag,
            Err(DecodeError::UnknownVersion(_)) => {
                bump(&mut self.stats.packets_dropped_version);
                return false;
            }
            Err(_) => {
                bump(&mut self.stats.packets_dropped_malformed);
                return false;
            }
        };
        let Ok((_, counter, hlen)) = wire::parse_header(bytes) else {
            bump(&mut self.stats.packets_dropped_malformed);
            return false;
        };
        // Trial decryption over the (usually single) contact with this tag.
        // The replay check is cheap and comes first, but the window only
        // moves once the packet authenticates.
        let mut replayed = false;
        let mut opened = None;
        for conv in self.by_tag.get(&tag).into_iter().flatten() {
            let Some(contact) = self.contacts.get(conv) else {
                continue;
            };
            if !contact.replay.fresh(counter) {
                replayed = true;
                continue;
            }
            if let Some(plain) = contact.keys.open(bytes, hlen, counter) {
                opened = Some((*conv, plain));
                break;
            }
        }
        let Some((conv, frames)) = opened else {
            if replayed {
                bump(&mut self.stats.packets_dropped_replay);
            } else {
                bump(&mut self.stats.packets_dropped_unauthenticated);
            }
            return false;
        };
        if let Some(contact) = self.contacts.get_mut(&conv) {
            contact.replay.mark(counter);
        }
        if wire::validate_frames(&frames).is_err() {
            bump(&mut self.stats.packets_dropped_malformed);
            return false;
        }
        if let Some(contact) = self.contacts.get_mut(&conv) {
            contact.route = Some(link);
            contact.heard(self.now, counter);
        }
        for frame in Frames::new(&frames).flatten() {
            match frame {
                Frame::Padding => {}
                Frame::Unknown { .. } => bump(&mut self.stats.frames_unknown),
                Frame::Msg(msg) => self.on_msg(conv, msg),
                Frame::Ack(ack) => self.on_ack(conv, ack),
                Frame::FragAck(fa) => self.on_frag_ack(conv, fa),
            }
        }
        true
    }

    fn on_msg(&mut self, conv: ConversationId, msg: MsgFrame<'_>) {
        let now = self.now;
        let ack_at = now.saturating_add_millis(self.config.ack_delay_ms);
        let max_events = usize_of(self.config.max_pending_events);
        let max_text = usize_of(self.config.max_text_len);
        let window = u64::from(self.config.max_reorder_window);
        let window_bytes = usize_of(self.config.max_reorder_window / 8).saturating_add(1);
        let local = self.local;
        let Some(contact) = self.contacts.get_mut(&conv) else {
            return;
        };
        let schedule_ack = |c: &mut Contact| {
            c.ack_due = Some(c.ack_due.map_or(ack_at, |t| t.min(ack_at)));
        };
        if contact.inbox.contains(msg.seq) {
            bump(&mut self.stats.messages_duplicate);
            schedule_ack(contact);
            return;
        }
        if msg.seq >= contact.inbox.cum.saturating_add(window) {
            bump(&mut self.stats.frames_dropped_window);
            return;
        }
        if self.events.len() >= max_events {
            bump(&mut self.stats.frames_dropped_backpressure);
            return;
        }
        let record = match self
            .reassembly
            .insert(conv, msg.seq, msg.count, msg.index, msg.data)
        {
            Insert::Incomplete => {
                contact.frag_ack_pending.insert(msg.seq);
                schedule_ack(contact);
                return;
            }
            Insert::Invalid => {
                bump(&mut self.stats.frames_dropped_invalid);
                return;
            }
            Insert::NoRoom => {
                bump(&mut self.stats.fragments_dropped_reassembly_full);
                return;
            }
            Insert::Complete(record) => record,
        };
        let Ok(rec) = decode_record(&record, max_text) else {
            bump(&mut self.stats.records_malformed);
            return;
        };
        let event = Event::MessageReceived(ReceivedMessage {
            conversation: conv,
            id: hash::message_id(&contact.key, &local, msg.seq, &record),
            seq: msg.seq,
            lamport: rec.lamport,
            missing_before: contact.inbox.missing_before(msg.seq),
            sender_time: rec.timestamp.map(|s| {
                Timestamp::from_millis(
                    s.saturating_add(TIMESTAMP_EPOCH_UNIX_SECS)
                        .saturating_mul(1000),
                )
            }),
            received_at: now,
            text: rec.text.to_string(),
        });
        let mut inbox = contact.inbox.clone();
        inbox.insert(msg.seq);
        let lamport = contact.lamport.max(rec.lamport);
        let n = self.next_event_key;
        let mut ops = alloc::vec![
            (
                inbox_key(&conv),
                Some(encode_inbox(&inbox, window_bytes, contact.replay.high()))
            ),
            (event_key(n), encode_event(&event)),
        ];
        if lamport != contact.lamport {
            let mut cr = contact.record();
            cr.lamport = lamport;
            ops.push((contact_key(&conv), Some(cr.encode())));
        }
        if commit(&mut self.storage, ops).is_err() {
            // Not acknowledged, so the peer will send it again.
            bump(&mut self.stats.storage_errors);
            return;
        }
        contact.inbox = inbox;
        contact.lamport = lamport;
        contact.frag_ack_pending.remove(&msg.seq);
        schedule_ack(contact);
        self.next_event_key = n.saturating_add(1);
        self.events.push_back((Some(n), event));
        bump(&mut self.stats.messages_received);
    }

    fn on_ack(&mut self, conv: ConversationId, ack: AckFrame<'_>) {
        let now = self.now;
        let room = usize_of(self.config.max_pending_events).saturating_sub(self.events.len());
        let Some(contact) = self.contacts.get_mut(&conv) else {
            return;
        };
        if contact.rtt_sampled.is_none_or(|s| ack.largest > s) {
            if let Some(sent) = contact.sent_at(ack.largest) {
                let raw = now.saturating_millis_since(sent);
                let rtt = if raw > ack.ack_delay {
                    raw.saturating_sub(ack.ack_delay)
                } else {
                    raw
                };
                contact.rtt.sample(rtt);
                contact.rtt_sampled = Some(ack.largest);
                bump(&mut self.stats.rtt_samples);
            }
        }
        // Beyond `room`, ACKed messages stay queued; the peer re-acks.
        let acked: Vec<(u64, MessageId)> = contact
            .outbox
            .range(..ack.horizon())
            .filter(|(&seq, _)| ack.covers(seq))
            .map(|(&seq, m)| (seq, m.id))
            .take(room)
            .collect();
        if acked.is_empty() {
            return;
        }
        let mut ops = Vec::with_capacity(acked.len().saturating_mul(2));
        let mut events = Vec::with_capacity(acked.len());
        let mut n = self.next_event_key;
        for &(seq, id) in &acked {
            let event = Event::MessageDelivered {
                conversation: conv,
                id,
            };
            ops.push((outbox_key(&conv, seq), None));
            ops.push((event_key(n), encode_event(&event)));
            events.push((Some(n), event));
            n = n.saturating_add(1);
        }
        if commit(&mut self.storage, ops).is_err() {
            bump(&mut self.stats.storage_errors);
            return;
        }
        for &(seq, _) in &acked {
            contact.outbox.remove(&seq);
        }
        self.outbox_len = self.outbox_len.saturating_sub(acked.len());
        self.stats.messages_delivered = self
            .stats
            .messages_delivered
            .saturating_add(u64_of(acked.len()));
        self.next_event_key = n;
        self.events.extend(events);
    }

    fn on_frag_ack(&mut self, conv: ConversationId, fa: FragAckFrame<'_>) {
        let now = self.now;
        let Some(planned) = self
            .contacts
            .get_mut(&conv)
            .and_then(|c| c.outbox.get_mut(&fa.seq))
            .and_then(|m| m.plan.as_mut())
        else {
            return;
        };
        if planned.plan.count != fa.count {
            return;
        }
        for (i, f) in (0u64..).zip(planned.frags.iter_mut()) {
            if fa.has(i) && f.held_at.is_none() {
                f.held_at = Some(now);
            }
        }
    }

    /// Advances timers. Call when [`Engine::next_timeout`] is reached, or at
    /// any other time; spurious calls are harmless.
    pub fn handle_timeout(&mut self, now: Timestamp) {
        // Timers are evaluated lazily by `poll_transmit`.
        self.observe(now);
    }

    fn timers(&self, contact: &Contact) -> Timers {
        let probe_floor = self
            .route_of(contact)
            .and_then(|l| self.links.get(&l))
            .map_or(0, |l| {
                Pacer::packet_cost_ms(&l.config.budget, l.config.mtu)
                    .saturating_mul(u64::from(PROBE_BUDGET_INVERSE_SHARE))
            });
        Timers {
            rto: contact.rtt.rto(
                self.config.initial_rto_ms,
                self.config.min_rto_ms,
                self.config.max_rto_ms,
                u64::from(self.config.rttvar_multiplier),
            ),
            max_rto: self.config.max_rto_ms,
            grace: u32::from(self.config.backoff_grace),
            probe_floor,
        }
    }

    /// The link traffic to `contact` goes out on.
    fn route_of(&self, contact: &Contact) -> Option<LinkId> {
        contact
            .route
            .filter(|l| self.links.contains_key(l))
            .or_else(|| self.default_link())
    }

    /// Returns the next packet to send, if any link has both work and budget
    /// for one now. Call repeatedly until it returns `None`.
    ///
    /// Contacts with data due are served before ACK-only packets.
    pub fn poll_transmit(&mut self, now: Timestamp) -> Option<Transmit> {
        self.observe(now);
        let order: Vec<ConversationId> = match self.last_served {
            Some(last) => self
                .contacts
                .range((
                    core::ops::Bound::Excluded(last),
                    core::ops::Bound::Unbounded,
                ))
                .chain(self.contacts.range(..=last))
                .map(|(c, _)| *c)
                .collect(),
            None => self.contacts.keys().copied().collect(),
        };
        for data_pass in [true, false] {
            for &conv in &order {
                if let Some(tx) = self.try_transmit(conv, data_pass) {
                    return Some(tx);
                }
            }
        }
        None
    }

    fn try_transmit(&mut self, conv: ConversationId, data_pass: bool) -> Option<Transmit> {
        let now = self.now;
        let min_space = self.min_frame_space()?;
        let default_link = self.default_link()?;
        let contact = self.contacts.get(&conv)?;
        let timers = self.timers(contact);
        let due = if data_pass {
            contact.data_due(timers)
        } else {
            contact.ack_due
        };
        if due.is_none_or(|t| t > now) {
            return None;
        }
        let link_id = contact
            .route
            .filter(|l| self.links.contains_key(l))
            .unwrap_or(default_link);
        let link = self.links.get(&link_id)?;
        let mtu = link.config.mtu;
        if link.pacer.ready_at(now, mtu) > now {
            return None;
        }
        self.reserve_counter(conv)?;

        let ctx = BuildCtx {
            conv,
            mtu: usize::from(mtu),
            min_space,
            now,
            timers,
            data: data_pass,
            max_ack_bitmap: usize::from(self.config.max_ack_bitmap_bytes),
            max_frag_acks: usize::from(self.config.max_frag_acks_per_packet),
        };
        let contact = self.contacts.get_mut(&conv)?;
        let counter = contact.tx_counter;
        let mut announced = Vec::new();
        let bytes = build_packet(
            contact,
            &ctx,
            &self.reassembly,
            &mut self.rng,
            &mut self.stats,
            &mut announced,
        )?;
        let room = usize_of(self.config.max_pending_events).saturating_sub(self.events.len());
        self.events
            .extend(announced.into_iter().take(room).map(|id| {
                (
                    None,
                    Event::MessageTransmitted {
                        conversation: conv,
                        id,
                    },
                )
            }));
        contact.log_sent(counter, now, usize::from(self.config.max_sent_log));
        let link = self.links.get_mut(&link_id)?;
        link.pacer.consume(now, bytes.len());
        bump(&mut link.stats.packets_sent);
        link.stats.bytes_sent = link.stats.bytes_sent.saturating_add(u64_of(bytes.len()));
        bump(&mut self.stats.packets_sent);
        self.stats.bytes_sent = self.stats.bytes_sent.saturating_add(u64_of(bytes.len()));
        self.last_served = Some(conv);
        Some(Transmit {
            link: link_id,
            to: conv,
            packet: Packet::from_vec(bytes),
        })
    }

    /// Ensures the contact's next packet counter is covered by a durable
    /// reservation, so a restored engine never reuses it.
    fn reserve_counter(&mut self, conv: ConversationId) -> Option<()> {
        let block = u64::from(self.config.counter_reservation);
        let contact = self.contacts.get_mut(&conv)?;
        if contact.tx_counter < contact.counter_reserved {
            return Some(());
        }
        let mut rec = contact.record();
        rec.counter_reserved = contact.tx_counter.saturating_add(block);
        if commit(
            &mut self.storage,
            alloc::vec![(contact_key(&conv), Some(rec.encode()))],
        )
        .is_err()
        {
            bump(&mut self.stats.storage_errors);
            return None;
        }
        contact.counter_reserved = rec.counter_reserved;
        Some(())
    }

    /// Returns the next pending event. Its storage copy is removed now: the
    /// host should process it before its next engine call
    /// (`docs/reliability.md` §4).
    pub fn poll_event(&mut self) -> Option<Event> {
        let (n, event) = self.events.pop_front()?;
        if let Some(n) = n {
            if commit(&mut self.storage, alloc::vec![(event_key(n), None)]).is_err() {
                // The event may be redelivered after a restore.
                bump(&mut self.stats.storage_errors);
            }
        }
        Some(event)
    }

    /// When the engine next wants [`Engine::handle_timeout`] /
    /// [`Engine::poll_transmit`] called. `None` means "only when a new
    /// input arrives". A value at or before the current time means "now".
    pub fn next_timeout(&self) -> Option<Timestamp> {
        let default_link = self.default_link()?;
        self.contacts
            .values()
            .filter_map(|c| {
                let work = c.next_work(self.timers(c))?;
                let link_id = c
                    .route
                    .filter(|l| self.links.contains_key(l))
                    .unwrap_or(default_link);
                let link = self.links.get(&link_id)?;
                Some(work.max(link.pacer.ready_at(self.now, link.config.mtu)))
            })
            .min()
    }

    /// Removes a contact: its outbox (undelivered messages are abandoned
    /// and their IDs returned), receive window and partial reassemblies, in
    /// one storage batch. Already-queued events are kept.
    pub fn remove_contact(
        &mut self,
        conversation: ConversationId,
    ) -> Result<Vec<MessageId>, Error> {
        let contact = self
            .contacts
            .get(&conversation)
            .ok_or(Error::UnknownConversation)?;
        let mut ops: Vec<Op> = contact
            .outbox
            .keys()
            .map(|&seq| (outbox_key(&conversation, seq), None))
            .collect();
        ops.push((contact_key(&conversation), None));
        ops.push((inbox_key(&conversation), None));
        commit(&mut self.storage, ops)?;
        let contact = self
            .contacts
            .remove(&conversation)
            .ok_or(Error::UnknownConversation)?;
        if let Some(convs) = self.by_tag.get_mut(&contact.keys.rx_tag) {
            convs.retain(|c| *c != conversation);
            if convs.is_empty() {
                self.by_tag.remove(&contact.keys.rx_tag);
            }
        }
        self.reassembly.discard_conversation(conversation);
        self.outbox_len = self.outbox_len.saturating_sub(contact.outbox.len());
        if self.last_served == Some(conversation) {
            self.last_served = None;
        }
        Ok(contact.outbox.values().map(|m| m.id).collect())
    }

    /// The public key behind a conversation.
    pub fn contact_key(&self, conversation: ConversationId) -> Option<PublicKey> {
        self.contacts.get(&conversation).map(|c| c.key)
    }

    /// Delivery progress of every undelivered message to `conversation`, in
    /// sequence order.
    pub fn outgoing(&self, conversation: ConversationId) -> Option<Vec<OutgoingStatus>> {
        let contact = self.contacts.get(&conversation)?;
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        Some(
            contact
                .outbox
                .iter()
                .map(|(&seq, m)| {
                    let frags = m.plan.as_ref().map_or(&[][..], |p| &p.frags[..]);
                    OutgoingStatus {
                        id: m.id,
                        seq,
                        queued_at: m.queued_at,
                        transmissions: frags.iter().map(|f| f.sends).max().unwrap_or(0),
                        fragments: count(frags.len()),
                        fragments_held: count(frags.iter().filter(|f| f.held_at.is_some()).count()),
                    }
                })
                .collect(),
        )
    }

    /// Counters and budget state of one link.
    pub fn link_stats(&self, link: LinkId) -> Option<LinkStats> {
        let l = self.links.get(&link)?;
        let ready = l.pacer.ready_at(self.now, l.config.mtu);
        Some(LinkStats {
            budget_blocked_until: (ready > self.now).then_some(ready),
            ..l.stats
        })
    }

    /// Reachability and timers of one contact.
    pub fn contact_status(&self, conversation: ConversationId) -> Option<ContactStatus> {
        let c = self.contacts.get(&conversation)?;
        Some(ContactStatus {
            last_heard: c.last_heard,
            srtt_ms: c.rtt.srtt(),
            rto_ms: self.timers(c).rto,
            unreachable: c.backoff > 0,
            outbox_len: c.outbox.len(),
        })
    }

    /// Diagnostic counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// The engine's configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// This engine's identity.
    pub fn local_key(&self) -> PublicKey {
        self.local
    }

    /// Undelivered outgoing messages across all conversations.
    pub fn outbox_len(&self) -> usize {
        self.outbox_len
    }

    /// Shared access to the host's storage.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    fn observe(&mut self, now: Timestamp) {
        self.now = self.now.max(now);
    }

    fn min_frame_space(&self) -> Option<usize> {
        self.links
            .values()
            .map(|l| frame_space(usize::from(l.config.mtu)))
            .min()
    }

    /// Cheapest link, lowest ID on ties.
    fn default_link(&self) -> Option<LinkId> {
        self.links
            .iter()
            .min_by_key(|(id, l)| (l.config.cost, **id))
            .map(|(id, _)| *id)
    }
}

struct BuildCtx {
    conv: ConversationId,
    mtu: usize,
    min_space: usize,
    now: Timestamp,
    timers: Timers,
    /// Whether data may be included (false: ACK-only pass).
    data: bool,
    max_ack_bitmap: usize,
    max_frag_acks: usize,
}

/// Fills one packet for `contact`: pending ACK and FRAG_ACKs first (small,
/// and they unblock the peer), then due fragments oldest-due first, or a
/// single probe's worth in backoff. Returns `None` if nothing was written.
fn build_packet<R: CryptoRngCore>(
    contact: &mut Contact,
    ctx: &BuildCtx,
    reassembly: &Reassembly,
    rng: &mut R,
    stats: &mut Stats,
    announced: &mut Vec<MessageId>,
) -> Option<Vec<u8>> {
    let now = ctx.now;
    let limit = ctx.mtu.saturating_sub(AEAD_TAG_LEN);
    let mut out = Vec::with_capacity(ctx.mtu);
    let counter = contact.tx_counter;
    begin_packet(&mut out, contact.keys.tx_tag, counter);
    let mut wrote = false;

    if contact.ack_due.is_some() {
        let room = limit.saturating_sub(out.len());
        let cum = contact.inbox.cum;
        let (largest, delay) = contact
            .rx_largest
            .map_or((0, 0), |(c, t)| (c, now.saturating_millis_since(t)));
        let max_bitmap = ctx
            .max_ack_bitmap
            .min(room.saturating_sub(ack_frame_len(cum, largest, delay, 0)));
        let bitmap = contact.inbox.bitmap(max_bitmap);
        if ack_frame_len(cum, largest, delay, bitmap.len()) <= room {
            put_ack_frame(&mut out, cum, largest, delay, &bitmap);
            contact.ack_due = None;
            bump(&mut stats.acks_sent);
            wrote = true;
        }
        let pending: Vec<u64> = contact.frag_ack_pending.iter().copied().collect();
        let mut sent = 0usize;
        for seq in pending {
            if sent >= ctx.max_frag_acks {
                break;
            }
            let Some((count, mut bm)) = reassembly.held(ctx.conv, seq) else {
                contact.frag_ack_pending.remove(&seq);
                continue;
            };
            // FRAG_ACK is advisory, so a bitmap prefix is still correct:
            // truncate to the room left rather than never sending it.
            let room = limit.saturating_sub(out.len());
            let overhead = frag_ack_frame_len(seq, count, 0);
            if overhead.saturating_add(1) > room {
                break;
            }
            bm.truncate(room.saturating_sub(overhead));
            while frag_ack_frame_len(seq, count, bm.len()) > room {
                bm.pop();
            }
            put_frag_ack_frame(&mut out, seq, count, &bm);
            contact.frag_ack_pending.remove(&seq);
            bump(&mut stats.frag_acks_sent);
            sent = sent.saturating_add(1);
            wrote = true;
        }
        if sent > 0 && !contact.frag_ack_pending.is_empty() && contact.ack_due.is_none() {
            // More progress to report than fitted; keep the ACK timer armed.
            // Only after progress, so every re-armed packet shrinks the set.
            contact.ack_due = Some(now);
        }
    }

    if ctx.data && !contact.outbox.is_empty() {
        wrote |= write_data(contact, ctx, &mut out, limit, rng, stats, announced);
    }

    if !wrote {
        return None;
    }
    contact.keys.seal(&mut out, header_len(counter), counter)?;
    contact.tx_counter = counter.saturating_add(1);
    Some(out)
}

/// Writes due fragments into `out`. Returns whether any were written.
fn write_data<R: CryptoRngCore>(
    contact: &mut Contact,
    ctx: &BuildCtx,
    out: &mut Vec<u8>,
    limit: usize,
    rng: &mut R,
    stats: &mut Stats,
    announced: &mut Vec<MessageId>,
) -> bool {
    let now = ctx.now;
    let t = ctx.timers;

    // Plan any message not yet fragmented (or planned for a larger MTU).
    for (&seq, msg) in contact.outbox.iter_mut() {
        if msg.plan.as_ref().is_some_and(|p| p.space <= ctx.min_space) {
            continue;
        }
        let Some(plan) = plan_fragments(ctx.min_space, seq, msg.record.len()) else {
            continue;
        };
        let count = usize::try_from(plan.count).unwrap_or(0);
        msg.plan = Some(Planned {
            plan,
            space: ctx.min_space,
            frags: alloc::vec![FragState::default(); count],
        });
    }

    // A retransmission timer that fires with nothing heard from the peer
    // since that send means the peer is unreachable: switch to probing.
    let mut probe = contact.backoff > 0;
    if !probe {
        let heard = contact.last_fresh;
        probe = contact.outbox.values().any(|m| {
            m.plan.as_ref().is_some_and(|p| {
                p.frags.iter().any(|f| {
                    f.held_at.is_none()
                        && f.last_sent.is_some_and(|sent| {
                            m.frag_due(f, t) <= now && heard.is_none_or(|h| h < sent)
                        })
                })
            })
        });
        if probe {
            contact.deepen_backoff();
        }
    }

    // Candidates in send order. Normal mode: due fragments, oldest-due
    // first (D-020), plus any due within a quarter RTO so that jittered
    // timers of one message still share packets. Probe: every fragment,
    // longest-waiting first, with ones the peer already holds last.
    let horizon = now.saturating_add_millis(t.rto / 4);
    let mut cands: Vec<((bool, Timestamp), u64, u64)> = Vec::new();
    for (&seq, msg) in &contact.outbox {
        let Some(p) = &msg.plan else {
            continue;
        };
        for (i, f) in (0u64..).zip(&p.frags) {
            if probe {
                let waited = f.last_sent.unwrap_or(msg.queued_at);
                cands.push(((f.held_at.is_some(), waited), seq, i));
            } else {
                let due = msg.frag_due(f, t);
                if due <= horizon {
                    cands.push(((false, due), seq, i));
                }
            }
        }
    }
    cands.sort_unstable();

    let mut wrote = false;
    for (_, seq, index) in cands {
        if limit.saturating_sub(out.len()) < 4 {
            break;
        }
        let Some(msg) = contact.outbox.get_mut(&seq) else {
            continue;
        };
        let Some(planned) = msg.plan.as_mut() else {
            continue;
        };
        let plan = planned.plan;
        let Some(data) = msg.record.get(plan.range(index, msg.record.len())) else {
            continue;
        };
        if out
            .len()
            .saturating_add(msg_frame_len(seq, plan.count, index, data.len()))
            > limit
        {
            continue;
        }
        let Some(frag) = usize::try_from(index)
            .ok()
            .and_then(|i| planned.frags.get_mut(i))
        else {
            continue;
        };
        put_msg_frame(out, seq, plan.count, index, data);
        wrote = true;
        if !msg.announced {
            msg.announced = true;
            announced.push(msg.id);
        }
        bump(&mut stats.fragments_sent);
        if frag.sends > 0 {
            bump(&mut stats.retransmissions);
        }
        frag.sends = frag.sends.saturating_add(1);
        frag.last_sent = Some(now);
        frag.held_at = None;
        frag.jitter_ms = rng
            .next_u64()
            .checked_rem((t.rto / 8).saturating_add(1))
            .unwrap_or(0);
    }
    if probe && wrote {
        bump(&mut stats.probes_sent);
        contact.probe_due = now.saturating_add_millis(contact.probe_interval(t));
        contact.deepen_backoff();
    }
    wrote
}

#[cfg(test)]
mod tests;
