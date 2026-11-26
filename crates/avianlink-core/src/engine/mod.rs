mod fec_rx;
mod persist;
mod state;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::ToString;
use alloc::vec::Vec;
use rand_core::CryptoRng;

use crate::config::{FecMode, HelloMode, MAX_SEQ};
use crate::crypto::{Identity, PairKeys};
use crate::fec;
use crate::hash;
use crate::mailbox;
use crate::pacer::Pacer;
use crate::reassembly::{Insert, Reassembly};
use crate::wire::{
    self, ack_frame_len, begin_packet, decode_record, encode_record, frag_ack_frame_len,
    frame_space, header_len, loss_frame_len, msg_frame_len, plan_fragments, put_ack_frame,
    put_frag_ack_frame, put_loss_frame, put_msg_frame, put_repair_frame, repair_frame_len,
    AckFrame, DecodeError, FragAckFrame, Frame, Frames, MsgFrame, PairTag, Record, SyncFrame,
    AEAD_TAG_LEN, HELLO_HINT_LEN, HELLO_KIND, HELLO_LEN, TIMESTAMP_EPOCH_UNIX_SECS,
};
use crate::wire::{
    encode_relay, put_sync_frame, sync_frame_len, ChainRole, Proof, PushHandle, ReceiptHash,
    RelayCode, RelayMsg, HELLO_HINT_LEN as HINT_LEN,
};
use crate::{
    Config, ConversationId, Error, Event, LinkConfig, LinkId, MessageId, Packet, PublicKey,
    ReceivedMessage, Storage, Timestamp,
};
use fec_rx::{FecRx, Window};
use persist::{
    contact_key, decode_event, decode_inbox, decode_outbox, decode_version, encode_event,
    encode_inbox, encode_outbox, event_key, inbox_key, outbox_key, parse_conv_key, parse_event_key,
    parse_outbox_key, tombstone_key, version_record, ContactRecord, Op, Tombstone, KEY_VERSION,
    PREFIX_CONTACT, PREFIX_EVENT, PREFIX_INBOX, PREFIX_OUTBOX, SCHEMA, SCHEMA_V3,
};
use state::{Contact, FragState, OutMsg, Planned, RelaySent, RepairOut, Replay, Timers};

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
    /// The packet carries (part of) a message, not only acknowledgements
    /// or control frames. A relay client marks such uploads so the
    /// recipient's phone is pushed only for them (`docs/push.md` §4.4).
    pub carries_message: bool,
}

/// What [`Engine::handle_packet`] made of a packet, for hosts that track
/// peer addresses (`docs/security.md` §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received {
    /// Dropped, or nothing the host needs to act on. Never move an address.
    Ignored,
    /// An authenticated data packet from this contact, with a counter the
    /// replay window accepted: its source address is the contact's current
    /// one.
    Contact(ConversationId),
    /// A verified Hello from a key that isn't a contact; an
    /// [`Event::ContactRequest`] was queued. Hellos can be replayed, so its
    /// source address is only a candidate for the contact, if accepted.
    ContactRequest(PublicKey),
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
    /// On a relay: fragments the relay has receipted (`docs/relay.md` §6).
    pub fragments_stored: u32,
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
    /// Loss we measure on packets from the contact, permille (before FEC).
    pub loss_in_permille: Option<u64>,
    /// Loss the contact reports on our packets, permille.
    pub loss_out_permille: Option<u64>,
    /// Whether the contact has shown it knows our key (sent us an
    /// authenticated packet). Until then the engine introduces us with
    /// Hellos.
    pub confirmed: bool,
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
    /// Times due work could not be turned into a packet and was pushed
    /// back instead (a bug if non-zero; never a busy loop).
    pub transmit_stalls: u64,
    /// SYNC frames sent.
    pub syncs_sent: u64,
    /// SYNC frames received.
    pub syncs_received: u64,
    /// Storage operations that failed (the triggering input was dropped).
    pub storage_errors: u64,
    /// Packets added to an FEC window as sources.
    pub fec_sources: u64,
    /// REPAIR packets sent.
    pub fec_repairs_sent: u64,
    /// Repairs discarded because the link had no spare budget.
    pub fec_repairs_dropped: u64,
    /// REPAIR frames received.
    pub fec_repairs_received: u64,
    /// Lost packets reconstructed from repairs.
    pub fec_recovered: u64,
    /// LOSS frames sent.
    pub loss_reports_sent: u64,
    /// Hellos sent.
    pub hellos_sent: u64,
    /// Hellos verified (from contacts and from unknown keys).
    pub hellos_received: u64,
    /// Hellos from a key whose contact request is still outstanding.
    pub hellos_duplicate: u64,
    /// Hellos whose hint is not ours.
    pub hellos_dropped_not_for_us: u64,
    /// Hellos from unknown keys dropped unverified: the verification rate
    /// cap was reached, or the event queue was full.
    pub hellos_dropped_rate: u64,
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
    /// A relay link (`docs/relay.md` §6): the relay's retention.
    relay: Option<u64>,
}

/// Retention assumed for a relay until it advertises its own.
const DEFAULT_RELAY_RETENTION_MS: u64 = 7 * 24 * 3_600_000;

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
    fec_rx: FecRx,
    /// Pending events with their storage key number (`None`: transient).
    events: VecDeque<(Option<u64>, Event)>,
    next_event_key: u64,
    stats: Stats,
    /// Latest time seen from the host; never decreases.
    now: Timestamp,
    outbox_len: usize,
    /// Round-robin cursor: the contact that sent most recently.
    last_served: Option<ConversationId>,
    /// Our Hello hint: Hellos with another hint are not for us.
    hint: [u8; HELLO_HINT_LEN],
    /// Verification bucket for Hellos from unknown keys, in thousandths of
    /// a token, and when it was last refilled.
    hello_tokens: u64,
    hello_refilled: Timestamp,
    /// Keys with a verified contact request outstanding, oldest first.
    recent_requests: VecDeque<PublicKey>,
}

impl<S: Storage, R: CryptoRng> Engine<S, R> {
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
            .ok_or(Error::StateMissing)?;
        let (schema, owner) = decode_version(&version).map_err(|_| Error::CorruptStorage)?;
        if schema != SCHEMA && schema != SCHEMA_V3 {
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
            let mut contact = Contact::from_record(&rec, keys);
            e.prepare_contact(&mut contact);
            e.insert_contact(conv, contact);
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
                    stored_announced: false,
                },
            );
            e.outbox_len = e.outbox_len.saturating_add(1);
        }
        for (conv, (inbox, replay_high, digests)) in inboxes {
            let contact = e.contacts.get_mut(&conv).ok_or(Error::CorruptStorage)?;
            contact.inbox = inbox;
            contact.replay = Replay::with_floor(replay_high);
            contact.recv_digests = digests;
        }
        // Announce the restored floor and next to every contact.
        for c in e.contacts.values_mut() {
            c.ack_due = Some(e.now);
        }
        for (n, ev) in events {
            e.next_event_key = e.next_event_key.max(n.saturating_add(1));
            e.events.push_back((Some(n), ev));
        }
        if schema == SCHEMA_V3 {
            // Schema 3 records read as confirmed; new writes carry the flag.
            commit(
                &mut e.storage,
                alloc::vec![(KEY_VERSION.to_vec(), Some(version_record(&local)))],
            )?;
        }
        Ok(e)
    }

    fn empty(config: Config, identity: Identity, storage: S, rng: R) -> Self {
        let local = identity.public_key();
        Self {
            identity,
            reassembly: Reassembly::new(
                usize_of(config.max_reassembly_bytes),
                usize_of(config.max_record_len()),
            ),
            fec_rx: FecRx::new(
                usize_of(config.max_fec_rx_bytes),
                usize::from(config.max_fec_pending_repairs),
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
            hint: hash::hello_hint(&local),
            hello_tokens: u64::from(config.hello_verify_burst).saturating_mul(1000),
            hello_refilled: Timestamp::ZERO,
            recent_requests: VecDeque::new(),
        }
    }

    /// Sets the runtime Hello state of a new or restored contact.
    fn prepare_contact(&self, contact: &mut Contact) {
        contact.introducing = !contact.confirmed && self.config.hello != HelloMode::Off;
        contact.hello = contact.keys.hello(&self.local, &contact.key);
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
                relay: None,
            },
        );
        Ok(())
    }

    /// Registers a link to a store-and-forward relay (`docs/relay.md` §6).
    /// Traffic routed over it relies on relay receipts
    /// ([`Engine::handle_receipt`]) for the hop and on the peer's ACKs end
    /// to end, with no probing. Its MTU must suit the smallest link any
    /// recipient fetches over.
    pub fn add_relay_link(&mut self, id: LinkId, link: LinkConfig) -> Result<(), Error> {
        self.add_link(id, link)?;
        if let Some(l) = self.links.get_mut(&id) {
            l.relay = Some(DEFAULT_RELAY_RETENTION_MS);
        }
        Ok(())
    }

    /// Sets a relay link's retention, as the relay advertises it in every
    /// REPLY. Stored fragments are resent every half of it.
    pub fn set_link_retention(&mut self, id: LinkId, retention_ms: u64) -> Result<(), Error> {
        match self.links.get_mut(&id) {
            Some(LinkState { relay: Some(r), .. }) => {
                *r = retention_ms.max(2);
                Ok(())
            }
            Some(_) => Err(Error::InvalidLinkConfig),
            None => Err(Error::UnknownLink),
        }
    }

    /// Feeds a relay RECEIPT that arrived on `link`: which uploaded
    /// packets the relay stored, or refused. Unknown hashes are ignored. A
    /// receipt never means delivery.
    pub fn handle_receipt(
        &mut self,
        link: LinkId,
        code: RelayCode,
        hashes: &[ReceiptHash],
        now: Timestamp,
    ) {
        self.observe(now);
        if self.links.get(&link).is_none_or(|l| l.relay.is_none()) {
            return;
        }
        let now = self.now;
        let max_rto = self.config.max_rto_ms;
        let room = usize_of(self.config.max_pending_events).saturating_sub(self.events.len());
        let mut stored_events = Vec::new();
        for (&conv, c) in self.contacts.iter_mut() {
            let mut i = 0;
            while i < c.relay_log.len() {
                let Some(entry) = c.relay_log.get(i) else {
                    break;
                };
                if !hashes.contains(&entry.hash) {
                    i = i.saturating_add(1);
                    continue;
                }
                let Some(entry) = c.relay_log.remove(i) else {
                    break;
                };
                match code {
                    RelayCode::Ok => {
                        c.rtt.sample(now.saturating_millis_since(entry.sent_at));
                        for &(seq, index) in &entry.frags {
                            if let Some(f) = c
                                .outbox
                                .get_mut(&seq)
                                .and_then(|m| m.plan.as_mut())
                                .and_then(|p| {
                                    usize::try_from(index).ok().and_then(|i| p.frags.get_mut(i))
                                })
                            {
                                f.stored_at = Some(now);
                            }
                        }
                        if entry.ack && c.ack_sent_at.is_some_and(|t| t <= entry.sent_at) {
                            c.ack_sent_at = None;
                            c.ack_retry_at = None;
                        }
                        if entry.hello {
                            c.hello_stored_at = Some(now);
                        }
                    }
                    RelayCode::Full | RelayCode::NoSession | RelayCode::RateLimited => {
                        // Refused: try again later (another relay, or once
                        // there is room / a session).
                        for &(seq, index) in &entry.frags {
                            if let Some(f) = c
                                .outbox
                                .get_mut(&seq)
                                .and_then(|m| m.plan.as_mut())
                                .and_then(|p| {
                                    usize::try_from(index).ok().and_then(|i| p.frags.get_mut(i))
                                })
                            {
                                f.jitter_ms = max_rto;
                            }
                        }
                        if entry.ack {
                            c.ack_retry_at = Some(now.saturating_add_millis(max_rto));
                        }
                        if entry.hello {
                            c.hello_sent_at = Some(now.saturating_add_millis(max_rto));
                        }
                    }
                    _ => {}
                }
            }
            for m in c.outbox.values_mut() {
                let all = m.plan.as_ref().is_some_and(|p| {
                    !p.frags.is_empty() && p.frags.iter().all(|f| f.stored_at.is_some())
                });
                if all && !m.stored_announced {
                    m.stored_announced = true;
                    stored_events.push(Event::MessageStored {
                        conversation: conv,
                        id: m.id,
                    });
                }
            }
        }
        self.events
            .extend(stored_events.into_iter().take(room).map(|e| (None, e)));
    }

    /// Whether it is safe to go offline from every relay link
    /// (`docs/relay.md` §6): every fragment, ACK and Hello owed to a contact
    /// reached through a relay is stored there. Hosts of the "come online,
    /// collect, reply, leave" kind wait for this before disconnecting.
    /// Contacts on other links are not considered.
    pub fn relay_settled(&self) -> bool {
        self.contacts.values().all(|c| {
            let t = self.timers(c);
            if !t.relay {
                return true;
            }
            let frags_stored = c.outbox.values().all(|m| {
                m.plan.as_ref().is_some_and(|p| {
                    p.frags
                        .iter()
                        .all(|f| f.stored_at.is_some() || f.held_at.is_some())
                })
            });
            let hello_ok = !c.introducing || c.hello_stored_at.is_some() || c.hello.is_none();
            frags_stored && c.ack_due.is_none() && c.ack_retry_at.is_none() && hello_ok
        })
    }

    /// The current relay mailbox epoch (`docs/relay.md` §2.1), from the
    /// host's wall clock.
    pub fn mailbox_epoch(&self) -> u64 {
        mailbox::epoch(self.now.as_millis())
    }

    /// REGISTER messages for both directions of `conversation`'s
    /// mailboxes at `epoch` (`docs/relay.md` §3): outgoing first, then
    /// incoming. Whichever side uses the relay first sends both.
    pub fn mailbox_register(
        &self,
        conversation: ConversationId,
        epoch: u64,
    ) -> Option<[Vec<u8>; 2]> {
        let c = self.contacts.get(&conversation)?;
        let (me, peer) = (self.local, c.key);
        let anchor = |from: &PublicKey, to: &PublicKey, role| {
            c.keys
                .mailbox_seed(from, to, role, epoch)
                .map(|s| mailbox::anchor(&s))
        };
        let out = RelayMsg::Register {
            tag: c.keys.tx_tag,
            up: anchor(&me, &peer, ChainRole::Up)?,
            down: anchor(&me, &peer, ChainRole::Down)?,
        };
        let inc = RelayMsg::Register {
            tag: c.keys.rx_tag,
            up: anchor(&peer, &me, ChainRole::Up)?,
            down: anchor(&peer, &me, ChainRole::Down)?,
        };
        Some([encode_relay(&out), encode_relay(&inc)])
    }

    /// The routing tags of `conversation`'s mailboxes: (outgoing,
    /// incoming). Relay REPLYs name requests by these.
    pub fn mailbox_tags(&self, conversation: ConversationId) -> Option<(PairTag, PairTag)> {
        self.contacts
            .get(&conversation)
            .map(|c| (c.keys.tx_tag, c.keys.rx_tag))
    }

    /// An OPEN for `conversation`'s outgoing mailbox at the current epoch,
    /// consuming (and persisting) one up-chain proof. Send it before
    /// uploading, and again when a session lapses or a RECEIPT says
    /// `NoSession`.
    pub fn mailbox_open(&mut self, conversation: ConversationId) -> Result<Vec<u8>, Error> {
        let epoch = self.mailbox_epoch();
        let proof = self.next_proof(conversation, ChainRole::Up, epoch)?;
        let tag = self
            .contacts
            .get(&conversation)
            .map(|c| c.keys.tx_tag)
            .ok_or(Error::UnknownConversation)?;
        Ok(encode_relay(&RelayMsg::Open { tag, proof }))
    }

    /// A FETCH for `conversation`'s incoming mailbox at `epoch` (the
    /// current one, or the previous while it still holds packets), from
    /// relay sequence number `since`, consuming one down-chain proof.
    /// `release` (≤ `since`) tells the relay every packet below it has
    /// arrived, so it may delete them. `max` limits the page (0: the
    /// relay's page size).
    pub fn mailbox_fetch(
        &mut self,
        conversation: ConversationId,
        epoch: u64,
        since: u64,
        release: u64,
        max: u8,
    ) -> Result<Vec<u8>, Error> {
        let proof = self.next_proof(conversation, ChainRole::Down, epoch)?;
        let tag = self
            .contacts
            .get(&conversation)
            .map(|c| c.keys.rx_tag)
            .ok_or(Error::UnknownConversation)?;
        Ok(encode_relay(&RelayMsg::Fetch {
            tag,
            proof,
            since,
            release: release.min(since),
            max,
        }))
    }

    /// A FETCH_HELLO for Hellos addressed to us (`docs/relay.md` §2.3).
    pub fn hello_fetch(&self, since: u64) -> Vec<u8> {
        encode_relay(&RelayMsg::FetchHello {
            hint: self.hint,
            since,
        })
    }

    /// Our Hello hint.
    pub fn hello_hint(&self) -> [u8; HINT_LEN] {
        self.hint
    }

    /// A PUSH_BIND binding `conversation`'s incoming mailbox at `epoch` to
    /// push `handle` (`docs/push.md` §4.2), consuming one down-chain proof.
    pub fn mailbox_push_bind(
        &mut self,
        conversation: ConversationId,
        epoch: u64,
        handle: PushHandle,
    ) -> Result<Vec<u8>, Error> {
        let proof = self.next_proof(conversation, ChainRole::Down, epoch)?;
        let tag = self
            .contacts
            .get(&conversation)
            .map(|c| c.keys.rx_tag)
            .ok_or(Error::UnknownConversation)?;
        Ok(encode_relay(&RelayMsg::PushBind { tag, proof, handle }))
    }

    /// A PUSH_BIND_HELLO, signed by our identity: push `handle` for Hellos
    /// to us, or with `on` false, stop (`docs/push.md` §4.3).
    pub fn push_bind_hello(&self, handle: PushHandle, on: bool) -> Vec<u8> {
        encode_relay(&RelayMsg::PushBindHello {
            key: self.local.0,
            handle,
            on,
            sig: crate::push::sign_hello_binding(&self.identity, &handle, on),
        })
    }

    /// The HELLO_NOTE to upload beside `hello`, a Hello to `conversation`'s
    /// contact (`docs/push.md` §4.3).
    pub fn hello_note(&self, conversation: ConversationId, hello: &[u8]) -> Option<Vec<u8>> {
        let c = self.contacts.get(&conversation)?;
        Some(encode_relay(&RelayMsg::HelloNote {
            hello_hash: crate::hash::receipt_hash(hello),
            detect: crate::push::detect(&c.key),
        }))
    }

    /// The next proof of one of `conversation`'s chains, persisted before
    /// it is returned so a proof is never reused.
    fn next_proof(
        &mut self,
        conversation: ConversationId,
        role: ChainRole,
        epoch: u64,
    ) -> Result<Proof, Error> {
        let local = self.local;
        let c = self
            .contacts
            .get(&conversation)
            .ok_or(Error::UnknownConversation)?;
        let (from, to) = match role {
            ChainRole::Up => (local, c.key),
            ChainRole::Down => (c.key, local),
        };
        let seed = c
            .keys
            .mailbox_seed(&from, &to, role, epoch)
            .ok_or(Error::InvalidContact)?;
        let used = c
            .chain_used
            .get(&(role, epoch))
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let proof = mailbox::proof(&seed, used).ok_or(Error::Exhausted)?;
        let mut rec = c.record();
        rec.chain_used.insert((role, epoch), used);
        // Keep the current and two previous epochs per role.
        rec.chain_used
            .retain(|&(r, e), _| r != role || e.saturating_add(2) >= epoch);
        commit(
            &mut self.storage,
            alloc::vec![(contact_key(&conversation), Some(rec.encode()))],
        )?;
        if let Some(c) = self.contacts.get_mut(&conversation) {
            c.chain_used = rec.chain_used;
        }
        Ok(proof)
    }

    /// Unregisters a link. Traffic routed over it moves to the cheapest
    /// remaining link.
    pub fn remove_link(&mut self, id: LinkId) -> Result<(), Error> {
        self.links.remove(&id).map(|_| ()).ok_or(Error::UnknownLink)
    }

    /// Adds a contact by public key (obtained out of band, or from an
    /// [`Event::ContactRequest`]) and returns the conversation with them.
    /// Persisted. Accepting a recent request sends a SYNC asking for a reply
    /// at once, so the peer, which has been probing us, learns we are here;
    /// any other new contact is introduced with Hellos (`reliability.md`
    /// §3).
    /// Fails with [`Error::InvalidContact`] for our own key, a duplicate, or
    /// a key that is not a valid, non-weak Ed25519 point.
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
        let mut contact = Contact::new(key, keys);
        // A verified Hello showed the key already knows ours.
        let requested = self.recent_requests.iter().position(|k| *k == key);
        contact.confirmed = requested.is_some();
        let tkey = tombstone_key(&conv);
        let tomb = match self.storage.load(&tkey).map_err(|_| Error::Storage)? {
            Some(v) => Some(Tombstone::decode(&v).map_err(|_| Error::CorruptStorage)?),
            None => None,
        };
        let mut ops = alloc::vec![];
        if let Some(t) = &tomb {
            // Re-added: resume counters, seqs and the receive position, so
            // nothing restarts under the same key (D-046).
            if t.contact.key != key {
                return Err(Error::CorruptStorage);
            }
            contact.next_seq = t.contact.next_seq;
            contact.lamport = t.contact.lamport;
            contact.tx_counter = t.contact.counter_reserved;
            contact.counter_reserved = t.contact.counter_reserved;
            contact.sent_digests = t.contact.sent_digests.clone();
            contact.confirmed |= t.contact.confirmed;
            contact.replay = Replay::with_floor(t.replay_high);
            contact.inbox.cum = t.inbox_cum;
            // Our floor and next tell the peer what we abandoned.
            contact.sync_due = true;
            let window_bytes = usize_of(self.config.max_reorder_window / 8).saturating_add(1);
            ops.push((
                inbox_key(&conv),
                Some(encode_inbox(
                    &contact.inbox,
                    window_bytes,
                    t.replay_high,
                    &[],
                )),
            ));
            ops.push((tkey, None));
        }
        ops.push((contact_key(&conv), Some(contact.record().encode())));
        commit(&mut self.storage, ops)?;
        if let Some(i) = requested {
            self.recent_requests.remove(i);
        }
        self.prepare_contact(&mut contact);
        if contact.confirmed {
            contact.ack_due = Some(self.now);
            contact.sync_due = true;
            contact.sync_reply = true;
        }
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
        Contact::fold_sent(&mut rec.sent_digests, seq, &id);
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
        contact.sent_digests = rec.sent_digests;
        if next_seq % wire::SYNC_BLOCK == 0 {
            // A block completed: its digest rides on the next ACK we send.
            contact.sync_due = true;
        }
        contact.outbox.insert(
            seq,
            OutMsg {
                id,
                record,
                queued_at: now,
                plan: None,
                announced: false,
                stored_announced: false,
            },
        );
        self.outbox_len = self.outbox_len.saturating_add(1);
        Ok(Queued { id, seq, lamport })
    }

    /// Feeds a packet received on `link`. The result tells hosts on
    /// point-to-point transports what to do with the packet's source
    /// address (see [`Received`]). Malformed, unauthenticated or replayed
    /// packets are dropped, counted in [`Stats`], and return
    /// [`Received::Ignored`]; this never fails or panics.
    pub fn handle_packet(&mut self, link: LinkId, bytes: &[u8], now: Timestamp) -> Received {
        self.observe(now);
        bump(&mut self.stats.packets_received);
        let Some(l) = self.links.get_mut(&link) else {
            bump(&mut self.stats.packets_dropped_unknown_link);
            return Received::Ignored;
        };
        bump(&mut l.stats.packets_received);
        l.stats.bytes_received = l.stats.bytes_received.saturating_add(u64_of(bytes.len()));
        let (received, dropped) = if bytes.first() == Some(&HELLO_KIND) {
            self.process_hello(link, bytes)
        } else {
            let sender = self.process_packet(link, bytes);
            (
                sender.map_or(Received::Ignored, Received::Contact),
                sender.is_none(),
            )
        };
        if dropped {
            if let Some(l) = self.links.get_mut(&link) {
                bump(&mut l.stats.packets_dropped);
            }
        }
        received
    }

    /// Handles a Hello (`wire-format.md` §2.5). Returns the result and
    /// whether the packet was dropped.
    fn process_hello(&mut self, link: LinkId, bytes: &[u8]) -> (Received, bool) {
        const DROPPED: (Received, bool) = (Received::Ignored, true);
        let Ok(hello) = wire::parse_hello(bytes) else {
            bump(&mut self.stats.packets_dropped_malformed);
            return DROPPED;
        };
        if hello.hint != self.hint {
            bump(&mut self.stats.hellos_dropped_not_for_us);
            return DROPPED;
        }
        if hello.sender == self.local {
            bump(&mut self.stats.packets_dropped_unauthenticated);
            return DROPPED;
        }
        let now = self.now;
        let conv = hash::conversation_id(&self.local, &hello.sender);
        if let Some(rto) = self.contacts.get(&conv).map(|c| self.timers(c).rto) {
            let Some(c) = self.contacts.get_mut(&conv) else {
                return DROPPED;
            };
            if !c.keys.verify_hello(&hello) {
                bump(&mut self.stats.packets_dropped_unauthenticated);
                return DROPPED;
            }
            bump(&mut self.stats.hellos_received);
            // The peer thinks we don't know it, or hasn't heard from us:
            // answer with a SYNC. A Hello can be a replay, so it doesn't
            // count as fresh and the reply is rate-limited.
            if c.hello_reply_at
                .is_none_or(|t| now.saturating_millis_since(t) >= rto)
            {
                c.hello_reply_at = Some(now);
                c.sync_due = true;
                c.sync_reply = true;
                c.ack_due = Some(c.ack_due.map_or(now, |t| t.min(now)));
            }
            return (Received::Ignored, false);
        }
        if self.recent_requests.contains(&hello.sender) {
            bump(&mut self.stats.hellos_duplicate);
            return (Received::Ignored, false);
        }
        if self.events.len() >= usize_of(self.config.max_pending_events) || !self.take_hello_token()
        {
            bump(&mut self.stats.hellos_dropped_rate);
            return DROPPED;
        }
        let verified = PairKeys::derive(&self.identity, &hello.sender)
            .is_some_and(|keys| keys.verify_hello(&hello));
        if !verified {
            bump(&mut self.stats.packets_dropped_unauthenticated);
            return DROPPED;
        }
        let event = Event::ContactRequest {
            public_key: hello.sender,
            link,
            received_at: now,
        };
        let n = self.next_event_key;
        if commit(
            &mut self.storage,
            alloc::vec![(event_key(n), encode_event(&event))],
        )
        .is_err()
        {
            bump(&mut self.stats.storage_errors);
            return DROPPED;
        }
        self.next_event_key = n.saturating_add(1);
        self.events.push_back((Some(n), event));
        while self.recent_requests.len() >= usize::from(self.config.hello_dedupe_entries) {
            self.recent_requests.pop_front();
        }
        self.recent_requests.push_back(hello.sender);
        bump(&mut self.stats.hellos_received);
        (Received::ContactRequest(hello.sender), false)
    }

    /// Takes one Hello verification token, refilling the bucket first.
    fn take_hello_token(&mut self) -> bool {
        let per_minute = u64::from(self.config.hello_verify_per_minute);
        if per_minute == 0 {
            return false;
        }
        let cap = u64::from(self.config.hello_verify_burst).saturating_mul(1000);
        let elapsed = self.now.saturating_millis_since(self.hello_refilled);
        // per_minute tokens per 60 000 ms = per_minute / 60 thousandths per ms.
        let refill = elapsed.saturating_mul(per_minute) / 60;
        self.hello_tokens = self.hello_tokens.saturating_add(refill).min(cap);
        self.hello_refilled = self.now;
        match self.hello_tokens.checked_sub(1000) {
            Some(left) => {
                self.hello_tokens = left;
                true
            }
            None => false,
        }
    }

    /// Authenticates and applies one packet. Returns the sender if accepted.
    fn process_packet(&mut self, link: LinkId, bytes: &[u8]) -> Option<ConversationId> {
        let tag = match wire::peek_tag(bytes) {
            Ok(tag) => tag,
            Err(DecodeError::UnknownVersion(_)) => {
                bump(&mut self.stats.packets_dropped_version);
                return None;
            }
            Err(_) => {
                bump(&mut self.stats.packets_dropped_malformed);
                return None;
            }
        };
        let Ok((_, counter, hlen)) = wire::parse_header(bytes) else {
            bump(&mut self.stats.packets_dropped_malformed);
            return None;
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
            return None;
        };
        if let Some(contact) = self.contacts.get_mut(&conv) {
            contact.replay.mark(counter);
        }
        if wire::validate_frames(&frames).is_err() {
            bump(&mut self.stats.packets_dropped_malformed);
            return None;
        }
        if let Some(contact) = self.contacts.get_mut(&conv) {
            contact.route = Some(link);
            contact.heard(self.now, counter);
            contact.arrivals.mark(counter);
            contact.rx_since_report = contact.rx_since_report.saturating_add(1);
            if !contact.confirmed {
                // The peer knows our key: introduction is over.
                let mut rec = contact.record();
                rec.confirmed = true;
                if commit(
                    &mut self.storage,
                    alloc::vec![(contact_key(&conv), Some(rec.encode()))],
                )
                .is_ok()
                {
                    contact.confirmed = true;
                    contact.introducing = false;
                } else {
                    bump(&mut self.stats.storage_errors);
                }
            }
        }
        // A repair packet carries only its REPAIR frame and is not a source.
        if let Some(Ok(Frame::Repair(r))) = Frames::new(&frames).next() {
            bump(&mut self.stats.fec_repairs_received);
            if let Some(window) = self.fec_rx.add_repair(conv, &r) {
                self.fec_recover(conv, alloc::vec![window]);
            } else {
                bump(&mut self.stats.frames_dropped_invalid);
            }
            return Some(conv);
        }
        self.fec_rx.store(conv, counter, &frames);
        self.apply_frames(conv, &frames);
        let windows = self.fec_rx.windows_with(conv, counter);
        self.fec_recover(conv, windows);
        Some(conv)
    }

    /// Applies the frames of an authenticated (or FEC-recovered) packet.
    fn apply_frames(&mut self, conv: ConversationId, frames: &[u8]) {
        for frame in Frames::new(frames).flatten() {
            match frame {
                Frame::Padding => {}
                Frame::Unknown { .. } => bump(&mut self.stats.frames_unknown),
                Frame::Msg(msg) => self.on_msg(conv, msg),
                Frame::Ack(ack) => self.on_ack(conv, ack),
                Frame::FragAck(fa) => self.on_frag_ack(conv, fa),
                Frame::Sync(sf) => self.on_sync(conv, sf),
                Frame::Loss(p) => {
                    if let Some(c) = self.contacts.get_mut(&conv) {
                        c.peer_loss = Some(p.min(1000));
                    }
                }
                // Only valid as the sole frame of a packet.
                Frame::Repair(_) => bump(&mut self.stats.frames_dropped_invalid),
            }
        }
    }

    /// Decodes the given windows and processes whatever they recover, which
    /// may in turn complete further windows.
    fn fec_recover(&mut self, conv: ConversationId, mut windows: Vec<Window>) {
        let mut budget = usize::from(self.config.max_fec_pending_repairs);
        while let Some(window) = windows.pop() {
            if budget == 0 {
                break;
            }
            budget = budget.saturating_sub(1);
            for (counter, plain) in self.fec_rx.try_window(conv, window) {
                let Some(contact) = self.contacts.get_mut(&conv) else {
                    return;
                };
                if !contact.replay.fresh(counter) {
                    continue;
                }
                if wire::validate_frames(&plain).is_err() {
                    bump(&mut self.stats.packets_dropped_malformed);
                    continue;
                }
                contact.replay.mark(counter);
                bump(&mut self.stats.fec_recovered);
                self.fec_rx.store(conv, counter, &plain);
                self.apply_frames(conv, &plain);
                windows.extend(self.fec_rx.windows_with(conv, counter));
            }
        }
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
        let record = match self.reassembly.insert(conv, msg.seq, msg.part, msg.data) {
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
        let mut digests = contact.recv_digests.clone();
        if let Event::MessageReceived(m) = &event {
            Contact::fold_recv(&mut digests, msg.seq, &m.id);
        }
        let lamport = contact.lamport.max(rec.lamport);
        let n = self.next_event_key;
        let mut ops = alloc::vec![
            (
                inbox_key(&conv),
                Some(encode_inbox(
                    &inbox,
                    window_bytes,
                    contact.replay.high(),
                    &digests
                ))
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
        contact.recv_digests = digests;
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
        // Through a relay an ACK's "round trip" is the peer's whole absence;
        // receipts measure the hop instead.
        let relay = self
            .contacts
            .get(&conv)
            .is_some_and(|c| self.timers(c).relay);
        let Some(contact) = self.contacts.get_mut(&conv) else {
            return;
        };
        if !relay && contact.rtt_sampled.is_none_or(|s| ack.largest > s) {
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

    /// The peer's reconciliation summary (`docs/reliability.md` §7).
    fn on_sync(&mut self, conv: ConversationId, sf: SyncFrame<'_>) {
        let now = self.now;
        let window_bytes = usize_of(self.config.max_reorder_window / 8).saturating_add(1);
        let room = usize_of(self.config.max_pending_events).saturating_sub(self.events.len());
        if sf.floor > sf.next {
            bump(&mut self.stats.frames_dropped_invalid);
            return;
        }
        let Some(contact) = self.contacts.get_mut(&conv) else {
            return;
        };
        bump(&mut self.stats.syncs_received);
        let ack_now = |c: &mut Contact| c.ack_due = Some(c.ack_due.map_or(now, |t| t.min(now)));
        if sf.reply_wanted() {
            contact.sync_due = true;
            ack_now(contact);
        }
        // Tail loss: seqs we have never seen exist; our ACK tells the peer.
        let known = contact
            .inbox
            .above
            .last()
            .map_or(contact.inbox.cum, |s| s.saturating_add(1))
            .max(contact.inbox.cum);
        if sf.next > known {
            ack_now(contact);
        }
        if room < 2 {
            // Events are backed up; the peer's next SYNC will retry the rest.
            return;
        }
        let mut events = Vec::new();
        for (block, hash) in sf.digests() {
            let full = u8::try_from(wire::SYNC_BLOCK).unwrap_or(u8::MAX);
            let ours = contact
                .recv_digests
                .iter()
                .find(|d| d.0 == block && d.2 == full);
            if ours.is_some_and(|d| d.1 != hash) && !contact.diverged.contains(&block) {
                let first_seq = block.saturating_mul(wire::SYNC_BLOCK);
                events.push(Event::SyncDiverged {
                    conversation: conv,
                    first_seq,
                    last_seq: first_seq.saturating_add(wire::SYNC_BLOCK - 1),
                });
            }
        }
        let mut inbox = None;
        if sf.floor > contact.inbox.cum {
            let mut new = contact.inbox.clone();
            let held = u64_of(new.above.range(new.cum..sf.floor).count());
            let missing = sf.floor.saturating_sub(new.cum).saturating_sub(held);
            if missing > 0 {
                events.push(Event::MessagesSkipped {
                    conversation: conv,
                    first_seq: new.cum,
                    count: missing,
                });
            }
            new.above = new.above.split_off(&sf.floor);
            new.cum = sf.floor;
            new.insert(sf.floor.saturating_sub(1)); // no-op; normalises cum
            while new.above.remove(&new.cum) {
                new.cum = new.cum.saturating_add(1);
            }
            inbox = Some(new);
        }
        if events.is_empty() && inbox.is_none() {
            return;
        }
        let mut ops = Vec::new();
        let mut keyed = Vec::new();
        let mut n = self.next_event_key;
        for ev in events {
            ops.push((event_key(n), encode_event(&ev)));
            keyed.push((Some(n), ev));
            n = n.saturating_add(1);
        }
        if let Some(new) = &inbox {
            ops.push((
                inbox_key(&conv),
                Some(encode_inbox(
                    new,
                    window_bytes,
                    contact.replay.high(),
                    &contact.recv_digests,
                )),
            ));
        }
        if commit(&mut self.storage, ops).is_err() {
            bump(&mut self.stats.storage_errors);
            return;
        }
        for (_, ev) in &keyed {
            if let Event::SyncDiverged { first_seq, .. } = ev {
                contact.diverged.push(first_seq / wire::SYNC_BLOCK);
                if contact.diverged.len() > 16 {
                    contact.diverged.remove(0);
                }
            }
        }
        if let Some(new) = inbox {
            contact.inbox = new;
            self.reassembly.discard_below(conv, sf.floor);
        }
        self.next_event_key = n;
        self.events.extend(keyed);
    }

    /// Tells the engine connectivity may have changed (e.g. the OS reports a
    /// new network): every contact in backoff probes at once instead of
    /// waiting out its probe interval.
    pub fn nudge(&mut self, now: Timestamp) {
        self.observe(now);
        let now = self.now;
        for c in self.contacts.values_mut() {
            if c.backoff > 0 || c.introducing {
                c.probe_due = now;
            }
        }
    }

    fn on_frag_ack(&mut self, conv: ConversationId, fa: FragAckFrame<'_>) {
        let now = self.now;
        let Ok(unit) = usize::try_from(fa.unit) else {
            return;
        };
        let Some(msg) = self
            .contacts
            .get_mut(&conv)
            .and_then(|c| c.outbox.get_mut(&fa.seq))
        else {
            return;
        };
        let len = msg.record.len();
        let Some(planned) = msg.plan.as_mut() else {
            return;
        };
        if unit == 0 {
            return;
        }
        let plan = planned.plan;
        // Fragment [a, b) is held when every block it touches is (wire §3.3).
        for (i, f) in (0u64..).zip(planned.frags.iter_mut()) {
            let r = plan.range(i, len);
            if r.is_empty() || f.held_at.is_some() {
                continue;
            }
            let (Some(first), Some(last)) = (
                r.start.checked_div(unit),
                r.end.saturating_sub(1).checked_div(unit),
            ) else {
                continue;
            };
            let held = (first..=last).all(|k| fa.has(u64::try_from(k).unwrap_or(u64::MAX)));
            if held {
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
        // A probe round may be a Hello plus the probe; both share the 10%.
        let hello_len = if self.hello_probes(contact) {
            u16::try_from(HELLO_LEN).unwrap_or(u16::MAX)
        } else {
            0
        };
        let probe_floor = self
            .route_of(contact)
            .and_then(|l| self.links.get(&l))
            .map_or(0, |l| {
                let hello =
                    (hello_len > 0).then(|| Pacer::packet_cost_ms(&l.config.budget, hello_len));
                Pacer::packet_cost_ms(&l.config.budget, l.config.mtu)
                    .saturating_add(hello.unwrap_or(0))
                    .saturating_mul(u64::from(PROBE_BUDGET_INVERSE_SHARE))
            });
        let relay = self
            .route_of(contact)
            .and_then(|l| self.links.get(&l))
            .and_then(|l| l.relay);
        Timers {
            relay: relay.is_some(),
            resend: relay.map_or(0, |r| r / 2),
            rto: contact.rtt.rto(
                self.config.initial_rto_ms,
                self.config.min_rto_ms,
                self.config.max_rto_ms,
                u64::from(self.config.rttvar_multiplier),
            ),
            max_rto: self.config.max_rto_ms,
            grace: u32::from(self.config.backoff_grace),
            probe_floor,
            probe_cap: self.config.max_probe_interval_ms,
            silence: contact
                .backoff_since
                .map_or(0, |t| self.now.saturating_millis_since(t)),
            deep: contact.backoff_since.is_some_and(|t| {
                self.now.saturating_millis_since(t) >= self.config.deep_backoff_after_ms
            }),
        }
    }

    /// Whether `contact`'s probe rounds start with a Hello
    /// (`reliability.md` §3).
    fn hello_probes(&self, contact: &Contact) -> bool {
        contact.introducing
            || (self.config.hello == HelloMode::UnconfirmedAndBackoff
                && contact.backoff >= u32::from(self.config.backoff_grace))
    }

    /// On a relay: when `contact`'s Hello is next due, while it is
    /// unconfirmed (`relay.md` §6).
    fn relay_hello_due(&self, contact: &Contact, t: Timers) -> Option<Timestamp> {
        if !t.relay || !contact.introducing || contact.hello.is_none() {
            return None;
        }
        Some(match (contact.hello_stored_at, contact.hello_sent_at) {
            (Some(s), _) => s.saturating_add_millis(t.resend),
            (None, Some(sent)) => sent.saturating_add_millis(t.rto),
            (None, None) => Timestamp::ZERO,
        })
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
        self.fec_tick();
        for pass in [Pass::Data, Pass::Repair, Pass::Ack] {
            for &conv in &order {
                if let Some(tx) = self.try_transmit(conv, pass) {
                    return Some(tx);
                }
            }
        }
        None
    }

    /// Whether outgoing traffic to `c` is FEC-coded right now.
    fn fec_on(&self, c: &Contact) -> bool {
        fec_enabled(&self.config, c) && self.fec_link_ok(c)
    }

    /// Whether `c`'s link has the budget for redundancy.
    fn fec_link_ok(&self, c: &Contact) -> bool {
        self.route_of(c)
            .and_then(|l| self.links.get(&l))
            .is_some_and(|l| {
                l.relay.is_none()
                    && Pacer::packet_cost_ms(&l.config.budget, l.config.mtu)
                        <= self.config.fec_max_packet_cost_ms
            })
    }

    /// Closes FEC windows that are full or have waited `fec_flush_ms`, and
    /// drops FEC state for contacts where FEC is off (e.g. in backoff).
    fn fec_tick(&mut self) {
        let now = self.now;
        let cfg = self.config;
        let link_ok: Vec<(ConversationId, bool)> = self
            .contacts
            .iter()
            .map(|(k, c)| (*k, self.fec_link_ok(c)))
            .collect();
        for (k, ok) in link_ok {
            let Some(c) = self.contacts.get_mut(&k) else {
                continue;
            };
            if !ok || !fec_enabled(&cfg, c) {
                c.fec_tx.sources.clear();
                c.fec_tx.pending.clear();
                continue;
            }
            let full = c.fec_tx.sources.len() >= usize::from(cfg.fec_max_sources);
            let due = c.fec_tx.opened.saturating_add_millis(cfg.fec_flush_ms) <= now;
            if !c.fec_tx.sources.is_empty() && (full || due) {
                close_fec_window(c, cfg.fec);
            }
        }
    }

    /// When FEC wants attention for `c`: a pending repair, or a window
    /// waiting to close.
    fn fec_due(&self, c: &Contact) -> Option<Timestamp> {
        if !self.fec_on(c) {
            return None;
        }
        if !c.fec_tx.pending.is_empty() {
            return Some(self.now);
        }
        (!c.fec_tx.sources.is_empty()).then(|| {
            c.fec_tx
                .opened
                .saturating_add_millis(self.config.fec_flush_ms)
        })
    }

    fn try_transmit(&mut self, conv: ConversationId, pass: Pass) -> Option<Transmit> {
        let now = self.now;
        let min_space = self.min_frame_space()?;
        let min_mtu = self.links.values().map(|l| l.config.mtu).min()?;
        let default_link = self.default_link()?;
        let contact = self.contacts.get(&conv)?;
        let timers = self.timers(contact);
        let fec = self.fec_on(contact);
        let relay_hello = self.relay_hello_due(contact, timers);
        let due = match pass {
            Pass::Data => match (contact.data_due(timers), relay_hello) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
            Pass::Repair => (fec && !contact.fec_tx.pending.is_empty()).then_some(now),
            Pass::Ack => contact.ack_due_at(timers),
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
        if pass == Pass::Data
            && contact.probing(timers)
            && contact.hello_round != Some(contact.probe_due)
            && self.hello_probes(contact)
        {
            if let Some(hello) = contact.hello {
                return self.send_hello(conv, link_id, hello, timers);
            }
        }
        if pass == Pass::Data && relay_hello.is_some_and(|t| t <= now) {
            if let Some(hello) = contact.hello {
                return self.send_relay_hello(conv, link_id, hello);
            }
        }
        if timers.relay && contact.ack_retry_at.is_some_and(|t| t <= now) {
            // The last ACK's upload was never receipted: send it again.
            if let Some(c) = self.contacts.get_mut(&conv) {
                c.ack_retry_at = None;
                c.ack_due = Some(now);
            }
        }
        // Repairs only use spare budget: if sending one would leave no room
        // for an MTU-sized packet right after, the link is busy with data and
        // redundancy would only delay it. Such repairs are dropped; the
        // retransmission timer covers any loss.
        if pass == Pass::Repair && link.pacer.ready_at(now, mtu.saturating_mul(2)) > now {
            let dropped = self.contacts.get_mut(&conv).map_or(0, |c| {
                let n = c.fec_tx.pending.len();
                c.fec_tx.pending.clear();
                n
            });
            self.stats.fec_repairs_dropped = self
                .stats
                .fec_repairs_dropped
                .saturating_add(u64_of(dropped));
            return None;
        }
        self.reserve_counter(conv)?;

        let counter = self.contacts.get(&conv)?.tx_counter;
        let fec_cap = fec.then(|| fec_symbol_cap(usize::from(mtu), counter));
        let plan_space = if fec {
            min_space.min(fec_symbol_cap(usize::from(min_mtu), counter))
        } else {
            min_space
        };
        let ctx = BuildCtx {
            conv,
            mtu: usize::from(mtu),
            min_space,
            plan_space,
            fec_cap,
            fec_mode: self.config.fec,
            fec_max_sources: usize::from(self.config.fec_max_sources),
            now,
            timers,
            data: pass == Pass::Data,
            max_ack_bitmap: usize::from(self.config.max_ack_bitmap_bytes),
            max_frag_acks: usize::from(self.config.max_frag_acks_per_packet),
        };
        let contact = self.contacts.get_mut(&conv)?;
        let counter = contact.tx_counter;
        let mut announced = Vec::new();
        let mut log = BuildLog::default();
        let built = if pass == Pass::Repair {
            build_repair(contact, &ctx, &mut self.stats)
        } else {
            build_packet(
                contact,
                &ctx,
                &self.reassembly,
                &mut self.rng,
                &mut self.stats,
                &mut announced,
                &mut log,
            )
        };
        let Some(bytes) = built else {
            if pass != Pass::Repair {
                // Work was due and the link ready, yet nothing could be
                // built. That is a bug, but a host must never spin on it:
                // push the work back and count it (tests assert zero).
                bump(&mut self.stats.transmit_stalls);
                if pass == Pass::Ack {
                    contact.ack_due = None;
                }
                for msg in contact.outbox.values_mut() {
                    if let Some(p) = msg.plan.as_mut() {
                        for f in p
                            .frags
                            .iter_mut()
                            .filter(|f| f.last_sent.is_none_or(|s| s <= now))
                        {
                            f.last_sent = Some(now);
                        }
                    }
                }
                contact.probe_due = contact.probe_due.max(now.saturating_add_millis(1));
            }
            return None;
        };
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
        let carries_message = !log.frags.is_empty();
        if timers.relay {
            // Track the upload until the relay receipts it.
            if log.ack {
                contact.ack_sent_at = Some(now);
                contact.ack_retry_at = Some(now.saturating_add_millis(timers.rto));
            }
            push_relay_log(
                contact,
                RelaySent {
                    hash: hash::receipt_hash(&bytes),
                    sent_at: now,
                    frags: log.frags,
                    ack: log.ack,
                    hello: false,
                },
                usize::from(self.config.max_sent_log),
            );
        }
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
            carries_message,
        })
    }

    /// Sends the Hello that opens `conv`'s current probe round; the probe
    /// itself follows on the next call. In deep backoff the Hello is the
    /// whole round: a peer that knows us answers it with a SYNC, and one
    /// that doesn't learns us from it, so a SYNC probe would add nothing.
    fn send_hello(
        &mut self,
        conv: ConversationId,
        link_id: LinkId,
        hello: [u8; HELLO_LEN],
        timers: Timers,
    ) -> Option<Transmit> {
        let now = self.now;
        let contact = self.contacts.get_mut(&conv)?;
        contact.hello_round = Some(contact.probe_due);
        if timers.deep {
            contact.probe_due = now.saturating_add_millis(contact.probe_interval(timers));
            contact.deepen_backoff(now);
            bump(&mut self.stats.probes_sent);
        }
        let link = self.links.get_mut(&link_id)?;
        link.pacer.consume(now, HELLO_LEN);
        bump(&mut link.stats.packets_sent);
        link.stats.bytes_sent = link.stats.bytes_sent.saturating_add(u64_of(HELLO_LEN));
        bump(&mut self.stats.packets_sent);
        bump(&mut self.stats.hellos_sent);
        self.stats.bytes_sent = self.stats.bytes_sent.saturating_add(u64_of(HELLO_LEN));
        Some(Transmit {
            link: link_id,
            to: conv,
            packet: Packet::from_vec(hello.to_vec()),
            carries_message: false,
        })
    }

    /// Uploads `conv`'s Hello to a relay and tracks it until receipted.
    fn send_relay_hello(
        &mut self,
        conv: ConversationId,
        link_id: LinkId,
        hello: [u8; HELLO_LEN],
    ) -> Option<Transmit> {
        let now = self.now;
        let max_log = usize::from(self.config.max_sent_log);
        let contact = self.contacts.get_mut(&conv)?;
        contact.hello_sent_at = Some(now);
        // A new copy is in flight; the old receipt no longer counts, or the
        // Hello would stay due and be resent forever.
        contact.hello_stored_at = None;
        push_relay_log(
            contact,
            RelaySent {
                hash: hash::receipt_hash(&hello),
                sent_at: now,
                frags: Vec::new(),
                ack: false,
                hello: true,
            },
            max_log,
        );
        let link = self.links.get_mut(&link_id)?;
        link.pacer.consume(now, HELLO_LEN);
        bump(&mut link.stats.packets_sent);
        link.stats.bytes_sent = link.stats.bytes_sent.saturating_add(u64_of(HELLO_LEN));
        bump(&mut self.stats.packets_sent);
        bump(&mut self.stats.hellos_sent);
        self.stats.bytes_sent = self.stats.bytes_sent.saturating_add(u64_of(HELLO_LEN));
        Some(Transmit {
            link: link_id,
            to: conv,
            packet: Packet::from_vec(hello.to_vec()),
            carries_message: false,
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
                let t = self.timers(c);
                let work = [c.next_work(t), self.fec_due(c), self.relay_hello_due(c, t)]
                    .into_iter()
                    .flatten()
                    .min()?;
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
    ///
    /// A tombstone of about 60 bytes stays in storage for good: packet
    /// counters, sequence numbers and the receive position. If the key is
    /// added again, it resumes from there instead of restarting at 0, which
    /// would reuse nonces and let stale ACKs "deliver" new messages (D-046).
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
        let tomb = Tombstone {
            contact: contact.record(),
            replay_high: contact.replay.high(),
            inbox_cum: contact.inbox.cum,
        };
        ops.push((contact_key(&conversation), None));
        ops.push((inbox_key(&conversation), None));
        ops.push((tombstone_key(&conversation), Some(tomb.encode())));
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
        self.fec_rx.discard_conversation(conversation);
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
                        fragments_stored: count(
                            frags.iter().filter(|f| f.stored_at.is_some()).count(),
                        ),
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
            loss_in_permille: c.arrivals.loss_permille(),
            loss_out_permille: c.peer_loss,
            confirmed: c.confirmed,
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

/// Transmit passes, in priority order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pass {
    Data,
    Repair,
    Ack,
}

fn fec_enabled(cfg: &Config, c: &Contact) -> bool {
    cfg.fec != FecMode::Off
        && c.backoff == 0
        && c.peer_loss
            .is_some_and(|p| p >= u64::from(cfg.fec_min_loss_permille))
}

/// Largest plaintext that can be a source: a REPAIR frame carrying it
/// (with a base near `counter` and a 16-bit mask) must fit a worst-case
/// packet on a link with this MTU.
fn fec_symbol_cap(mtu: usize, counter: u64) -> usize {
    let space = frame_space(mtu);
    let overhead =
        repair_frame_len(counter.saturating_add(64), 0xffff, space).saturating_sub(space);
    space.saturating_sub(overhead)
}

/// Turns the current window into repairs.
fn close_fec_window(c: &mut Contact, mode: FecMode) {
    let sources = core::mem::take(&mut c.fec_tx.sources);
    let Some(&(base, _)) = sources.first() else {
        return;
    };
    let k = sources.len();
    // Each window accrues its expected repair need; whole repairs are sent
    // when the credit covers them, so sparse, lightly lossy traffic does not
    // pay a full duplicate per lone packet (D-038).
    let loss = c.peer_loss.unwrap_or(0);
    c.fec_tx.credit = c
        .fec_tx
        .credit
        .saturating_add(fec::repair_credit(k, loss))
        .min(2000u64.saturating_mul(u64::try_from(k).unwrap_or(0)));
    let whole = usize::try_from(c.fec_tx.credit / 1000).unwrap_or(0);
    let m = match mode {
        FecMode::Off => 0,
        FecMode::Xor => whole.min(1),
        FecMode::ReedSolomon => whole.min(k),
    };
    c.fec_tx.credit = c
        .fec_tx
        .credit
        .saturating_sub(u64::try_from(m).unwrap_or(0).saturating_mul(1000));
    if m == 0 {
        return;
    }
    let mask = sources.iter().fold(0u64, |m, &(ctr, _)| {
        m | ctr
            .checked_sub(base)
            .filter(|&d| d < 16)
            .map_or(0, |d| 1u64 << d)
    });
    let refs: Vec<&[u8]> = sources.iter().map(|(_, s)| &s[..]).collect();
    let shape_m = u8::try_from(m.saturating_sub(1)).unwrap_or(0) << 4;
    for (j, data) in fec::encode(&refs, m).into_iter().enumerate() {
        let shape = shape_m | u8::try_from(j).unwrap_or(0) & 0x0f;
        c.fec_tx.pending.push_back(RepairOut {
            base,
            mask,
            shape,
            data,
        });
    }
    while c.fec_tx.pending.len() > 2 * fec::MAX_SOURCES {
        c.fec_tx.pending.pop_front();
    }
}

/// Builds a REPAIR-only packet from the contact's oldest pending repair.
/// Repairs that no longer fit (the counter grew too much) are dropped.
fn build_repair(contact: &mut Contact, ctx: &BuildCtx, stats: &mut Stats) -> Option<Vec<u8>> {
    let counter = contact.tx_counter;
    let mut out = Vec::with_capacity(ctx.mtu);
    begin_packet(&mut out, contact.keys.tx_tag, counter);
    let limit = ctx.mtu.saturating_sub(AEAD_TAG_LEN);
    // Repairs sized for a larger link than the current route cannot be
    // sent; discard all of them now, not one per call (a busy loop found by
    // fuzzing).
    let r = loop {
        let r = contact.fec_tx.pending.pop_front()?;
        if out
            .len()
            .saturating_add(repair_frame_len(r.base, r.mask, r.data.len()))
            <= limit
        {
            break r;
        }
        bump(&mut stats.fec_repairs_dropped);
    };
    put_repair_frame(&mut out, r.base, r.mask, r.shape, &r.data);
    contact.keys.seal(&mut out, header_len(counter), counter)?;
    contact.tx_counter = counter.saturating_add(1);
    bump(&mut stats.fec_repairs_sent);
    Some(out)
}

/// What a built packet carried, for relay receipt tracking.
#[derive(Default)]
struct BuildLog {
    /// (seq, fragment index) written.
    frags: Vec<(u64, u64)>,
    /// An ACK frame was written.
    ack: bool,
}

/// Records a relay upload, dropping the oldest beyond `max` (those then
/// fall back to plain retransmission).
fn push_relay_log(contact: &mut Contact, entry: RelaySent, max: usize) {
    while contact.relay_log.len() >= max {
        contact.relay_log.pop_front();
    }
    contact.relay_log.push_back(entry);
}

struct BuildCtx {
    conv: ConversationId,
    mtu: usize,
    min_space: usize,
    /// Frame space for new fragment plans (smaller while FEC is on).
    plan_space: usize,
    /// While FEC is on: the largest plaintext that can be a source.
    fec_cap: Option<usize>,
    fec_mode: FecMode,
    fec_max_sources: usize,
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
fn build_packet<R: CryptoRng>(
    contact: &mut Contact,
    ctx: &BuildCtx,
    reassembly: &Reassembly,
    rng: &mut R,
    stats: &mut Stats,
    announced: &mut Vec<MessageId>,
    log: &mut BuildLog,
) -> Option<Vec<u8>> {
    let now = ctx.now;
    let hard = ctx.mtu.saturating_sub(AEAD_TAG_LEN);
    let mut out = Vec::with_capacity(ctx.mtu);
    let counter = contact.tx_counter;
    begin_packet(&mut out, contact.keys.tx_tag, counter);
    let hlen = out.len();
    // While FEC is on, pack only up to what a repair can carry, so the
    // packet can be a source. A fragment planned before FEC turned on may
    // still exceed that; `write_data` lets it through alone (uncoded).
    let limit = ctx
        .fec_cap
        .map_or(hard, |cap| hard.min(hlen.saturating_add(cap)));
    let mut wrote = false;
    let mut synced = false;

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
            log.ack = true;
            bump(&mut stats.acks_sent);
            wrote = true;
            if contact.sync_due {
                let (floor, next) = (contact.floor(), contact.next_seq);
                let flags = if contact.sync_reply {
                    wire::SYNC_REPLY_WANTED
                } else {
                    0
                };
                let mut digests = contact.sync_digests();
                // Drop the oldest digests until the frame fits.
                while !digests.is_empty()
                    && out
                        .len()
                        .saturating_add(sync_frame_len(flags, floor, next, &digests))
                        > limit
                {
                    digests.remove(0);
                }
                if out
                    .len()
                    .saturating_add(sync_frame_len(flags, floor, next, &digests))
                    <= limit
                {
                    put_sync_frame(&mut out, flags, floor, next, &digests);
                    contact.sync_due = false;
                    contact.sync_reply = false;
                    synced = true;
                    bump(&mut stats.syncs_sent);
                }
            }
            if let Some(loss) = contact.loss_report_due() {
                if out.len().saturating_add(loss_frame_len(loss)) <= limit {
                    put_loss_frame(&mut out, loss);
                    contact.loss_reported = Some(loss);
                    contact.rx_since_report = 0;
                    bump(&mut stats.loss_reports_sent);
                }
            }
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
        wrote |= write_data(
            contact, ctx, &mut out, limit, hard, rng, stats, announced, log,
        );
    } else if ctx.data && contact.introducing {
        // An introduction with nothing queued: the probe is a SYNC asking
        // for a reply, behind this round's Hello.
        let (floor, next) = (contact.floor(), contact.next_seq);
        let flags = wire::SYNC_REPLY_WANTED;
        if !synced
            && out
                .len()
                .saturating_add(sync_frame_len(flags, floor, next, &[]))
                <= limit
        {
            put_sync_frame(&mut out, flags, floor, next, &[]);
            bump(&mut stats.syncs_sent);
            synced = true;
        }
        if synced {
            wrote = true;
            bump(&mut stats.probes_sent);
        }
        contact.probe_due = now.saturating_add_millis(contact.probe_interval(ctx.timers));
        contact.deepen_backoff(now);
    }

    if !wrote {
        return None;
    }
    if let (Some(cap), Some(plain)) = (ctx.fec_cap, out.get(hlen..)) {
        if plain.len() <= cap {
            let window = &mut contact.fec_tx;
            if window
                .sources
                .first()
                .is_some_and(|&(base, _)| counter.saturating_sub(base) >= 16)
            {
                close_fec_window(contact, ctx.fec_mode);
            }
            let window = &mut contact.fec_tx;
            if window.sources.is_empty() {
                window.opened = now;
            }
            window.sources.push((counter, plain.to_vec()));
            bump(&mut stats.fec_sources);
            if window.sources.len() >= ctx.fec_max_sources {
                close_fec_window(contact, ctx.fec_mode);
            }
        }
    }
    contact.keys.seal(&mut out, header_len(counter), counter)?;
    contact.tx_counter = counter.saturating_add(1);
    Some(out)
}

/// Writes due fragments into `out`. Returns whether any were written.
#[allow(clippy::too_many_arguments)]
fn write_data<R: CryptoRng>(
    contact: &mut Contact,
    ctx: &BuildCtx,
    out: &mut Vec<u8>,
    limit: usize,
    hard: usize,
    rng: &mut R,
    stats: &mut Stats,
    announced: &mut Vec<MessageId>,
    log: &mut BuildLog,
) -> bool {
    let now = ctx.now;
    let t = ctx.timers;

    // Plan any message not yet fragmented (or planned for a larger MTU).
    for (&seq, msg) in contact.outbox.iter_mut() {
        if msg.plan.as_ref().is_some_and(|p| p.space <= ctx.min_space) {
            continue;
        }
        let Some(plan) = plan_fragments(ctx.plan_space, seq, msg.record.len()) else {
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
    let mut probe = contact.probing(t);
    if !probe && !t.relay {
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
            contact.deepen_backoff(now);
        }
    }

    // Candidates in send order. Normal mode: due fragments, oldest-due
    // first (D-020), plus any due within a quarter RTO so that jittered
    // timers of one message still share packets. Probe: every fragment,
    // longest-waiting first, with ones the peer already holds last.
    let horizon = now.saturating_add_millis(t.rto / 4);
    let mut wrote = false;
    // Probes carry the oldest data, as in Phase 2-4, so the first packet
    // through after an outage delivers something. Only in deep backoff
    // (`deep_backoff_after_ms` of silence) do they shrink to a bare SYNC
    // asking for a reply, so long silences stay cheap (D-040).
    let data_probe = !t.deep;
    if probe && !data_probe {
        // No digests: a bare SYNC (≤ 14 bytes) fits any MTU, so a probe can
        // always be built.
        let (floor, next) = (contact.floor(), contact.next_seq);
        let flags = wire::SYNC_REPLY_WANTED;
        if out
            .len()
            .saturating_add(sync_frame_len(flags, floor, next, &[]))
            <= limit
        {
            put_sync_frame(out, flags, floor, next, &[]);
            bump(&mut stats.syncs_sent);
            wrote = true;
        }
    }
    let mut cands: Vec<((bool, Timestamp), u64, u64)> = Vec::new();
    for (&seq, msg) in contact.outbox.iter().filter(|_| !probe || data_probe) {
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
        let part = plan.part(index, msg.record.len());
        let flen = msg_frame_len(seq, part, data.len());
        let end = out.len().saturating_add(flen);
        // A frame that cannot fit `limit` even alone (planned before FEC
        // turned on) may use the hard limit; that packet is not coded.
        let oversize = flen > limit.saturating_sub(header_len(contact.tx_counter));
        if end > limit && !(oversize && end <= hard) {
            continue;
        }
        let Some(frag) = usize::try_from(index)
            .ok()
            .and_then(|i| planned.frags.get_mut(i))
        else {
            continue;
        };
        put_msg_frame(out, seq, part, data);
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
        frag.stored_at = None;
        log.frags.push((seq, index));
        frag.jitter_ms = rng
            .next_u64()
            .checked_rem((t.rto / 8).saturating_add(1))
            .unwrap_or(0);
    }
    if probe && data_probe {
        // If room is left, tell the peer our floor and next: it can then
        // see at once which newer messages it lacks and ACK immediately.
        let (floor, next) = (contact.floor(), contact.next_seq);
        if out
            .len()
            .saturating_add(sync_frame_len(0, floor, next, &[]))
            <= limit
        {
            put_sync_frame(out, 0, floor, next, &[]);
            bump(&mut stats.syncs_sent);
        }
    }
    if probe {
        // Advance the probe timer even if nothing fit, so a probe can never
        // leave the contact due-but-unsendable (a busy loop for the host).
        if wrote {
            bump(&mut stats.probes_sent);
        }
        contact.probe_due = now.saturating_add_millis(contact.probe_interval(t));
        contact.deepen_backoff(now);
    }
    wrote
}

#[cfg(test)]
mod tests;
