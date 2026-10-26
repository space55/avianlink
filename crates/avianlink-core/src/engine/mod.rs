mod state;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::ToString;
use alloc::vec::Vec;
use rand_core::CryptoRngCore;

use crate::hash;
use crate::pacer::Pacer;
use crate::reassembly::{Insert, Reassembly};
use crate::wire::{
    self, ack_frame_len, begin_packet, decode_record, encode_record, frame_space, msg_frame_len,
    plan_fragments, put_ack_frame, put_msg_frame, seal_packet, AckFrame, DecodeError, Frame,
    Frames, MsgFrame, PairTag, Record, CHECK_LEN, TIMESTAMP_EPOCH_UNIX_SECS,
};
use crate::{
    Config, ConversationId, Error, Event, LinkConfig, LinkId, MessageId, Packet, PublicKey,
    ReceivedMessage, Storage, Timestamp,
};
use state::{Contact, FragState, OutMsg, Planned};

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

/// Diagnostic counters. All counters saturate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Packets passed to [`Engine::handle_packet`].
    pub packets_received: u64,
    /// Dropped: arrived on an unregistered link.
    pub packets_dropped_unknown_link: u64,
    /// Dropped: unknown version byte.
    pub packets_dropped_version: u64,
    /// Dropped: too short, or structurally malformed after the check passed.
    pub packets_dropped_malformed: u64,
    /// Dropped: no contact's tag and check matched.
    pub packets_dropped_unauthenticated: u64,
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
    /// ACK frames sent.
    pub acks_sent: u64,
}

fn bump(c: &mut u64) {
    *c = c.saturating_add(1);
}

#[derive(Debug)]
struct LinkState {
    config: LinkConfig,
    pacer: Pacer,
}

/// The sans-IO messaging engine.
///
/// `S` is the host's durable storage, `R` the host's cryptographically
/// secure RNG. See the crate docs for the driving loop.
pub struct Engine<S, R> {
    config: Config,
    local: PublicKey,
    storage: S,
    rng: R,
    links: BTreeMap<LinkId, LinkState>,
    contacts: BTreeMap<ConversationId, Contact>,
    by_tag: BTreeMap<PairTag, Vec<ConversationId>>,
    reassembly: Reassembly,
    events: VecDeque<Event>,
    stats: Stats,
    /// Latest time seen from the host; never decreases.
    now: Timestamp,
    outbox_len: usize,
    /// Round-robin cursor: the contact that sent most recently.
    last_served: Option<ConversationId>,
}

fn usize_of(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

impl<S: Storage, R: CryptoRngCore> Engine<S, R> {
    /// Creates an engine for the identity `local`.
    pub fn new(config: Config, local: PublicKey, storage: S, rng: R) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self {
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
            stats: Stats::default(),
            now: Timestamp::ZERO,
            outbox_len: 0,
            last_served: None,
        })
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
    /// conversation with them.
    pub fn add_contact(&mut self, key: PublicKey) -> Result<ConversationId, Error> {
        if key == self.local {
            return Err(Error::InvalidContact);
        }
        let conv = hash::conversation_id(&self.local, &key);
        if self.contacts.contains_key(&conv) {
            return Err(Error::InvalidContact);
        }
        if self.contacts.len() >= usize_of(self.config.max_contacts) {
            return Err(Error::TooManyContacts);
        }
        let tx_tag = hash::pair_tag(&self.local, &key);
        let rx_tag = hash::pair_tag(&key, &self.local);
        self.contacts.insert(conv, Contact::new(key, tx_tag));
        self.by_tag.entry(rx_tag).or_default().push(conv);
        Ok(conv)
    }

    /// Queues a text message. On `Ok` the message is queued ("sent");
    /// delivery is reported later as [`Event::MessageDelivered`] with the
    /// returned ID.
    pub fn send_text(
        &mut self,
        conversation: ConversationId,
        text: &str,
        now: Timestamp,
    ) -> Result<MessageId, Error> {
        self.observe(now);
        if text.len() > usize_of(self.config.max_text_len) {
            return Err(Error::TextTooLong);
        }
        let timestamp = self
            .config
            .wall_clock
            .then(|| (self.now.as_millis() / 1000).saturating_sub(TIMESTAMP_EPOCH_UNIX_SECS));
        let local = self.local;
        let contact = self
            .contacts
            .get_mut(&conversation)
            .ok_or(Error::UnknownConversation)?;
        if self.outbox_len >= usize_of(self.config.max_outbox_messages) {
            return Err(Error::OutboxFull);
        }
        let seq = contact.next_seq;
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
        contact.next_seq = next_seq;
        contact.lamport = lamport;
        contact.outbox.insert(
            seq,
            OutMsg {
                id,
                record,
                queued_at: self.now,
                plan: None,
            },
        );
        self.outbox_len = self.outbox_len.saturating_add(1);
        Ok(id)
    }

    /// Feeds a packet received on `link`. Malformed or unauthenticated
    /// packets are dropped and counted in [`Stats`]; this never fails or
    /// panics.
    pub fn handle_packet(&mut self, link: LinkId, bytes: &[u8], now: Timestamp) {
        self.observe(now);
        bump(&mut self.stats.packets_received);
        if !self.links.contains_key(&link) {
            bump(&mut self.stats.packets_dropped_unknown_link);
            return;
        }
        let tag = match wire::peek_tag(bytes) {
            Ok(tag) => tag,
            Err(DecodeError::UnknownVersion(_)) => {
                bump(&mut self.stats.packets_dropped_version);
                return;
            }
            Err(_) => {
                bump(&mut self.stats.packets_dropped_malformed);
                return;
            }
        };
        let local = self.local;
        let contacts = &self.contacts;
        let sender = self.by_tag.get(&tag).and_then(|candidates| {
            candidates.iter().copied().find(|c| {
                contacts
                    .get(c)
                    .is_some_and(|ct| wire::verify_check(bytes, &ct.key, &local))
            })
        });
        let Some(conv) = sender else {
            bump(&mut self.stats.packets_dropped_unauthenticated);
            return;
        };
        let frames = match wire::split_verified(bytes) {
            Ok((_counter, frames)) if wire::validate_frames(frames).is_ok() => frames,
            _ => {
                bump(&mut self.stats.packets_dropped_malformed);
                return;
            }
        };
        if let Some(contact) = self.contacts.get_mut(&conv) {
            contact.route = Some(link);
        }
        for frame in Frames::new(frames).flatten() {
            match frame {
                Frame::Padding => {}
                Frame::Unknown { .. } => bump(&mut self.stats.frames_unknown),
                Frame::Msg(msg) => self.on_msg(conv, msg),
                Frame::Ack(ack) => self.on_ack(conv, ack),
            }
        }
    }

    fn on_msg(&mut self, conv: ConversationId, msg: MsgFrame<'_>) {
        let now = self.now;
        let ack_at = now.saturating_add_millis(self.config.ack_delay_ms);
        let max_events = usize_of(self.config.max_pending_events);
        let max_text = usize_of(self.config.max_text_len);
        let window = u64::from(self.config.max_reorder_window);
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
            Insert::Incomplete => return,
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
        let id = hash::message_id(&contact.key, &local, msg.seq, &record);
        contact.inbox.insert(msg.seq);
        contact.lamport = contact.lamport.max(rec.lamport);
        schedule_ack(contact);
        let sender_time = rec.timestamp.map(|s| {
            Timestamp::from_millis(
                s.saturating_add(TIMESTAMP_EPOCH_UNIX_SECS)
                    .saturating_mul(1000),
            )
        });
        self.events
            .push_back(Event::MessageReceived(ReceivedMessage {
                conversation: conv,
                id,
                seq: msg.seq,
                lamport: rec.lamport,
                sender_time,
                received_at: now,
                text: rec.text.to_string(),
            }));
        bump(&mut self.stats.messages_received);
    }

    fn on_ack(&mut self, conv: ConversationId, ack: AckFrame<'_>) {
        let max_events = usize_of(self.config.max_pending_events);
        let Some(contact) = self.contacts.get_mut(&conv) else {
            return;
        };
        let acked: Vec<u64> = contact
            .outbox
            .range(..ack.horizon())
            .map(|(&seq, _)| seq)
            .filter(|&seq| ack.covers(seq))
            .collect();
        for seq in acked {
            if self.events.len() >= max_events {
                // Left in the outbox; the peer re-acks on retransmission.
                break;
            }
            if let Some(msg) = contact.outbox.remove(&seq) {
                self.outbox_len = self.outbox_len.saturating_sub(1);
                bump(&mut self.stats.messages_delivered);
                self.events.push_back(Event::MessageDelivered {
                    conversation: conv,
                    id: msg.id,
                });
            }
        }
    }

    /// Advances timers. Call when [`Engine::next_timeout`] is reached, or at
    /// any other time; spurious calls are harmless.
    pub fn handle_timeout(&mut self, now: Timestamp) {
        // Phase 1 timers are evaluated lazily by `poll_transmit`.
        self.observe(now);
    }

    /// Returns the next packet to send, if any link has both work and budget
    /// for one now. Call repeatedly until it returns `None`.
    pub fn poll_transmit(&mut self, now: Timestamp) -> Option<Transmit> {
        self.observe(now);
        let now = self.now;
        let min_space = self.min_frame_space()?;
        let default_link = self.default_link()?;
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
        let rto = self.config.retransmit_interval_ms;
        for conv in order {
            let Some(contact) = self.contacts.get_mut(&conv) else {
                continue;
            };
            if contact.next_work().is_none_or(|t| t > now) {
                continue;
            }
            let link_id = contact
                .route
                .filter(|l| self.links.contains_key(l))
                .unwrap_or(default_link);
            let Some(link) = self.links.get_mut(&link_id) else {
                continue;
            };
            let mtu = link.config.mtu;
            if link.pacer.ready_at(now, mtu) > now {
                continue;
            }
            let ctx = BuildCtx {
                local: &self.local,
                mtu: usize::from(mtu),
                min_space,
                now,
                rto,
                max_ack_bitmap: usize::from(self.config.max_ack_bitmap_bytes),
            };
            let Some(bytes) = build_packet(contact, &ctx, &mut self.rng, &mut self.stats) else {
                continue;
            };
            link.pacer.consume(now, bytes.len());
            bump(&mut self.stats.packets_sent);
            self.stats.bytes_sent = self
                .stats
                .bytes_sent
                .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
            self.last_served = Some(conv);
            return Some(Transmit {
                link: link_id,
                to: conv,
                packet: Packet::from_vec(bytes),
            });
        }
        None
    }

    /// Returns the next pending event.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When the engine next wants [`Engine::handle_timeout`] /
    /// [`Engine::poll_transmit`] called. `None` means "only when a new
    /// input arrives". A value at or before the current time means "now".
    pub fn next_timeout(&self) -> Option<Timestamp> {
        let default_link = self.default_link()?;
        self.contacts
            .values()
            .filter_map(|c| {
                let work = c.next_work()?;
                let link_id = c
                    .route
                    .filter(|l| self.links.contains_key(l))
                    .unwrap_or(default_link);
                let link = self.links.get(&link_id)?;
                Some(work.max(link.pacer.ready_at(self.now, link.config.mtu)))
            })
            .min()
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

struct BuildCtx<'a> {
    local: &'a PublicKey,
    mtu: usize,
    min_space: usize,
    now: Timestamp,
    rto: u64,
    max_ack_bitmap: usize,
}

/// Fills one packet for `contact`: a pending ACK first (it is small and
/// unblocks the peer), then due fragments in seq order. Returns `None` if
/// nothing was due.
fn build_packet<R: CryptoRngCore>(
    contact: &mut Contact,
    ctx: &BuildCtx<'_>,
    rng: &mut R,
    stats: &mut Stats,
) -> Option<Vec<u8>> {
    let limit = ctx.mtu.saturating_sub(CHECK_LEN);
    let mut out = Vec::with_capacity(ctx.mtu);
    begin_packet(&mut out, contact.tx_tag, contact.tx_counter);
    let mut wrote = false;

    if contact.ack_due.is_some() {
        let room = limit.saturating_sub(out.len());
        let cum = contact.inbox.cum;
        let max_bitmap = ctx
            .max_ack_bitmap
            .min(room.saturating_sub(ack_frame_len(cum, 0)));
        let bitmap = contact.inbox.bitmap(max_bitmap);
        if ack_frame_len(cum, bitmap.len()) <= room {
            put_ack_frame(&mut out, cum, &bitmap);
            contact.ack_due = None;
            bump(&mut stats.acks_sent);
            wrote = true;
        }
    }

    for (&seq, msg) in contact.outbox.iter_mut() {
        if msg.plan.as_ref().is_none_or(|p| p.space > ctx.min_space) {
            let Some(plan) = plan_fragments(ctx.min_space, seq, msg.record.len()) else {
                continue;
            };
            let count = usize::try_from(plan.count).unwrap_or(0);
            msg.plan = Some(Planned {
                plan,
                space: ctx.min_space,
                frags: alloc::vec![
                    FragState {
                        next_send: ctx.now,
                        sends: 0
                    };
                    count
                ],
            });
        }
        let Some(planned) = msg.plan.as_mut() else {
            continue;
        };
        let plan = planned.plan;
        for (index, frag) in (0u64..).zip(planned.frags.iter_mut()) {
            if frag.next_send > ctx.now {
                continue;
            }
            let Some(data) = msg.record.get(plan.range(index, msg.record.len())) else {
                continue;
            };
            let len = msg_frame_len(seq, plan.count, index, data.len());
            if out.len().saturating_add(len) > limit {
                continue;
            }
            put_msg_frame(&mut out, seq, plan.count, index, data);
            wrote = true;
            bump(&mut stats.fragments_sent);
            if frag.sends > 0 {
                bump(&mut stats.retransmissions);
            }
            frag.sends = frag.sends.saturating_add(1);
            let jitter = rng
                .next_u64()
                .checked_rem((ctx.rto / 4).saturating_add(1))
                .unwrap_or(0);
            frag.next_send = ctx
                .now
                .saturating_add_millis(ctx.rto.saturating_add(jitter));
        }
        if limit.saturating_sub(out.len()) < 4 {
            break;
        }
    }

    if !wrote {
        return None;
    }
    seal_packet(&mut out, ctx.local, &contact.key);
    contact.tx_counter = contact.tx_counter.saturating_add(1);
    Some(out)
}

#[cfg(test)]
mod tests;
