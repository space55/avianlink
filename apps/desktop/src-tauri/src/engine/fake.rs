//! An engine that behaves like a bad link, in process.
//!
//! **Phase 0 scope: structurally complete, behaviourally inert.** It keeps
//! real contact, link and outbox state and assigns real sequence and Lamport
//! numbers, so the command layer and the driver can be built and tested
//! against it. It does not yet transmit, deliver, lose, delay or reorder
//! anything: a message sent through it stays `queued` forever, which is an
//! honest state for a link with no peer on the far end.
//!
//! Phase 1 adds the impairments the UI must be designed against — delivery
//! delays from seconds to hours with jitter, loss with eventual delivery,
//! out-of-order arrival, scripted peers whose replies arrive long after the
//! message they answer, and link up/down transitions. The extension points
//! are marked below.
//!
//! The RNG is seeded from a constant so that a session replays identically
//! and a UI bug seen in a demo can be reproduced (desktop DA-010).

use std::collections::{BTreeMap, VecDeque};

use avianlink_core::{
    hashes, Config, ConversationId, Error, LinkConfig, LinkId, MessageId, PublicKey, Queued,
    Timestamp, Transmit,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

use super::{EngineEvent, EngineHandle, LinkHealth};

/// Seed for the fake's RNG. Fixed so sessions are reproducible.
const FAKE_SEED: u64 = 0x6176_6961_6e6c_696e;

/// Domain separator for the fake's message identifiers.
///
/// The fake invents its own IDs rather than using the real wire format's,
/// because its packets never meet a real peer. Content-addressing is kept:
/// the same text at the same sequence number yields the same ID, so the
/// deduplication the UI relies on is exercised.
const FAKE_MESSAGE_LABEL: &[u8] = b"avianlink/fake/msg";

/// Per-conversation state the fake tracks.
#[derive(Clone, Debug)]
struct Contact {
    #[expect(dead_code, reason = "Phase 1 routes to the scripted peer by key")]
    key: PublicKey,
    /// Next sequence number we will use for this conversation.
    next_seq: u64,
    /// Lamport clock, advanced on send and on receive.
    lamport: u64,
    /// Queued outgoing messages, by sequence number.
    outbox: BTreeMap<u64, OutMessage>,
}

/// An outgoing message the fake is holding.
#[derive(Clone, Debug)]
struct OutMessage {
    #[expect(dead_code, reason = "Phase 1 reports it with MessageTransmitted")]
    id: MessageId,
    #[expect(dead_code, reason = "Phase 1 delivers the text to the scripted peer")]
    text: String,
    #[expect(dead_code, reason = "Phase 1 computes the retransmission deadline")]
    queued_at: Timestamp,
    /// Transmissions so far.
    #[expect(dead_code, reason = "Phase 1 increments it per retransmission")]
    attempts: u32,
}

/// A link the fake is pretending to own.
#[derive(Clone, Debug)]
struct Link {
    #[expect(dead_code, reason = "Phase 1 sizes fake fragments from its MTU")]
    config: LinkConfig,
    health: LinkHealth,
}

/// In-process stand-in for the real engine.
pub struct FakeEngine {
    local: PublicKey,
    config: Config,
    contacts: BTreeMap<ConversationId, Contact>,
    links: BTreeMap<LinkId, Link>,
    events: VecDeque<EngineEvent>,
    outbox_len: usize,
    /// Reserved for Phase 1's impairments; constructed now so the seed and
    /// its reproducibility guarantee are established from the start.
    #[expect(dead_code, reason = "Phase 1 draws loss, delay and jitter from it")]
    rng: ChaCha20Rng,
}

impl FakeEngine {
    /// Creates a fake engine with the default engine limits.
    pub fn new(local: PublicKey) -> Self {
        Self::with_config(local, Config::default())
    }

    /// Creates a fake engine with explicit limits, so tests can drive the
    /// app into `OutboxFull` and `TextTooLong` without queueing a thousand
    /// messages.
    pub fn with_config(local: PublicKey, config: Config) -> Self {
        Self {
            local,
            config,
            contacts: BTreeMap::new(),
            links: BTreeMap::new(),
            events: VecDeque::new(),
            outbox_len: 0,
            rng: ChaCha20Rng::seed_from_u64(FAKE_SEED),
        }
    }

    /// Pushes an event for the driver to drain. Used by Phase 1's scripted
    /// scenarios and by tests.
    pub fn push_event(&mut self, event: EngineEvent) {
        self.events.push_back(event);
    }

    /// The conversation this fake shares with `key`, whether or not it is a
    /// contact. Lets tests name a conversation before adding it.
    pub fn conversation_with(&self, key: &PublicKey) -> ConversationId {
        hashes::conversation_id(&self.local, key)
    }

    /// Content-addressed identifier for a fake message.
    fn message_id(&self, conversation: &ConversationId, seq: u64, text: &str) -> MessageId {
        let mut hasher = Sha256::new();
        hasher.update(FAKE_MESSAGE_LABEL);
        hasher.update(conversation.0);
        hasher.update(seq.to_be_bytes());
        hasher.update(text.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        MessageId(out)
    }
}

impl EngineHandle for FakeEngine {
    fn local_key(&self) -> PublicKey {
        self.local
    }

    fn add_contact(&mut self, key: PublicKey) -> Result<ConversationId, Error> {
        if key == self.local {
            return Err(Error::InvalidContact);
        }
        if self.contacts.len() >= self.config.max_contacts as usize {
            return Err(Error::TooManyContacts);
        }
        let conversation = hashes::conversation_id(&self.local, &key);
        if self.contacts.contains_key(&conversation) {
            return Err(Error::InvalidContact);
        }
        self.contacts.insert(
            conversation,
            Contact {
                key,
                next_seq: 0,
                lamport: 0,
                outbox: BTreeMap::new(),
            },
        );
        Ok(conversation)
    }

    fn add_link(&mut self, id: LinkId, config: LinkConfig) -> Result<(), Error> {
        config.validate()?;
        if self.links.len() >= self.config.max_links as usize {
            return Err(Error::TooManyLinks);
        }
        if self.links.contains_key(&id) {
            return Err(Error::LinkExists);
        }
        let health = LinkHealth {
            up: true,
            // The fake knows exactly what it drops, so unlike the real engine
            // it can report loss. Phase 0 drops nothing.
            loss_permille: Some(0),
            budget_blocked_until: None,
        };
        self.links.insert(id, Link { config, health });
        self.events
            .push_back(EngineEvent::LinkChanged { link: id, health });
        Ok(())
    }

    fn remove_link(&mut self, id: LinkId) -> Result<(), Error> {
        self.links.remove(&id).ok_or(Error::UnknownLink)?;
        self.events.push_back(EngineEvent::LinkChanged {
            link: id,
            health: LinkHealth::default(),
        });
        Ok(())
    }

    fn send_text(
        &mut self,
        conversation: ConversationId,
        text: &str,
        now: Timestamp,
    ) -> Result<Queued, Error> {
        if text.len() > self.config.max_text_len as usize {
            return Err(Error::TextTooLong);
        }
        if self.outbox_len >= self.config.max_outbox_messages as usize {
            return Err(Error::OutboxFull);
        }
        let id = self.message_id(
            &conversation,
            self.contacts
                .get(&conversation)
                .ok_or(Error::UnknownConversation)?
                .next_seq,
            text,
        );
        let contact = self
            .contacts
            .get_mut(&conversation)
            .ok_or(Error::UnknownConversation)?;
        let seq = contact.next_seq;
        let lamport = contact.lamport.checked_add(1).ok_or(Error::Exhausted)?;
        contact.next_seq = seq.checked_add(1).ok_or(Error::Exhausted)?;
        contact.lamport = lamport;
        contact.outbox.insert(
            seq,
            OutMessage {
                id,
                text: text.to_string(),
                queued_at: now,
                attempts: 0,
            },
        );
        self.outbox_len = self.outbox_len.saturating_add(1);
        // Phase 1: schedule the first transmission here, which is what
        // produces `MessageTransmitted` and eventually `MessageDelivered`.
        Ok(Queued { id, seq, lamport })
    }

    fn handle_packet(&mut self, _link: LinkId, _bytes: &[u8], _now: Timestamp) {
        // Phase 1: decode the fake's own framing and deliver to the peer
        // side of the simulated conversation. Nothing can arrive in Phase 0
        // because nothing is transmitted.
    }

    fn handle_timeout(&mut self, _now: Timestamp) {
        // Phase 1: fire scheduled deliveries, retransmissions, scripted
        // replies and link outage transitions.
    }

    fn poll_transmit(&mut self, _now: Timestamp) -> Option<Transmit> {
        // Phase 1: pace queued fragments onto the fake links.
        None
    }

    fn poll_event(&mut self) -> Option<EngineEvent> {
        self.events.pop_front()
    }

    fn next_timeout(&self) -> Option<Timestamp> {
        // Phase 1: the earliest scheduled delivery, retransmission or outage
        // transition. `None` means "nothing pending", and the driver then
        // sleeps until a packet or a command arrives.
        None
    }

    fn link_health(&self, link: LinkId) -> Option<LinkHealth> {
        self.links.get(&link).map(|l| l.health)
    }

    fn outbox_len(&self) -> usize {
        self.outbox_len
    }

    fn reports_transmissions(&self) -> bool {
        // The fake owns its links, so it knows exactly which message left and
        // on which attempt.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use avianlink_core::{LinkBudget, MIN_MTU};

    fn link_config() -> LinkConfig {
        LinkConfig {
            mtu: 1200,
            budget: LinkBudget::Unlimited,
            cost: 1,
        }
    }

    fn engine() -> FakeEngine {
        FakeEngine::new(PublicKey([1; 32]))
    }

    #[test]
    fn conversation_id_is_symmetric_with_the_librarys() {
        // The fake must agree with the real engine about conversation IDs, or
        // a contact added on the fake would change identity on the real one.
        let local = PublicKey([1; 32]);
        let peer = PublicKey([2; 32]);
        let fake = FakeEngine::new(local);
        assert_eq!(
            fake.conversation_with(&peer),
            hashes::conversation_id(&peer, &local)
        );
    }

    #[test]
    fn adding_a_contact_twice_conflicts_and_self_is_refused() {
        let mut e = engine();
        let peer = PublicKey([2; 32]);
        let conversation = e.add_contact(peer).unwrap();
        assert_eq!(conversation, e.conversation_with(&peer));
        assert_eq!(e.add_contact(peer), Err(Error::InvalidContact));
        assert_eq!(
            e.add_contact(PublicKey([1; 32])),
            Err(Error::InvalidContact)
        );
    }

    #[test]
    fn contact_limit_is_enforced() {
        let config = Config {
            max_contacts: 1,
            ..Config::default()
        };
        let mut e = FakeEngine::with_config(PublicKey([1; 32]), config);
        e.add_contact(PublicKey([2; 32])).unwrap();
        assert_eq!(
            e.add_contact(PublicKey([3; 32])),
            Err(Error::TooManyContacts)
        );
    }

    #[test]
    fn links_register_once_and_report_health() {
        let mut e = engine();
        e.add_link(LinkId(1), link_config()).unwrap();
        assert_eq!(
            e.poll_event(),
            Some(EngineEvent::LinkChanged {
                link: LinkId(1),
                health: LinkHealth {
                    up: true,
                    loss_permille: Some(0),
                    budget_blocked_until: None,
                },
            })
        );
        assert!(e.link_health(LinkId(1)).is_some_and(|h| h.up));
        assert_eq!(e.add_link(LinkId(1), link_config()), Err(Error::LinkExists));
        assert_eq!(e.remove_link(LinkId(2)), Err(Error::UnknownLink));
        e.remove_link(LinkId(1)).unwrap();
        assert_eq!(e.link_health(LinkId(1)), None);
    }

    #[test]
    fn invalid_link_config_is_rejected() {
        let mut e = engine();
        let bad = LinkConfig {
            mtu: MIN_MTU - 1,
            ..link_config()
        };
        assert_eq!(e.add_link(LinkId(1), bad), Err(Error::InvalidLinkConfig));
    }

    #[test]
    fn sending_assigns_dense_seqs_and_increasing_lamports() {
        let mut e = engine();
        let c = e.add_contact(PublicKey([2; 32])).unwrap();
        let a = e.send_text(c, "one", Timestamp::from_millis(1)).unwrap();
        let b = e.send_text(c, "two", Timestamp::from_millis(2)).unwrap();
        assert_eq!((a.seq, b.seq), (0, 1));
        assert!(b.lamport > a.lamport);
        assert_eq!(e.outbox_len(), 2);
    }

    #[test]
    fn message_ids_are_content_addressed() {
        // Same text at the same seq in the same conversation must collide, so
        // the deduplication the UI relies on is real.
        let mut e = engine();
        let c = e.add_contact(PublicKey([2; 32])).unwrap();
        let first = e.send_text(c, "hello", Timestamp::ZERO).unwrap();
        let mut other = engine();
        let c2 = other.add_contact(PublicKey([2; 32])).unwrap();
        let same = other.send_text(c2, "hello", Timestamp::ZERO).unwrap();
        assert_eq!(first.id, same.id);
        let different = e.send_text(c, "hello", Timestamp::ZERO).unwrap();
        assert_ne!(first.id, different.id, "different seq, different id");
    }

    #[test]
    fn sending_to_an_unknown_conversation_fails() {
        let mut e = engine();
        let missing = ConversationId([9; 16]);
        assert_eq!(
            e.send_text(missing, "hi", Timestamp::ZERO),
            Err(Error::UnknownConversation)
        );
        assert_eq!(e.outbox_len(), 0, "a failed send must not consume a slot");
    }

    #[test]
    fn text_longer_than_the_limit_is_refused_before_a_seq_is_burned() {
        let mut e = engine();
        let c = e.add_contact(PublicKey([2; 32])).unwrap();
        let long = "x".repeat(Config::default().max_text_len as usize + 1);
        assert_eq!(
            e.send_text(c, &long, Timestamp::ZERO),
            Err(Error::TextTooLong)
        );
        // The next good send must still be seq 0: a rejected message must not
        // leave a hole in the sequence space.
        assert_eq!(e.send_text(c, "ok", Timestamp::ZERO).unwrap().seq, 0);
    }

    #[test]
    fn outbox_full_is_reported_rather_than_silently_dropping() {
        let config = Config {
            max_outbox_messages: 1,
            ..Config::default()
        };
        let mut e = FakeEngine::with_config(PublicKey([1; 32]), config);
        let c = e.add_contact(PublicKey([2; 32])).unwrap();
        e.send_text(c, "one", Timestamp::ZERO).unwrap();
        assert_eq!(
            e.send_text(c, "two", Timestamp::ZERO),
            Err(Error::OutboxFull)
        );
    }

    #[test]
    fn phase_zero_is_inert_but_honest() {
        // Nothing is transmitted, so nothing can be delivered and there is no
        // deadline to wake for. A message stays queued, which is the truthful
        // state for a link with nobody on the far end.
        let mut e = engine();
        let c = e.add_contact(PublicKey([2; 32])).unwrap();
        e.add_link(LinkId(1), link_config()).unwrap();
        e.send_text(c, "hello", Timestamp::ZERO).unwrap();
        assert_eq!(e.poll_transmit(Timestamp::ZERO), None);
        assert_eq!(e.next_timeout(), None);
        e.handle_timeout(Timestamp::from_millis(10_000));
        // Only the link registration event; no delivery, no transmission.
        assert!(matches!(
            e.poll_event(),
            Some(EngineEvent::LinkChanged { .. })
        ));
        assert_eq!(e.poll_event(), None);
    }

    #[test]
    fn replays_identically_from_its_seed() {
        let run = || {
            let mut e = engine();
            let c = e.add_contact(PublicKey([2; 32])).unwrap();
            (0..5)
                .map(|i| e.send_text(c, &format!("m{i}"), Timestamp::ZERO).unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(run(), run());
    }
}
