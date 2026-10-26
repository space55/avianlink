//! The boundary between the app and the messaging engine.
//!
//! [`EngineHandle`] has the shape of `avianlink_core::Engine`: it is a
//! sans-IO state machine that the driver task pumps. It is deliberately *not*
//! a UI-level interface — message history, pagination and conversation lists
//! come from the app's own store, which is populated from this trait's event
//! stream. See desktop decision DA-004.
//!
//! Two implementations exist:
//!
//! - [`FakeEngine`], which simulates a bad link in process. The UI is built
//!   against it first, so every state the real link produces is designed for
//!   before the real link exists.
//! - `RealEngine` (app Phase 3), wrapping `avianlink_core::Engine`.
//!
//! Where the trait is richer than today's `Engine`, the gap is filed in
//! `docs/api-requests.md` and the richer shape is the one the UI is built
//! against, so that adopting the library's version later is a deletion.

mod fake;

pub use avianlink_core::Queued;
pub use fake::FakeEngine;

use avianlink_core::{
    ConversationId, Error, LinkConfig, LinkId, MessageId, PublicKey, ReceivedMessage, Timestamp,
    Transmit,
};

// `Queued` comes from the library: `avianlink_core::Engine::send_text`
// returns the message's id, sequence number and Lamport value, which is what
// the app needs to place its own messages in the thread's causal order. It
// was api-request AR-001; the library adopted the proposed shape, so there is
// nothing for the app to re-declare.

/// Why the engine stopped trying to deliver a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbandonReason {
    /// The outbox was full and this was the message evicted.
    OutboxEvicted,
    /// A retry or age limit was reached.
    RetryLimit,
    /// The contact was removed while the message was queued.
    ContactRemoved,
}

impl AbandonReason {
    /// Short phrase for the UI's failure explanation.
    pub fn describe(self) -> &'static str {
        match self {
            Self::OutboxEvicted => "the outbox filled up",
            Self::RetryLimit => "it was retried for too long",
            Self::ContactRemoved => "the contact was removed",
        }
    }
}

/// Health of one link, as observed below the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct LinkHealth {
    /// Whether the link is usable. Says nothing about the peer answering.
    pub up: bool,
    /// Measured loss, parts per thousand. `None` when unmeasurable, which the
    /// UI must render as "not measured" rather than zero.
    pub loss_permille: Option<u16>,
    /// When pacing will next allow a packet; not a fault.
    pub budget_blocked_until: Option<Timestamp>,
}

/// Anything the app needs to know about, drained with
/// [`EngineHandle::poll_event`].
///
/// This is the union of what the engine reports and what the layer *below* it
/// reports. `FakeEngine` owns its own links, so it is the source of both. In
/// the real stack the engine supplies the message variants and the UDP
/// adapter supplies [`EngineEvent::LinkChanged`]; the adapter merges them into
/// one stream so the driver has a single thing to drain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineEvent {
    /// A new message arrived. Not in causal order; sort by `lamport`.
    MessageReceived(ReceivedMessage),
    /// A message left this machine. The `queued` -> `sent` transition.
    ///
    /// Not available from `avianlink_core` today (AR-002); `FakeEngine`
    /// reports it exactly, and `RealEngine` approximates it.
    MessageTransmitted {
        /// Conversation the message belongs to.
        conversation: ConversationId,
        /// The message that went out.
        id: MessageId,
        /// 1 for the first transmission, incrementing per retransmission.
        attempt: u32,
    },
    /// The peer acknowledged a message.
    MessageDelivered {
        /// Conversation the message belongs to.
        conversation: ConversationId,
        /// The delivered message.
        id: MessageId,
    },
    /// The engine gave up. Not available from `avianlink_core` (AR-003).
    MessageAbandoned {
        /// Conversation the message belongs to.
        conversation: ConversationId,
        /// The abandoned message.
        id: MessageId,
        /// Why.
        reason: AbandonReason,
    },
    /// A link's health changed.
    LinkChanged {
        /// Which link.
        link: LinkId,
        /// Its new health.
        health: LinkHealth,
    },
}

/// Counters the app shows in the link-health display.
///
/// `avianlink_core::Stats` is global, not per link (AR-007), so the driver
/// counts per link itself. This struct is what it accumulates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkCounters {
    /// Packets handed to the link.
    pub packets_sent: u64,
    /// Packets received on the link.
    pub packets_received: u64,
    /// Bytes handed to the link.
    pub bytes_sent: u64,
    /// Bytes received on the link.
    pub bytes_received: u64,
    /// Unix milliseconds.
    pub last_sent_at: Option<Timestamp>,
    /// Unix milliseconds.
    pub last_received_at: Option<Timestamp>,
}

/// The sans-IO engine the driver task pumps.
///
/// The contract is the library's: after any input, drain `poll_transmit`
/// until `None`, drain `poll_event` until `None`, then sleep until
/// `next_timeout` or the next packet or command.
///
/// `Send` is required because the driver owns the engine inside a `tokio`
/// task. It is intentionally not `Sync`: exactly one task may touch it, which
/// is what keeps the state machine deterministic.
pub trait EngineHandle: Send {
    /// This machine's public identity key.
    fn local_key(&self) -> PublicKey;

    /// Registers a peer and returns the conversation it shares with us.
    fn add_contact(&mut self, key: PublicKey) -> Result<ConversationId, Error>;

    /// Registers a link.
    fn add_link(&mut self, id: LinkId, config: LinkConfig) -> Result<(), Error>;

    /// Unregisters a link. Queued messages stay queued.
    fn remove_link(&mut self, id: LinkId) -> Result<(), Error>;

    /// Queues a message. On `Ok` the message is durably queued; delivery is
    /// reported later as [`EngineEvent::MessageDelivered`].
    fn send_text(
        &mut self,
        conversation: ConversationId,
        text: &str,
        now: Timestamp,
    ) -> Result<Queued, Error>;

    /// Feeds a received packet. Never fails and never panics: malformed input
    /// is dropped and counted.
    fn handle_packet(&mut self, link: LinkId, bytes: &[u8], now: Timestamp);

    /// Advances timers. Called when the deadline from `next_timeout` passes.
    fn handle_timeout(&mut self, now: Timestamp);

    /// Takes the next packet to send, if pacing allows one now.
    fn poll_transmit(&mut self, now: Timestamp) -> Option<Transmit>;

    /// Takes the next event, if any.
    fn poll_event(&mut self) -> Option<EngineEvent>;

    /// The next instant at which [`Self::handle_timeout`] wants to be called.
    fn next_timeout(&self) -> Option<Timestamp>;

    /// Current health of a registered link.
    fn link_health(&self, link: LinkId) -> Option<LinkHealth>;

    /// Number of queued, undelivered outgoing messages.
    fn outbox_len(&self) -> usize;

    /// Whether this implementation emits [`EngineEvent::MessageTransmitted`]
    /// itself.
    ///
    /// When `false`, the driver infers the `queued` -> `sent` transition from
    /// `poll_transmit`, which over-reports (api-requests AR-002). The method
    /// exists so that the inaccurate path is used only where it is
    /// unavoidable: `FakeEngine` returns `true` and reports transmissions
    /// exactly, so the UI is designed against correct semantics, and the flag
    /// disappears entirely once AR-002 lands.
    fn reports_transmissions(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trait_is_object_safe() {
        // The driver stores the engine as `Box<dyn EngineHandle>` so the
        // binary does not need to be generic over the implementation.
        fn assert_object_safe(_: &dyn EngineHandle) {}
        let mut fake = FakeEngine::new(PublicKey([1; 32]));
        assert_object_safe(&fake);
        let boxed: Box<dyn EngineHandle> = Box::new(FakeEngine::new(PublicKey([2; 32])));
        assert_eq!(boxed.outbox_len(), 0);
        assert_eq!(fake.poll_event(), None);
    }

    #[test]
    fn abandon_reasons_read_as_a_sentence() {
        // These are concatenated after "Couldn't send because".
        for reason in [
            AbandonReason::OutboxEvicted,
            AbandonReason::RetryLimit,
            AbandonReason::ContactRemoved,
        ] {
            assert!(!reason.describe().is_empty());
            assert!(reason.describe().starts_with(|c: char| c.is_lowercase()));
        }
    }
}
