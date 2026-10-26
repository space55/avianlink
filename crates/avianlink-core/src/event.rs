use alloc::string::String;

use crate::{ConversationId, MessageId, Timestamp};

/// Something the host should know about, drained with
/// [`crate::Engine::poll_event`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A new message arrived. Messages arrive in network order, not causal
    /// order; sort by [`ReceivedMessage::lamport`] for display.
    MessageReceived(ReceivedMessage),
    /// One of our messages went out for the first time since it was queued
    /// (or since this engine was restored). Best-effort: not persisted, and
    /// skipped if the event queue is full. Retry counts are available from
    /// [`crate::Engine::outgoing`].
    MessageTransmitted {
        /// Conversation the message belongs to.
        conversation: ConversationId,
        /// The transmitted message.
        id: MessageId,
    },
    /// The peer will never send these messages: they were acknowledged by,
    /// or abandoned toward, a previous state of this engine (for example a
    /// reinstall with the same identity). Reported once.
    MessagesSkipped {
        /// Conversation.
        conversation: ConversationId,
        /// First skipped seq.
        first_seq: u64,
        /// How many seqs at or after `first_seq` (below the peer's floor)
        /// will never arrive.
        count: u64,
    },
    /// Both sides hold different messages under the same seqs
    /// (`docs/reliability.md` §7), e.g. after the peer restored old
    /// storage. Detected, not repaired. Reported once per block.
    SyncDiverged {
        /// Conversation.
        conversation: ConversationId,
        /// First seq of the mismatched block.
        first_seq: u64,
        /// Last seq of the mismatched block.
        last_seq: u64,
    },
    /// The peer acknowledged one of our messages.
    MessageDelivered {
        /// Conversation the message belongs to.
        conversation: ConversationId,
        /// The delivered message.
        id: MessageId,
    },
}

/// A message received from a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedMessage {
    /// Conversation the message belongs to (and therefore its sender).
    pub conversation: ConversationId,
    /// Content-addressed ID; equal to the sender's `send_text` result.
    pub id: MessageId,
    /// The sender's sequence number for this message.
    pub seq: u64,
    /// Lamport clock value; the causal order key.
    pub lamport: u64,
    /// Earlier messages from this sender not yet received. Non-zero means
    /// this one overtook them in the network.
    pub missing_before: u64,
    /// Sender-asserted wall-clock time, second precision, if the sender has a
    /// wall clock. Display metadata only.
    pub sender_time: Option<Timestamp>,
    /// When this engine received the message.
    pub received_at: Timestamp,
    /// Message body.
    pub text: String,
}
