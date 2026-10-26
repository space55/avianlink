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
    /// Sender-asserted wall-clock time, second precision, if the sender has a
    /// wall clock. Display metadata only.
    pub sender_time: Option<Timestamp>,
    /// When this engine received the message.
    pub received_at: Timestamp,
    /// Message body.
    pub text: String,
}
