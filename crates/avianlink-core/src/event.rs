use alloc::string::String;

use crate::{ConversationId, MessageId, Timestamp};

/// Something the host should know about, drained with
/// [`crate::Engine::poll_event`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A new message arrived. Messages may arrive out of causal order.
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
    /// Conversation the message belongs to.
    pub conversation: ConversationId,
    /// Content-addressed ID.
    pub id: MessageId,
    /// Sender-asserted timestamp. Display metadata only; never trusted for
    /// ordering.
    pub sender_time: Timestamp,
    /// Message body.
    pub text: String,
}
