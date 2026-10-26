/// Engine-wide limits. Every queue and table in the engine is bounded by one
/// of these; the documented behaviour when a limit is hit is listed per field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Maximum registered links. `add_link` beyond this returns
    /// [`crate::Error::TooManyLinks`].
    pub max_links: u16,
    /// Maximum undelivered outgoing messages. `send_text` beyond this returns
    /// [`crate::Error::OutboxFull`].
    pub max_outbox_messages: u32,
    /// Maximum queued events. When full, the engine stops accepting new
    /// inbound messages (they are not acked, so the peer will resend) until
    /// the host drains events.
    pub max_pending_events: u32,
    /// Maximum UTF-8 bytes in one message. `send_text` beyond this returns
    /// [`crate::Error::TextTooLong`].
    pub max_text_len: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_links: 8,
            max_outbox_messages: 1024,
            max_pending_events: 256,
            max_text_len: 4096,
        }
    }
}
