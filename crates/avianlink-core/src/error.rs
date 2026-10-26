use core::fmt;

/// Errors returned by host-initiated engine calls.
///
/// Malformed network input is never an `Error`: bad packets are dropped and
/// counted in [`crate::Stats`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The [`crate::Config`] failed validation.
    InvalidConfig,
    /// The link configuration failed validation (e.g. MTU below
    /// [`crate::MIN_MTU`], or one packet exceeds the duty-cycle budget).
    InvalidLinkConfig,
    /// A link with this ID is already registered.
    LinkExists,
    /// No link with this ID is registered.
    UnknownLink,
    /// The configured link limit has been reached.
    TooManyLinks,
    /// The contact is already known, or is this engine's own key.
    InvalidContact,
    /// The configured contact limit has been reached.
    TooManyContacts,
    /// No conversation with this ID.
    UnknownConversation,
    /// The message text exceeds [`crate::Config::max_text_len`].
    TextTooLong,
    /// The outbox is at capacity; retry after deliveries free space.
    OutboxFull,
    /// A sequence counter is exhausted.
    Exhausted,
    /// The host's [`crate::Storage`] reported a failure.
    Storage,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidConfig => "invalid engine configuration",
            Self::InvalidLinkConfig => "invalid link configuration",
            Self::LinkExists => "link already registered",
            Self::UnknownLink => "unknown link",
            Self::TooManyLinks => "too many links",
            Self::InvalidContact => "invalid or duplicate contact",
            Self::TooManyContacts => "too many contacts",
            Self::UnknownConversation => "unknown conversation",
            Self::TextTooLong => "message text too long",
            Self::OutboxFull => "outbox full",
            Self::Exhausted => "sequence counter exhausted",
            Self::Storage => "storage failure",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for Error {}
