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
    /// The host's [`crate::Storage`] reported a failure. Nothing changed.
    Storage,
    /// `Engine::new` on storage that already holds an engine; use
    /// `Engine::restore`.
    StorageNotEmpty,
    /// `Engine::restore` found undecodable state.
    CorruptStorage,
    /// `Engine::restore` on storage that holds no engine. If the identity
    /// is not new, its state was lost: reusing the identity would restart
    /// packet counters and reuse nonces, so the host must create a new
    /// identity (`docs/security.md` §4).
    StateMissing,
    /// `Engine::restore` with a different identity than the stored one.
    IdentityMismatch,
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
            Self::StorageNotEmpty => "storage already holds an engine",
            Self::CorruptStorage => "stored engine state is corrupt",
            Self::StateMissing => "storage holds no engine state",
            Self::IdentityMismatch => "stored engine belongs to another identity",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for Error {}
