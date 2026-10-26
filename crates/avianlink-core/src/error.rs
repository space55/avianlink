use core::fmt;

/// Errors returned by host-initiated engine calls.
///
/// Malformed network input is never an `Error`: bad packets are dropped and
/// counted in [`crate::Stats`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The link configuration failed validation (e.g. MTU below
    /// [`crate::MIN_MTU`]).
    InvalidLinkConfig,
    /// A link with this ID is already registered.
    LinkExists,
    /// No link with this ID is registered.
    UnknownLink,
    /// The configured link limit has been reached.
    TooManyLinks,
    /// The message text exceeds [`crate::Config::max_text_len`].
    TextTooLong,
    /// The outbox is at capacity; retry after deliveries free space.
    OutboxFull,
    /// The host's [`crate::Storage`] reported a failure.
    Storage,
    /// The operation is not implemented yet (Phase 0 skeleton only).
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidLinkConfig => "invalid link configuration",
            Self::LinkExists => "link already registered",
            Self::UnknownLink => "unknown link",
            Self::TooManyLinks => "too many links",
            Self::TextTooLong => "message text too long",
            Self::OutboxFull => "outbox full",
            Self::Storage => "storage failure",
            Self::Unsupported => "not yet supported",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for Error {}
