//! The single error type that crosses the IPC boundary.
//!
//! See `docs/ipc.md` § Errors. The split between [`IpcErrorKind`] (what the
//! frontend branches on) and the message (what it shows) exists so a new
//! failure cause can be surfaced without a frontend change.

use serde::Serialize;
use ts_rs::TS;

/// Machine-readable error class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub enum IpcErrorKind {
    /// A malformed argument: bad hex, empty text, out-of-range number.
    BadRequest,
    /// No such conversation, contact, link or message.
    NotFound,
    /// The thing already exists, or would collide with something that does.
    Conflict,
    /// A configured engine limit was reached.
    Limit,
    /// Persistence or keychain failure.
    Storage,
    /// The engine rejected the call for another reason.
    Engine,
    /// A bug in the app. The message is a diagnostic.
    Internal,
}

/// Error returned by every Tauri command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct IpcError {
    /// Error class the frontend branches on.
    pub kind: IpcErrorKind,
    /// Human-readable text, safe to show in the UI.
    pub message: String,
}

impl IpcError {
    /// Builds an error of `kind` with `message`.
    pub fn new(kind: IpcErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// A malformed-argument error.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(IpcErrorKind::BadRequest, message)
    }

    /// A missing-entity error.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(IpcErrorKind::NotFound, message)
    }

    /// A collision error.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(IpcErrorKind::Conflict, message)
    }

    /// A limit-reached error.
    pub fn limit(message: impl Into<String>) -> Self {
        Self::new(IpcErrorKind::Limit, message)
    }

    /// A persistence failure.
    pub fn storage(message: impl Into<String>) -> Self {
        Self::new(IpcErrorKind::Storage, message)
    }

    /// An internal invariant failure.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(IpcErrorKind::Internal, message)
    }
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for IpcError {}

/// Maps the engine's errors onto IPC error classes.
///
/// The mapping is deliberately explicit rather than a catch-all, so that a
/// new variant in the (non-exhaustive) core `Error` enum shows up here as a
/// decision to make rather than silently becoming `internal`.
impl From<avianlink_core::Error> for IpcError {
    fn from(err: avianlink_core::Error) -> Self {
        use avianlink_core::Error as E;
        let kind = match err {
            E::TextTooLong | E::OutboxFull | E::TooManyContacts | E::TooManyLinks => {
                IpcErrorKind::Limit
            }
            E::UnknownConversation | E::UnknownLink => IpcErrorKind::NotFound,
            E::InvalidContact | E::LinkExists => IpcErrorKind::Conflict,
            E::InvalidConfig | E::InvalidLinkConfig => IpcErrorKind::BadRequest,
            E::Storage => IpcErrorKind::Storage,
            // `Error` is `#[non_exhaustive]`; `Exhausted` and anything added
            // later is an engine-level refusal the UI cannot act on.
            _ => IpcErrorKind::Engine,
        };
        Self::new(kind, err.to_string())
    }
}

/// Convenience alias for command results.
pub type IpcResult<T> = Result<T, IpcError>;

#[cfg(test)]
mod tests {
    use super::*;
    use avianlink_core::Error as E;

    #[test]
    fn engine_errors_map_to_actionable_kinds() {
        // The UI must not clear the composer on a full outbox, so this one
        // has to be `limit` and not `engine`.
        assert_eq!(IpcError::from(E::OutboxFull).kind, IpcErrorKind::Limit);
        assert_eq!(IpcError::from(E::TextTooLong).kind, IpcErrorKind::Limit);
        assert_eq!(
            IpcError::from(E::UnknownConversation).kind,
            IpcErrorKind::NotFound
        );
        assert_eq!(
            IpcError::from(E::InvalidContact).kind,
            IpcErrorKind::Conflict
        );
        assert_eq!(IpcError::from(E::Storage).kind, IpcErrorKind::Storage);
        assert_eq!(IpcError::from(E::Exhausted).kind, IpcErrorKind::Engine);
    }

    #[test]
    fn serialises_as_kind_and_message() {
        let json = serde_json::to_value(IpcError::bad_request("nope")).unwrap();
        assert_eq!(json["kind"], "bad_request");
        assert_eq!(json["message"], "nope");
    }
}
