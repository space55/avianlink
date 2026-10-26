//! Typed events emitted to the frontend.
//!
//! Emission goes through [`EventSink`] rather than straight to Tauri's
//! `AppHandle`, for two reasons: the driver can then be tested without a
//! webview (see [`RecordingSink`]), and every event name exists exactly once,
//! as a constant, so a rename cannot leave the frontend listening to a string
//! nothing emits any more.
//!
//! Payload shapes and delivery guarantees are in `docs/ipc.md` § Events. The
//! important one: events are a cache-coherence mechanism, not a transport. The
//! frontend is correct if it ignores every event and re-runs the commands.

use std::sync::Mutex;

use tauri::{AppHandle, Emitter};

use crate::ipc::{Contact, Link, Message, MessageStatusChanged};

/// A new incoming message was stored. Payload: [`Message`].
pub const MESSAGE_RECEIVED: &str = "message_received";

/// An outgoing message advanced. Payload: [`MessageStatusChanged`].
pub const MESSAGE_STATUS_CHANGED: &str = "message_status_changed";

/// A link's state or health changed. Payload: [`Link`].
pub const LINK_STATUS_CHANGED: &str = "link_status_changed";

/// A contact was added, renamed, verified, or heard from. Payload: [`Contact`].
pub const CONTACT_CHANGED: &str = "contact_changed";

/// Every event name, in a stable order. Used by the frontend-binding test to
/// check that the TypeScript client subscribes to all of them.
pub const ALL: [&str; 4] = [
    MESSAGE_RECEIVED,
    MESSAGE_STATUS_CHANGED,
    LINK_STATUS_CHANGED,
    CONTACT_CHANGED,
];

/// Where backend events go.
pub trait EventSink: Send + Sync {
    /// A new incoming message was stored.
    fn message_received(&self, message: &Message);
    /// An outgoing message's status advanced.
    fn message_status_changed(&self, change: &MessageStatusChanged);
    /// A link's state or health changed.
    fn link_status_changed(&self, link: &Link);
    /// A contact changed.
    fn contact_changed(&self, contact: &Contact);
}

/// Emits through Tauri to the webview.
pub struct TauriSink {
    app: AppHandle,
}

impl TauriSink {
    /// Wraps an app handle.
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }

    /// Emits, logging rather than propagating a failure.
    ///
    /// An emit fails when the webview is gone — during shutdown, or if the
    /// user closed the window. That is not a reason to stop the driver or to
    /// fail the command that triggered it: the frontend re-reads state with
    /// commands when it comes back, so a lost event costs nothing.
    fn emit<T: serde::Serialize + Clone>(&self, name: &str, payload: T) {
        if let Err(err) = self.app.emit(name, payload) {
            eprintln!("avianlink: dropping event {name}: {err}");
        }
    }
}

impl EventSink for TauriSink {
    fn message_received(&self, message: &Message) {
        self.emit(MESSAGE_RECEIVED, message.clone());
    }

    fn message_status_changed(&self, change: &MessageStatusChanged) {
        self.emit(MESSAGE_STATUS_CHANGED, change.clone());
    }

    fn link_status_changed(&self, link: &Link) {
        self.emit(LINK_STATUS_CHANGED, link.clone());
    }

    fn contact_changed(&self, contact: &Contact) {
        self.emit(CONTACT_CHANGED, contact.clone());
    }
}

/// Collects events in memory so tests can assert on what the UI would see.
#[derive(Debug, Default)]
pub struct RecordingSink {
    events: Mutex<Vec<Recorded>>,
}

/// One recorded event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recorded {
    /// [`MESSAGE_RECEIVED`].
    MessageReceived(Message),
    /// [`MESSAGE_STATUS_CHANGED`].
    MessageStatusChanged(MessageStatusChanged),
    /// [`LINK_STATUS_CHANGED`].
    LinkStatusChanged(Link),
    /// [`CONTACT_CHANGED`].
    ContactChanged(Contact),
}

impl RecordingSink {
    /// Creates an empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything recorded so far, in order.
    pub fn events(&self) -> Vec<Recorded> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// Drains and returns everything recorded so far.
    pub fn take(&self) -> Vec<Recorded> {
        self.events
            .lock()
            .map(|mut e| std::mem::take(&mut *e))
            .unwrap_or_default()
    }

    /// Only the status changes, which is what most assertions want.
    pub fn status_changes(&self) -> Vec<MessageStatusChanged> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                Recorded::MessageStatusChanged(c) => Some(c),
                _ => None,
            })
            .collect()
    }

    /// Only the received messages.
    pub fn received(&self) -> Vec<Message> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                Recorded::MessageReceived(m) => Some(m),
                _ => None,
            })
            .collect()
    }

    fn push(&self, event: Recorded) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }
}

impl EventSink for RecordingSink {
    fn message_received(&self, message: &Message) {
        self.push(Recorded::MessageReceived(message.clone()));
    }

    fn message_status_changed(&self, change: &MessageStatusChanged) {
        self.push(Recorded::MessageStatusChanged(change.clone()));
    }

    fn link_status_changed(&self, link: &Link) {
        self.push(Recorded::LinkStatusChanged(link.clone()));
    }

    fn contact_changed(&self, contact: &Contact) {
        self.push(Recorded::ContactChanged(contact.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::MessageStatus;

    fn change(status: MessageStatus) -> MessageStatusChanged {
        MessageStatusChanged {
            conversation_id: "a".repeat(32),
            message_id: "b".repeat(32),
            status,
            delivered_at: None,
            attempts: 1,
        }
    }

    #[test]
    fn event_names_are_unique_and_snake_case() {
        let mut names = ALL.to_vec();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate event name");
        assert!(ALL
            .iter()
            .all(|n| n.chars().all(|c| c.is_ascii_lowercase() || c == '_')));
    }

    #[test]
    fn recording_sink_preserves_order_and_drains() {
        let sink = RecordingSink::new();
        sink.message_status_changed(&change(MessageStatus::Sent));
        sink.message_status_changed(&change(MessageStatus::Delivered));
        let statuses: Vec<MessageStatus> = sink
            .status_changes()
            .into_iter()
            .map(|c| c.status)
            .collect();
        assert_eq!(
            statuses,
            vec![MessageStatus::Sent, MessageStatus::Delivered]
        );
        assert_eq!(sink.take().len(), 2);
        assert!(sink.events().is_empty());
    }
}
