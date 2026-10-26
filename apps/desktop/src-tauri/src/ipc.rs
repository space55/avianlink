//! Every type that crosses the Tauri boundary, defined once.
//!
//! The TypeScript in `apps/desktop/src/lib/ipc/bindings.ts` is generated from
//! this module by `ts-rs` (desktop DA-006/DA-007). `docs/ipc.md` is the prose
//! contract: units, invariants, and what the UI may believe. Keep the three
//! in step — the doc explains *why* each field exists, which neither the Rust
//! nor the generated TypeScript can.
//!
//! ## Why every `u64` carries `#[ts(type = "number")]`
//!
//! `ts-rs` maps `u64` to TypeScript `bigint`, which is right for a transport
//! that can carry 64-bit integers. Tauri's IPC is not one: command results
//! are serialised with `serde_json` and parsed with `JSON.parse`, so a `u64`
//! arrives in the webview as a `number`. Leaving the default would generate a
//! type that lies about the runtime value, and any `typeof x === "bigint"`
//! check would fail against real data. The annotation makes the generated
//! type match what actually crosses the boundary. The precision limit this
//! implies is discussed in `docs/ipc.md` § Conventions.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Characters of message text kept in a conversation-list preview.
pub const PREVIEW_CHARS: usize = 160;

/// Default gap between send and receive time above which the UI shows both.
pub const DEFAULT_RECEIVE_TIME_THRESHOLD_MS: u64 = 5 * 60 * 1000;

/// Largest page `get_messages` will return.
pub const MAX_PAGE_LIMIT: u32 = 500;

/// This machine's own identity, as the frontend is allowed to see it.
///
/// There is deliberately no field here that could hold secret key material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct Identity {
    /// 64 lowercase hex characters.
    pub public_key: String,
    /// Five dash-separated groups of four hex characters.
    pub fingerprint: String,
    /// What we call ourselves. Local only; never transmitted.
    pub display_name: Option<String>,
}

/// A peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct Contact {
    /// 32 lowercase hex characters. The identifier used everywhere else.
    pub conversation_id: String,
    /// 64 lowercase hex characters.
    pub public_key: String,
    /// Derived from `public_key`; never stored, so it cannot disagree.
    pub fingerprint: String,
    /// Local label. Never leaves this machine.
    pub display_name: String,
    /// The user asserts they compared the fingerprint out of band.
    pub verified: bool,
    /// Unix milliseconds.
    #[ts(type = "number")]
    pub added_at: u64,
    /// Last packet attributed to this peer, unix milliseconds. Best effort.
    #[ts(type = "number")]
    pub last_packet_at: Option<u64>,
    /// Last message received from this peer, unix milliseconds.
    #[ts(type = "number")]
    pub last_message_at: Option<u64>,
    /// Messages received but not yet marked read.
    pub unread_count: u32,
}

/// Honest delivery state of an outgoing message.
///
/// Monotonic: the backend never moves a message backwards through these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub enum MessageStatus {
    /// Durably saved locally. Nothing has gone out yet.
    Queued,
    /// At least one transmission left this machine.
    Sent,
    /// The recipient acknowledged it.
    Delivered,
    /// The engine gave up. Unreachable with the real engine today (AR-003).
    Failed,
}

impl MessageStatus {
    /// Rank used to keep status monotonic when a stale update arrives late.
    pub fn rank(self) -> u8 {
        match self {
            Self::Queued => 0,
            Self::Sent => 1,
            Self::Delivered => 2,
            // `Failed` is terminal and outranks everything: once the engine
            // has given up, a stale "sent" must not resurrect the message.
            Self::Failed => 3,
        }
    }

    /// Returns the further-along of two statuses.
    pub fn max(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// A message in a conversation thread.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct Message {
    /// 32 lowercase hex characters.
    pub id: String,
    /// 32 lowercase hex characters.
    pub conversation_id: String,
    /// Whether we sent it.
    pub outgoing: bool,
    /// Body.
    pub text: String,
    /// Causal order key from the engine's Lamport clock.
    #[ts(type = "number")]
    pub lamport: u64,
    /// Per-sender sequence number within the conversation.
    #[ts(type = "number")]
    pub seq: u64,
    /// Opaque sort and pagination key; sort ascending. See [`order_key`].
    pub order_key: String,
    /// Sender-asserted wall clock, unix milliseconds.
    #[ts(type = "number")]
    pub sent_at: Option<u64>,
    /// When our engine received it, unix milliseconds. Incoming only.
    #[ts(type = "number")]
    pub received_at: Option<u64>,
    /// Outgoing only; `None` for incoming messages.
    pub status: Option<MessageStatus>,
    /// Unix milliseconds. Outgoing only.
    #[ts(type = "number")]
    pub delivered_at: Option<u64>,
    /// Transmissions so far. Outgoing only.
    pub attempts: Option<u32>,
    /// Set at insert time if a strictly greater `order_key` already existed.
    pub arrived_late: bool,
}

/// Builds the opaque sort key: `<lamport as 16 hex digits>:<message id hex>`.
///
/// Lexicographic order on this string is `(lamport, id)` order, so the
/// frontend never needs to know the ordering rule and the tiebreak between
/// concurrent messages stays a backend decision (`docs/ipc.md`).
pub fn order_key(lamport: u64, message_id_hex: &str) -> String {
    format!("{lamport:016x}:{message_id_hex}")
}

/// A page of messages, oldest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct MessagePage {
    /// Ascending by `order_key`.
    pub messages: Vec<Message>,
    /// Whether older messages exist before this page.
    pub has_more: bool,
    /// Pass as `before` to fetch the next page back.
    pub oldest_order_key: Option<String>,
    /// Total messages in the conversation, for the scrollbar's benefit.
    pub total: u32,
}

/// Short form of a message for the conversation list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct MessagePreview {
    /// Truncated to [`PREVIEW_CHARS`] by the backend.
    pub text: String,
    /// Whether we sent it.
    pub outgoing: bool,
    /// `sent_at` if known, else `received_at`. Unix milliseconds.
    #[ts(type = "number")]
    pub at: u64,
    /// Outgoing only.
    pub status: Option<MessageStatus>,
}

/// A row in the conversation sidebar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct ConversationSummary {
    /// 32 lowercase hex characters.
    pub conversation_id: String,
    /// The peer.
    pub contact: Contact,
    /// `None` for a conversation with no messages yet.
    pub last_message: Option<MessagePreview>,
    /// Messages received but not yet marked read.
    pub unread_count: u32,
    /// Outgoing messages not yet delivered.
    pub undelivered_count: u32,
}

/// What a link is carried by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub enum LinkKind {
    /// A UDP socket.
    Udp,
    /// The in-process fake link used before the real engine exists.
    Fake,
}

/// Observed state of a link.
///
/// Separate from [`Link::enabled`], which is the user's intent: a link the
/// user switched off is `Disabled`, not `Down`, because those two warrant
/// very different tones in the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub enum LinkStatus {
    /// Usable. Says nothing about whether the peer is answering.
    Up,
    /// The app tried and could not: bind failed, interface gone.
    Down,
    /// The user switched it off.
    Disabled,
}

/// A configured UDP peer address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct UdpPeer {
    /// 32 lowercase hex characters.
    pub conversation_id: String,
    /// `host:port`.
    pub address: String,
}

/// Per-kind link settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub enum LinkSettings {
    /// A UDP socket bound locally, with per-peer addresses.
    Udp {
        /// Local bind port. 0 asks the OS to choose.
        local_port: u16,
        /// Where to send each conversation's packets.
        peers: Vec<UdpPeer>,
    },
    /// The in-process fake link.
    Fake {
        /// Impairment profile name, e.g. `disaster_cellular`.
        profile: String,
    },
}

/// A link and its health, as the sidebar indicator shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct Link {
    /// Engine link id.
    pub id: u16,
    /// Human label.
    pub label: String,
    /// Transport.
    pub kind: LinkKind,
    /// User intent.
    pub enabled: bool,
    /// Observed state.
    pub status: LinkStatus,
    /// Maximum packet size in bytes.
    pub mtu: u16,
    /// Per-kind settings.
    pub config: LinkSettings,
    /// Packets handed to the link.
    #[ts(type = "number")]
    pub packets_sent: u64,
    /// Packets received on the link.
    #[ts(type = "number")]
    pub packets_received: u64,
    /// Bytes handed to the link.
    #[ts(type = "number")]
    pub bytes_sent: u64,
    /// Bytes received on the link.
    #[ts(type = "number")]
    pub bytes_received: u64,
    /// 0..=1000. `None` means not measured, which must not render as 0.
    pub recent_loss_permille: Option<u16>,
    /// Unix milliseconds.
    #[ts(type = "number")]
    pub last_sent_at: Option<u64>,
    /// Unix milliseconds.
    #[ts(type = "number")]
    pub last_received_at: Option<u64>,
    /// Pacing, not a fault: the link is up but out of airtime until then.
    #[ts(type = "number")]
    pub budget_blocked_until: Option<u64>,
}

/// Impairments the fake engine applies, so the UI can be driven through every
/// state on demand. Dev builds only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct FakeEngineSettings {
    /// Impairment profile name.
    pub profile: String,
    /// Base one-way delay, milliseconds.
    #[ts(type = "number")]
    pub delay_ms: u64,
    /// Uniform jitter added to the delay, milliseconds.
    #[ts(type = "number")]
    pub jitter_ms: u64,
    /// Per-packet loss, parts per thousand.
    pub loss_permille: u16,
    /// Probability a delivered packet is reordered, parts per thousand.
    pub reorder_permille: u16,
    /// Whether scripted link outages are running.
    pub outages: bool,
    /// Whether scripted peers reply.
    pub scripted_replies: bool,
}

/// User-visible app settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct Settings {
    /// What we call ourselves. Local only.
    pub display_name: Option<String>,
    /// Gap between send and receive time above which the UI shows both.
    #[ts(type = "number")]
    pub show_receive_time_threshold_ms: u64,
    /// Present only when the app is running on `FakeEngine`.
    pub fake_engine: Option<FakeEngineSettings>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            display_name: None,
            show_receive_time_threshold_ms: DEFAULT_RECEIVE_TIME_THRESHOLD_MS,
            fake_engine: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Command arguments
//
// Each command takes a single named struct so that adding an optional field
// is never a breaking change.
// ---------------------------------------------------------------------------

/// Arguments to `add_contact`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct AddContactArgs {
    /// 64 lowercase hex characters, as pasted by the user.
    pub public_key: String,
    /// Local label. May be empty; the backend then uses the short fingerprint.
    pub display_name: String,
    /// Whether the user ticked "I compared the fingerprint".
    pub verified: bool,
}

/// Arguments to `get_messages`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct GetMessagesArgs {
    /// 32 lowercase hex characters.
    pub conversation_id: String,
    /// Return messages with `order_key` strictly less than this.
    pub before: Option<String>,
    /// Page size, clamped to 1..=[`MAX_PAGE_LIMIT`].
    pub limit: u32,
}

/// Arguments to `send_message`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct SendMessageArgs {
    /// 32 lowercase hex characters.
    pub conversation_id: String,
    /// Body. Rejected if empty after trimming.
    pub text: String,
}

/// Arguments to `configure_link`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct ConfigureLinkArgs {
    /// Engine link id.
    pub id: u16,
    /// Replacement settings.
    pub config: LinkSettings,
}

/// Arguments to `set_link_enabled`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct SetLinkEnabledArgs {
    /// Engine link id.
    pub id: u16,
    /// Desired state.
    pub enabled: bool,
}

/// Arguments to `mark_conversation_read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct MarkReadArgs {
    /// 32 lowercase hex characters.
    pub conversation_id: String,
    /// Mark read up to and including this `order_key`.
    pub through_order_key: String,
}

/// Arguments to `set_contact_verified`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct SetContactVerifiedArgs {
    /// 32 lowercase hex characters.
    pub conversation_id: String,
    /// Desired state.
    pub verified: bool,
}

/// Arguments to `set_settings`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct SetSettingsArgs {
    /// Replacement settings.
    pub settings: Settings,
}

// ---------------------------------------------------------------------------
// Event payloads
// ---------------------------------------------------------------------------

/// Payload of the `message_status_changed` event.
///
/// A delta rather than a whole [`Message`], because retransmission can
/// produce these at a rate that makes resending the body wasteful
/// (`docs/ipc.md` § Events).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../src/lib/ipc/bindings.ts")]
pub struct MessageStatusChanged {
    /// 32 lowercase hex characters.
    pub conversation_id: String,
    /// 32 lowercase hex characters.
    pub message_id: String,
    /// New status.
    pub status: MessageStatus,
    /// Unix milliseconds; set when `status` is `delivered`.
    #[ts(type = "number")]
    pub delivered_at: Option<u64>,
    /// Transmissions so far.
    pub attempts: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_key_sorts_by_lamport_then_id() {
        let a = order_key(1, "ff");
        let b = order_key(2, "00");
        // Lamport dominates, even though "ff" > "00" lexicographically.
        assert!(a < b);
        // Equal lamport falls back to the id, deterministically.
        assert!(order_key(2, "00") < order_key(2, "01"));
    }

    #[test]
    fn order_key_is_fixed_width_so_string_order_is_numeric_order() {
        // The bug this guards against: without zero padding, lamport 9 would
        // sort above lamport 10.
        assert!(order_key(9, "aa") < order_key(10, "aa"));
        assert!(order_key(u64::MAX - 1, "aa") < order_key(u64::MAX, "aa"));
        assert_eq!(order_key(0, "aa").len(), 16 + 1 + 2);
    }

    #[test]
    fn status_is_monotonic_under_out_of_order_updates() {
        use MessageStatus::*;
        assert_eq!(Delivered.max(Sent), Delivered);
        assert_eq!(Sent.max(Delivered), Delivered);
        assert_eq!(Queued.max(Sent), Sent);
        // Terminal: a late "sent" must not resurrect an abandoned message.
        assert_eq!(Failed.max(Delivered), Failed);
    }

    #[test]
    fn link_settings_is_internally_tagged() {
        let json = serde_json::to_value(LinkSettings::Udp {
            local_port: 7777,
            peers: vec![],
        })
        .unwrap();
        assert_eq!(json["kind"], "udp");
        assert_eq!(json["local_port"], 7777);
    }

    #[test]
    fn status_serialises_in_snake_case() {
        let json = serde_json::to_value(MessageStatus::Delivered).unwrap();
        assert_eq!(json, serde_json::json!("delivered"));
    }
}
