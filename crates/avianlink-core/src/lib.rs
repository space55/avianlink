//! Sans-IO engine for end-to-end encrypted text messaging over extremely
//! poor packet links.
//!
//! The [`Engine`] is a deterministic state machine. It never touches sockets,
//! clocks, files or threads. The host feeds it packets, outgoing text and the
//! current time, and drains packets to transmit, events, and the next deadline
//! at which it wants [`Engine::handle_timeout`] called.
//!
//! ```text
//! host ──handle_packet / send_text / handle_timeout──▶ Engine
//! host ◀──poll_transmit / poll_event / next_timeout─── Engine
//! ```
//!
//! A host loop, after any input: call `poll_transmit` until `None`, drain
//! `poll_event`, then sleep until `next_timeout` or the next packet.
//!
//! Every packet is end-to-end encrypted and authenticated between two
//! contacts' static keys. Read `docs/security.md` for what that does and
//! does not protect — notably, v1 has no forward secrecy.

#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::float_arithmetic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod config;
pub mod crypto;
mod engine;
mod error;
mod event;
pub mod fec;
mod hash;
mod link;
mod pacer;
mod reassembly;
mod storage;
mod time;
mod types;
pub mod wire;

pub use config::{Config, FecMode, HelloMode};
pub use engine::{
    ContactStatus, Engine, LinkStats, OutgoingStatus, Queued, Received, Stats, Transmit,
};
pub use error::Error;
pub use event::{Event, ReceivedMessage};
pub use link::{AirtimeModel, LinkBudget, LinkConfig, LinkId, MIN_MTU};
pub use storage::{MemoryStorage, MemoryStorageError, Storage};
pub use time::Timestamp;
pub use types::{ConversationId, MessageId, Packet, PublicKey};

pub use crypto::{format_fingerprint, Identity, FINGERPRINT_LEN};

/// Hash helpers, exposed for tests and tooling. Not a stable API.
pub mod hashes {
    pub use crate::hash::{conversation_id, hello_hint, message_id};
}
