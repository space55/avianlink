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
mod engine;
mod error;
mod event;
mod link;
mod storage;
mod time;
mod types;

pub use config::Config;
pub use engine::{Engine, Stats, Transmit};
pub use error::Error;
pub use event::{Event, ReceivedMessage};
pub use link::{AirtimeModel, LinkBudget, LinkConfig, LinkId, MIN_MTU};
pub use storage::{MemoryStorage, Storage};
pub use time::Timestamp;
pub use types::{ConversationId, MessageId, Packet};
