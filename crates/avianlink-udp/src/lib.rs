//! UDP link adapter, durable file storage and driver loop for avianlink
//! (`docs/hosting.md`).
//!
//! [`UdpHost`] owns an [`avianlink_core::Engine`], a UDP socket and the wall
//! clock, and pumps the engine on its own thread. A UI talks to it through
//! [`Command`] and [`HostEvent`] channels.

mod host;
mod identity;
mod storage;

pub use host::{
    init_node, init_state, now, os_rng, Command, HostConfig, HostError, HostEvent, StatusReport,
    UdpHost, LINK,
};
pub use identity::{load_identity, parse_public_key, public_key_hex};
pub use storage::{FileStorage, FileStorageError};
