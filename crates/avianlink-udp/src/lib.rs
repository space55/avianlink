//! UDP link adapter and driver loop for avianlink (Phase 6).
//!
//! Owns the socket and the wall clock, and pumps an
//! [`avianlink_core::Engine`]: received datagrams go to `handle_packet`,
//! `poll_transmit` output goes to `send_to`, and the loop sleeps until
//! `next_timeout`.
