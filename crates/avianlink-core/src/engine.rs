use alloc::collections::{BTreeMap, VecDeque};
use rand_core::CryptoRngCore;

use crate::{
    Config, ConversationId, Error, Event, LinkConfig, LinkId, MessageId, Packet, Storage, Timestamp,
};

/// A packet the host should send on a link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    /// Link to send on.
    pub link: LinkId,
    /// Encoded packet, no larger than the link's MTU.
    pub packet: Packet,
}

/// Counters for diagnostics. All counters saturate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Packets passed to [`Engine::handle_packet`].
    pub packets_received: u64,
    /// Packets dropped because they arrived on an unregistered link.
    pub packets_dropped_unknown_link: u64,
    /// Packets dropped because they failed to decode.
    pub packets_dropped_malformed: u64,
}

/// The sans-IO messaging engine.
///
/// `S` is the host's durable storage, and `R` the host's cryptographically
/// secure RNG.
pub struct Engine<S, R> {
    config: Config,
    storage: S,
    // Consumed from Phase 1 onward (message nonces, jitter, key generation).
    #[allow(dead_code)]
    rng: R,
    links: BTreeMap<LinkId, LinkConfig>,
    events: VecDeque<Event>,
    stats: Stats,
}

impl<S: Storage, R: CryptoRngCore> Engine<S, R> {
    /// Creates an engine. Restoring persisted state from `storage` arrives in
    /// Phase 2.
    pub fn new(config: Config, storage: S, rng: R) -> Self {
        Self {
            config,
            storage,
            rng,
            links: BTreeMap::new(),
            events: VecDeque::new(),
            stats: Stats::default(),
        }
    }

    /// Registers a link.
    pub fn add_link(&mut self, id: LinkId, link: LinkConfig) -> Result<(), Error> {
        link.validate()?;
        if self.links.contains_key(&id) {
            return Err(Error::LinkExists);
        }
        if self.links.len() >= usize::from(self.config.max_links) {
            return Err(Error::TooManyLinks);
        }
        self.links.insert(id, link);
        Ok(())
    }

    /// Unregisters a link. Queued traffic is rescheduled onto other links.
    pub fn remove_link(&mut self, id: LinkId) -> Result<(), Error> {
        self.links.remove(&id).map(|_| ()).ok_or(Error::UnknownLink)
    }

    /// Feeds a packet received on `link`. Malformed packets are dropped and
    /// counted in [`Stats`]; this never fails or panics.
    pub fn handle_packet(&mut self, link: LinkId, bytes: &[u8], now: Timestamp) {
        let _ = (bytes, now);
        self.stats.packets_received = self.stats.packets_received.saturating_add(1);
        if !self.links.contains_key(&link) {
            self.stats.packets_dropped_unknown_link =
                self.stats.packets_dropped_unknown_link.saturating_add(1);
            return;
        }
        // Phase 0: there is no wire format yet, so every packet is malformed.
        self.stats.packets_dropped_malformed =
            self.stats.packets_dropped_malformed.saturating_add(1);
    }

    /// Queues a text message. On `Ok` the message is durably queued
    /// ("sent"); delivery is reported later as [`Event::MessageDelivered`].
    pub fn send_text(
        &mut self,
        conversation: ConversationId,
        text: &str,
        now: Timestamp,
    ) -> Result<MessageId, Error> {
        let _ = (conversation, now);
        let max = usize::try_from(self.config.max_text_len).unwrap_or(usize::MAX);
        if text.len() > max {
            return Err(Error::TextTooLong);
        }
        Err(Error::Unsupported)
    }

    /// Advances timers. Call when [`Engine::next_timeout`] is reached, or at
    /// any other time; spurious calls are harmless.
    pub fn handle_timeout(&mut self, now: Timestamp) {
        let _ = now;
    }

    /// Returns the next packet to send, if any link has budget for one now.
    pub fn poll_transmit(&mut self, now: Timestamp) -> Option<Transmit> {
        let _ = now;
        None
    }

    /// Returns the next pending event.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When the engine next wants [`Engine::handle_timeout`] called. `None`
    /// means "only when a new input arrives".
    pub fn next_timeout(&self) -> Option<Timestamp> {
        None
    }

    /// Diagnostic counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// The engine's configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Shared access to the host's storage.
    pub fn storage(&self) -> &S {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LinkBudget, MemoryStorage};
    use rand_core::{CryptoRng, RngCore};

    /// Deterministic stand-in RNG for unit tests. Not secure.
    struct TestRng(u64);

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            // SplitMix64.
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            rand_core::impls::fill_bytes_via_next(self, dest)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}

    fn engine() -> Engine<MemoryStorage, TestRng> {
        Engine::new(Config::default(), MemoryStorage::new(), TestRng(1))
    }

    fn link() -> LinkConfig {
        LinkConfig {
            mtu: 64,
            budget: LinkBudget::Unlimited,
            cost: 1,
        }
    }

    #[test]
    fn idle_engine_is_quiet() {
        let mut e = engine();
        let now = Timestamp::from_millis(0);
        e.handle_timeout(now);
        assert_eq!(e.poll_transmit(now), None);
        assert_eq!(e.poll_event(), None);
        assert_eq!(e.next_timeout(), None);
    }

    #[test]
    fn link_registration_limits() {
        let mut e = Engine::new(
            Config {
                max_links: 1,
                ..Config::default()
            },
            MemoryStorage::new(),
            TestRng(1),
        );
        assert_eq!(e.add_link(LinkId(1), link()), Ok(()));
        assert_eq!(e.add_link(LinkId(1), link()), Err(Error::LinkExists));
        assert_eq!(e.add_link(LinkId(2), link()), Err(Error::TooManyLinks));
        assert_eq!(e.remove_link(LinkId(1)), Ok(()));
        assert_eq!(e.remove_link(LinkId(1)), Err(Error::UnknownLink));
    }

    #[test]
    fn garbage_packets_are_counted_not_fatal() {
        let mut e = engine();
        e.add_link(LinkId(1), link()).unwrap();
        let now = Timestamp::ZERO;
        e.handle_packet(LinkId(1), &[0xff; 300], now);
        e.handle_packet(LinkId(1), &[], now);
        e.handle_packet(LinkId(9), &[1, 2, 3], now);
        let s = e.stats();
        assert_eq!(s.packets_received, 3);
        assert_eq!(s.packets_dropped_malformed, 2);
        assert_eq!(s.packets_dropped_unknown_link, 1);
    }

    #[test]
    fn send_text_enforces_length_limit() {
        let mut e = engine();
        let long = "x".repeat(5000);
        let conv = ConversationId([0; 16]);
        assert_eq!(
            e.send_text(conv, &long, Timestamp::ZERO),
            Err(Error::TextTooLong)
        );
    }
}
