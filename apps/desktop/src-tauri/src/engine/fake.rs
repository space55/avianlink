//! An engine that behaves like a bad link, in process.
//!
//! **It wraps two real `avianlink_core::Engine` instances** — ours, and one
//! per scripted contact — connected by an impaired [`Channel`]. It does not
//! imitate the protocol; it runs it. Fragmentation at the real MTU, real
//! acknowledgements, real adaptive retransmission, real duplicate suppression
//! and real causal ordering all happen, over a link that really does lose,
//! delay, corrupt, duplicate and reorder packets.
//!
//! That matters more than it sounds. The alternative — a hand-written fake
//! that emits plausible events — would let the interface be built against
//! behaviour the real engine never produces, and every difference would
//! surface in the app's Phase 3 as a UI bug. Here the only thing the Phase 3
//! adapter changes is where the packets go.
//!
//! Because it runs the real engine, every state the interface shows comes
//! from the library rather than from an imitation of it: `MessageTransmitted`
//! and `MessageDelivered` are the engine's own events, retry counts come from
//! `Engine::outgoing`, and link counters come from `Engine::link_stats`.
//!
//! ## Reproducibility
//!
//! Every random draw comes from a `ChaCha20Rng` seeded from a constant, so a
//! session replays identically and a bug seen in a demo can be reproduced.

use std::collections::{BTreeMap, VecDeque};

use avianlink_core::{
    Config, ConversationId, Engine, Error, Event, Identity, LinkBudget, LinkConfig, LinkId,
    MemoryStorage, MessageId, PublicKey, Queued, Timestamp, Transmit,
};
use avianlink_sim::impair::LinkProfile;
use avianlink_sim::Profile;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use super::channel::{Channel, Outages};
use super::{EngineEvent, EngineHandle, LinkCounters, LinkHealth};
use crate::ipc::FakeEngineSettings;

/// Seed for the fake's randomness. Fixed so sessions replay identically.
const FAKE_SEED: u64 = 0x6176_6961_6e6c_696e;

/// Default profile when none is named.
const DEFAULT_PROFILE: &str = "disaster_cellular";

/// Lines a scripted contact says, cycled. Deliberately the kind of terse
/// traffic these links actually carry.
const SCRIPT: &[&str] = &[
    "copy that",
    "still here, signal is poor",
    "the repeater is back up",
    "moving to the ridge, back in an hour",
    "understood",
    "no change overnight",
    "water drop is scheduled for 06:00",
    "say again, last was garbled",
];

/// An `Engine` configured the way the app configures its own.
type SimEngine = Engine<MemoryStorage, ChaCha20Rng>;

/// A simulated contact: a real engine with a real identity, plus a script.
struct Peer {
    engine: SimEngine,
    /// The conversation id, which is the same on both sides.
    conversation: ConversationId,
    /// Link this peer is reached over.
    link: LinkId,
    /// Our packets, on their way to the peer.
    to_peer: Channel,
    /// The peer's packets, on their way to us.
    to_us: Channel,
    /// Replies the peer intends to send, with the time it will send them.
    pending: VecDeque<(u64, String)>,
    /// Position in [`SCRIPT`].
    next_line: usize,
}

/// A simulated link.
struct FakeLink {
    config: LinkConfig,
    profile: LinkProfile,
    outages: Outages,
    /// Whether the link was up at the last advance.
    up: bool,
}

/// In-process stand-in for the real engine, over a genuinely bad link.
pub struct FakeEngine {
    config: Config,
    local: SimEngine,
    peers: BTreeMap<ConversationId, Peer>,
    links: BTreeMap<LinkId, FakeLink>,
    events: VecDeque<EngineEvent>,
    settings: FakeEngineSettings,
    rng: ChaCha20Rng,
    /// Secrets for keys handed out by [`FakeEngine::invent_key`], held until
    /// the caller adds the matching contact. A real peer's device keeps its
    /// own secret; the fake has to keep both sides' because it *is* both
    /// sides.
    pending_identities: BTreeMap<PublicKey, Identity>,
    /// When the simulation started, for the outage schedule.
    started_at: u64,
    /// The most recent time the fake was advanced to.
    now: u64,
}

/// Builds the engine configuration the fake uses on both sides.
fn engine_config() -> Config {
    Config {
        wall_clock: true,
        ..Config::default()
    }
}

/// The link configuration implied by an impairment profile.
///
/// The MTU and the budget come from the profile, so the engine really does
/// fragment to a 51-byte LoRa packet and really does pace against a 1% duty
/// cycle when those profiles are selected.
fn link_config_for(profile: &LinkProfile) -> LinkConfig {
    let budget = match (profile.duty, profile.rate_bytes_per_sec) {
        (Some(duty), _) => LinkBudget::DutyCycle {
            permille: duty.permille,
            window_ms: duty.window_ms,
            airtime: duty.airtime,
        },
        (None, Some(rate)) => LinkBudget::BytesPerSecond(rate),
        (None, None) => LinkBudget::Unlimited,
    };
    LinkConfig {
        mtu: profile.mtu,
        budget,
        cost: 1,
    }
}

/// Looks up a named profile, falling back to the default.
fn profile_by_name(name: &str) -> LinkProfile {
    Profile::from_name(name)
        .or_else(|| Profile::from_name(DEFAULT_PROFILE))
        .map(Profile::link)
        .unwrap_or_else(|| Profile::Clean.link())
}

impl FakeEngine {
    /// Creates a fake engine with the default profile.
    pub fn new(identity: Identity) -> Self {
        Self::with_profile(identity, DEFAULT_PROFILE, 0)
    }

    /// Creates a fake engine running `profile`, starting at `now_ms`.
    pub fn with_profile(identity: Identity, profile: &str, now_ms: u64) -> Self {
        let config = engine_config();
        let mut rng = ChaCha20Rng::seed_from_u64(FAKE_SEED);
        let engine_rng = ChaCha20Rng::seed_from_u64(rng.next_u64());
        let engine = Engine::new(config, identity, MemoryStorage::new(), engine_rng)
            .expect("the default engine configuration is valid");
        Self {
            config,
            local: engine,
            peers: BTreeMap::new(),
            links: BTreeMap::new(),
            events: VecDeque::new(),
            settings: FakeEngineSettings {
                profile: profile.to_string(),
                available_profiles: Profile::ALL.iter().map(|p| p.name().to_string()).collect(),
                reply_delay_ms: 20_000,
                reply_jitter_ms: 90_000,
                scripted_replies: true,
                outages: true,
            },
            rng,
            pending_identities: BTreeMap::new(),
            started_at: now_ms,
            now: now_ms,
        }
    }

    /// The link configuration this engine's current profile implies.
    ///
    /// The app registers its simulated link with this, so the engine really
    /// does fragment to a 51-byte LoRa packet and really does pace against a
    /// 1% duty cycle when those profiles are chosen.
    pub fn link_config(&self) -> LinkConfig {
        link_config_for(&profile_by_name(&self.settings.profile))
    }

    /// Gives up on a message, producing the `failed` state.
    ///
    /// The real engine has no "gave up" event and arguably should not acquire
    /// one with a default (api-requests AR-003): on these links a peer silent
    /// for days is normal, and a message marked failed after an hour would be
    /// a lie. This exists so the state can be built, demonstrated and tested
    /// rather than designed blind.
    pub fn abandon(
        &mut self,
        conversation: ConversationId,
        id: MessageId,
        reason: super::AbandonReason,
    ) {
        self.events.push_back(EngineEvent::MessageAbandoned {
            conversation,
            id,
            reason,
        });
    }

    /// The impairment settings currently in force.
    pub fn settings(&self) -> FakeEngineSettings {
        self.settings.clone()
    }

    /// Replaces the impairment settings.
    ///
    /// Re-aiming a channel does not discard packets already in flight:
    /// switching from a clean link to a terrible one should not
    /// retroactively lose what was already on its way, and switching the
    /// other way should not teleport it.
    pub fn set_settings(&mut self, settings: FakeEngineSettings) {
        let profile_changed = settings.profile != self.settings.profile;
        let outages_changed = settings.outages != self.settings.outages;
        self.settings = settings;
        if !profile_changed && !outages_changed {
            return;
        }
        let profile = profile_by_name(&self.settings.profile);
        let now = self.now;
        for link in self.links.values_mut() {
            link.profile = profile;
            link.outages = Outages::new(
                self.settings.outages.then_some(profile.outage).flatten(),
                ChaCha20Rng::seed_from_u64(self.rng.next_u64()),
                now,
            );
            // Switching outages off brings the link straight back up; leaving
            // it reported as down when nothing can take it down again would
            // strand the interface in a state with no exit.
            if !self.settings.outages {
                link.up = true;
            }
        }
        for peer in self.peers.values_mut() {
            peer.to_peer.set_profile(profile);
            peer.to_us.set_profile(profile);
        }
    }

    /// Generates a fresh identity for a simulated contact and returns its
    /// public key, keeping the secret so the peer's engine can use it.
    ///
    /// Drawn from the fake's seeded RNG, so a session still replays exactly.
    pub fn invent_key(&mut self) -> PublicKey {
        let identity = Identity::generate(&mut self.rng);
        let key = identity.public_key();
        self.pending_identities.insert(key, identity);
        key
    }

    /// Seeds a conversation with scripted history, as though it had been
    /// going for a while.
    ///
    /// The messages are injected into the peer's engine at `now`, so they
    /// travel the real link and arrive with real delays: the thread fills in
    /// over the following seconds rather than appearing at once, which is
    /// what the real thing looks like.
    pub fn seed_history(&mut self, conversation: ConversationId, lines: usize) {
        let now = self.now;
        let Some(peer) = self.peers.get_mut(&conversation) else {
            return;
        };
        for index in 0..lines {
            let line = SCRIPT[peer.next_line % SCRIPT.len()];
            peer.next_line = peer.next_line.wrapping_add(1);
            // Spread them over the recent past so they do not all share a
            // timestamp, then let them transmit immediately.
            let _ = peer.engine.send_text(
                peer.conversation,
                line,
                Timestamp::from_millis(now + index as u64),
            );
        }
    }

    /// Draws how long a scripted peer takes to answer.
    ///
    /// Base plus a uniform jitter, so replies land anywhere from seconds to
    /// hours after the message they answer, which is the case the interface
    /// most needs to be designed against.
    fn reply_delay(&mut self) -> u64 {
        let jitter = if self.settings.reply_jitter_ms == 0 {
            0
        } else {
            self.rng.next_u64() % self.settings.reply_jitter_ms
        };
        self.settings.reply_delay_ms.saturating_add(jitter)
    }

    /// Whether the link a peer uses is currently down.
    fn link_down(&self, link: LinkId) -> bool {
        self.links.get(&link).is_some_and(|l| !l.up)
    }

    /// Advances outages and reports any that changed.
    fn advance_links(&mut self, now: u64) {
        let mut changed = Vec::new();
        for (id, link) in &mut self.links {
            let up = !link.outages.is_down(now);
            if up != link.up {
                link.up = up;
                changed.push(*id);
            }
        }
        for id in changed {
            let health = self.health(id);
            if let Some(health) = health {
                self.events
                    .push_back(EngineEvent::LinkChanged { link: id, health });
            }
        }
    }

    /// Current health of a link, aggregating its peers' channels.
    fn health(&self, link: LinkId) -> Option<LinkHealth> {
        let record = self.links.get(&link)?;
        // Loss is averaged over the peers reached on this link. With one
        // contact — the common case — that is just that contact's channel.
        let samples: Vec<u16> = self
            .peers
            .values()
            .filter(|p| p.link == link)
            .filter_map(|p| p.to_us.recent_loss_permille())
            .collect();
        let loss = if samples.is_empty() {
            None
        } else {
            Some((samples.iter().map(|s| u32::from(*s)).sum::<u32>() / samples.len() as u32) as u16)
        };
        Some(LinkHealth {
            up: record.up,
            loss_permille: loss,
            // The pacer is the only thing that knows when a duty-cycled link
            // will next have airtime, and "paced until 14:02" is a calm and
            // true thing to show.
            budget_blocked_until: self
                .local
                .link_stats(link)
                .and_then(|stats| stats.budget_blocked_until),
        })
    }

    /// Drains our engine's transmits onto the links.
    fn flush_local(&mut self, now: u64) {
        let timestamp = Timestamp::from_millis(now);
        let mut transmits: Vec<Transmit> = Vec::new();
        while let Some(transmit) = self.local.poll_transmit(timestamp) {
            transmits.push(transmit);
        }
        for transmit in transmits {
            let down = self.link_down(transmit.link);
            if let Some(peer) = self.peers.get_mut(&transmit.to) {
                peer.to_peer.send(now, transmit.packet.as_bytes(), down);
            }
        }
    }

    /// How many times a message has been transmitted, from the engine.
    fn transmissions(&self, conversation: ConversationId, id: MessageId) -> u32 {
        self.local
            .outgoing(conversation)
            .unwrap_or_default()
            .iter()
            .find(|status| status.id == id)
            .map_or(1, |status| status.transmissions.max(1))
    }

    /// Runs every scripted peer: deliver, pump, reply, transmit.
    fn advance_peers(&mut self, now: u64) {
        let timestamp = Timestamp::from_millis(now);
        let scripted = self.settings.scripted_replies;
        let mut replies: Vec<(ConversationId, u64)> = Vec::new();
        let down: BTreeMap<LinkId, bool> = self
            .links
            .iter()
            .map(|(id, link)| (*id, !link.up))
            .collect();

        for peer in self.peers.values_mut() {
            for packet in peer.to_peer.take_due(now) {
                peer.engine.handle_packet(peer.link, &packet, timestamp);
            }
            peer.engine.handle_timeout(timestamp);

            while let Some(event) = peer.engine.poll_event() {
                if let Event::MessageReceived(_) = event {
                    if scripted {
                        replies.push((peer.conversation, 0));
                    }
                }
            }

            while peer.pending.front().is_some_and(|(at, _)| *at <= now) {
                if let Some((_, text)) = peer.pending.pop_front() {
                    let _ = peer.engine.send_text(peer.conversation, &text, timestamp);
                }
            }

            let link_down = down.get(&peer.link).copied().unwrap_or(false);
            while let Some(transmit) = peer.engine.poll_transmit(timestamp) {
                peer.to_us.send(now, transmit.packet.as_bytes(), link_down);
            }
        }

        // Scheduling a reply needs `self.rng`, so it happens outside the
        // borrow of `self.peers` above.
        for (conversation, _) in replies {
            let delay = self.reply_delay();
            if let Some(peer) = self.peers.get_mut(&conversation) {
                let line = SCRIPT[peer.next_line % SCRIPT.len()];
                peer.next_line = peer.next_line.wrapping_add(1);
                peer.pending
                    .push_back((now.saturating_add(delay), line.to_string()));
            }
        }
    }

    /// Delivers due peer packets into our engine.
    fn deliver_to_local(&mut self, now: u64) {
        let timestamp = Timestamp::from_millis(now);
        let mut arrivals: Vec<(LinkId, Vec<u8>)> = Vec::new();
        for peer in self.peers.values_mut() {
            for packet in peer.to_us.take_due(now) {
                arrivals.push((peer.link, packet));
            }
        }
        for (link, packet) in arrivals {
            self.local.handle_packet(link, &packet, timestamp);
        }
    }

    /// Advances the whole simulation to `now`.
    fn advance(&mut self, now: u64) {
        // A clock that jumps backwards must not rewind the simulation; the
        // engine makes the same promise.
        let now = now.max(self.now);
        self.now = now;
        self.advance_links(now);
        self.flush_local(now);
        self.advance_peers(now);
        self.deliver_to_local(now);
        self.local.handle_timeout(Timestamp::from_millis(now));
        while let Some(event) = self.local.poll_event() {
            match event {
                Event::MessageReceived(received) => {
                    self.events
                        .push_back(EngineEvent::MessageReceived(received));
                }
                Event::MessageDelivered { conversation, id } => {
                    self.events
                        .push_back(EngineEvent::MessageDelivered { conversation, id });
                }
                Event::MessageTransmitted { conversation, id } => {
                    let attempt = self.transmissions(conversation, id);
                    self.events.push_back(EngineEvent::MessageTransmitted {
                        conversation,
                        id,
                        attempt,
                    });
                }
                // `Event` is non-exhaustive. A variant the app does not know
                // about is not an error; it is a newer library.
                _ => {}
            }
        }
    }
}

impl super::Simulation for FakeEngine {
    fn settings(&self) -> FakeEngineSettings {
        FakeEngine::settings(self)
    }

    fn set_settings(&mut self, settings: FakeEngineSettings) {
        FakeEngine::set_settings(self, settings);
    }

    fn invent_key(&mut self) -> PublicKey {
        FakeEngine::invent_key(self)
    }

    fn seed_history(&mut self, conversation: ConversationId, lines: usize) {
        FakeEngine::seed_history(self, conversation, lines);
    }

    fn abandon(
        &mut self,
        conversation: ConversationId,
        id: MessageId,
        reason: super::AbandonReason,
    ) {
        FakeEngine::abandon(self, conversation, id, reason);
    }
}

impl EngineHandle for FakeEngine {
    fn local_key(&self) -> PublicKey {
        self.local.local_key()
    }

    fn add_contact(&mut self, key: PublicKey) -> Result<ConversationId, Error> {
        let conversation = self.local.add_contact(key)?;
        // Give the new contact a simulated device: a real engine with its own
        // identity, reachable over the first registered link.
        let Some((&link, record)) = self.links.iter().next() else {
            // No link yet. The peer is created when one is registered; until
            // then messages queue, which is the honest outcome.
            return Ok(conversation);
        };
        let profile = record.profile;
        let link_config = record.config;
        let engine_rng = ChaCha20Rng::seed_from_u64(self.rng.next_u64());
        // The peer needs the *secret* for the key the caller was handed, or
        // nothing it signs will verify against the contact we just added.
        let identity = self
            .pending_identities
            .remove(&key)
            .ok_or(Error::InvalidContact)?;
        let mut engine = Engine::new(self.config, identity, MemoryStorage::new(), engine_rng)
            .map_err(|_| Error::InvalidContact)?;
        engine.add_link(link, link_config)?;
        let peer_conversation = engine.add_contact(self.local.local_key())?;
        debug_assert_eq!(
            peer_conversation, conversation,
            "conversation ids are symmetric"
        );
        let to_peer = Channel::new(profile, ChaCha20Rng::seed_from_u64(self.rng.next_u64()));
        let to_us = Channel::new(profile, ChaCha20Rng::seed_from_u64(self.rng.next_u64()));
        self.peers.insert(
            conversation,
            Peer {
                engine,
                conversation,
                link,
                to_peer,
                to_us,
                pending: VecDeque::new(),
                next_line: 0,
            },
        );
        Ok(conversation)
    }

    fn add_link(&mut self, id: LinkId, config: LinkConfig) -> Result<(), Error> {
        self.local.add_link(id, config)?;
        let profile = profile_by_name(&self.settings.profile);
        let outages = Outages::new(
            self.settings.outages.then_some(profile.outage).flatten(),
            ChaCha20Rng::seed_from_u64(self.rng.next_u64()),
            self.started_at,
        );
        self.links.insert(
            id,
            FakeLink {
                config,
                profile,
                outages,
                up: true,
            },
        );
        if let Some(health) = self.health(id) {
            self.events
                .push_back(EngineEvent::LinkChanged { link: id, health });
        }
        Ok(())
    }

    fn remove_link(&mut self, id: LinkId) -> Result<(), Error> {
        self.local.remove_link(id)?;
        self.links.remove(&id);
        self.events.push_back(EngineEvent::LinkChanged {
            link: id,
            health: LinkHealth::default(),
        });
        Ok(())
    }

    fn send_text(
        &mut self,
        conversation: ConversationId,
        text: &str,
        now: Timestamp,
    ) -> Result<Queued, Error> {
        self.local.send_text(conversation, text, now)
    }

    fn handle_packet(&mut self, link: LinkId, bytes: &[u8], now: Timestamp) {
        // Nothing outside the fake produces packets for it, but the driver is
        // allowed to call this and the engine must not care.
        self.local.handle_packet(link, bytes, now);
    }

    fn handle_timeout(&mut self, now: Timestamp) {
        // For this implementation `handle_timeout` means "advance the whole
        // simulation to `now`": the fake owns both ends of the link, so there
        // is no other moment at which the far side can run. The driver calls
        // it at the top of every pump, which is exactly what is needed.
        self.advance(now.as_millis());
    }

    fn poll_transmit(&mut self, _now: Timestamp) -> Option<Transmit> {
        // The fake is its own transport: packets go into its channels during
        // `advance`, not out through the driver.
        None
    }

    fn poll_event(&mut self) -> Option<EngineEvent> {
        self.events.pop_front()
    }

    fn next_timeout(&self) -> Option<Timestamp> {
        let mut earliest: Option<u64> = self.local.next_timeout().map(Timestamp::as_millis);
        let mut consider = |candidate: Option<u64>| {
            if let Some(value) = candidate {
                earliest = Some(earliest.map_or(value, |current| current.min(value)));
            }
        };
        for link in self.links.values() {
            consider(link.outages.next_change());
        }
        for peer in self.peers.values() {
            consider(peer.engine.next_timeout().map(Timestamp::as_millis));
            consider(peer.to_peer.next_arrival());
            consider(peer.to_us.next_arrival());
            consider(peer.pending.front().map(|(at, _)| *at));
        }
        earliest.map(Timestamp::from_millis)
    }

    fn link_health(&self, link: LinkId) -> Option<LinkHealth> {
        self.health(link)
    }

    fn link_counters(&self, link: LinkId) -> Option<LinkCounters> {
        // Straight from the engine, which counts what it actually handed out
        // and took in. Summing the fake's own channels would double-count a
        // duplicated packet and miss one the engine refused.
        let stats = self.local.link_stats(link)?;
        Some(LinkCounters {
            packets_sent: stats.packets_sent,
            packets_received: stats.packets_received,
            bytes_sent: stats.bytes_sent,
            bytes_received: stats.bytes_received,
            last_sent_at: None,
            last_received_at: None,
        })
    }

    fn contact_last_heard(&self, conversation: ConversationId) -> Option<Timestamp> {
        self.local.contact_status(conversation)?.last_heard
    }

    fn outbox_len(&self) -> usize {
        self.local.outbox_len()
    }

    fn simulation(&mut self) -> Option<&mut dyn super::Simulation> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::AbandonReason;

    const T0: u64 = 1_700_000_000_000;
    const LINK: LinkId = LinkId(1);

    /// A deterministic identity, so a test's fingerprints and conversation
    /// ids are the same on every run.
    fn identity(seed: u8) -> Identity {
        Identity::from_secret_bytes(&[seed; 32])
    }

    /// A fake engine on `profile`, with one link and one scripted contact.
    fn engine_on(profile: &str) -> (FakeEngine, ConversationId) {
        let mut engine = FakeEngine::with_profile(identity(1), profile, T0);
        let config = engine.link_config();
        engine.add_link(LINK, config).unwrap();
        let peer = engine.invent_key();
        let conversation = engine.add_contact(peer).unwrap();
        while engine.poll_event().is_some() {}
        (engine, conversation)
    }

    /// Advances the simulation until `done` or `limit_ms` of virtual time has
    /// passed, collecting every event produced.
    ///
    /// Steps to the engine's own next deadline rather than by a fixed tick,
    /// which is what the driver does and what lets a test cover six hours of
    /// a bad link in a few hundred iterations.
    fn run_until(
        engine: &mut FakeEngine,
        limit_ms: u64,
        mut done: impl FnMut(&[EngineEvent]) -> bool,
    ) -> Vec<EngineEvent> {
        let mut events = Vec::new();
        let mut now = engine.now;
        let deadline = now + limit_ms;
        for _ in 0..200_000 {
            engine.handle_timeout(Timestamp::from_millis(now));
            while let Some(event) = engine.poll_event() {
                events.push(event);
            }
            if done(&events) {
                return events;
            }
            let next = engine
                .next_timeout()
                .map(Timestamp::as_millis)
                .unwrap_or(now + 1_000);
            // Never go backwards, and always make progress.
            now = next.max(now + 1).min(deadline);
            if now >= deadline {
                engine.handle_timeout(Timestamp::from_millis(now));
                while let Some(event) = engine.poll_event() {
                    events.push(event);
                }
                break;
            }
        }
        events
    }

    fn delivered(events: &[EngineEvent], id: MessageId) -> bool {
        events
            .iter()
            .any(|e| matches!(e, EngineEvent::MessageDelivered { id: got, .. } if *got == id))
    }

    fn received_texts(events: &[EngineEvent]) -> Vec<String> {
        events
            .iter()
            .filter_map(|e| match e {
                EngineEvent::MessageReceived(m) => Some(m.text.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_message_is_transmitted_then_delivered_over_a_clean_link() {
        let (mut engine, conversation) = engine_on("clean");
        let queued = engine
            .send_text(conversation, "hello", Timestamp::from_millis(T0))
            .unwrap();

        let events = run_until(&mut engine, 60_000, |e| delivered(e, queued.id));

        // The honest state machine, in order and without invention.
        let first_transmit = events
            .iter()
            .find(|e| matches!(e, EngineEvent::MessageTransmitted { .. }))
            .expect("the message must be reported as transmitted");
        assert!(
            matches!(first_transmit, EngineEvent::MessageTransmitted { id, attempt, .. }
                     if *id == queued.id && *attempt == 1)
        );
        assert!(delivered(&events, queued.id), "clean link must deliver");
    }

    #[test]
    fn a_message_is_eventually_delivered_through_heavy_bursty_loss() {
        // The whole point of the library, and the state the interface has to
        // be calm about while it happens.
        let (mut engine, conversation) = engine_on("disaster_cellular");
        let queued = engine
            .send_text(
                conversation,
                "water drop at 06:00",
                Timestamp::from_millis(T0),
            )
            .unwrap();

        let events = run_until(&mut engine, 6 * 60 * 60 * 1000, |e| delivered(e, queued.id));
        assert!(
            delivered(&events, queued.id),
            "eventual delivery is the library's contract, even here"
        );

        let attempts = events
            .iter()
            .filter(|e| matches!(e, EngineEvent::MessageTransmitted { id, .. } if *id == queued.id))
            .count();
        assert!(attempts >= 1, "it had to go out at least once");
    }

    #[test]
    fn a_tiny_mtu_fragments_and_still_delivers() {
        // LoRa: 51-byte packets and a 1% duty cycle. A message longer than
        // one packet exercises fragmentation, per-fragment acknowledgement
        // and pacing all at once.
        let (mut engine, conversation) = engine_on("lora_like");
        let long = "the water drop is scheduled for 06:00 at the north clearing, \
                    bring the long hose and the spare coupling";
        let queued = engine
            .send_text(conversation, long, Timestamp::from_millis(T0))
            .unwrap();

        let events = run_until(&mut engine, 24 * 60 * 60 * 1000, |e| {
            delivered(e, queued.id)
        });
        assert!(
            delivered(&events, queued.id),
            "a fragmented message must still converge"
        );
    }

    #[test]
    fn attempts_count_transmission_rounds_not_packets() {
        // A multi-fragment message sent once is one attempt. Keying on
        // fragment 0 is what buys that; counting packets would report three.
        let (mut engine, conversation) = engine_on("clean");
        let long = "x".repeat(3_000);
        let queued = engine
            .send_text(conversation, &long, Timestamp::from_millis(T0))
            .unwrap();
        let events = run_until(&mut engine, 2_000, |e| {
            e.iter()
                .any(|e| matches!(e, EngineEvent::MessageTransmitted { .. }))
        });
        let attempts: Vec<u32> = events
            .iter()
            .filter_map(|e| match e {
                EngineEvent::MessageTransmitted { id, attempt, .. } if *id == queued.id => {
                    Some(*attempt)
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            attempts.first().copied(),
            Some(1),
            "a message spanning several packets is one attempt, not several"
        );
    }

    #[test]
    fn transmitted_events_name_the_right_message() {
        // Two queued messages must not be conflated; this is exactly what the
        // driver's AR-002 workaround gets wrong and the fake gets right.
        let (mut engine, conversation) = engine_on("clean");
        let first = engine
            .send_text(conversation, "one", Timestamp::from_millis(T0))
            .unwrap();
        let second = engine
            .send_text(conversation, "two", Timestamp::from_millis(T0))
            .unwrap();
        let events = run_until(&mut engine, 60_000, |e| {
            delivered(e, first.id) && delivered(e, second.id)
        });
        let named: Vec<MessageId> = events
            .iter()
            .filter_map(|e| match e {
                EngineEvent::MessageTransmitted { id, .. } => Some(*id),
                _ => None,
            })
            .collect();
        assert!(named.contains(&first.id));
        assert!(named.contains(&second.id));
        assert_ne!(first.id, second.id);
    }

    #[test]
    fn a_scripted_contact_replies_long_after_the_message_it_answers() {
        // The case the interface most needs: a reply whose send time is hours
        // after the message it responds to.
        let (mut engine, conversation) = engine_on("clean");
        engine.set_settings(FakeEngineSettings {
            reply_delay_ms: 30 * 60 * 1000,
            reply_jitter_ms: 30 * 60 * 1000,
            ..engine.settings()
        });
        engine
            .send_text(conversation, "are you there", Timestamp::from_millis(T0))
            .unwrap();

        let events = run_until(&mut engine, 6 * 60 * 60 * 1000, |e| {
            !received_texts(e).is_empty()
        });
        let replies = received_texts(&events);
        assert!(!replies.is_empty(), "the scripted contact must answer");
        assert!(SCRIPT.contains(&replies[0].as_str()));

        let received_at = events
            .iter()
            .find_map(|e| match e {
                EngineEvent::MessageReceived(m) => Some(m.received_at.as_millis()),
                _ => None,
            })
            .unwrap();
        assert!(
            received_at >= T0 + 30 * 60 * 1000,
            "the reply arrived at {received_at}, too soon to be a long-delayed answer"
        );
    }

    #[test]
    fn scripted_replies_can_be_switched_off() {
        let (mut engine, conversation) = engine_on("clean");
        engine.set_settings(FakeEngineSettings {
            scripted_replies: false,
            ..engine.settings()
        });
        engine
            .send_text(conversation, "are you there", Timestamp::from_millis(T0))
            .unwrap();
        let events = run_until(&mut engine, 60 * 60 * 1000, |_| false);
        assert!(
            received_texts(&events).is_empty(),
            "nothing should answer when replies are off"
        );
    }

    #[test]
    fn a_link_goes_down_and_comes_back() {
        let (mut engine, _) = engine_on("disaster_cellular");
        let events = run_until(&mut engine, 24 * 60 * 60 * 1000, |e| {
            let downs = e
                .iter()
                .filter(|e| matches!(e, EngineEvent::LinkChanged { health, .. } if !health.up))
                .count();
            let ups = e
                .iter()
                .filter(|e| matches!(e, EngineEvent::LinkChanged { health, .. } if health.up))
                .count();
            downs >= 1 && ups >= 2
        });
        let downs = events
            .iter()
            .filter(|e| matches!(e, EngineEvent::LinkChanged { health, .. } if !health.up))
            .count();
        assert!(downs >= 1, "this profile schedules outages; none happened");
    }

    #[test]
    fn outages_can_be_switched_off() {
        let (mut engine, _) = engine_on("disaster_cellular");
        engine.set_settings(FakeEngineSettings {
            outages: false,
            ..engine.settings()
        });
        let events = run_until(&mut engine, 24 * 60 * 60 * 1000, |_| false);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, EngineEvent::LinkChanged { health, .. } if !health.up)),
            "no link should go down with outages disabled"
        );
    }

    #[test]
    fn loss_is_measured_and_reported_once_there_is_evidence() {
        let (mut engine, conversation) = engine_on("disaster_cellular");
        // Before any traffic, loss is unmeasured and must not read as zero.
        assert_eq!(engine.link_health(LINK).unwrap().loss_permille, None);

        for i in 0..20 {
            let _ = engine.send_text(conversation, &format!("m{i}"), Timestamp::from_millis(T0));
        }
        run_until(&mut engine, 60 * 60 * 1000, |_| false);
        let loss = engine.link_health(LINK).unwrap().loss_permille;
        assert!(
            loss.is_some(),
            "loss should be measurable after real traffic"
        );
        assert!(loss.unwrap() <= 1000);
    }

    #[test]
    fn link_counters_move_because_the_fake_is_its_own_transport() {
        let (mut engine, conversation) = engine_on("clean");
        assert_eq!(engine.link_counters(LINK).unwrap(), LinkCounters::default());
        engine
            .send_text(conversation, "hello", Timestamp::from_millis(T0))
            .unwrap();
        run_until(&mut engine, 60_000, |_| false);
        let counters = engine.link_counters(LINK).unwrap();
        assert!(counters.packets_sent > 0);
        assert!(counters.bytes_sent > 0);
        assert!(
            counters.packets_received > 0,
            "the peer acknowledges, so packets come back"
        );
        assert_eq!(engine.link_counters(LinkId(9)), None);
    }

    #[test]
    fn the_driver_never_sees_a_transmit_from_the_fake() {
        // The fake is its own transport; if this changed, link counters would
        // be double-counted by the driver.
        let (mut engine, conversation) = engine_on("clean");
        engine
            .send_text(conversation, "hello", Timestamp::from_millis(T0))
            .unwrap();
        run_until(&mut engine, 10_000, |_| false);
        assert_eq!(
            engine.poll_transmit(Timestamp::from_millis(T0 + 10_000)),
            None
        );
    }

    #[test]
    fn the_simulation_replays_identically_from_its_seed() {
        let run = || {
            let (mut engine, conversation) = engine_on("disaster_cellular");
            engine
                .send_text(conversation, "hello", Timestamp::from_millis(T0))
                .unwrap();
            let events = run_until(&mut engine, 60 * 60 * 1000, |_| false);
            (events.len(), engine.link_counters(LINK).unwrap())
        };
        assert_eq!(run(), run(), "a session must replay exactly from its seed");
    }

    #[test]
    fn a_clock_that_jumps_backwards_does_not_rewind_the_simulation() {
        let (mut engine, conversation) = engine_on("clean");
        engine
            .send_text(conversation, "hello", Timestamp::from_millis(T0))
            .unwrap();
        run_until(&mut engine, 10_000, |_| false);
        let before = engine.link_counters(LINK).unwrap();
        engine.handle_timeout(Timestamp::from_millis(T0 - 1_000_000));
        assert_eq!(
            engine.link_counters(LINK).unwrap(),
            before,
            "going backwards must be a no-op, not a replay"
        );
    }

    #[test]
    fn a_contact_added_before_any_link_still_queues() {
        // Order of setup must not matter: the user can add a contact before
        // configuring a link, and the message should wait rather than fail.
        let mut engine = FakeEngine::with_profile(identity(1), "clean", T0);
        let peer = engine.invent_key();
        let conversation = engine.add_contact(peer).unwrap();
        let queued = engine.send_text(conversation, "hello", Timestamp::from_millis(T0));
        assert!(queued.is_ok(), "queueing must not need a link");
        assert_eq!(engine.outbox_len(), 1);
    }

    #[test]
    fn seeded_history_arrives_over_the_real_link() {
        let (mut engine, conversation) = engine_on("clean");
        engine.seed_history(conversation, 4);
        let events = run_until(&mut engine, 60_000, |e| received_texts(e).len() >= 4);
        assert!(received_texts(&events).len() >= 4);
    }

    #[test]
    fn switching_profile_does_not_lose_packets_already_in_flight() {
        let (mut engine, conversation) = engine_on("geo_satellite");
        let queued = engine
            .send_text(conversation, "hello", Timestamp::from_millis(T0))
            .unwrap();
        // Advance just enough to get the packet onto the wire, then retune.
        run_until(&mut engine, 100, |_| false);
        engine.set_settings(FakeEngineSettings {
            profile: "clean".to_string(),
            ..engine.settings()
        });
        let events = run_until(&mut engine, 60 * 60 * 1000, |e| delivered(e, queued.id));
        assert!(delivered(&events, queued.id));
    }

    #[test]
    fn an_unknown_profile_falls_back_rather_than_failing() {
        let (engine, _) = engine_on("not_a_profile");
        // Falls back to the default, so the link still has a sane MTU.
        assert!(engine.link_config().mtu >= avianlink_core::MIN_MTU);
    }

    #[test]
    fn abandon_reasons_are_available_for_the_failed_state() {
        // `FakeEngine` wraps a real engine, which never gives up (AR-003), so
        // the failed state is produced by pushing the event directly. This
        // test pins that the path exists for the UI to be built against.
        let (mut engine, conversation) = engine_on("clean");
        let queued = engine
            .send_text(conversation, "hello", Timestamp::from_millis(T0))
            .unwrap();
        engine.abandon(conversation, queued.id, AbandonReason::RetryLimit);
        let event = engine.poll_event().unwrap();
        assert!(matches!(
            event,
            EngineEvent::MessageAbandoned { id, .. } if id == queued.id
        ));
    }
}
