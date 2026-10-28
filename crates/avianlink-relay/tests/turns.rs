//! A and B are never online at the same time; a relay carries everything
//! (`docs/relay.md` §1).

use avianlink_core::{
    Config, ConversationId, Engine, Event, Identity, LinkBudget, LinkConfig, LinkId, MemoryStorage,
    PublicKey, Timestamp,
};
use avianlink_relay::{Relay, RelayClient, RelayConfig};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

type E = Engine<MemoryStorage, ChaCha20Rng>;
const LINK: LinkId = LinkId(0);
/// 2026-10-27, so epochs are realistic.
const T0: u64 = 1_793_000_000_000;

struct Node {
    engine: E,
    client: RelayClient,
    events: Vec<Event>,
}

impl Node {
    fn new(seed: u8) -> Self {
        let mut engine = Engine::new(
            Config::default(),
            Identity::from_secret_bytes(&[seed; 32]),
            MemoryStorage::new(),
            ChaCha20Rng::seed_from_u64(seed.into()),
        )
        .unwrap();
        let link = LinkConfig {
            mtu: 48,
            budget: LinkBudget::Unlimited,
            cost: 1,
        };
        engine.add_relay_link(LINK, link).unwrap();
        Self {
            engine,
            client: RelayClient::new(LINK),
            events: Vec::new(),
        }
    }

    fn key(&self) -> PublicKey {
        self.engine.local_key()
    }

    fn received(&self) -> Vec<String> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::MessageReceived(m) => Some(m.text.clone()),
                _ => None,
            })
            .collect()
    }

    fn count(&self, f: fn(&Event) -> bool) -> usize {
        self.events.iter().filter(|e| f(e)).count()
    }
}

struct World {
    relay: Relay<MemoryStorage, u8>,
    now: u64,
    /// Datagrams lost on the way: every `drop_every`-th one, if set.
    drop_every: Option<u64>,
    sent: u64,
}

impl World {
    fn new() -> Self {
        Self {
            relay: Relay::open(RelayConfig::default(), MemoryStorage::new()).unwrap(),
            now: T0,
            drop_every: None,
            sent: 0,
        }
    }

    fn lost(&mut self) -> bool {
        self.sent += 1;
        self.drop_every.is_some_and(|n| self.sent.is_multiple_of(n))
    }

    /// Runs `node` (address `addr`) online for `secs`, then offline.
    fn session(&mut self, node: &mut Node, addr: u8, secs: u64, accept_requests: bool) {
        let t = Timestamp::from_millis;
        node.client.connect(&mut node.engine, t(self.now));
        let end = self.now + secs * 1000;
        while self.now < end {
            let now = t(self.now);
            node.engine.handle_timeout(now);
            node.client.handle_timeout(&mut node.engine, now);
            while let Some(tx) = node.engine.poll_transmit(now) {
                node.client.upload(&mut node.engine, tx, now);
            }
            while let Some(bytes) = node.client.poll_transmit() {
                if !self.lost() {
                    self.relay.handle(addr, &bytes, now);
                }
            }
            while let Some((to, bytes)) = self.relay.poll_transmit() {
                if to == addr && !self.lost() {
                    node.client.handle(&mut node.engine, &bytes, now);
                }
            }
            while let Some(ev) = node.engine.poll_event() {
                if let (true, Event::ContactRequest { public_key, .. }) = (accept_requests, &ev) {
                    node.engine.add_contact(*public_key).unwrap();
                }
                node.events.push(ev);
            }
            self.now += 250;
        }
        node.client.disconnect();
    }

    /// Time passes with both offline.
    fn wait(&mut self, secs: u64) {
        self.now += secs * 1000;
        self.relay.handle_timeout(Timestamp::from_millis(self.now));
    }
}

fn befriend(a: &mut Node, b: &mut Node) -> (ConversationId, ConversationId) {
    (
        a.engine.add_contact(b.key()).unwrap(),
        b.engine.add_contact(a.key()).unwrap(),
    )
}

#[test]
fn alternating_turns_deliver_and_confirm_everything() {
    let mut w = World::new();
    let (mut a, mut b) = (Node::new(1), Node::new(2));
    let (ab, ba) = befriend(&mut a, &mut b);
    let long = "a 200-byte-ish message that needs several 48-byte packets ".repeat(4);
    for turn in 0..4 {
        let now = Timestamp::from_millis(w.now);
        a.engine
            .send_text(ab, &format!("A{turn}: {long}"), now)
            .unwrap();
        w.session(&mut a, 1, 60, false);
        w.wait(3_600);
        let now = Timestamp::from_millis(w.now);
        b.engine.send_text(ba, &format!("B{turn}"), now).unwrap();
        w.session(&mut b, 2, 60, false);
        w.wait(3_600);
    }
    w.session(&mut a, 1, 60, false);
    // B collects A's ACK of its last message.
    w.wait(3_600);
    w.session(&mut b, 2, 60, false);
    assert_eq!(b.received().len(), 4, "{:?}", b.received());
    assert_eq!(a.received(), ["B0", "B1", "B2", "B3"]);
    // Every message confirmed by the peer's own ACK, carried by the relay.
    assert_eq!(a.count(|e| matches!(e, Event::MessageDelivered { .. })), 4);
    assert_eq!(b.count(|e| matches!(e, Event::MessageDelivered { .. })), 4);
    // "Safe to go offline" was reported for each before its sender left.
    assert_eq!(a.count(|e| matches!(e, Event::MessageStored { .. })), 4);
    assert_eq!(
        a.engine.stats().probes_sent,
        0,
        "no probing through a relay"
    );
    assert_eq!(a.engine.outbox_len() + b.engine.outbox_len(), 0);
    // The relay released what the recipients proved they have.
    assert!(w.relay.stats().released > 0);
}

#[test]
fn turns_survive_loss_on_the_way_to_and_from_the_relay() {
    let mut w = World::new();
    w.drop_every = Some(5); // 20% of datagrams, both directions
    let (mut a, mut b) = (Node::new(1), Node::new(2));
    let (ab, ba) = befriend(&mut a, &mut b);
    for turn in 0..3 {
        let now = Timestamp::from_millis(w.now);
        a.engine
            .send_text(ab, &format!("A{turn} {}", "x".repeat(150)), now)
            .unwrap();
        w.session(&mut a, 1, 120, false);
        w.wait(1_800);
        let now = Timestamp::from_millis(w.now);
        b.engine.send_text(ba, &format!("B{turn}"), now).unwrap();
        w.session(&mut b, 2, 120, false);
        w.wait(1_800);
    }
    w.session(&mut a, 1, 120, false);
    w.wait(1_800);
    w.session(&mut b, 2, 120, false);
    assert_eq!(b.received().len(), 3);
    assert_eq!(a.received().len(), 3);
    assert_eq!(a.count(|e| matches!(e, Event::MessageDelivered { .. })), 3);
    assert_eq!(b.count(|e| matches!(e, Event::MessageDelivered { .. })), 3);
}

#[test]
fn introduction_through_the_relay() {
    let mut w = World::new();
    let (mut a, mut b) = (Node::new(1), Node::new(2));
    // A knows B; B has never heard of A.
    let ab = a.engine.add_contact(b.key()).unwrap();
    a.engine
        .send_text(
            ab,
            "hello B, you don't know me",
            Timestamp::from_millis(w.now),
        )
        .unwrap();
    w.session(&mut a, 1, 60, false);
    w.wait(3_600);
    // B comes online, finds the request, accepts, and gets the message.
    w.session(&mut b, 2, 60, true);
    assert_eq!(b.count(|e| matches!(e, Event::ContactRequest { .. })), 1);
    assert_eq!(b.received(), ["hello B, you don't know me"]);
    let ba = b.engine.contacts().next().unwrap().0;
    b.engine
        .send_text(ba, "hi A", Timestamp::from_millis(w.now))
        .unwrap();
    w.session(&mut b, 2, 30, true);
    w.wait(3_600);
    w.session(&mut a, 1, 60, false);
    assert_eq!(a.received(), ["hi A"]);
    assert_eq!(a.count(|e| matches!(e, Event::MessageDelivered { .. })), 1);
    assert!(a.engine.contact_status(ab).unwrap().confirmed);
}

#[test]
fn a_wiped_relay_costs_only_a_resend() {
    let mut w = World::new();
    let (mut a, mut b) = (Node::new(1), Node::new(2));
    let (ab, _) = befriend(&mut a, &mut b);
    a.engine
        .send_text(ab, "first", Timestamp::from_millis(w.now))
        .unwrap();
    w.session(&mut a, 1, 60, false);
    // The relay is rebuilt empty: A's stored message is gone.
    w.relay = Relay::open(RelayConfig::default(), MemoryStorage::new()).unwrap();
    w.wait(3_600);
    w.session(&mut b, 2, 60, false);
    assert!(b.received().is_empty());
    // Half a retention later A, online again, resends what B never ACKed.
    w.wait(4 * 24 * 3_600);
    w.session(&mut a, 1, 60, false);
    w.wait(3_600);
    w.session(&mut b, 2, 60, false);
    assert_eq!(b.received(), ["first"]);
}
