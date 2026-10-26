//! End-to-end through the app's own backend: driver, store and the simulated
//! engine together.
//!
//! The other suites isolate pieces — the driver against a scripted engine,
//! the store against hand-built messages. This one takes the real
//! `FakeEngine`, which runs two real `avianlink_core::Engine` instances over
//! a genuinely lossy link, and checks that what ends up in the app's store is
//! what the interface should show.
//!
//! That is the Phase 1 claim worth testing: not that the parts work, but that
//! a message survives a bad link and arrives in the UI's model with honest
//! state attached.

use std::sync::Arc;

use avianlink_core::{Identity, LinkId, PublicKey, Timestamp};
use avianlink_desktop_lib::driver::{Clock, LinkRecord, NullTransport, Shared, TestClock};
use avianlink_desktop_lib::engine::{FakeEngine, LinkCounters, LinkHealth};
use avianlink_desktop_lib::events::{EventSink, RecordingSink};
use avianlink_desktop_lib::ipc::{LinkKind, LinkSettings, MessageStatus};
use avianlink_desktop_lib::storage::OutgoingMessage;

const T0: u64 = 1_700_000_000_000;
const LINK: LinkId = LinkId(1);

struct App {
    shared: Arc<Shared>,
    sink: Arc<RecordingSink>,
    clock: Arc<TestClock>,
}

impl App {
    /// Builds the app's backend on the simulated engine, as `run` does.
    async fn new(profile: &str) -> Self {
        let identity = Identity::from_secret_bytes(&[7; 32]);
        let local = identity.public_key();
        let engine = FakeEngine::with_profile(identity, profile, T0);
        let config = engine.link_config();
        let sink = Arc::new(RecordingSink::new());
        let clock = Arc::new(TestClock::new(T0));
        let shared = Arc::new(Shared::new(
            Box::new(engine),
            Box::new(NullTransport),
            Arc::clone(&clock) as Arc<dyn Clock>,
            Arc::clone(&sink) as Arc<dyn EventSink>,
        ));
        shared.with_store(|store| store.set_identity(local));
        shared.engine.lock().await.add_link(LINK, config).unwrap();
        shared.with_links(|links| {
            links.insert(
                LINK.0,
                LinkRecord {
                    label: "Simulated link".into(),
                    kind: LinkKind::Fake,
                    enabled: true,
                    config,
                    settings: LinkSettings::Fake {
                        profile: profile.into(),
                    },
                    health: LinkHealth {
                        up: true,
                        loss_permille: None,
                        budget_blocked_until: None,
                    },
                    counters: LinkCounters::default(),
                },
            );
        });
        shared.pump().await;
        sink.take();
        Self {
            shared,
            sink,
            clock,
        }
    }

    /// Adds a contact whose simulated device will answer.
    async fn add_contact(&self, name: &str) -> avianlink_core::ConversationId {
        let key: PublicKey = {
            let mut engine = self.shared.engine.lock().await;
            engine
                .simulation()
                .expect("the simulated engine must expose its controls")
                .invent_key()
        };
        let conversation = self.shared.engine.lock().await.add_contact(key).unwrap();
        self.shared
            .with_store(|store| store.upsert_contact(conversation, key, name, false, T0));
        conversation
    }

    /// Queues a message exactly as the `send_message` command does.
    async fn send(&self, conversation: avianlink_core::ConversationId, text: &str) -> String {
        let now = self.shared.now();
        let queued = {
            let mut engine = self.shared.engine.lock().await;
            engine.send_text(conversation, text, now).unwrap()
        };
        self.shared.with_store(|store| {
            store.insert_outgoing(OutgoingMessage {
                conversation,
                id: queued.id,
                seq: queued.seq,
                lamport: queued.lamport,
                text,
                queued_at: now.as_millis(),
            })
        });
        avianlink_desktop_lib::identity::encode_message_id(&queued.id)
    }

    /// Advances the simulation, pumping as the driver loop would, until
    /// `done` or `limit_ms` of virtual time has passed.
    async fn run_until(&self, limit_ms: u64, mut done: impl FnMut() -> bool) {
        let start = self.clock.now_ms();
        for _ in 0..100_000 {
            let next = self.shared.pump().await;
            if done() {
                return;
            }
            let now = self.clock.now_ms();
            if now.saturating_sub(start) >= limit_ms {
                return;
            }
            let step = next.map_or(now + 1_000, |deadline| deadline.max(now + 1));
            self.clock.set(step.min(start + limit_ms));
        }
    }

    /// The status the interface would show for a message.
    fn status(
        &self,
        conversation: avianlink_core::ConversationId,
        id: &str,
    ) -> Option<MessageStatus> {
        self.shared.with_store(|store| {
            store
                .messages(&conversation, None, 500)?
                .messages
                .into_iter()
                .find(|m| m.id == id)
                .and_then(|m| m.status)
        })
    }
}

#[tokio::test]
async fn a_message_reaches_delivered_over_a_clean_link() {
    let app = App::new("clean").await;
    let conversation = app.add_contact("Rook").await;
    let id = app.send(conversation, "are you there").await;

    assert_eq!(
        app.status(conversation, &id),
        Some(MessageStatus::Queued),
        "it must be queued the instant the command returns"
    );

    app.run_until(120_000, || {
        app.status(conversation, &id) == Some(MessageStatus::Delivered)
    })
    .await;

    assert_eq!(
        app.status(conversation, &id),
        Some(MessageStatus::Delivered)
    );
}

#[tokio::test]
async fn a_message_survives_heavy_bursty_loss_and_outages() {
    // The claim the whole app rests on: eventual delivery on a link that
    // loses most of what it carries and disappears for minutes at a time.
    let app = App::new("disaster_cellular").await;
    let conversation = app.add_contact("Rook").await;
    let id = app.send(conversation, "water drop at 06:00").await;

    app.run_until(6 * 60 * 60 * 1000, || {
        app.status(conversation, &id) == Some(MessageStatus::Delivered)
    })
    .await;

    assert_eq!(
        app.status(conversation, &id),
        Some(MessageStatus::Delivered),
        "the message never got through"
    );
}

#[tokio::test]
async fn the_interface_sees_queued_then_sent_then_delivered_in_order() {
    let app = App::new("clean").await;
    let conversation = app.add_contact("Rook").await;
    let id = app.send(conversation, "hello").await;
    app.run_until(120_000, || {
        app.status(conversation, &id) == Some(MessageStatus::Delivered)
    })
    .await;

    let seen: Vec<MessageStatus> = app
        .sink
        .status_changes()
        .into_iter()
        .filter(|change| change.message_id == id)
        .map(|change| change.status)
        .collect();
    assert_eq!(
        seen,
        vec![MessageStatus::Sent, MessageStatus::Delivered],
        "the UI must be told each transition exactly once, in order"
    );
}

#[tokio::test]
async fn a_scripted_contact_answers_and_the_reply_is_stored() {
    let app = App::new("clean").await;
    let conversation = app.add_contact("Rook").await;
    app.send(conversation, "are you there").await;

    app.run_until(6 * 60 * 60 * 1000, || !app.sink.received().is_empty())
        .await;

    let received = app.sink.received();
    assert!(!received.is_empty(), "the scripted contact never answered");
    let reply = &received[0];
    assert!(!reply.outgoing);
    assert_eq!(reply.status, None, "an incoming message has no status");
    assert!(reply.received_at.is_some());
}

#[tokio::test]
async fn a_long_message_fragments_at_a_tiny_mtu_and_still_arrives() {
    // LoRa: 51-byte packets, 1% duty cycle. The engine fragments, paces
    // against the airtime budget, and the app shows the same four states.
    let app = App::new("lora_like").await;
    let conversation = app.add_contact("Rook").await;
    let text = "the water drop is scheduled for 06:00 at the north clearing, \
                bring the long hose and the spare coupling";
    let id = app.send(conversation, text).await;

    app.run_until(24 * 60 * 60 * 1000, || {
        app.status(conversation, &id) == Some(MessageStatus::Delivered)
    })
    .await;

    assert_eq!(
        app.status(conversation, &id),
        Some(MessageStatus::Delivered)
    );
}

#[tokio::test]
async fn link_counters_and_loss_reach_the_interface() {
    let app = App::new("disaster_cellular").await;
    let conversation = app.add_contact("Rook").await;
    for index in 0..10 {
        app.send(conversation, &format!("message {index}")).await;
    }
    app.run_until(2 * 60 * 60 * 1000, || false).await;

    let link = app.shared.with_links(|links| links.get(LINK.0)).unwrap();
    assert!(link.packets_sent > 0, "nothing was counted as sent");
    assert!(link.bytes_sent > 0);
    assert!(
        link.recent_loss_permille.is_some(),
        "loss should be measurable after real traffic on this profile"
    );
}

#[tokio::test]
async fn an_outage_is_reported_and_the_outbox_simply_waits() {
    // Being unreachable is not an error state: queued messages stay queued
    // and nothing is marked failed.
    let app = App::new("disaster_cellular").await;
    let conversation = app.add_contact("Rook").await;
    let id = app.send(conversation, "hello").await;

    app.run_until(24 * 60 * 60 * 1000, || {
        app.sink
            .events()
            .iter()
            .any(|event| matches!(event, avianlink_desktop_lib::events::Recorded::LinkStatusChanged(link) if !link.enabled || link.status != avianlink_desktop_lib::ipc::LinkStatus::Up))
    })
    .await;

    assert_ne!(
        app.status(conversation, &id),
        Some(MessageStatus::Failed),
        "an outage must never mark a message failed"
    );
}

#[tokio::test]
async fn the_contacts_last_heard_time_includes_acknowledgement_only_packets() {
    // The number the thread header shows. Only the engine can answer it: a
    // packet carrying nothing but an acknowledgement still proves the peer is
    // there, and never reaches the app as an event.
    let app = App::new("clean").await;
    let conversation = app.add_contact("Rook").await;
    assert_eq!(
        app.shared
            .with_store(|store| store.contact_last_packet_at(&conversation)),
        None
    );

    let id = app.send(conversation, "hello").await;
    app.run_until(120_000, || {
        app.status(conversation, &id) == Some(MessageStatus::Delivered)
    })
    .await;

    assert!(
        app.shared
            .with_store(|store| store.contact_last_packet_at(&conversation))
            .is_some(),
        "the acknowledgement should have updated the last-heard time"
    );
}

#[tokio::test]
async fn seeded_history_arrives_as_ordinary_received_messages() {
    let app = App::new("clean").await;
    let conversation = app.add_contact("Rook").await;
    {
        let mut engine = app.shared.engine.lock().await;
        engine.simulation().unwrap().seed_history(conversation, 4);
    }
    app.run_until(120_000, || app.sink.received().len() >= 4)
        .await;

    let page = app
        .shared
        .with_store(|store| store.messages(&conversation, None, 50))
        .unwrap();
    assert!(page.total >= 4);
    assert!(
        page.messages
            .windows(2)
            .all(|w| w[0].order_key < w[1].order_key),
        "history must be stored in causal order"
    );
}

#[tokio::test]
async fn the_simulation_replays_identically() {
    async fn run() -> (Option<MessageStatus>, u64) {
        let app = App::new("disaster_cellular").await;
        let conversation = app.add_contact("Rook").await;
        let id = app.send(conversation, "hello").await;
        app.run_until(60 * 60 * 1000, || false).await;
        let link = app.shared.with_links(|links| links.get(LINK.0)).unwrap();
        (app.status(conversation, &id), link.packets_sent)
    }
    assert_eq!(run().await, run().await);
}

#[tokio::test]
async fn timestamps_use_the_apps_clock_not_the_systems() {
    let app = App::new("clean").await;
    let conversation = app.add_contact("Rook").await;
    let id = app.send(conversation, "hello").await;
    let page = app
        .shared
        .with_store(|store| store.messages(&conversation, None, 10))
        .unwrap();
    let message = page.messages.iter().find(|m| m.id == id).unwrap();
    assert_eq!(message.sent_at, Some(T0));
}

#[tokio::test]
async fn an_engine_with_no_simulation_offers_no_simulation_controls() {
    // Guards the escape hatch: the real engine must report `None` so the
    // dev-only command refuses rather than inventing a contact nothing will
    // ever answer.
    let app = App::new("clean").await;
    let mut engine = app.shared.engine.lock().await;
    assert!(
        engine.simulation().is_some(),
        "the fake must expose its controls"
    );
    drop(engine);
    assert_eq!(
        app.shared.now(),
        Timestamp::from_millis(app.clock.now_ms()),
        "the app's clock is the one the engine is driven by"
    );
}
