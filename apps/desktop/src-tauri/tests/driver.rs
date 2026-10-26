//! Driver tests.
//!
//! These exercise the pump loop against a hand-scripted engine rather than
//! `FakeEngine`, so a test can produce an exact sequence of engine outputs —
//! including ones `FakeEngine` cannot yet produce — and assert on what the
//! store ends up holding and what the frontend would have been told.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use avianlink_core::{
    ConversationId, Error, LinkBudget, LinkConfig, LinkId, MessageId, Packet, PublicKey,
    ReceivedMessage, Timestamp, Transmit,
};
use avianlink_desktop_lib::driver::{
    Clock, Inbound, LinkRecord, NullTransport, Shared, TestClock, Transport,
};
use avianlink_desktop_lib::engine::{
    AbandonReason, EngineEvent, EngineHandle, LinkCounters, LinkHealth, Queued,
};
use avianlink_desktop_lib::events::{Recorded, RecordingSink};
use avianlink_desktop_lib::ipc::{LinkKind, LinkSettings, LinkStatus, MessageStatus};

const T0: u64 = 1_700_000_000_000;

/// A poisoned test mutex means an assertion already failed somewhere else;
/// recovering keeps the real failure visible instead of masking it.
fn lock(script: &Arc<Mutex<Script>>) -> MutexGuard<'_, Script> {
    script.lock().unwrap_or_else(|e| e.into_inner())
}
const LINK: LinkId = LinkId(1);

/// Everything a test wants to write into, or read back out of, the engine.
///
/// Shared rather than reached for by downcasting: the driver holds the engine
/// as `Box<dyn EngineHandle>`, and a test that had to downcast through that
/// would be testing the test harness as much as the driver.
#[derive(Default)]
struct Script {
    events: VecDeque<EngineEvent>,
    transmits: VecDeque<Transmit>,
    /// Packets handed back in through `handle_packet`.
    received: Vec<(LinkId, Vec<u8>)>,
    /// Times `handle_timeout` was called.
    timeouts: Vec<Timestamp>,
    next_timeout: Option<Timestamp>,
}

/// An engine whose every output a test writes by hand.
struct ScriptedEngine {
    local: PublicKey,
    contacts: BTreeMap<ConversationId, PublicKey>,
    links: BTreeMap<LinkId, LinkHealth>,
    reports_transmissions: bool,
    script: Arc<Mutex<Script>>,
    seq: u64,
    lamport: u64,
    outbox: usize,
}

impl ScriptedEngine {
    fn new(reports_transmissions: bool, script: Arc<Mutex<Script>>) -> Self {
        Self {
            local: PublicKey([1; 32]),
            contacts: BTreeMap::new(),
            links: BTreeMap::new(),
            reports_transmissions,
            script,
            seq: 0,
            lamport: 0,
            outbox: 0,
        }
    }
}

impl EngineHandle for ScriptedEngine {
    fn local_key(&self) -> PublicKey {
        self.local
    }

    fn add_contact(&mut self, key: PublicKey) -> Result<ConversationId, Error> {
        let conversation = avianlink_core::hashes::conversation_id(&self.local, &key);
        self.contacts.insert(conversation, key);
        Ok(conversation)
    }

    fn add_link(&mut self, id: LinkId, _config: LinkConfig) -> Result<(), Error> {
        self.links.insert(
            id,
            LinkHealth {
                up: true,
                loss_permille: None,
                budget_blocked_until: None,
            },
        );
        Ok(())
    }

    fn remove_link(&mut self, id: LinkId) -> Result<(), Error> {
        self.links.remove(&id).ok_or(Error::UnknownLink)?;
        Ok(())
    }

    fn send_text(
        &mut self,
        _conversation: ConversationId,
        _text: &str,
        _now: Timestamp,
    ) -> Result<Queued, Error> {
        let seq = self.seq;
        self.seq += 1;
        self.lamport += 1;
        self.outbox += 1;
        let mut id = [0u8; 16];
        id[0] = seq as u8;
        Ok(Queued {
            id: MessageId(id),
            seq,
            lamport: self.lamport,
        })
    }

    fn handle_packet(&mut self, link: LinkId, bytes: &[u8], _now: Timestamp) {
        lock(&self.script).received.push((link, bytes.to_vec()));
    }

    fn handle_timeout(&mut self, now: Timestamp) {
        lock(&self.script).timeouts.push(now);
    }

    fn poll_transmit(&mut self, _now: Timestamp) -> Option<Transmit> {
        lock(&self.script).transmits.pop_front()
    }

    fn poll_event(&mut self) -> Option<EngineEvent> {
        lock(&self.script).events.pop_front()
    }

    fn next_timeout(&self) -> Option<Timestamp> {
        lock(&self.script).next_timeout
    }

    fn link_health(&self, link: LinkId) -> Option<LinkHealth> {
        self.links.get(&link).copied()
    }

    fn outbox_len(&self) -> usize {
        self.outbox
    }

    fn reports_transmissions(&self) -> bool {
        self.reports_transmissions
    }
}

/// What the transport was handed: one entry per accepted packet.
type SentPackets = Arc<Mutex<Vec<(LinkId, Vec<u8>)>>>;

/// Lets a test see and refuse what the transport was handed.
#[derive(Default)]
struct SpyTransport {
    sent: SentPackets,
    accept: bool,
}

impl Transport for SpyTransport {
    fn send(&mut self, link: LinkId, _to: ConversationId, packet: &[u8], _now: Timestamp) -> bool {
        if self.accept {
            if let Ok(mut sent) = self.sent.lock() {
                sent.push((link, packet.to_vec()));
            }
        }
        self.accept
    }
}

struct Harness {
    shared: Arc<Shared>,
    sink: Arc<RecordingSink>,
    clock: Arc<TestClock>,
    conversation: ConversationId,
    script: Arc<Mutex<Script>>,
}

impl Harness {
    /// Queues engine events for the next pump.
    fn script(&self, events: Vec<EngineEvent>) {
        lock(&self.script).events.extend(events);
    }

    /// Queues a packet for the engine to hand to the transport.
    fn queue_transmit(&self, bytes: &[u8]) {
        lock(&self.script).transmits.push_back(Transmit {
            link: LINK,
            to: self.conversation,
            packet: Packet::from_vec(bytes.to_vec()),
        });
    }

    /// Queues an outgoing message in both the engine and the store, as
    /// `send_message` would.
    async fn send(&self, text: &str) -> MessageId {
        let queued = {
            let mut engine = self.shared.engine.lock().await;
            engine
                .send_text(self.conversation, text, self.shared.now())
                .unwrap()
        };
        self.shared.with_store(|store| {
            store.insert_outgoing(
                self.conversation,
                queued.id,
                queued.seq,
                queued.lamport,
                text,
                T0,
            )
        });
        queued.id
    }
}

fn link_config() -> LinkConfig {
    LinkConfig {
        mtu: 1200,
        budget: LinkBudget::Unlimited,
        cost: 1,
    }
}

fn link_record() -> LinkRecord {
    LinkRecord {
        label: "Test link".into(),
        kind: LinkKind::Fake,
        enabled: true,
        config: link_config(),
        settings: LinkSettings::Fake {
            profile: "clean".into(),
        },
        health: LinkHealth {
            up: true,
            loss_permille: None,
            budget_blocked_until: None,
        },
        counters: LinkCounters::default(),
    }
}

/// Builds a harness with one contact and one registered link.
async fn harness_with(reports_transmissions: bool, transport: Box<dyn Transport>) -> Harness {
    let script = Arc::new(Mutex::new(Script::default()));
    let engine = ScriptedEngine::new(reports_transmissions, Arc::clone(&script));
    let sink = Arc::new(RecordingSink::new());
    let clock = Arc::new(TestClock::new(T0));
    let peer = PublicKey([2; 32]);
    let conversation = avianlink_core::hashes::conversation_id(&PublicKey([1; 32]), &peer);
    let shared = Arc::new(Shared::new(
        Box::new(engine),
        transport,
        Arc::clone(&clock) as Arc<dyn Clock>,
        Arc::clone(&sink) as Arc<dyn avianlink_desktop_lib::events::EventSink>,
    ));
    shared.with_store(|store| {
        store.set_identity(PublicKey([1; 32]));
        store.upsert_contact(conversation, peer, "Rook", false, T0);
    });
    shared.with_links(|links| links.insert(LINK.0, link_record()));
    shared.engine.lock().await.add_contact(peer).unwrap();
    sink.take();
    Harness {
        shared,
        sink,
        clock,
        conversation,
        script,
    }
}

async fn harness(reports_transmissions: bool) -> Harness {
    harness_with(reports_transmissions, Box::new(NullTransport)).await
}

fn received(conversation: ConversationId, seq: u64, lamport: u64, text: &str) -> EngineEvent {
    let mut id = [0u8; 16];
    id[0] = 0x80 | seq as u8;
    EngineEvent::MessageReceived(ReceivedMessage {
        conversation,
        id: MessageId(id),
        seq,
        lamport,
        // Earlier messages we have not seen; the engine reports it so the UI
        // can say "something is still on its way" rather than guessing.
        missing_before: 0,
        sender_time: Some(Timestamp::from_millis(T0)),
        received_at: Timestamp::from_millis(T0 + 1_000),
        text: text.to_string(),
    })
}

#[tokio::test]
async fn pump_uses_the_injected_clock_and_advances_the_engines_timers() {
    let h = harness(true).await;
    h.clock.set(T0 + 9_999);
    h.shared.pump().await;
    assert_eq!(h.shared.now().as_millis(), T0 + 9_999);
    assert_eq!(
        lock(&h.script).timeouts,
        vec![Timestamp::from_millis(T0 + 9_999)],
        "the engine must be told the time the app believes, not the system's"
    );
}

#[tokio::test]
async fn an_incoming_message_is_stored_and_announced() {
    let h = harness(true).await;
    h.script(vec![received(h.conversation, 0, 1, "hello")]);
    h.shared.pump().await;

    let page = h
        .shared
        .with_store(|s| s.messages(&h.conversation, None, 10))
        .unwrap();
    assert_eq!(page.messages.len(), 1);
    assert_eq!(page.messages[0].text, "hello");
    assert!(!page.messages[0].outgoing);
    assert_eq!(page.messages[0].status, None, "incoming has no status");

    let events = h.sink.take();
    assert!(matches!(events[0], Recorded::MessageReceived(_)));
    // The contact's "last heard from" moved, so the sidebar must be told.
    assert!(events
        .iter()
        .any(|e| matches!(e, Recorded::ContactChanged(_))));
}

#[tokio::test]
async fn a_retransmitted_message_is_stored_once_and_announced_once() {
    // Retransmission is the normal case on these links, not an anomaly. The
    // UI must not flash a second copy of the message.
    let h = harness(true).await;
    h.script(vec![
        received(h.conversation, 0, 1, "hello"),
        received(h.conversation, 0, 1, "hello"),
    ]);
    h.shared.pump().await;

    let page = h
        .shared
        .with_store(|s| s.messages(&h.conversation, None, 10))
        .unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(h.sink.received().len(), 1);
}

#[tokio::test]
async fn a_message_that_arrives_late_is_marked_and_sorted_into_place() {
    let h = harness(true).await;
    h.script(vec![
        received(h.conversation, 0, 1, "first"),
        received(h.conversation, 2, 3, "third"),
        received(h.conversation, 1, 2, "second"),
    ]);
    h.shared.pump().await;

    let page = h
        .shared
        .with_store(|s| s.messages(&h.conversation, None, 10))
        .unwrap();
    let texts: Vec<&str> = page.messages.iter().map(|m| m.text.as_str()).collect();
    assert_eq!(texts, vec!["first", "second", "third"], "causal order");
    let late: Vec<bool> = page.messages.iter().map(|m| m.arrived_late).collect();
    assert_eq!(late, vec![false, true, false], "only 'second' was late");
}

#[tokio::test]
async fn an_engine_that_reports_transmissions_moves_exactly_one_message() {
    let h = harness(true).await;
    let first = h.send("one").await;
    h.send("two").await;
    h.sink.take();

    h.script(vec![EngineEvent::MessageTransmitted {
        conversation: h.conversation,
        id: first,
        attempt: 1,
    }]);
    h.shared.pump().await;

    let changes = h.sink.status_changes();
    assert_eq!(changes.len(), 1, "only the message that actually went out");
    assert_eq!(changes[0].status, MessageStatus::Sent);
    let page = h
        .shared
        .with_store(|s| s.messages(&h.conversation, None, 10))
        .unwrap();
    let statuses: Vec<_> = page.messages.iter().map(|m| m.status).collect();
    assert_eq!(
        statuses,
        vec![Some(MessageStatus::Sent), Some(MessageStatus::Queued)]
    );
}

#[tokio::test]
async fn an_engine_that_cannot_report_transmissions_over_reports() {
    // Pins the api-requests AR-002 workaround's real cost, so that when the
    // library gains the event this test fails and the workaround is deleted
    // rather than quietly left in.
    let h = harness(false).await;
    h.send("one").await;
    h.send("two").await;
    h.sink.take();

    // One packet, which in reality carries only the first message.
    h.queue_transmit(b"packet");
    h.shared.pump().await;

    let statuses: Vec<MessageStatus> = h
        .sink
        .status_changes()
        .into_iter()
        .map(|c| c.status)
        .collect();
    assert_eq!(
        statuses,
        vec![MessageStatus::Sent, MessageStatus::Sent],
        "both messages were promoted, though only one went out"
    );
}

#[tokio::test]
async fn delivery_advances_status_once_and_retries_are_silent() {
    let h = harness(true).await;
    let id = h.send("one").await;
    h.sink.take();

    h.clock.set(T0 + 3_600_000);
    h.script(vec![
        EngineEvent::MessageTransmitted {
            conversation: h.conversation,
            id,
            attempt: 1,
        },
        EngineEvent::MessageTransmitted {
            conversation: h.conversation,
            id,
            attempt: 2,
        },
        EngineEvent::MessageDelivered {
            conversation: h.conversation,
            id,
        },
    ]);
    h.shared.pump().await;

    let changes = h.sink.status_changes();
    let statuses: Vec<MessageStatus> = changes.iter().map(|c| c.status).collect();
    assert_eq!(
        statuses,
        vec![MessageStatus::Sent, MessageStatus::Delivered],
        "the second transmission attempt is not an event"
    );
    let delivered = changes.last().unwrap();
    assert_eq!(delivered.delivered_at, Some(T0 + 3_600_000));
    assert_eq!(delivered.attempts, 2, "attempts were still counted");
}

#[tokio::test]
async fn abandonment_marks_a_message_failed() {
    let h = harness(true).await;
    let id = h.send("one").await;
    h.sink.take();
    h.script(vec![EngineEvent::MessageAbandoned {
        conversation: h.conversation,
        id,
        reason: AbandonReason::RetryLimit,
    }]);
    h.shared.pump().await;
    assert_eq!(h.sink.status_changes()[0].status, MessageStatus::Failed);
}

#[tokio::test]
async fn flushing_counts_packets_against_the_link() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let transport = SpyTransport {
        sent: Arc::clone(&sent),
        accept: true,
    };
    let h = harness_with(true, Box::new(transport)).await;
    h.queue_transmit(b"0123456789");
    h.queue_transmit(b"abc");
    h.clock.set(T0 + 50);
    h.shared.pump().await;

    assert_eq!(sent.lock().unwrap().len(), 2);
    let link = h.shared.with_links(|l| l.get(LINK.0)).unwrap();
    assert_eq!(link.packets_sent, 2);
    assert_eq!(link.bytes_sent, 13);
    assert_eq!(link.last_sent_at, Some(T0 + 50));
}

#[tokio::test]
async fn a_packet_the_transport_refuses_is_not_counted_as_sent() {
    // Dropping at the transport is ordinary on these links; the engine will
    // retransmit. What must not happen is the UI claiming it was sent.
    let transport = SpyTransport {
        sent: Arc::new(Mutex::new(Vec::new())),
        accept: false,
    };
    let h = harness_with(false, Box::new(transport)).await;
    h.send("one").await;
    h.queue_transmit(b"packet");
    h.sink.take();
    h.shared.pump().await;

    let link = h.shared.with_links(|l| l.get(LINK.0)).unwrap();
    assert_eq!(link.packets_sent, 0);
    assert!(h.sink.status_changes().is_empty(), "still queued");
}

#[tokio::test]
async fn an_inbound_packet_is_counted_and_fed_to_the_engine() {
    let h = harness(true).await;
    h.clock.set(T0 + 25);
    h.shared
        .deliver(Inbound {
            link: LINK,
            bytes: b"hello world".to_vec(),
        })
        .await;

    let link = h.shared.with_links(|l| l.get(LINK.0)).unwrap();
    assert_eq!(link.packets_received, 1);
    assert_eq!(link.bytes_received, 11);
    assert_eq!(link.last_received_at, Some(T0 + 25));
    assert_eq!(
        lock(&h.script).received,
        vec![(LINK, b"hello world".to_vec())]
    );
}

#[tokio::test]
async fn a_link_going_down_is_reported_but_a_disabled_link_reads_disabled() {
    let h = harness(true).await;
    h.script(vec![EngineEvent::LinkChanged {
        link: LINK,
        health: LinkHealth {
            up: false,
            loss_permille: Some(400),
            budget_blocked_until: None,
        },
    }]);
    h.shared.pump().await;

    let link = h.shared.with_links(|l| l.get(LINK.0)).unwrap();
    assert_eq!(link.status, LinkStatus::Down);
    assert_eq!(link.recent_loss_permille, Some(400));

    // The user switching it off is a different thing, and must read
    // differently even though the link is equally unusable.
    h.shared.with_links(|l| {
        l.record_mut(LINK.0).unwrap().enabled = false;
    });
    assert_eq!(
        h.shared.with_links(|l| l.get(LINK.0)).unwrap().status,
        LinkStatus::Disabled
    );
}

#[tokio::test]
async fn being_out_of_airtime_is_reported_without_the_link_going_down() {
    // Duty-cycled radios spend most of their time out of budget. That is
    // pacing working correctly, not a fault, and the UI has to be able to
    // say so.
    let h = harness(true).await;
    h.script(vec![EngineEvent::LinkChanged {
        link: LINK,
        health: LinkHealth {
            up: true,
            loss_permille: Some(0),
            budget_blocked_until: Some(Timestamp::from_millis(T0 + 600_000)),
        },
    }]);
    h.shared.pump().await;

    let link = h.shared.with_links(|l| l.get(LINK.0)).unwrap();
    assert_eq!(link.status, LinkStatus::Up);
    assert_eq!(link.budget_blocked_until, Some(T0 + 600_000));
}

#[tokio::test]
async fn an_unchanged_link_health_is_not_re_announced() {
    let h = harness(true).await;
    let health = h
        .shared
        .with_links(|l| l.record_mut(LINK.0).unwrap().health);
    h.script(vec![EngineEvent::LinkChanged { link: LINK, health }]);
    h.shared.pump().await;
    assert!(
        h.sink
            .events()
            .iter()
            .all(|e| !matches!(e, Recorded::LinkStatusChanged(_))),
        "a repeat of the current health is not news"
    );
}

#[tokio::test]
async fn the_loop_wakes_on_a_poke_rather_than_waiting_out_its_sleep() {
    // Without this, a message queued while the engine had no deadline would
    // sit in the outbox until something unrelated woke the driver.
    let h = harness(true).await;
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let task = tokio::spawn(avianlink_desktop_lib::driver::run(
        Arc::clone(&h.shared),
        rx,
    ));

    h.script(vec![received(h.conversation, 0, 1, "late")]);
    h.shared.poke();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while h.sink.received().is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "the driver did not wake on a poke"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    drop(tx);
    task.await.unwrap();
}

#[tokio::test]
async fn the_loop_stops_when_the_inbound_channel_closes() {
    let h = harness(true).await;
    let (tx, rx) = tokio::sync::mpsc::channel::<Inbound>(8);
    let task = tokio::spawn(avianlink_desktop_lib::driver::run(
        Arc::clone(&h.shared),
        rx,
    ));
    drop(tx);
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .expect("the driver should stop when its channel closes")
        .unwrap();
}
