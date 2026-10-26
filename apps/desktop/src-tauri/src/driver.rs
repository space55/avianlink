//! The one task that owns the engine.
//!
//! The loop is the library's documented host contract: after any input, drain
//! `poll_transmit` until `None`, drain `poll_event` until `None`, then sleep
//! until the earlier of `next_timeout()`, an incoming packet, or a command.
//!
//! Exactly one task touches the engine, which is what keeps a deterministic
//! state machine deterministic. Commands do not get their own access path:
//! they take the same mutex, briefly, and then poke [`Shared::wake`] so the
//! loop re-pumps immediately instead of waiting out its sleep. Without that
//! poke, a message sent while the engine had no pending deadline would sit in
//! the outbox until something else happened to wake the loop.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use avianlink_core::{ConversationId, LinkId, Timestamp};
use tokio::sync::{mpsc, Mutex as AsyncMutex, Notify};
use tokio::time::{sleep_until, Instant};

use crate::engine::{EngineEvent, EngineHandle, LinkCounters, LinkHealth};
use crate::events::EventSink;
use crate::ipc::{Link, LinkKind, LinkSettings, LinkStatus, MessageStatus};
use crate::storage::{AppStore, Inserted};

/// How long the loop will sleep when the engine has no deadline.
///
/// Not a timeout: the loop is woken by commands and packets. It exists so a
/// clock jump or a missed notification cannot wedge the driver forever, and is
/// long because a quiet link is the normal case here — waking every few
/// seconds to do nothing would be the wrong default on a laptop battery.
const IDLE_POLL: Duration = Duration::from_secs(60);

/// The wall clock, injected so the driver can be tested without waiting.
pub trait Clock: Send + Sync {
    /// Unix-epoch milliseconds.
    fn now_ms(&self) -> u64;
}

/// The real clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
    }
}

/// A clock tests move by hand.
#[derive(Debug)]
pub struct TestClock(AtomicU64);

impl TestClock {
    /// Starts at `now_ms`.
    pub fn new(now_ms: u64) -> Self {
        Self(AtomicU64::new(now_ms))
    }

    /// Jumps forward by `ms`.
    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }

    /// Sets the time.
    pub fn set(&self, ms: u64) {
        self.0.store(ms, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Where flushed packets go.
///
/// Phase 3 implements this over a UDP socket. It is a separate trait from
/// [`EngineHandle`] because the engine is sans-IO by construction: the thing
/// that can fail to put bytes on a wire is not the thing that decides which
/// bytes to put there.
pub trait Transport: Send {
    /// Hands a packet to a link. Returns whether the link accepted it.
    ///
    /// A `false` return means the packet was dropped at the transport, which
    /// is not an error on these links: the engine will retransmit.
    fn send(&mut self, link: LinkId, to: ConversationId, packet: &[u8], now: Timestamp) -> bool;
}

/// Accepts and discards. Used while `FakeEngine` models its own links.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullTransport;

impl Transport for NullTransport {
    fn send(
        &mut self,
        _link: LinkId,
        _to: ConversationId,
        _packet: &[u8],
        _now: Timestamp,
    ) -> bool {
        true
    }
}

/// A packet that arrived on a link.
#[derive(Clone, Debug)]
pub struct Inbound {
    /// Which link it arrived on.
    pub link: LinkId,
    /// The bytes, untrusted.
    pub bytes: Vec<u8>,
}

/// One link, as the app tracks it.
#[derive(Clone, Debug)]
pub struct LinkRecord {
    /// Human label.
    pub label: String,
    /// Transport kind.
    pub kind: LinkKind,
    /// User intent.
    pub enabled: bool,
    /// MTU, budget and cost, as the engine was given them.
    pub config: avianlink_core::LinkConfig,
    /// Per-kind settings.
    pub settings: LinkSettings,
    /// Observed health.
    pub health: LinkHealth,
    /// Packet and byte counters, maintained by the driver (AR-007).
    pub counters: LinkCounters,
}

impl LinkRecord {
    /// Converts to the IPC shape.
    ///
    /// `status` is derived rather than stored: it is a function of the user's
    /// intent and the observed health, and deriving it means the two can
    /// never disagree. A link the user switched off reads `disabled`, not
    /// `down`, because those deserve very different tones in the UI.
    pub fn to_ipc(&self, id: u16) -> Link {
        let status = if !self.enabled {
            LinkStatus::Disabled
        } else if self.health.up {
            LinkStatus::Up
        } else {
            LinkStatus::Down
        };
        Link {
            id,
            label: self.label.clone(),
            kind: self.kind,
            enabled: self.enabled,
            status,
            mtu: self.config.mtu,
            config: self.settings.clone(),
            packets_sent: self.counters.packets_sent,
            packets_received: self.counters.packets_received,
            bytes_sent: self.counters.bytes_sent,
            bytes_received: self.counters.bytes_received,
            recent_loss_permille: self.health.loss_permille,
            last_sent_at: self.counters.last_sent_at.map(Timestamp::as_millis),
            last_received_at: self.counters.last_received_at.map(Timestamp::as_millis),
            budget_blocked_until: self.health.budget_blocked_until.map(Timestamp::as_millis),
        }
    }
}

/// The app's links.
#[derive(Debug, Default)]
pub struct LinkTable {
    links: BTreeMap<u16, LinkRecord>,
}

impl LinkTable {
    /// Empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces a link record.
    pub fn insert(&mut self, id: u16, record: LinkRecord) {
        self.links.insert(id, record);
    }

    /// One link's IPC shape.
    pub fn get(&self, id: u16) -> Option<Link> {
        self.links.get(&id).map(|l| l.to_ipc(id))
    }

    /// Mutable access to a record.
    pub fn record_mut(&mut self, id: u16) -> Option<&mut LinkRecord> {
        self.links.get_mut(&id)
    }

    /// All links, sorted by id.
    pub fn list(&self) -> Vec<Link> {
        self.links.iter().map(|(id, l)| l.to_ipc(*id)).collect()
    }

    /// Whether a link with this id exists.
    pub fn contains(&self, id: u16) -> bool {
        self.links.contains_key(&id)
    }

    /// Removes everything.
    pub fn clear(&mut self) {
        self.links.clear();
    }
}

/// State shared between the driver loop and the command handlers.
pub struct Shared {
    /// App history, contacts and settings.
    pub store: Mutex<AppStore>,
    /// Links and their counters.
    pub links: Mutex<LinkTable>,
    /// The engine. Async mutex because commands await it.
    pub engine: AsyncMutex<Box<dyn EngineHandle>>,
    /// Where packets go.
    pub transport: AsyncMutex<Box<dyn Transport>>,
    /// Wall clock.
    pub clock: Arc<dyn Clock>,
    /// Where events go.
    pub sink: Arc<dyn EventSink>,
    /// Poked after a command touches the engine, so the loop re-pumps now.
    pub wake: Notify,
}

impl Shared {
    /// Assembles the shared state.
    pub fn new(
        engine: Box<dyn EngineHandle>,
        transport: Box<dyn Transport>,
        clock: Arc<dyn Clock>,
        sink: Arc<dyn EventSink>,
    ) -> Self {
        Self {
            store: Mutex::new(AppStore::new()),
            links: Mutex::new(LinkTable::new()),
            engine: AsyncMutex::new(engine),
            transport: AsyncMutex::new(transport),
            clock,
            sink,
            wake: Notify::new(),
        }
    }

    /// Current time, as the engine sees it.
    pub fn now(&self) -> Timestamp {
        Timestamp::from_millis(self.clock.now_ms())
    }

    /// Asks the driver loop to pump the engine as soon as it can.
    pub fn poke(&self) {
        self.wake.notify_one();
    }

    /// Runs the store under its lock.
    ///
    /// A poisoned mutex means a previous holder panicked. Recovering the
    /// guard is the right call for a GUI: the alternative is that one panic
    /// in a command permanently bricks every later read, and the store's
    /// invariants are rebuilt from the engine and disk rather than held
    /// across calls.
    pub fn with_store<T>(&self, f: impl FnOnce(&mut AppStore) -> T) -> T {
        let mut guard = self.store.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    /// Runs the link table under its lock.
    pub fn with_links<T>(&self, f: impl FnOnce(&mut LinkTable) -> T) -> T {
        let mut guard = self.links.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    /// One full pump. Returns the next deadline the engine wants, if any.
    ///
    /// Public so commands and tests can force a pump without waiting for the
    /// loop to come round.
    pub async fn pump(&self) -> Option<u64> {
        let now = self.now();
        let mut engine = self.engine.lock().await;
        engine.handle_timeout(now);
        self.flush(&mut **engine, now).await;
        // Events can be produced by the flush, so drain after it.
        while let Some(event) = engine.poll_event() {
            self.apply(event, now);
        }
        engine.next_timeout().map(Timestamp::as_millis)
    }

    /// Drains `poll_transmit` to the transport, counting as it goes.
    async fn flush(&self, engine: &mut dyn EngineHandle, now: Timestamp) {
        let infer_sent = !engine.reports_transmissions();
        let mut transport = self.transport.lock().await;
        while let Some(transmit) = engine.poll_transmit(now) {
            let bytes = transmit.packet.as_bytes();
            let accepted = transport.send(transmit.link, transmit.to, bytes, now);
            if accepted {
                self.count_sent(transmit.link, bytes.len() as u64, now);
            }
            if infer_sent && accepted {
                self.infer_sent(transmit.to, now);
            }
        }
    }

    /// Records an outgoing packet against its link.
    fn count_sent(&self, link: LinkId, len: u64, now: Timestamp) {
        let changed = self.with_links(|links| {
            let record = links.record_mut(link.0)?;
            record.counters.packets_sent = record.counters.packets_sent.saturating_add(1);
            record.counters.bytes_sent = record.counters.bytes_sent.saturating_add(len);
            record.counters.last_sent_at = Some(now);
            links.get(link.0)
        });
        if let Some(link) = changed {
            self.sink.link_status_changed(&link);
        }
    }

    /// The AR-002 workaround: promote every still-queued message in the
    /// conversation to `sent`, because a packet for that conversation went
    /// out and the engine will not say which messages were in it.
    ///
    /// This over-reports. An acknowledgement-only packet, or a packet
    /// carrying the first of three queued messages, promotes all of them.
    /// It is used only for engines whose `reports_transmissions()` is false;
    /// `FakeEngine` reports transmissions exactly, so the UI is still
    /// designed against correct semantics.
    fn infer_sent(&self, conversation: ConversationId, now: Timestamp) {
        let changes =
            self.with_store(|store| store.promote_queued_to_sent(&conversation, now.as_millis()));
        for change in &changes {
            self.sink.message_status_changed(change);
        }
    }

    /// Applies one engine event to the store and the frontend.
    fn apply(&self, event: EngineEvent, now: Timestamp) {
        match event {
            EngineEvent::MessageReceived(received) => {
                let stored = self.with_store(|store| {
                    let inserted = store.insert_incoming(
                        received.conversation,
                        received.id,
                        received.seq,
                        received.lamport,
                        &received.text,
                        received.sender_time.map(Timestamp::as_millis),
                        received.received_at.as_millis(),
                    );
                    let contact = store.contact(&received.conversation);
                    (inserted, contact)
                });
                // A retransmission of something we already have is the common
                // case, not an error: emit nothing and let the UI be.
                if let (Inserted::New(message), contact) = stored {
                    self.sink.message_received(&message);
                    if let Some(contact) = contact {
                        self.sink.contact_changed(&contact);
                    }
                }
            }
            EngineEvent::MessageTransmitted {
                conversation, id, ..
            } => self.set_status(conversation, id, MessageStatus::Sent, now),
            EngineEvent::MessageDelivered { conversation, id } => {
                self.set_status(conversation, id, MessageStatus::Delivered, now);
            }
            EngineEvent::MessageAbandoned {
                conversation, id, ..
            } => self.set_status(conversation, id, MessageStatus::Failed, now),
            EngineEvent::LinkChanged { link, health } => self.set_link_health(link, health),
        }
    }

    fn set_status(
        &self,
        conversation: ConversationId,
        id: avianlink_core::MessageId,
        status: MessageStatus,
        now: Timestamp,
    ) {
        let change = self
            .with_store(|store| store.update_status(&conversation, &id, status, now.as_millis()));
        // `None` means the status did not move: under retransmission that is
        // most updates, and not emitting them is what keeps the stream quiet.
        if let Some(change) = change {
            self.sink.message_status_changed(&change);
        }
    }

    fn set_link_health(&self, link: LinkId, health: LinkHealth) {
        let changed = self.with_links(|links| {
            let record = links.record_mut(link.0)?;
            if record.health == health {
                return None;
            }
            record.health = health;
            links.get(link.0)
        });
        if let Some(link) = changed {
            self.sink.link_status_changed(&link);
        }
    }

    /// Feeds a received packet to the engine and counts it.
    pub async fn deliver(&self, inbound: Inbound) {
        let now = self.now();
        let len = inbound.bytes.len() as u64;
        let changed = self.with_links(|links| {
            let record = links.record_mut(inbound.link.0)?;
            record.counters.packets_received = record.counters.packets_received.saturating_add(1);
            record.counters.bytes_received = record.counters.bytes_received.saturating_add(len);
            record.counters.last_received_at = Some(now);
            links.get(inbound.link.0)
        });
        if let Some(link) = changed {
            self.sink.link_status_changed(&link);
        }
        let mut engine = self.engine.lock().await;
        engine.handle_packet(inbound.link, &inbound.bytes, now);
    }
}

/// Sleeps until `deadline_ms` in wall-clock terms, or for [`IDLE_POLL`] when
/// there is no deadline.
///
/// Converting a wall-clock deadline into a monotonic instant each time round
/// the loop means a clock that jumps forward shortens the sleep rather than
/// being ignored, and a clock that jumps backwards lengthens it by at most
/// one `IDLE_POLL`.
fn sleep_target(deadline_ms: Option<u64>, now_ms: u64) -> Instant {
    let delay = match deadline_ms {
        Some(deadline) => Duration::from_millis(deadline.saturating_sub(now_ms)).min(IDLE_POLL),
        None => IDLE_POLL,
    };
    Instant::now() + delay
}

/// Runs the driver loop until the inbound channel closes.
pub async fn run(shared: Arc<Shared>, mut inbound: mpsc::Receiver<Inbound>) {
    loop {
        let deadline = shared.pump().await;
        let target = sleep_target(deadline, shared.clock.now_ms());
        tokio::select! {
            // A command touched the engine; pump before sleeping again.
            () = shared.wake.notified() => {}
            packet = inbound.recv() => match packet {
                Some(packet) => shared.deliver(packet).await,
                // The app is shutting down.
                None => return,
            },
            () = sleep_until(target) => {}
        }
    }
}
