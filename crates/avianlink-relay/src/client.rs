//! The client side of the relay protocol (`docs/relay.md` §3–4, §6).
//!
//! [`RelayClient`] is sans-IO and works alongside an [`Engine`] whose
//! relay link it serves: it registers mailboxes, opens upload sessions,
//! holds packets until a session is open, pages through fetches of the
//! current and previous epochs and of our Hellos, retries requests that go
//! unanswered, and passes receipts and the relay's retention to the engine.
//! Everything it sends goes to the one relay.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use avianlink_core::hashes::receipt_hash;
use avianlink_core::mailbox::EPOCH_MS;
use avianlink_core::push;
use avianlink_core::wire::{
    self, encode_relay, parse_relay, PairTag, ReceiptHash, RelayCode, RelayMsg, PUSH_SECRET_LEN,
    RELAY_FETCH, RELAY_FETCH_HELLO, RELAY_OPEN, RELAY_PUSH_BIND, RELAY_PUSH_BIND_HELLO,
    RELAY_PUSH_REGISTER, RELAY_REGISTER,
};
use avianlink_core::{ConversationId, Engine, LinkId, Received, Storage, Timestamp, Transmit};
use rand_core::CryptoRng;

/// How long before the relay's 10-minute session ends we stop relying on it.
const SESSION_MS: u64 = 9 * 60_000;
/// Re-fetch interval while online; keeps the relay's lease alive too.
const POLL_MS: u64 = 5 * 60_000;
/// A request with no REPLY is retried after this, doubling, up to 4 tries.
const RETRY_MS: u64 = 3_000;
const MAX_TRIES: u32 = 4;
/// Re-reads in a row that recover nothing before waiting for the next poll.
const MAX_REREADS: u32 = 8;
/// Packets held per conversation while its upload session opens.
const MAX_HELD: usize = 256;
/// Missing sequence numbers tracked per mailbox.
const MAX_MISSING: usize = 4096;
/// Hashes of recently arrived packets remembered, so a page packet that
/// arrives after its REPLY still counts.
const MAX_ARRIVED: usize = 4096;
/// Register the next epoch this close to its start, so clocks that
/// disagree by up to a day still meet.
const EPOCH_SLACK_MS: u64 = 24 * 3_600_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Req {
    Register(ConversationId, u64),
    Open(ConversationId),
    Fetch(ConversationId, u64),
    Hellos,
    PushRegister,
    PushBind(ConversationId, u64),
    PushBindHello(bool),
}

/// Push notifications for this client (`docs/push.md`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushConfig {
    /// A random secret the host chose once and keeps with its state; the
    /// relay names the registration by its hash.
    pub secret: [u8; PUSH_SECRET_LEN],
    /// The registration sealed to the push service
    /// ([`avianlink_core::push::seal`]).
    pub blob: Vec<u8>,
    /// Also push for contact requests (Hellos). Lets the relay operator
    /// link this registration to our key (`push.md` §4.3).
    pub hellos: bool,
}

/// Push progress at the relay.
#[derive(Debug, Default)]
struct PushState {
    config: Option<PushConfig>,
    /// A registration to delete (push was turned off).
    clear: Option<[u8; PUSH_SECRET_LEN]>,
    /// PUSH_REGISTER answered OK in this session.
    registered: bool,
    /// The relay has no push service; don't retry this session.
    unsupported: bool,
    /// Mailboxes (conversation, epoch) bound to our handle.
    bound: BTreeSet<(ConversationId, u64)>,
    /// Bindings refused in this session; retried next session.
    failed: BTreeSet<(ConversationId, u64)>,
    /// The Hello binding the relay last confirmed.
    hellos: Option<bool>,
}

#[derive(Debug)]
struct Pending {
    sent_at: Timestamp,
    tries: u32,
}

/// Reading one mailbox (or our Hellos): what has arrived, by relay
/// sequence number (`relay.md` §4.3).
#[derive(Debug, Default)]
struct FetchState {
    /// Everything below has been seen in a page.
    next: u64,
    /// Seen in a page but never arrived.
    missing: BTreeSet<u64>,
    /// The last page reached the end.
    at_end: bool,
    /// At the end with nothing missing.
    done: bool,
    last: Option<Timestamp>,
    rereads: u32,
}

impl FetchState {
    /// Where the next page should start: re-read the first gap once the
    /// end is reached.
    fn since(&self) -> u64 {
        match (self.at_end, self.missing.first()) {
            (true, Some(&gap)) => gap,
            _ => self.next,
        }
    }

    /// Everything below this has arrived.
    fn release(&self) -> u64 {
        self.missing.first().copied().unwrap_or(self.next)
    }

    /// Packets to ask for: when re-reading, just the span covering the gaps
    /// within one page; otherwise a full page (0). After a re-read that
    /// recovered nothing, a full page: the next exchange then has a
    /// different length, so loss that happens to recur with the same
    /// period as the exchange cannot hit the same packet every time.
    fn max(&self) -> u8 {
        if self.rereads % 2 == 1 {
            return 0;
        }
        let Some((true, &first)) = self.missing.first().map(|f| (self.at_end, f)) else {
            return 0;
        };
        let last = self
            .missing
            .range(first..first + wire::MAX_PAGE as u64)
            .next_back()
            .copied()
            .unwrap_or(first);
        u8::try_from(last - first + 1).unwrap_or(0)
    }

    /// Applies a page: which of its sequence numbers arrived.
    fn page(&mut self, cursor: u64, page: &[ReceiptHash], arrived: &BTreeSet<ReceiptHash>) {
        let first = cursor.saturating_sub(page.len() as u64);
        for (i, h) in page.iter().enumerate() {
            let seq = first + i as u64;
            if arrived.contains(h) {
                self.missing.remove(&seq);
            } else if seq >= self.next && self.missing.len() < MAX_MISSING {
                self.missing.insert(seq);
            }
        }
        self.next = self.next.max(cursor);
    }
}

#[derive(Debug, Default)]
struct Mailbox {
    registered: BTreeMap<u64, bool>,
    session_until: Option<Timestamp>,
    held: VecDeque<Vec<u8>>,
    fetch: BTreeMap<u64, FetchState>,
}

/// Counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientStats {
    /// Requests sent (including retries).
    pub requests: u64,
    /// Requests abandoned after their tries ran out.
    pub requests_failed: u64,
    /// Packets uploaded.
    pub uploads: u64,
    /// Packets fetched and fed to the engine.
    pub fetched: u64,
    /// Fetches that re-read packets lost on the way.
    pub rereads: u64,
    /// REPLYs with an error code.
    pub errors: u64,
}

/// The relay protocol for one engine's relay link.
#[derive(Debug)]
pub struct RelayClient {
    link: LinkId,
    online: bool,
    mailboxes: BTreeMap<ConversationId, Mailbox>,
    hellos: FetchState,
    pending: BTreeMap<Req, Pending>,
    out: VecDeque<Vec<u8>>,
    /// Hashes of recently arrived packets, and their arrival order.
    arrived: BTreeSet<ReceiptHash>,
    arrived_order: VecDeque<ReceiptHash>,
    stats: ClientStats,
    push: PushState,
    /// Conversations whose uploads carried a message since their last
    /// PUSH_NOTE, with their outgoing tag.
    note_due: BTreeMap<ConversationId, PairTag>,
}

impl RelayClient {
    /// A client for `link`, which must be registered with
    /// [`Engine::add_relay_link`].
    pub fn new(link: LinkId) -> Self {
        Self {
            link,
            online: false,
            mailboxes: BTreeMap::new(),
            hellos: FetchState::default(),
            pending: BTreeMap::new(),
            out: VecDeque::new(),
            arrived: BTreeSet::new(),
            arrived_order: VecDeque::new(),
            stats: ClientStats::default(),
            push: PushState::default(),
            note_due: BTreeMap::new(),
        }
    }

    /// Sets (or with `None`, removes) push notifications. Takes effect at
    /// once if online, else at the next [`RelayClient::connect`].
    pub fn set_push(&mut self, config: Option<PushConfig>) {
        let old = self.push.config.take();
        match (&old, &config) {
            (Some(o), Some(n)) if o.secret == n.secret => {
                if o.blob != n.blob {
                    self.push.registered = false;
                }
            }
            (Some(o), _) => {
                self.push.clear = Some(o.secret);
                self.push.registered = false;
                self.push.bound.clear();
                self.push.hellos = None;
            }
            (None, _) => self.push.registered = false,
        }
        if config
            .as_ref()
            .is_some_and(|n| Some(n.secret) == self.push.clear)
        {
            self.push.clear = None;
        }
        self.push.config = config;
    }

    /// The relay link.
    pub fn link(&self) -> LinkId {
        self.link
    }

    /// Counters.
    pub fn stats(&self) -> ClientStats {
        self.stats
    }

    /// The host came online (or just started): register, open sessions and
    /// fetch everything waiting.
    pub fn connect<S: Storage, R: CryptoRng>(&mut self, engine: &mut Engine<S, R>, now: Timestamp) {
        self.online = true;
        for m in self.mailboxes.values_mut() {
            m.session_until = None;
            for f in m.fetch.values_mut() {
                f.done = false;
                f.at_end = false;
                f.last = None;
            }
        }
        self.hellos.done = false;
        self.hellos.at_end = false;
        self.hellos.last = None;
        // Re-register every session: it keeps the handle from expiring.
        self.push.registered = false;
        self.push.unsupported = false;
        self.push.failed.clear();
        engine.nudge(now);
        self.tick(engine, now);
    }

    /// The host is going offline: stop polling (nothing is lost; the engine
    /// keeps what isn't stored or delivered). Leaves one datagram to send,
    /// a LEAVE: until the relay has it, it keeps forwarding to this address
    /// for the rest of its lease instead of pushing (`relay.md` §4.3), so
    /// drain [`RelayClient::poll_transmit`] once more and send it.
    pub fn disconnect(&mut self) {
        let was_online = self.online;
        self.online = false;
        self.pending.clear();
        self.out.clear();
        self.note_due.clear();
        if was_online {
            self.out.push_back(encode_relay(&RelayMsg::Leave));
        }
        for m in self.mailboxes.values_mut() {
            m.session_until = None;
            m.held.clear();
        }
    }

    /// A datagram from the relay. Relay messages are handled here; packets
    /// and Hellos go to the engine, whose answer is returned.
    pub fn handle<S: Storage, R: CryptoRng>(
        &mut self,
        engine: &mut Engine<S, R>,
        bytes: &[u8],
        now: Timestamp,
    ) -> Received {
        let Some(&kind) = bytes.first() else {
            return Received::Ignored;
        };
        if !wire::is_relay_kind(kind) {
            self.stats.fetched += 1;
            let h = receipt_hash(bytes);
            if self.arrived.insert(h) {
                self.arrived_order.push_back(h);
                if self.arrived_order.len() > MAX_ARRIVED {
                    if let Some(old) = self.arrived_order.pop_front() {
                        self.arrived.remove(&old);
                    }
                }
            }
            return engine.handle_packet(self.link, bytes, now);
        }
        match parse_relay(bytes) {
            Ok(RelayMsg::Receipt { code, hashes }) => {
                engine.handle_receipt(self.link, code, &hashes, now);
                if code == RelayCode::NoSession {
                    for m in self.mailboxes.values_mut() {
                        m.session_until = None;
                    }
                }
            }
            Ok(RelayMsg::Reply {
                request,
                code,
                key,
                retention_s,
                cursor,
                page,
            }) => {
                let _ = engine.set_link_retention(self.link, retention_s.saturating_mul(1000));
                let arrived = std::mem::take(&mut self.arrived);
                self.on_reply(engine, request, code, key, (cursor, &page, &arrived), now);
                self.arrived = arrived;
            }
            _ => {}
        }
        self.tick(engine, now);
        Received::Ignored
    }

    /// A packet the engine wants sent on the relay link. It goes out once
    /// the conversation's upload session is open.
    pub fn upload<S: Storage, R: CryptoRng>(
        &mut self,
        engine: &mut Engine<S, R>,
        tx: Transmit,
        now: Timestamp,
    ) {
        if !self.online {
            // Offline: the engine sends it again once the host reconnects.
            return;
        }
        let bytes = tx.packet.into_vec();
        if bytes.first() == Some(&wire::HELLO_KIND) {
            // Hellos are filed by hint: no session needed. The note lets
            // the relay push to the recipient (`push.md` §4.3).
            let note = engine.hello_note(tx.to, &bytes);
            self.out.push_back(bytes);
            self.out.extend(note);
            self.stats.uploads += 1;
            return;
        }
        if tx.carries_message {
            if let Some((tag, _)) = engine.mailbox_tags(tx.to) {
                self.note_due.insert(tx.to, tag);
            }
        }
        let m = self.mailboxes.entry(tx.to).or_default();
        if m.session_until.is_some_and(|t| t > now) {
            self.out.push_back(bytes);
            self.stats.uploads += 1;
        } else {
            if m.held.len() >= MAX_HELD {
                m.held.pop_front(); // the engine resends it
            }
            m.held.push_back(bytes);
            self.ensure_open(engine, tx.to, now);
        }
    }

    /// Whether everything waiting at the relay has been read: no requests
    /// outstanding, every mailbox read to the end with nothing missing, and
    /// our Hellos read. A host leaving after a session waits for this and
    /// for [`Engine::relay_settled`].
    pub fn caught_up(&self) -> bool {
        self.online
            && self.pending.is_empty()
            && self.hellos.done
            && self
                .mailboxes
                .values()
                .all(|m| m.held.is_empty() && m.fetch.values().all(|f| f.done))
    }

    /// The next datagram for the relay.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        if let Some(bytes) = self.out.pop_front() {
            return Some(bytes);
        }
        // After a burst of uploads, one PUSH_NOTE per conversation whose
        // uploads carried a message and are out (`push.md` §4.4).
        let conv = self.note_due.keys().copied().find(|c| {
            self.mailboxes
                .get(c)
                .is_some_and(|m| m.held.is_empty() && m.session_until.is_some())
        })?;
        let tag = self.note_due.remove(&conv)?;
        Some(encode_relay(&RelayMsg::PushNote { tag }))
    }

    /// Advances timers: retries, session refreshes, periodic fetches.
    pub fn handle_timeout<S: Storage, R: CryptoRng>(
        &mut self,
        engine: &mut Engine<S, R>,
        now: Timestamp,
    ) {
        self.tick(engine, now);
    }

    /// When [`RelayClient::handle_timeout`] next has work.
    pub fn next_timeout(&self) -> Option<Timestamp> {
        if !self.online {
            return None;
        }
        let retries = self.pending.values().map(|p| {
            p.sent_at
                .saturating_add_millis(RETRY_MS.saturating_mul(1 << p.tries.min(6)))
        });
        let polls = self
            .mailboxes
            .values()
            .flat_map(|m| m.fetch.values())
            .chain(std::iter::once(&self.hellos))
            .filter_map(|f| f.last.map(|t| t.saturating_add_millis(POLL_MS)));
        retries.chain(polls).min()
    }

    fn send<S: Storage, R: CryptoRng>(
        &mut self,
        engine: &mut Engine<S, R>,
        req: Req,
        now: Timestamp,
    ) {
        let msgs: Vec<Vec<u8>> = match req {
            Req::Register(conv, epoch) => match engine.mailbox_register(conv, epoch) {
                Some(pair) => pair.into(),
                None => return,
            },
            Req::Open(conv) => match engine.mailbox_open(conv) {
                Ok(m) => vec![m],
                Err(_) => return,
            },
            Req::Fetch(conv, epoch) => {
                let (since, release, max) = self
                    .mailboxes
                    .get(&conv)
                    .and_then(|m| m.fetch.get(&epoch))
                    .map_or((0, 0, 0), |f| (f.since(), f.release(), f.max()));
                match engine.mailbox_fetch(conv, epoch, since, release, max) {
                    Ok(m) => vec![m],
                    Err(_) => return,
                }
            }
            Req::Hellos => vec![engine.hello_fetch(self.hellos.since())],
            Req::PushRegister => {
                let (secret, blob) = match (&self.push.config, self.push.clear) {
                    (_, Some(old)) => (old, Vec::new()),
                    (Some(c), None) => (c.secret, c.blob.clone()),
                    (None, None) => return,
                };
                vec![encode_relay(&RelayMsg::PushRegister { secret, blob })]
            }
            Req::PushBind(conv, epoch) => {
                let Some(secret) = self.push.config.as_ref().map(|c| c.secret) else {
                    return;
                };
                match engine.mailbox_push_bind(conv, epoch, push::handle(&secret)) {
                    Ok(m) => vec![m],
                    Err(_) => return,
                }
            }
            Req::PushBindHello(on) => {
                let Some(secret) = self.push.config.as_ref().map(|c| c.secret) else {
                    return;
                };
                vec![engine.push_bind_hello(push::handle(&secret), on)]
            }
        };
        let tries = self.pending.get(&req).map_or(0, |p| p.tries + 1);
        self.pending.insert(
            req,
            Pending {
                sent_at: now,
                tries,
            },
        );
        self.stats.requests += msgs.len() as u64;
        self.out.extend(msgs);
    }

    fn ensure_open<S: Storage, R: CryptoRng>(
        &mut self,
        engine: &mut Engine<S, R>,
        conv: ConversationId,
        now: Timestamp,
    ) {
        let epoch = engine.mailbox_epoch();
        let registered = self
            .mailboxes
            .get(&conv)
            .is_some_and(|m| m.registered.get(&epoch) == Some(&true));
        if !registered && !self.pending.contains_key(&Req::Register(conv, epoch)) {
            self.send(engine, Req::Register(conv, epoch), now);
        }
        if !self.pending.contains_key(&Req::Open(conv)) {
            self.send(engine, Req::Open(conv), now);
        }
    }

    /// Applies a page to `f` and says whether to fetch again at once.
    fn read_page(
        f: &mut FetchState,
        code: RelayCode,
        page: (u64, &[ReceiptHash], &BTreeSet<ReceiptHash>),
        stats: &mut ClientStats,
        now: Timestamp,
    ) -> bool {
        f.last = Some(now);
        let (cursor, hashes, arrived) = page;
        let before = (f.missing.len(), f.next);
        f.page(cursor, hashes, arrived);
        if f.missing.len() < before.0 || f.next > before.1 {
            // Progress: only re-reads that recover nothing count.
            f.rereads = 0;
        }
        // A re-read of the gaps ends below what was already read, so the
        // relay says MORE; but the end is already known, so going on to
        // read forward again would only cost a round trip.
        let reread = f.at_end && cursor <= before.1;
        match code {
            RelayCode::More if !reread => {
                f.at_end = false;
                true
            }
            RelayCode::Ok | RelayCode::More => {
                f.at_end = true;
                f.done = f.missing.is_empty();
                if f.done {
                    f.rereads = 0;
                    false
                } else if f.rereads < MAX_REREADS {
                    // Re-read what was lost on the way.
                    f.rereads += 1;
                    stats.rereads += 1;
                    true
                } else {
                    f.rereads = 0;
                    false
                }
            }
            _ => {
                f.done = true;
                false
            }
        }
    }

    fn on_reply<S: Storage, R: CryptoRng>(
        &mut self,
        engine: &mut Engine<S, R>,
        request: u8,
        code: RelayCode,
        key: [u8; 3],
        page: (u64, &[ReceiptHash], &BTreeSet<ReceiptHash>),
        now: Timestamp,
    ) {
        if !matches!(code, RelayCode::Ok | RelayCode::More) {
            self.stats.errors += 1;
        }
        let epoch = engine.mailbox_epoch();
        if request == RELAY_PUSH_REGISTER {
            self.on_push_register(code, page.0);
            return;
        }
        if request == RELAY_PUSH_BIND_HELLO {
            for on in [false, true] {
                if self.pending.remove(&Req::PushBindHello(on)).is_some() && code == RelayCode::Ok {
                    self.push.hellos = Some(on);
                }
            }
            return;
        }
        if request == RELAY_FETCH_HELLO {
            self.pending.remove(&Req::Hellos);
            if Self::read_page(&mut self.hellos, code, page, &mut self.stats, now) {
                self.send(engine, Req::Hellos, now);
            }
            return;
        }
        let tag: PairTag = key;
        let convs: Vec<(ConversationId, bool)> = engine
            .contacts()
            .filter_map(|(c, _)| {
                let (out, inc) = engine.mailbox_tags(c)?;
                (out == tag)
                    .then_some((c, true))
                    .or((inc == tag).then_some((c, false)))
            })
            .collect();
        for (conv, outgoing) in convs {
            match request {
                RELAY_REGISTER => {
                    // Registration covers both directions at once.
                    for e in [epoch, epoch + 1] {
                        if self.pending.remove(&Req::Register(conv, e)).is_some()
                            && code == RelayCode::Ok
                        {
                            self.mailboxes
                                .entry(conv)
                                .or_default()
                                .registered
                                .insert(e, true);
                        }
                    }
                }
                RELAY_OPEN if outgoing => {
                    self.pending.remove(&Req::Open(conv));
                    match code {
                        RelayCode::Ok => {
                            let m = self.mailboxes.entry(conv).or_default();
                            m.session_until = Some(now.saturating_add_millis(SESSION_MS));
                            self.stats.uploads += m.held.len() as u64;
                            self.out.extend(m.held.drain(..));
                        }
                        RelayCode::UnknownMailbox => {
                            self.mailboxes.entry(conv).or_default().registered.clear();
                            self.ensure_open(engine, conv, now);
                        }
                        _ => {}
                    }
                }
                RELAY_PUSH_BIND if !outgoing => {
                    for e in [epoch, epoch + 1] {
                        if self.pending.remove(&Req::PushBind(conv, e)).is_none() {
                            continue;
                        }
                        match code {
                            RelayCode::Ok => {
                                self.push.bound.insert((conv, e));
                            }
                            RelayCode::UnknownMailbox => {
                                // The relay lost our handle (or the
                                // mailbox): register again, bind next time.
                                self.push.registered = false;
                                self.push.failed.insert((conv, e));
                            }
                            _ => {
                                self.push.failed.insert((conv, e));
                            }
                        }
                    }
                }
                RELAY_FETCH if !outgoing => {
                    let Some(e) = [epoch, epoch.saturating_sub(1)]
                        .into_iter()
                        .find(|e| self.pending.contains_key(&Req::Fetch(conv, *e)))
                    else {
                        continue;
                    };
                    self.pending.remove(&Req::Fetch(conv, e));
                    if code == RelayCode::UnknownMailbox {
                        // Nobody registered it yet (or it expired):
                        // register both directions and fetch later.
                        let m = self.mailboxes.entry(conv).or_default();
                        let f = m.fetch.entry(e).or_default();
                        f.last = Some(now);
                        f.done = true;
                        if e == epoch {
                            m.registered.remove(&e);
                            self.send(engine, Req::Register(conv, e), now);
                        }
                        continue;
                    }
                    let f = self
                        .mailboxes
                        .entry(conv)
                        .or_default()
                        .fetch
                        .entry(e)
                        .or_default();
                    if Self::read_page(f, code, page, &mut self.stats, now) {
                        self.send(engine, Req::Fetch(conv, e), now);
                    }
                }
                _ => {}
            }
        }
    }

    fn on_push_register(&mut self, code: RelayCode, existed: u64) {
        if self.pending.remove(&Req::PushRegister).is_none() {
            return;
        }
        match code {
            RelayCode::Ok if self.push.clear.is_some() => self.push.clear = None,
            RelayCode::Ok => {
                self.push.registered = true;
                if existed == 0 {
                    // A new handle at the relay: nothing is bound to it.
                    self.push.bound.clear();
                    self.push.hellos = None;
                }
            }
            RelayCode::Full => self.push.unsupported = true,
            _ => {}
        }
    }

    /// Push requests due: deregister, register, then bind.
    fn push_wants<S: Storage, R: CryptoRng>(
        &self,
        engine: &Engine<S, R>,
        now: Timestamp,
    ) -> Vec<Req> {
        let p = &self.push;
        if p.unsupported {
            return Vec::new();
        }
        if p.clear.is_some() || (p.config.is_some() && !p.registered) {
            return vec![Req::PushRegister];
        }
        let Some(config) = &p.config else {
            return Vec::new();
        };
        let epoch = engine.mailbox_epoch();
        let near_next = (now.as_millis() % EPOCH_MS) + EPOCH_SLACK_MS >= EPOCH_MS;
        let mut wants = Vec::new();
        for (conv, m) in &self.mailboxes {
            for e in [epoch, epoch + 1] {
                let key = (*conv, e);
                if (e == epoch || near_next)
                    && m.registered.get(&e) == Some(&true)
                    && !p.bound.contains(&key)
                    && !p.failed.contains(&key)
                {
                    wants.push(Req::PushBind(*conv, e));
                }
            }
        }
        if p.hellos != Some(config.hellos) {
            wants.push(Req::PushBindHello(config.hellos));
        }
        wants
    }

    fn tick<S: Storage, R: CryptoRng>(&mut self, engine: &mut Engine<S, R>, now: Timestamp) {
        if !self.online {
            return;
        }
        // Retries, with fresh proofs.
        let due: Vec<Req> = self
            .pending
            .iter()
            .filter(|(_, p)| {
                p.sent_at
                    .saturating_add_millis(RETRY_MS.saturating_mul(1 << p.tries.min(6)))
                    <= now
            })
            .map(|(r, _)| *r)
            .collect();
        for req in due {
            if self
                .pending
                .get(&req)
                .is_some_and(|p| p.tries + 1 >= MAX_TRIES)
            {
                self.pending.remove(&req);
                self.stats.requests_failed += 1;
            } else {
                self.send(engine, req, now);
            }
        }
        let epoch = engine.mailbox_epoch();
        let near_next = (now.as_millis() % EPOCH_MS) + EPOCH_SLACK_MS >= EPOCH_MS;
        let convs: Vec<ConversationId> = engine.contacts().map(|(c, _)| c).collect();
        for conv in convs {
            let m = self.mailboxes.entry(conv).or_default();
            m.fetch.retain(|e, _| *e + 1 >= epoch);
            let mut wants = Vec::new();
            for e in [epoch, epoch + 1] {
                if (e == epoch || near_next) && m.registered.get(&e) != Some(&true) {
                    wants.push(Req::Register(conv, e));
                }
            }
            // One fetch in flight per conversation: a REPLY names the tag,
            // not the epoch. The older epoch goes first.
            let fetching = self
                .pending
                .keys()
                .any(|r| matches!(r, Req::Fetch(c, _) if *c == conv));
            if !fetching {
                for e in [epoch.saturating_sub(1), epoch] {
                    let f = m.fetch.entry(e).or_default();
                    let stale = f
                        .last
                        .is_none_or(|t| t.saturating_add_millis(POLL_MS) <= now);
                    // The previous epoch only until it is empty.
                    if stale && !(e < epoch && f.done) {
                        wants.push(Req::Fetch(conv, e));
                        break;
                    }
                }
            }
            for req in wants {
                if !self.pending.contains_key(&req) {
                    self.send(engine, req, now);
                }
            }
        }
        let stale = self
            .hellos
            .last
            .is_none_or(|t| t.saturating_add_millis(POLL_MS) <= now);
        if stale && !self.pending.contains_key(&Req::Hellos) {
            self.send(engine, Req::Hellos, now);
        }
        for req in self.push_wants(engine, now) {
            if !self.pending.contains_key(&req) {
                self.send(engine, req, now);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_state_tracks_gaps_and_releases_only_below_them() {
        let h = |n: u8| [n; 4];
        let mut f = FetchState::default();
        // Page 0..6; packets 2 and 4 lost.
        let arrived: BTreeSet<_> = [0, 1, 3, 5].map(h).into();
        f.page(6, &[0, 1, 2, 3, 4, 5].map(h), &arrived);
        assert_eq!(f.missing, BTreeSet::from([2, 4]));
        assert_eq!((f.next, f.release()), (6, 2));
        assert_eq!(f.since(), 6, "keep reading forward first");
        f.at_end = true;
        assert_eq!(f.since(), 2, "then re-read the first gap");
        // Re-read from 2: 2 arrives now, 3 is lost this time (already had it).
        let arrived: BTreeSet<_> = [2, 4, 5].map(h).into();
        f.page(6, &[2, 3, 4, 5].map(h), &arrived);
        assert!(f.missing.is_empty(), "3 was never missing");
        assert_eq!(f.release(), 6);
    }
}
