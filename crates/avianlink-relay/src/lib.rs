//! An identity-less store-and-forward relay (`docs/relay.md`).
//!
//! [`Relay`] is sans-IO, like the engine: the host feeds it datagrams with
//! their source address and the time, and drains what to send. It holds no
//! keys and no conversation state: mailboxes are (routing tag, chain
//! anchors) pairs, and everything stored is end-to-end encrypted. Accepted
//! packets are committed to [`Storage`] before they are receipted, and kept
//! until the configured retention expires or the recipient proves it has
//! them.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

mod client;
mod notify;
mod push;
pub use client::{ClientStats, PushConfig, RelayClient};
pub use notify::{Acked, Notifier, NotifierStats};
pub use push::PushDue;

use avianlink_core::hashes::receipt_hash;
use avianlink_core::mailbox;
use avianlink_core::wire::{
    self, encode_relay, parse_relay, ChainRole, PairTag, Proof, Reader, ReceiptHash, RelayCode,
    RelayMsg, HELLO_HINT_LEN, HELLO_KIND, MAX_PAGE, RELAY_FETCH, RELAY_FETCH_HELLO, RELAY_OPEN,
    RELAY_REGISTER, VERSION,
};
use avianlink_core::{Storage, Timestamp};

/// Longest retention a relay may be configured with.
pub const MAX_RETENTION_MS: u64 = 30 * 24 * 3_600_000;

/// Relay-side policy (`relay.md` §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayConfig {
    /// How long packets and Hellos are kept (at most [`MAX_RETENTION_MS`]).
    /// Mailboxes idle this long expire too.
    pub retention_ms: u64,
    /// Space one mailbox (or one hint's Hellos) may use, in bytes.
    pub mailbox_quota_bytes: u64,
    /// Space all packets together may use, in bytes.
    pub total_quota_bytes: u64,
    /// Most mailboxes.
    pub max_mailboxes: u32,
    /// Packets per fetch page (at most [`MAX_PAGE`]).
    pub page_packets: u16,
    /// How long an upload session lasts after OPEN or the last upload.
    pub session_ms: u64,
    /// How long new uploads are forwarded live after a fetch.
    pub lease_ms: u64,
    /// Proof checks and registrations per source address per minute.
    pub requests_per_minute: u32,
    /// Source addresses tracked for rate limiting; the oldest is forgotten.
    pub max_tracked_addresses: u32,
    /// Whether a push service is configured (`push.md`). Without one,
    /// push registrations are refused with `FULL`.
    pub push: bool,
    /// Most push handles.
    pub max_push_handles: u32,
    /// Most mailboxes one push handle may be bound to.
    pub max_push_bindings: u32,
    /// Least time between two pushes to one handle; anything in between is
    /// coalesced into one push at the end.
    pub push_interval_ms: u64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            retention_ms: 7 * 24 * 3_600_000,
            mailbox_quota_bytes: 1 << 20,
            total_quota_bytes: 1 << 30,
            max_mailboxes: 1_000_000,
            page_packets: MAX_PAGE as u16,
            session_ms: 600_000,
            lease_ms: 600_000,
            requests_per_minute: 120,
            max_tracked_addresses: 65_536,
            push: false,
            max_push_handles: 1_000_000,
            max_push_bindings: 1024,
            push_interval_ms: 60_000,
        }
    }
}

impl RelayConfig {
    /// Whether the settings are usable.
    pub fn is_valid(&self) -> bool {
        self.retention_ms > 0
            && self.retention_ms <= MAX_RETENTION_MS
            && self.mailbox_quota_bytes > 0
            && self.total_quota_bytes >= self.mailbox_quota_bytes
            && self.max_mailboxes > 0
            && self.page_packets > 0
            && usize::from(self.page_packets) <= MAX_PAGE
            && self.requests_per_minute > 0
            && self.max_tracked_addresses > 0
            && self.push_interval_ms > 0
    }
}

/// Why the relay could not start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayError {
    /// [`RelayConfig::is_valid`] failed.
    InvalidConfig,
    /// Storage failed or holds something undecodable.
    Storage,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid relay configuration",
            Self::Storage => "relay storage failed or is corrupt",
        })
    }
}

impl std::error::Error for RelayError {}

/// Counters for monitoring.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayStats {
    /// Datagrams handled.
    pub received: u64,
    /// Datagrams dropped as malformed or unknown.
    pub dropped: u64,
    /// Packets and Hellos stored.
    pub stored: u64,
    /// Uploads already stored (byte-identical), receipted again.
    pub duplicates: u64,
    /// Uploads refused for lack of space.
    pub refused_full: u64,
    /// Data packets with no upload session.
    pub refused_no_session: u64,
    /// Proofs that didn't verify.
    pub bad_proofs: u64,
    /// Requests refused by the rate limit.
    pub rate_limited: u64,
    /// Packets sent to fetchers (pages and live forwards).
    pub delivered: u64,
    /// Packets deleted below a proved fetch cursor.
    pub released: u64,
    /// Packets and Hellos evicted at expiry.
    pub expired: u64,
    /// Storage failures (the triggering upload was refused, not lost).
    pub storage_errors: u64,
    /// Push handles created or refreshed.
    pub push_registrations: u64,
    /// Pushes queued for the push service.
    pub pushes: u64,
    /// Pushes folded into a later one by the per-handle interval.
    pub pushes_coalesced: u64,
}

#[derive(Clone, Debug)]
struct Stored {
    at: Timestamp,
    hash: ReceiptHash,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Mailbox {
    tag: PairTag,
    up_anchor: Proof,
    down_anchor: Proof,
    up_last: Proof,
    down_last: Proof,
    active: Timestamp,
    next_seq: u64,
    packets: BTreeMap<u64, Stored>,
    hashes: BTreeSet<ReceiptHash>,
    bytes: u64,
}

#[derive(Clone, Debug, Default)]
struct HelloBox {
    next_seq: u64,
    packets: BTreeMap<u64, Stored>,
    hashes: BTreeSet<ReceiptHash>,
    bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: u64,
    at: Timestamp,
}

// Storage keys: "n" next mailbox id; "m" id → header; "p" id seq →
// packet; "h" hint seq → Hello; "H" hint → next seq.
const KEY_NEXT: &[u8] = b"n";
const P_MAILBOX: &[u8] = b"m";
const P_PACKET: &[u8] = b"p";
const P_HELLO: &[u8] = b"h";
const P_HELLO_SEQ: &[u8] = b"H";

fn key(prefix: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut k = prefix.to_vec();
    parts.iter().for_each(|p| k.extend_from_slice(p));
    k
}

fn encode_stored(s: &Stored) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.bytes.len() + 10);
    wire::put_varint(&mut v, s.at.as_millis());
    v.extend_from_slice(&s.bytes);
    v
}

fn decode_stored(v: &[u8]) -> Option<Stored> {
    let mut r = Reader::new(v);
    let at = Timestamp::from_millis(r.varint().ok()?);
    let bytes = r.rest().to_vec();
    Some(Stored {
        at,
        hash: receipt_hash(&bytes),
        bytes,
    })
}

impl Mailbox {
    fn header(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(90);
        v.extend_from_slice(&self.tag);
        for p in [
            &self.up_anchor,
            &self.down_anchor,
            &self.up_last,
            &self.down_last,
        ] {
            v.extend_from_slice(p);
        }
        wire::put_varint(&mut v, self.active.as_millis());
        wire::put_varint(&mut v, self.next_seq);
        v
    }

    fn from_header(v: &[u8]) -> Option<Self> {
        let mut r = Reader::new(v);
        Some(Self {
            tag: r.array().ok()?,
            up_anchor: r.array().ok()?,
            down_anchor: r.array().ok()?,
            up_last: r.array().ok()?,
            down_last: r.array().ok()?,
            active: Timestamp::from_millis(r.varint().ok()?),
            next_seq: r.varint().ok()?,
            packets: BTreeMap::new(),
            hashes: BTreeSet::new(),
            bytes: 0,
        })
    }
}

/// The relay state machine. `A` is the transport's address type.
pub struct Relay<S, A> {
    config: RelayConfig,
    storage: S,
    mailboxes: BTreeMap<u64, Mailbox>,
    by_tag: BTreeMap<PairTag, Vec<u64>>,
    hellos: BTreeMap<[u8; HELLO_HINT_LEN], HelloBox>,
    next_id: u64,
    used_bytes: u64,
    sessions: BTreeMap<(A, PairTag), (u64, Timestamp)>,
    /// Push state of upload sessions (`push.md` §4.4).
    session_push: BTreeMap<(A, PairTag), push::SessionPush>,
    leases: BTreeMap<u64, (A, Timestamp)>,
    buckets: BTreeMap<A, Bucket>,
    out: VecDeque<(A, Vec<u8>)>,
    now: Timestamp,
    stats: RelayStats,
    push: push::PushState,
}

/// A pending storage batch.
type Ops = Vec<(Vec<u8>, Option<Vec<u8>>)>;

impl<S: Storage, A: Ord + Copy> Relay<S, A> {
    /// Opens a relay on `storage`, loading whatever it already holds.
    pub fn open(config: RelayConfig, mut storage: S) -> Result<Self, RelayError> {
        if !config.is_valid() {
            return Err(RelayError::InvalidConfig);
        }
        let mut bad = false;
        let mut mailboxes = BTreeMap::new();
        storage
            .scan_prefix(P_MAILBOX, &mut |k, v| {
                let id = k.get(1..).and_then(|b| <[u8; 8]>::try_from(b).ok());
                match (id, Mailbox::from_header(v)) {
                    (Some(id), Some(m)) => {
                        mailboxes.insert(u64::from_be_bytes(id), m);
                    }
                    _ => bad = true,
                }
            })
            .map_err(|_| RelayError::Storage)?;
        let mut packets = Vec::new();
        storage
            .scan_prefix(P_PACKET, &mut |k, v| {
                let id = k.get(1..9).and_then(|b| <[u8; 8]>::try_from(b).ok());
                let seq = k.get(9..17).and_then(|b| <[u8; 8]>::try_from(b).ok());
                match (id, seq, decode_stored(v)) {
                    (Some(id), Some(seq), Some(s)) if k.len() == 17 => {
                        packets.push((u64::from_be_bytes(id), u64::from_be_bytes(seq), s))
                    }
                    _ => bad = true,
                }
            })
            .map_err(|_| RelayError::Storage)?;
        let mut hellos: BTreeMap<[u8; HELLO_HINT_LEN], HelloBox> = BTreeMap::new();
        let mut hello_packets = Vec::new();
        storage
            .scan_prefix(P_HELLO, &mut |k, v| {
                let hint = k.get(1..3).and_then(|b| <[u8; 2]>::try_from(b).ok());
                let seq = k.get(3..11).and_then(|b| <[u8; 8]>::try_from(b).ok());
                match (hint, seq, decode_stored(v)) {
                    (Some(h), Some(seq), Some(s)) if k.len() == 11 => {
                        hello_packets.push((h, u64::from_be_bytes(seq), s))
                    }
                    _ => bad = true,
                }
            })
            .map_err(|_| RelayError::Storage)?;
        storage
            .scan_prefix(P_HELLO_SEQ, &mut |k, v| {
                let hint = k.get(1..3).and_then(|b| <[u8; 2]>::try_from(b).ok());
                let seq = <[u8; 8]>::try_from(v).ok();
                match (hint, seq) {
                    (Some(h), Some(seq)) if k.len() == 3 => {
                        hellos.entry(h).or_default().next_seq = u64::from_be_bytes(seq);
                    }
                    _ => bad = true,
                }
            })
            .map_err(|_| RelayError::Storage)?;
        let next_id = match storage.load(KEY_NEXT).map_err(|_| RelayError::Storage)? {
            Some(v) => u64::from_be_bytes(
                <[u8; 8]>::try_from(v.as_slice()).map_err(|_| RelayError::Storage)?,
            ),
            None => 0,
        };
        if bad {
            return Err(RelayError::Storage);
        }
        let mut r = Self {
            config,
            storage,
            mailboxes,
            by_tag: BTreeMap::new(),
            hellos,
            next_id,
            used_bytes: 0,
            sessions: BTreeMap::new(),
            session_push: BTreeMap::new(),
            leases: BTreeMap::new(),
            buckets: BTreeMap::new(),
            out: VecDeque::new(),
            now: Timestamp::ZERO,
            stats: RelayStats::default(),
            push: push::PushState::default(),
        };
        for (id, m) in &r.mailboxes {
            r.by_tag.entry(m.tag).or_default().push(*id);
        }
        for (id, seq, s) in packets {
            let len = s.bytes.len() as u64;
            let Some(m) = r.mailboxes.get_mut(&id) else {
                return Err(RelayError::Storage);
            };
            m.hashes.insert(s.hash);
            m.bytes += len;
            m.packets.insert(seq, s);
            r.used_bytes += len;
        }
        for (hint, seq, s) in hello_packets {
            let len = s.bytes.len() as u64;
            let b = r.hellos.entry(hint).or_default();
            b.hashes.insert(s.hash);
            b.bytes += len;
            b.next_seq = b.next_seq.max(seq + 1);
            b.packets.insert(seq, s);
            r.used_bytes += len;
        }
        r.load_push()?;
        Ok(r)
    }

    /// Handles one datagram from `from`.
    pub fn handle(&mut self, from: A, bytes: &[u8], now: Timestamp) {
        self.observe(now);
        self.stats.received += 1;
        match bytes.first().copied() {
            Some(VERSION) => self.upload_packet(from, bytes),
            Some(HELLO_KIND) => self.upload_hello(from, bytes),
            Some(k) if wire::is_relay_kind(k) => match parse_relay(bytes) {
                Ok(msg) => self.request(from, msg),
                Err(_) => self.stats.dropped += 1,
            },
            _ => self.stats.dropped += 1,
        }
    }

    /// Advances time: evicts expired packets, Hellos, mailboxes, sessions
    /// and leases.
    pub fn handle_timeout(&mut self, now: Timestamp) {
        self.observe(now);
        self.expire();
        self.push_tick();
    }

    /// The next datagram to send, and to whom.
    pub fn poll_transmit(&mut self) -> Option<(A, Vec<u8>)> {
        self.out.pop_front()
    }

    /// When something next expires.
    pub fn next_timeout(&self) -> Option<Timestamp> {
        let ret = self.config.retention_ms;
        let oldest_packet = self
            .mailboxes
            .values()
            .filter_map(|m| m.packets.values().next().map(|s| s.at))
            .chain(
                self.hellos
                    .values()
                    .filter_map(|b| b.packets.values().next().map(|s| s.at)),
            )
            .min()
            .map(|t| t.saturating_add_millis(ret));
        let idle = self
            .mailboxes
            .values()
            .map(|m| m.active.saturating_add_millis(ret))
            .min();
        [oldest_packet, idle, self.push_next_timeout()]
            .into_iter()
            .flatten()
            .min()
    }

    /// Counters.
    pub fn stats(&self) -> RelayStats {
        self.stats
    }

    /// Mailboxes held.
    pub fn mailbox_count(&self) -> usize {
        self.mailboxes.len()
    }

    /// Bytes of packets and Hellos held.
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    /// The configuration.
    pub fn config(&self) -> &RelayConfig {
        &self.config
    }

    /// The storage, for inspection.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    fn observe(&mut self, now: Timestamp) {
        self.now = self.now.max(now);
    }

    fn send(&mut self, to: A, msg: &RelayMsg) {
        self.out.push_back((to, encode_relay(msg)));
    }

    fn receipt(&mut self, to: A, code: RelayCode, hash: ReceiptHash) {
        self.send(
            to,
            &RelayMsg::Receipt {
                code,
                hashes: vec![hash],
            },
        );
    }

    fn reply(&mut self, to: A, request: u8, code: RelayCode, key: [u8; 3], cursor: u64) {
        self.reply_page(to, request, code, key, cursor, Vec::new());
    }

    fn reply_page(
        &mut self,
        to: A,
        request: u8,
        code: RelayCode,
        key: [u8; 3],
        cursor: u64,
        page: Vec<ReceiptHash>,
    ) {
        let msg = RelayMsg::Reply {
            request,
            code,
            key,
            retention_s: self.config.retention_ms / 1000,
            cursor,
            page,
        };
        self.send(to, &msg);
    }

    fn commit(&mut self, ops: Ops) -> bool {
        let ok = (|| {
            self.storage.begin().map_err(|_| ())?;
            for (k, v) in &ops {
                let r = match v {
                    Some(v) => self.storage.store(k, v),
                    None => self.storage.remove(k),
                };
                if r.is_err() {
                    self.storage.rollback();
                    return Err(());
                }
            }
            self.storage.commit().map_err(|_| {
                self.storage.rollback();
            })
        })();
        if ok.is_err() {
            self.stats.storage_errors += 1;
        }
        ok.is_ok()
    }

    /// Takes one rate-limit token for `from`.
    fn allow(&mut self, from: A) -> bool {
        let per_min = u64::from(self.config.requests_per_minute);
        let cap = per_min.max(1) * 1000 / 4 + 1000; // a quarter-minute burst
        let now = self.now;
        if !self.buckets.contains_key(&from)
            && self.buckets.len() >= self.config.max_tracked_addresses as usize
        {
            // Forget the stalest address.
            if let Some(stalest) = self
                .buckets
                .iter()
                .min_by_key(|(_, b)| b.at)
                .map(|(a, _)| *a)
            {
                self.buckets.remove(&stalest);
            }
        }
        let b = self.buckets.entry(from).or_insert(Bucket {
            tokens: cap,
            at: now,
        });
        let refill = now.saturating_millis_since(b.at).saturating_mul(per_min) / 60;
        b.tokens = (b.tokens + refill).min(cap);
        b.at = now;
        if b.tokens >= 1000 {
            b.tokens -= 1000;
            true
        } else {
            self.stats.rate_limited += 1;
            false
        }
    }

    fn has_room(&self, mailbox_bytes: u64, len: u64) -> bool {
        mailbox_bytes + len <= self.config.mailbox_quota_bytes
            && self.used_bytes + len <= self.config.total_quota_bytes
    }

    fn upload_packet(&mut self, from: A, bytes: &[u8]) {
        let Ok(tag) = wire::peek_tag(bytes) else {
            self.stats.dropped += 1;
            return;
        };
        let now = self.now;
        let hash = receipt_hash(bytes);
        let session = self
            .sessions
            .get(&(from, tag))
            .filter(|(_, until)| *until > now)
            .map(|(id, _)| *id);
        let Some(id) = session else {
            self.stats.refused_no_session += 1;
            self.receipt(from, RelayCode::NoSession, hash);
            return;
        };
        let session_until = now.saturating_add_millis(self.config.session_ms);
        self.sessions.insert((from, tag), (id, session_until));
        let Some(m) = self.mailboxes.get(&id) else {
            self.receipt(from, RelayCode::NoSession, hash);
            return;
        };
        if m.hashes.contains(&hash) {
            self.stats.duplicates += 1;
            self.receipt(from, RelayCode::Ok, hash);
            return;
        }
        let len = bytes.len() as u64;
        if !self.has_room(m.bytes, len) {
            self.stats.refused_full += 1;
            self.receipt(from, RelayCode::Full, hash);
            return;
        }
        let seq = m.next_seq;
        let stored = Stored {
            at: now,
            hash,
            bytes: bytes.to_vec(),
        };
        let mut header = m.clone();
        header.next_seq = seq + 1;
        let ops = vec![
            (
                key(P_PACKET, &[&id.to_be_bytes(), &seq.to_be_bytes()]),
                Some(encode_stored(&stored)),
            ),
            (key(P_MAILBOX, &[&id.to_be_bytes()]), Some(header.header())),
        ];
        if !self.commit(ops) {
            self.receipt(from, RelayCode::Full, hash);
            return;
        }
        let Some(m) = self.mailboxes.get_mut(&id) else {
            return;
        };
        m.next_seq = seq + 1;
        m.bytes += len;
        m.hashes.insert(hash);
        m.packets.insert(seq, stored);
        self.used_bytes += len;
        self.stats.stored += 1;
        self.receipt(from, RelayCode::Ok, hash);
        let mut live = false;
        if let Some(&(to, until)) = self.leases.get(&id) {
            if until > now {
                self.out.push_back((to, bytes.to_vec()));
                self.stats.delivered += 1;
                live = true;
            }
        }
        self.packet_stored(from, tag, id, live);
    }

    fn upload_hello(&mut self, from: A, bytes: &[u8]) {
        let Ok(hello) = wire::parse_hello(bytes) else {
            self.stats.dropped += 1;
            return;
        };
        let hint = hello.hint;
        let hash = receipt_hash(bytes);
        let (dup, box_bytes, seq) = {
            let b = self.hellos.entry(hint).or_default();
            (b.hashes.contains(&hash), b.bytes, b.next_seq)
        };
        if dup {
            self.stats.duplicates += 1;
            self.receipt(from, RelayCode::Ok, hash);
            return;
        }
        let len = bytes.len() as u64;
        if !self.has_room(box_bytes, len) {
            self.stats.refused_full += 1;
            self.receipt(from, RelayCode::Full, hash);
            return;
        }
        let stored = Stored {
            at: self.now,
            hash,
            bytes: bytes.to_vec(),
        };
        let ops = vec![
            (
                key(P_HELLO, &[&hint, &seq.to_be_bytes()]),
                Some(encode_stored(&stored)),
            ),
            (
                key(P_HELLO_SEQ, &[&hint]),
                Some((seq + 1).to_be_bytes().to_vec()),
            ),
        ];
        if !self.commit(ops) {
            self.receipt(from, RelayCode::Full, hash);
            return;
        }
        let b = self.hellos.entry(hint).or_default();
        b.next_seq = seq + 1;
        b.bytes += len;
        b.hashes.insert(hash);
        b.packets.insert(seq, stored);
        self.used_bytes += len;
        self.stats.stored += 1;
        self.receipt(from, RelayCode::Ok, hash);
        self.hello_stored(&hash);
    }

    fn request(&mut self, from: A, msg: RelayMsg) {
        match msg {
            RelayMsg::Register { tag, up, down } => self.register(from, tag, up, down),
            RelayMsg::Open { tag, proof } => {
                if !self.allow(from) {
                    return self.reply(from, RELAY_OPEN, RelayCode::RateLimited, tag, 0);
                }
                match self.prove(tag, ChainRole::Up, &proof) {
                    Ok(id) => {
                        let until = self.now.saturating_add_millis(self.config.session_ms);
                        self.sessions.insert((from, tag), (id, until));
                        self.reply(from, RELAY_OPEN, RelayCode::Ok, tag, 0);
                    }
                    Err(code) => self.reply(from, RELAY_OPEN, code, tag, 0),
                }
            }
            RelayMsg::Fetch {
                tag,
                proof,
                since,
                release,
                max,
            } => {
                if !self.allow(from) {
                    return self.reply(from, RELAY_FETCH, RelayCode::RateLimited, tag, since);
                }
                match self.prove(tag, ChainRole::Down, &proof) {
                    Ok(id) => self.fetch(from, id, tag, since, release.min(since), max),
                    Err(code) => self.reply(from, RELAY_FETCH, code, tag, since),
                }
            }
            RelayMsg::FetchHello { hint, since } => self.fetch_hello(from, hint, since),
            RelayMsg::PushRegister { secret, blob } => self.push_register(from, secret, blob),
            RelayMsg::PushBind { tag, proof, handle } => self.push_bind(from, tag, proof, handle),
            RelayMsg::PushBindHello {
                key,
                handle,
                on,
                sig,
            } => self.push_bind_hello(from, key, handle, on, sig),
            RelayMsg::HelloNote { hello_hash, detect } => self.hello_note(hello_hash, detect),
            RelayMsg::PushNote { tag } => self.push_note(from, tag),
            // Relays don't take replies or receipts.
            RelayMsg::Reply { .. } | RelayMsg::Receipt { .. } => self.stats.dropped += 1,
        }
    }

    fn register(&mut self, from: A, tag: PairTag, up: Proof, down: Proof) {
        if !self.allow(from) {
            return self.reply(from, RELAY_REGISTER, RelayCode::RateLimited, tag, 0);
        }
        let now = self.now;
        let existing = self.by_tag.get(&tag).and_then(|ids| {
            ids.iter().copied().find(|id| {
                self.mailboxes
                    .get(id)
                    .is_some_and(|m| m.up_anchor == up && m.down_anchor == down)
            })
        });
        if let Some(id) = existing {
            self.touch(id);
            return self.reply(from, RELAY_REGISTER, RelayCode::Ok, tag, 0);
        }
        if self.mailboxes.len() >= self.config.max_mailboxes as usize {
            return self.reply(from, RELAY_REGISTER, RelayCode::Full, tag, 0);
        }
        let id = self.next_id;
        let m = Mailbox {
            tag,
            up_anchor: up,
            down_anchor: down,
            up_last: up,
            down_last: down,
            active: now,
            next_seq: 0,
            packets: BTreeMap::new(),
            hashes: BTreeSet::new(),
            bytes: 0,
        };
        let ops = vec![
            (key(P_MAILBOX, &[&id.to_be_bytes()]), Some(m.header())),
            (KEY_NEXT.to_vec(), Some((id + 1).to_be_bytes().to_vec())),
        ];
        if !self.commit(ops) {
            return self.reply(from, RELAY_REGISTER, RelayCode::Full, tag, 0);
        }
        self.next_id = id + 1;
        self.mailboxes.insert(id, m);
        self.by_tag.entry(tag).or_default().push(id);
        self.reply(from, RELAY_REGISTER, RelayCode::Ok, tag, 0);
    }

    /// Marks a mailbox active (persisted lazily with its next write, or
    /// now if nothing else is written).
    fn touch(&mut self, id: u64) {
        let now = self.now;
        if let Some(m) = self.mailboxes.get_mut(&id) {
            m.active = now;
            let header = m.header();
            self.commit(vec![(key(P_MAILBOX, &[&id.to_be_bytes()]), Some(header))]);
        }
    }

    /// Verifies a proof against the mailboxes for `tag`, advances the
    /// matching chain durably, and returns the mailbox.
    fn prove(&mut self, tag: PairTag, role: ChainRole, proof: &Proof) -> Result<u64, RelayCode> {
        let ids = self.by_tag.get(&tag).cloned().unwrap_or_default();
        if ids.is_empty() {
            return Err(RelayCode::UnknownMailbox);
        }
        let now = self.now;
        for id in ids {
            let Some(m) = self.mailboxes.get(&id) else {
                continue;
            };
            let last = match role {
                ChainRole::Up => &m.up_last,
                ChainRole::Down => &m.down_last,
            };
            if !mailbox::verify(last, proof) {
                continue;
            }
            let mut next = m.clone();
            match role {
                ChainRole::Up => next.up_last = *proof,
                ChainRole::Down => next.down_last = *proof,
            }
            next.active = now;
            if !self.commit(vec![(
                key(P_MAILBOX, &[&id.to_be_bytes()]),
                Some(next.header()),
            )]) {
                return Err(RelayCode::Full);
            }
            if let Some(slot) = self.mailboxes.get_mut(&id) {
                slot.up_last = next.up_last;
                slot.down_last = next.down_last;
                slot.active = now;
            }
            return Ok(id);
        }
        self.stats.bad_proofs += 1;
        Err(RelayCode::BadProof)
    }

    fn fetch(&mut self, from: A, id: u64, tag: PairTag, since: u64, release: u64, max: u8) {
        // The recipient proved it holds everything below `release`.
        let released: Vec<u64> = self
            .mailboxes
            .get(&id)
            .map(|m| m.packets.range(..release).map(|(s, _)| *s).collect())
            .unwrap_or_default();
        if !released.is_empty() {
            let ops = released
                .iter()
                .map(|s| (key(P_PACKET, &[&id.to_be_bytes(), &s.to_be_bytes()]), None))
                .collect();
            if self.commit(ops) {
                if let Some(m) = self.mailboxes.get_mut(&id) {
                    for s in &released {
                        if let Some(p) = m.packets.remove(s) {
                            m.bytes -= p.bytes.len() as u64;
                            m.hashes.remove(&p.hash);
                            self.used_bytes -= p.bytes.len() as u64;
                            self.stats.released += 1;
                        }
                    }
                }
            }
        }
        let page = match usize::from(max) {
            0 => usize::from(self.config.page_packets),
            n => n.min(usize::from(self.config.page_packets)),
        };
        let Some(m) = self.mailboxes.get(&id) else {
            return;
        };
        let batch: Vec<(u64, Vec<u8>, ReceiptHash)> = m
            .packets
            .range(since..)
            .take(page)
            .map(|(s, p)| (*s, p.bytes.clone(), p.hash))
            .collect();
        let cursor = batch.last().map_or(since, |(s, _, _)| s + 1);
        let more = m.packets.range(cursor..).next().is_some();
        let page = page_hashes(&batch);
        for (_, bytes, _) in batch {
            self.out.push_back((from, bytes));
            self.stats.delivered += 1;
        }
        let until = self.now.saturating_add_millis(self.config.lease_ms);
        self.leases.insert(id, (from, until));
        let code = if more { RelayCode::More } else { RelayCode::Ok };
        self.reply_page(from, RELAY_FETCH, code, tag, cursor, page);
    }

    fn fetch_hello(&mut self, from: A, hint: [u8; HELLO_HINT_LEN], since: u64) {
        self.hellos_fetched(hint);
        let page = usize::from(self.config.page_packets);
        let key3 = [hint[0], hint[1], 0];
        let Some(b) = self.hellos.get(&hint) else {
            return self.reply(from, RELAY_FETCH_HELLO, RelayCode::Ok, key3, since);
        };
        let batch: Vec<(u64, Vec<u8>, ReceiptHash)> = b
            .packets
            .range(since..)
            .take(page)
            .map(|(s, p)| (*s, p.bytes.clone(), p.hash))
            .collect();
        let cursor = batch.last().map_or(since, |(s, _, _)| s + 1);
        let more = b.packets.range(cursor..).next().is_some();
        let page = page_hashes(&batch);
        for (_, bytes, _) in batch {
            self.out.push_back((from, bytes));
            self.stats.delivered += 1;
        }
        let code = if more { RelayCode::More } else { RelayCode::Ok };
        self.reply_page(from, RELAY_FETCH_HELLO, code, key3, cursor, page);
    }

    fn expire(&mut self) {
        let now = self.now;
        let ret = self.config.retention_ms;
        let dead = |at: Timestamp| at.saturating_add_millis(ret) <= now;
        let mut ops: Ops = Vec::new();
        let mut gone_mailboxes = Vec::new();
        for (id, m) in &self.mailboxes {
            for (seq, p) in &m.packets {
                if !dead(p.at) {
                    break;
                }
                ops.push((
                    key(P_PACKET, &[&id.to_be_bytes(), &seq.to_be_bytes()]),
                    None,
                ));
            }
            if dead(m.active) {
                self.unbind_mailbox_ops(*id, &mut ops);
                gone_mailboxes.push(*id);
                ops.push((key(P_MAILBOX, &[&id.to_be_bytes()]), None));
                for seq in m.packets.keys() {
                    ops.push((
                        key(P_PACKET, &[&id.to_be_bytes(), &seq.to_be_bytes()]),
                        None,
                    ));
                }
            }
        }
        for (hint, b) in &self.hellos {
            for (seq, p) in &b.packets {
                if !dead(p.at) {
                    break;
                }
                ops.push((key(P_HELLO, &[hint, &seq.to_be_bytes()]), None));
            }
        }
        if !ops.is_empty() {
            ops.sort();
            ops.dedup();
            if !self.commit(ops) {
                return;
            }
        }
        for m in self.mailboxes.values_mut() {
            while let Some((&seq, p)) = m.packets.iter().next() {
                if !dead(p.at) {
                    break;
                }
                let len = p.bytes.len() as u64;
                m.hashes.remove(&p.hash);
                m.packets.remove(&seq);
                m.bytes -= len;
                self.used_bytes -= len;
                self.stats.expired += 1;
            }
        }
        for b in self.hellos.values_mut() {
            while let Some((&seq, p)) = b.packets.iter().next() {
                if !dead(p.at) {
                    break;
                }
                let len = p.bytes.len() as u64;
                b.hashes.remove(&p.hash);
                b.packets.remove(&seq);
                b.bytes -= len;
                self.used_bytes -= len;
                self.stats.expired += 1;
            }
        }
        for id in gone_mailboxes {
            if let Some(m) = self.mailboxes.remove(&id) {
                self.used_bytes -= m.bytes;
                self.stats.expired += m.packets.len() as u64;
                if let Some(ids) = self.by_tag.get_mut(&m.tag) {
                    ids.retain(|x| *x != id);
                    if ids.is_empty() {
                        self.by_tag.remove(&m.tag);
                    }
                }
                self.leases.remove(&id);
            }
            self.mailbox_gone(id);
        }
        self.sessions.retain(|_, (_, until)| *until > now);
        let sessions = &self.sessions;
        self.session_push.retain(|k, _| sessions.contains_key(k));
        self.leases.retain(|_, (_, until)| *until > now);
    }
}

/// The receipt hashes of a page's packets, in order. Pages are consecutive
/// runs of stored packets, so the client can tell which sequence number
/// each was.
fn page_hashes(batch: &[(u64, Vec<u8>, ReceiptHash)]) -> Vec<ReceiptHash> {
    batch.iter().map(|(_, _, h)| *h).collect()
}

#[cfg(test)]
mod tests;
