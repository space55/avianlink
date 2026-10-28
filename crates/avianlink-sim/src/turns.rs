//! The relay use case (`docs/relay.md` §1): A and B are never online at
//! the same time, and a relay carries everything. Each hop between a client
//! and the relay has its own impaired channel; clients come online in
//! alternating sessions, write a few messages, and leave once
//! [`Engine::relay_settled`] (or after a cap).

use std::collections::BTreeMap;
use std::fmt;
use std::time::Instant;

use avianlink_core::{
    Config, Engine, Event, Identity, LinkConfig, LinkId, MemoryStorage, MessageId, Timestamp,
};
use avianlink_relay::{Relay, RelayClient, RelayConfig};
use rand_chacha::ChaCha20Rng;

use crate::impair::{below, unit, Channel, LinkProfile, Outages};
use crate::sim::{exp_ms, random_text, stream};
use crate::{fmt_ms, percentile, LengthMix, Profile, SIM_EPOCH_MS};

const LINK: LinkId = LinkId(0);
const STEP_MS: u64 = 100;
const RELAY_ADDR: u8 = 255;

/// A turns scenario.
#[derive(Clone, Debug)]
pub struct TurnsScenario {
    /// Name used in reports.
    pub name: String,
    /// Master seed.
    pub seed: u64,
    /// Impairments of every client↔relay hop (outages are ignored: being
    /// offline is the point).
    pub hop: LinkProfile,
    /// The engines' relay link (its MTU must suit the smallest hop).
    pub link: LinkConfig,
    /// Sessions per client.
    pub sessions: usize,
    /// Longest a session lasts, even if not settled.
    pub max_session_ms: u64,
    /// Shortest a session lasts.
    pub min_session_ms: u64,
    /// Mean time offline between one client's session and the other's.
    pub mean_gap_ms: u64,
    /// Messages written per session: 0 to this many.
    pub max_per_session: u64,
    /// Message size distribution.
    pub lengths: LengthMix,
    /// Relay policy.
    pub relay: RelayConfig,
}

impl TurnsScenario {
    /// Turns over `profile`'s hops: 40 sessions each, 0–2 messages per
    /// session, ~2 h apart, sessions of 30 s to 5 min.
    pub fn new(profile: Profile, seed: u64) -> Self {
        let hop = profile.link();
        Self {
            name: format!("turns_{}", profile.name()),
            seed,
            hop,
            // The hop's own budget, as a host would register it; packets
            // sized for the hop (at most 200 bytes, for small recipients).
            link: LinkConfig {
                mtu: hop.mtu.min(200),
                ..hop.engine_link()
            },
            sessions: 40,
            max_session_ms: 300_000,
            min_session_ms: 30_000,
            mean_gap_ms: 2 * 3_600_000,
            max_per_session: 2,
            lengths: LengthMix::default(),
            relay: RelayConfig::default(),
        }
    }

    /// Runs it.
    pub fn run(&self) -> TurnsReport {
        TurnsSim::new(self).run()
    }
}

struct Node {
    engine: Engine<MemoryStorage, ChaCha20Rng>,
    client: RelayClient,
    conv: avianlink_core::ConversationId,
    up: Channel,
    down: Channel,
    /// Arrivals at the relay (from this node) and at this node.
    to_relay: Vec<(u64, Vec<u8>)>,
    to_node: Vec<(u64, Vec<u8>)>,
}

struct Msg {
    id: MessageId,
    from: usize,
    text_len: usize,
    sent_at: u64,
    sent_session: usize,
    delivered: Option<(u64, usize)>,
    acked: bool,
}

/// What a turns run measured.
#[derive(Clone, Debug, Default)]
pub struct TurnsReport {
    /// Scenario name.
    pub name: String,
    /// Seed.
    pub seed: u64,
    /// Messages written.
    pub messages: usize,
    /// Messages the recipient received.
    pub delivered: usize,
    /// Messages whose sender saw the recipient's ACK.
    pub acked: usize,
    /// Undelivered messages still in their sender's outbox (in flight, to
    /// be resent).
    pub still_queued: usize,
    /// Undelivered messages gone from their sender's outbox: lost (bug).
    pub lost: usize,
    /// Sessions from writing a message to its receipt (1: the recipient's
    /// next session), p50 / p95 / max.
    pub sessions_p50: usize,
    /// See `sessions_p50`.
    pub sessions_p95: usize,
    /// See `sessions_p50`.
    pub sessions_max: usize,
    /// Time from writing to receipt, p50 / p95.
    pub latency_p50_ms: u64,
    /// See `latency_p50_ms`.
    pub latency_p95_ms: u64,
    /// Payload bytes delivered.
    pub payload_bytes: u64,
    /// Bytes clients sent to the relay.
    pub uplink_bytes: u64,
    /// Bytes the relay sent to clients.
    pub downlink_bytes: u64,
    /// Sessions that ended before settling (hit the cap).
    pub unsettled_sessions: usize,
    /// Largest relay storage used, bytes.
    pub relay_peak_bytes: u64,
    /// Fetches that re-read packets lost on the way.
    pub rereads: u64,
    /// Messages surfaced twice (bug).
    pub duplicates: usize,
    /// Engine transmit stalls (bug).
    pub stalls: u64,
    /// Simulated time.
    pub sim_ms: u64,
    /// Wall time.
    pub wall_ms: f64,
}

impl TurnsReport {
    /// Bug counters: must be zero.
    pub fn bugs(&self) -> u64 {
        self.duplicates as u64 + self.stalls + self.lost as u64
    }

    /// Bytes on the wire (both directions of both hops) per payload byte.
    pub fn wire_per_payload(&self) -> f64 {
        (self.uplink_bytes + self.downlink_bytes) as f64 / self.payload_bytes.max(1) as f64
    }
}

impl fmt::Display for TurnsReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "scenario {} (seed {})", self.name, self.seed)?;
        writeln!(
            f,
            "  delivered   {}/{}, acked {}; {} still queued by their sender, {} lost",
            self.delivered, self.messages, self.acked, self.still_queued, self.lost
        )?;
        writeln!(
            f,
            "  sessions    p50 {}  p95 {}  max {} (1 = the recipient's next session)",
            self.sessions_p50, self.sessions_p95, self.sessions_max
        )?;
        writeln!(
            f,
            "  latency     p50 {}  p95 {}",
            fmt_ms(self.latency_p50_ms),
            fmt_ms(self.latency_p95_ms)
        )?;
        writeln!(
            f,
            "  wire        {:.2} bytes/payload byte (up {} B, down {} B)",
            self.wire_per_payload(),
            self.uplink_bytes,
            self.downlink_bytes
        )?;
        writeln!(
            f,
            "  relay       peak {} B; {} re-reads; {} sessions left unsettled",
            self.relay_peak_bytes, self.rereads, self.unsettled_sessions
        )?;
        write!(
            f,
            "  bugs        {} (duplicates {}, stalls {}, lost {}); sim {}, wall {:.0} ms",
            self.bugs(),
            self.duplicates,
            self.stalls,
            self.lost,
            fmt_ms(self.sim_ms),
            self.wall_ms
        )
    }
}

struct TurnsSim<'a> {
    sc: &'a TurnsScenario,
    now: u64,
    relay: Relay<MemoryStorage, u8>,
    nodes: Vec<Node>,
    outages: Outages,
    msgs: Vec<Msg>,
    by_id: BTreeMap<MessageId, usize>,
    session: usize,
    report: TurnsReport,
    workload: ChaCha20Rng,
}

impl<'a> TurnsSim<'a> {
    fn new(sc: &'a TurnsScenario) -> Self {
        let mut secrets = [[0u8; 32]; 2];
        let mut key_rng = stream(sc.seed, 1);
        for s in &mut secrets {
            rand_core::Rng::fill_bytes(&mut key_rng, s);
        }
        let keys = secrets.map(|s| Identity::from_secret_bytes(&s).public_key());
        let nodes = (0..2)
            .map(|i| {
                let mut engine = Engine::new(
                    Config::default(),
                    Identity::from_secret_bytes(&secrets[i]),
                    MemoryStorage::new(),
                    stream(sc.seed, 10 + i as u64),
                )
                .expect("valid config");
                engine
                    .add_relay_link(LINK, sc.link)
                    .expect("valid relay link");
                let conv = engine.add_contact(keys[1 - i]).expect("contact");
                let mut hop = sc.hop;
                hop.outage = None;
                Node {
                    engine,
                    client: RelayClient::new(LINK),
                    conv,
                    up: Channel::new(hop, stream(sc.seed, 20 + i as u64)),
                    down: Channel::new(hop, stream(sc.seed, 30 + i as u64)),
                    to_relay: Vec::new(),
                    to_node: Vec::new(),
                }
            })
            .collect();
        Self {
            sc,
            now: SIM_EPOCH_MS,
            relay: Relay::open(sc.relay, MemoryStorage::new()).expect("valid relay config"),
            nodes,
            outages: Outages::new(None, stream(sc.seed, 5), SIM_EPOCH_MS),
            msgs: Vec::new(),
            by_id: BTreeMap::new(),
            session: 0,
            report: TurnsReport {
                name: sc.name.clone(),
                seed: sc.seed,
                ..TurnsReport::default()
            },
            workload: stream(sc.seed, 2),
        }
    }

    fn run(mut self) -> TurnsReport {
        let wall = Instant::now();
        let total = 2 * self.sc.sessions;
        // Extra sessions with nothing new, so the last messages and ACKs land.
        for s in 0..total + 12 {
            let node = s % 2;
            let writing = s < total;
            self.online(node, writing);
            let gap = exp_ms(&mut self.workload, self.sc.mean_gap_ms).max(60_000);
            self.offline(gap);
            if !writing && self.all_done() {
                break;
            }
        }
        self.finish(wall.elapsed().as_secs_f64() * 1000.0)
    }

    fn all_done(&self) -> bool {
        self.msgs.iter().all(|m| m.delivered.is_some() && m.acked)
    }

    fn online(&mut self, i: usize, writing: bool) {
        self.session += 1;
        let start = self.now;
        let t = Timestamp::from_millis;
        {
            let n = &mut self.nodes[i];
            n.client.connect(&mut n.engine, t(start));
        }
        if writing {
            let k = below(&mut self.workload, self.sc.max_per_session + 1);
            for _ in 0..k {
                let r = unit(&mut self.workload);
                let len = if r < self.sc.lengths.short {
                    5 + below(&mut self.workload, 76)
                } else if r < self.sc.lengths.short + self.sc.lengths.medium {
                    80 + below(&mut self.workload, 221)
                } else {
                    300 + below(&mut self.workload, 901)
                };
                let text = random_text(&mut self.workload, len as usize);
                let n = &mut self.nodes[i];
                if let Ok(q) = n.engine.send_text(n.conv, &text, t(start)) {
                    self.by_id.insert(q.id, self.msgs.len());
                    self.msgs.push(Msg {
                        id: q.id,
                        from: i,
                        text_len: text.len(),
                        sent_at: start,
                        sent_session: self.session,
                        delivered: None,
                        acked: false,
                    });
                }
            }
        }
        let mut settled_at = None;
        loop {
            let now = self.now;
            self.step(i, true);
            let elapsed = now - start;
            if self.nodes[i].engine.relay_settled() && self.nodes[i].client.caught_up() {
                settled_at.get_or_insert(now);
            } else {
                settled_at = None;
            }
            // Leave once settled for a moment (so stray replies land), after
            // the minimum session, or at the cap regardless.
            let settled = settled_at.is_some_and(|s| now - s >= 2_000);
            if (elapsed >= self.sc.min_session_ms && settled) || elapsed >= self.sc.max_session_ms {
                if !settled {
                    self.report.unsettled_sessions += 1;
                }
                break;
            }
            self.now += STEP_MS;
        }
        let n = &mut self.nodes[i];
        self.report.rereads += n.client.stats().rereads;
        n.client.disconnect();
        n.to_node.clear(); // arrives at a device that is offline
    }

    fn offline(&mut self, ms: u64) {
        let end = self.now + ms;
        // Uploads still in flight reach the relay; replies to an offline
        // device are lost.
        while self.now < end {
            let next = self
                .nodes
                .iter()
                .flat_map(|n| n.to_relay.iter().map(|(at, _)| *at))
                .min();
            match next {
                Some(at) if at < end => {
                    self.now = self.now.max(at);
                    self.step(usize::MAX, false);
                }
                _ => self.now = end,
            }
        }
        for n in &mut self.nodes {
            n.to_node.clear();
        }
        self.relay.handle_timeout(Timestamp::from_millis(self.now));
    }

    /// One step: `online` is the node that's up (or none).
    fn step(&mut self, online: usize, up: bool) {
        let now = self.now;
        let t = Timestamp::from_millis(now);
        // Deliveries to the relay.
        for (i, n) in self.nodes.iter_mut().enumerate() {
            let (due, rest): (Vec<_>, Vec<_>) =
                n.to_relay.drain(..).partition(|(at, _)| *at <= now);
            n.to_relay = rest;
            for (_, bytes) in due {
                self.relay.handle(i as u8, &bytes, t);
            }
        }
        self.relay.handle_timeout(t);
        while let Some((to, bytes)) = self.relay.poll_transmit() {
            if to == RELAY_ADDR {
                continue;
            }
            let n = &mut self.nodes[usize::from(to)];
            self.report.downlink_bytes += bytes.len() as u64;
            let copies = n.down.send(now, bytes, &mut self.outages);
            n.to_node.extend(copies);
        }
        self.report.relay_peak_bytes = self.report.relay_peak_bytes.max(self.relay.used_bytes());
        if !up {
            return;
        }
        let i = online;
        let mut events = Vec::new();
        {
            let n = &mut self.nodes[i];
            let (due, rest): (Vec<_>, Vec<_>) = n.to_node.drain(..).partition(|(at, _)| *at <= now);
            n.to_node = rest;
            for (_, bytes) in due {
                n.client.handle(&mut n.engine, &bytes, t);
            }
            n.engine.handle_timeout(t);
            n.client.handle_timeout(&mut n.engine, t);
            while let Some(tx) = n.engine.poll_transmit(t) {
                n.client.upload(&mut n.engine, tx, t);
            }
            while let Some(bytes) = n.client.poll_transmit() {
                self.report.uplink_bytes += bytes.len() as u64;
                let copies = n.up.send(now, bytes, &mut self.outages);
                n.to_relay.extend(copies);
            }
            while let Some(ev) = n.engine.poll_event() {
                events.push(ev);
            }
            self.report.stalls = self.report.stalls.max(n.engine.stats().transmit_stalls);
        }
        for ev in events {
            match ev {
                Event::MessageReceived(m) => {
                    if let Some(&k) = self.by_id.get(&m.id) {
                        let msg = &mut self.msgs[k];
                        if msg.delivered.is_some() {
                            self.report.duplicates += 1;
                        } else {
                            msg.delivered = Some((now, self.session));
                        }
                    }
                }
                Event::MessageDelivered { id, .. } => {
                    if let Some(&k) = self.by_id.get(&id) {
                        self.msgs[k].acked = true;
                    }
                }
                _ => {}
            }
        }
    }

    fn finish(mut self, wall_ms: f64) -> TurnsReport {
        let queued: Vec<std::collections::BTreeSet<MessageId>> = self
            .nodes
            .iter()
            .map(|n| {
                n.engine
                    .outgoing(n.conv)
                    .unwrap_or_default()
                    .iter()
                    .map(|o| o.id)
                    .collect()
            })
            .collect();
        let r = &mut self.report;
        for m in self.msgs.iter().filter(|m| m.delivered.is_none()) {
            if queued[m.from].contains(&m.id) {
                r.still_queued += 1;
            } else {
                r.lost += 1;
            }
        }
        r.messages = self.msgs.len();
        r.delivered = self.msgs.iter().filter(|m| m.delivered.is_some()).count();
        r.acked = self.msgs.iter().filter(|m| m.acked).count();
        r.payload_bytes = self
            .msgs
            .iter()
            .filter(|m| m.delivered.is_some())
            .map(|m| m.text_len as u64)
            .sum();
        let mut sessions: Vec<u64> = self
            .msgs
            .iter()
            .filter_map(|m| {
                let (_, s) = m.delivered?;
                // Sessions of the recipient between writing and receipt.
                Some(((s - m.sent_session) as u64).div_ceil(2))
            })
            .collect();
        sessions.sort_unstable();
        r.sessions_p50 = percentile(&sessions, 50) as usize;
        r.sessions_p95 = percentile(&sessions, 95) as usize;
        r.sessions_max = sessions.last().copied().unwrap_or(0) as usize;
        let mut lat: Vec<u64> = self
            .msgs
            .iter()
            .filter_map(|m| Some(m.delivered?.0 - m.sent_at))
            .collect();
        lat.sort_unstable();
        r.latency_p50_ms = percentile(&lat, 50);
        r.latency_p95_ms = percentile(&lat, 95);
        r.sim_ms = self.now - SIM_EPOCH_MS;
        r.wall_ms = wall_ms;
        self.report
    }
}
