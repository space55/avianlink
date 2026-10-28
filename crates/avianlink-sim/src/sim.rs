//! Discrete-event simulation of two peers over one impaired link.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::time::Instant;

use avianlink_core::{
    Config, ConversationId, Engine, Error, Event, Identity, LinkBudget, LinkConfig, LinkId,
    MemoryStorage, MessageId, Stats, Timestamp,
};
use rand_chacha::ChaCha20Rng;
use rand_core::Rng;

use crate::impair::{
    below, unit, Channel, ChannelStats, GilbertElliott, LinkProfile, OutageModel, Outages,
};
use crate::metrics::{percentile, Report};
use crate::Profile;

/// Simulated time starts at 2026-01-01T00:00:00Z so timestamps are real.
pub const SIM_EPOCH_MS: u64 = 1_767_225_600_000;

const LINK: LinkId = LinkId(0);

impl LinkProfile {
    /// The engine-side registration matching this profile's limits.
    pub fn engine_link(&self) -> LinkConfig {
        let budget = if let Some(d) = self.duty {
            LinkBudget::DutyCycle {
                permille: d.permille,
                window_ms: d.window_ms,
                airtime: d.airtime,
            }
        } else if let Some(rate) = self.rate_bytes_per_sec {
            LinkBudget::BytesPerSecond(rate)
        } else {
            LinkBudget::Unlimited
        };
        LinkConfig {
            mtu: self.mtu,
            budget,
            cost: 1,
        }
    }
}

/// Distribution of message lengths, in bytes of UTF-8.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LengthMix {
    /// Fraction of short (5–80 byte) messages.
    pub short: f64,
    /// Fraction of medium (80–300 byte) messages; the rest are long
    /// (300–1200 bytes).
    pub medium: f64,
}

impl LengthMix {
    /// The default: messages average about 200 bytes, the expected real
    /// workload (D-041).
    pub const TYPICAL: Self = Self {
        short: 0.45,
        medium: 0.42,
    };

    /// The Phase 1–5 workload, averaging about 100 bytes. Kept so tests
    /// that pin numbers from those phases stay comparable.
    pub const LEGACY: Self = Self {
        short: 0.80,
        medium: 0.15,
    };
}

impl Default for LengthMix {
    fn default() -> Self {
        Self::TYPICAL
    }
}

/// Random process crashes. A crash discards everything not committed to
/// storage; the node then restarts with `Engine::restore`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CrashModel {
    /// Mean time between crashes per node (exponential).
    pub mean_interval_ms: u64,
    /// How long a crashed node stays down; packets to it are lost and its
    /// application's sends wait.
    pub downtime_ms: u64,
}

/// An on-path attacker. It sees every packet on the link and can inject
/// its own, but holds no keys.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Adversary {
    /// Per packet sent: probability of later re-injecting a copy of some
    /// earlier packet (a replay).
    pub replay_prob: f64,
    /// Per packet sent: probability of injecting a forgery that reuses the
    /// packet's header with random ciphertext.
    pub forge_prob: f64,
    /// Per delivered packet: probability of flipping one bit (tampering);
    /// unlike link corruption, aimed at the header and tag too.
    pub tamper_prob: f64,
}

/// A complete, reproducible simulation setup.
#[derive(Clone, Debug)]
pub struct Scenario {
    /// Name used in reports.
    pub name: String,
    /// Master seed; everything random derives from it.
    pub seed: u64,
    /// Link impairments.
    pub link: LinkProfile,
    /// Engine configuration for both peers.
    pub config: Config,
    /// Messages to send, split randomly between the two directions.
    pub messages: usize,
    /// Mean time between consecutive messages (exponential).
    pub mean_interval_ms: u64,
    /// Message size distribution.
    pub lengths: LengthMix,
    /// Give up after this much simulated time.
    pub deadline_ms: u64,
    /// Process crashes, if any.
    pub crashes: Option<CrashModel>,
    /// On-path attacker, if any.
    pub adversary: Option<Adversary>,
    /// Scheduled outages as (start offset, duration) in ms, on top of the
    /// profile's outage model.
    pub fixed_outages: Vec<(u64, u64)>,
    /// Whether hosts call `Engine::nudge` when a scheduled outage ends (as
    /// an OS reporting "network available" would).
    pub nudge_on_reconnect: bool,
    /// Peer B starts without A's key and learns it from A's Hello (D-044).
    pub introduce: bool,
    /// Peer B loses all its state at this offset (ms) and restarts empty
    /// with the same identity, like a relay rebuilt from scratch.
    pub wipe_at_ms: Option<u64>,
    /// Every message goes from A to B.
    pub one_way: bool,
}

impl Scenario {
    /// Defaults for a named profile: 1000 messages averaging ~200 bytes,
    /// one every 30 s on average (every 25 min on `lora_like`, whose 1% duty
    /// cycle carries only ~3 KB/hour), 30-day deadline, no crashes.
    pub fn new(profile: Profile, seed: u64) -> Self {
        let mean_interval_ms = match profile {
            Profile::LoraLike => 1_500_000,
            _ => 30_000,
        };
        Self {
            name: profile.name().to_string(),
            seed,
            link: profile.link(),
            config: Config::default(),
            messages: 1000,
            mean_interval_ms,
            lengths: LengthMix::default(),
            deadline_ms: 30 * 24 * 3_600_000,
            crashes: None,
            adversary: None,
            fixed_outages: Vec::new(),
            nudge_on_reconnect: false,
            introduce: false,
            wipe_at_ms: None,
            one_way: false,
        }
    }

    /// The Phase 2 stress scenario: `disaster_cellular` shrunk to a 64-byte
    /// MTU, with ~50% Gilbert-Elliott loss and outages of 90 s up / 10 min
    /// down on average.
    pub fn harsh_64(seed: u64) -> Self {
        let mut sc = Self::new(Profile::DisasterCellular, seed);
        sc.name = "harsh_64".to_string();
        sc.link.mtu = 64;
        sc.link.loss = GilbertElliott {
            p_good_to_bad: 0.1,
            p_bad_to_good: 0.1,
            loss_good: 0.2,
            loss_bad: 0.8,
        };
        sc.link.outage = Some(OutageModel {
            up_ms: 90_000,
            down_ms: 600_000,
            randomize: true,
        });
        sc
    }

    /// [`Scenario::harsh_64`] with both nodes crashing every 30 minutes on
    /// average and staying down 30 s.
    pub fn harsh_64_crashy(seed: u64) -> Self {
        let mut sc = Self::harsh_64(seed);
        sc.name = "harsh_64_crashy".to_string();
        sc.crashes = Some(CrashModel {
            mean_interval_ms: 30 * 60_000,
            downtime_ms: 30_000,
        });
        sc
    }

    /// `disaster_cellular` with an on-path attacker replaying 20% and
    /// forging 20% of packets, and tampering with 10% of deliveries.
    pub fn disaster_hostile(seed: u64) -> Self {
        let mut sc = Self::new(Profile::DisasterCellular, seed);
        sc.name = "disaster_hostile".to_string();
        sc.adversary = Some(Adversary {
            replay_prob: 0.2,
            forge_prob: 0.2,
            tamper_prob: 0.1,
        });
        sc
    }

    /// `disaster_cellular`'s bursty ~35% loss, heavy-tailed delay and
    /// corruption, but no outages: the case FEC is for.
    pub fn bursty_loss(seed: u64) -> Self {
        let mut sc = Self::new(Profile::DisasterCellular, seed);
        sc.name = "bursty_loss".to_string();
        sc.link.outage = None;
        sc
    }

    /// Phase 5: an `edge_2g` link that goes down for a full week. 1000
    /// messages are written over 9 days, most of them while the link is
    /// down; both peers must converge afterwards with bounded bytes.
    pub fn week_offline(seed: u64) -> Self {
        const DAY: u64 = 24 * 3_600_000;
        let mut sc = Self::new(Profile::Edge2g, seed);
        sc.name = "week_offline".to_string();
        sc.link.outage = None;
        sc.mean_interval_ms = 9 * DAY / 1000;
        sc.fixed_outages = vec![(DAY, 7 * DAY)];
        sc
    }

    /// D-044: on `disaster_cellular`, B doesn't know A and accepts A's
    /// contact request automatically when A's Hello gets through.
    pub fn introduction(seed: u64) -> Self {
        let mut sc = Self::new(Profile::DisasterCellular, seed);
        sc.name = "introduction".to_string();
        sc.introduce = true;
        sc
    }

    /// [`Scenario::introduction`] on `lora_like`.
    pub fn introduction_lora(seed: u64) -> Self {
        let mut sc = Self::new(Profile::LoraLike, seed);
        sc.name = "introduction_lora".to_string();
        sc.introduce = true;
        sc
    }

    /// D-044: a client (A) sending to a relay (B) on `edge_2g`. Four hours
    /// in, the relay loses all state and comes back empty; it relearns A
    /// from the Hellos A sends while in backoff, and accepts automatically.
    pub fn relay_restart(seed: u64) -> Self {
        let mut sc = Self::new(Profile::Edge2g, seed);
        sc.name = "relay_restart".to_string();
        sc.one_way = true;
        sc.wipe_at_ms = Some(4 * 3_600_000);
        sc
    }

    /// Scenario names run by `--profile everything`. [`Scenario::named`]
    /// also accepts `relay_restart`, which is kept out of sweeps while it
    /// exposes counter reuse after state loss (D-044, "Open problem").
    pub const NAMES: [&'static str; 12] = [
        "clean",
        "geo_satellite",
        "edge_2g",
        "disaster_cellular",
        "lora_like",
        "harsh_64",
        "harsh_64_crashy",
        "disaster_hostile",
        "bursty_loss",
        "week_offline",
        "introduction",
        "introduction_lora",
    ];

    /// A profile's default scenario, or one of the stress scenarios.
    pub fn named(name: &str, seed: u64) -> Option<Self> {
        match name {
            "harsh_64" => Some(Self::harsh_64(seed)),
            "harsh_64_crashy" => Some(Self::harsh_64_crashy(seed)),
            "disaster_hostile" => Some(Self::disaster_hostile(seed)),
            "bursty_loss" => Some(Self::bursty_loss(seed)),
            "week_offline" => Some(Self::week_offline(seed)),
            "introduction" => Some(Self::introduction(seed)),
            "introduction_lora" => Some(Self::introduction_lora(seed)),
            "relay_restart" => Some(Self::relay_restart(seed)),
            _ => Profile::from_name(name).map(|p| Self::new(p, seed)),
        }
    }

    /// This scenario with the Phase 1–5 workload (~100-byte messages; one
    /// every 10 min on LoRa), for comparisons pinned to those phases.
    pub fn legacy_workload(mut self) -> Self {
        self.lengths = LengthMix::LEGACY;
        if self.mean_interval_ms == 1_500_000 {
            self.mean_interval_ms = 600_000;
        }
        self
    }

    /// Runs the scenario to completion or deadline.
    pub fn run(&self) -> Report {
        Sim::new(self).run()
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Ev {
    Send {
        msg: usize,
    },
    Arrive {
        node: usize,
        bytes: Vec<u8>,
    },
    Wake {
        node: usize,
        generation: u64,
    },
    /// Arms a crash: it happens inside the node's next input, before the
    /// host drains events (the harshest point).
    Crash {
        node: usize,
    },
    Restart {
        node: usize,
    },
    Nudge {
        node: usize,
    },
    /// The node loses all state and restarts empty.
    Wipe {
        node: usize,
    },
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Scheduled {
    at: u64,
    order: u64,
    ev: Ev,
}

type SimEngine = Engine<MemoryStorage, ChaCha20Rng>;

struct Node {
    /// Identity seed; the host's "keychain".
    secret: [u8; 32],
    /// `None` while crashed.
    engine: Option<SimEngine>,
    /// Storage left behind by a crash, waiting for the restart.
    wreck: Option<MemoryStorage>,
    conv: ConversationId,
    wake: Option<u64>,
    generation: u64,
    crash_armed: bool,
    incarnation: u64,
    /// Counters of previous incarnations.
    retired: Stats,
    /// Accepts contact requests automatically (a relay, or an app whose
    /// user taps "accept").
    accept_requests: bool,
}

struct Msg {
    from: usize,
    text: String,
    scheduled_at: u64,
    sent_at: Option<u64>,
    id: Option<MessageId>,
    delivered_at: Option<u64>,
    acked_at: Option<u64>,
}

struct Sim<'a> {
    sc: &'a Scenario,
    now: u64,
    order: u64,
    queue: BinaryHeap<Reverse<Scheduled>>,
    nodes: Vec<Node>,
    channels: [Channel; 2],
    outages: Outages,
    crash_rng: ChaCha20Rng,
    adv_rng: ChaCha20Rng,
    /// Recent packets the adversary has recorded, per direction.
    recorded: [Vec<Vec<u8>>; 2],
    injected: u64,
    msgs: Vec<Msg>,
    by_id: BTreeMap<MessageId, usize>,
    delivered: usize,
    acked: usize,
    wire_bytes: u64,
    packets: u64,
    stalls: u64,
    outbox_full_retries: u64,
    duplicate_deliveries: u64,
    integrity_violations: u64,
    out_of_order: u64,
    crashes: u64,
    max_storage_bytes: usize,
    outage_wire_bytes: u64,
    outage_packets: u64,
    sync_anomalies: u64,
    wipes: u64,
    redelivered_after_wipe: u64,
    skipped_after_wipe: u64,
}

pub(crate) fn stream(seed: u64, n: u64) -> ChaCha20Rng {
    let mut rng = crate::seeded_rng(seed);
    rng.set_stream(n);
    rng
}

const WORDS: &[&str] = &[
    "help",
    "water",
    "need",
    "ok",
    "road",
    "blocked",
    "bridge",
    "north",
    "café",
    "straße",
    "日本",
    "медицина",
    "🙂",
    "42",
    "shelter",
    "battery",
    "low",
    "coming",
    "now",
    "safe",
    "where",
    "are",
    "you",
    "?",
    "!",
    "meet",
    "at",
    "school",
    "gate",
    "2km",
    "east",
];

pub(crate) fn random_text(rng: &mut ChaCha20Rng, target: usize) -> String {
    let mut s = String::new();
    while s.len() < target {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(WORDS[below(rng, WORDS.len() as u64) as usize]);
    }
    s
}

pub(crate) fn exp_ms(rng: &mut ChaCha20Rng, mean: u64) -> u64 {
    ((-(unit(rng).max(f64::MIN_POSITIVE)).ln()) * mean as f64) as u64
}

/// Field-wise sum, for counters that span engine incarnations.
pub fn add_stats(a: &Stats, b: &Stats) -> Stats {
    macro_rules! sum {
        ($($f:ident),*) => { Stats { $($f: a.$f + b.$f),* } };
    }
    sum!(
        packets_received,
        packets_dropped_unknown_link,
        packets_dropped_version,
        packets_dropped_malformed,
        packets_dropped_unauthenticated,
        packets_dropped_replay,
        frames_unknown,
        frames_dropped_invalid,
        frames_dropped_window,
        frames_dropped_backpressure,
        fragments_dropped_reassembly_full,
        records_malformed,
        messages_received,
        messages_duplicate,
        messages_delivered,
        packets_sent,
        bytes_sent,
        fragments_sent,
        retransmissions,
        probes_sent,
        acks_sent,
        frag_acks_sent,
        rtt_samples,
        storage_errors,
        fec_sources,
        fec_repairs_sent,
        fec_repairs_dropped,
        fec_repairs_received,
        fec_recovered,
        loss_reports_sent,
        syncs_sent,
        syncs_received,
        transmit_stalls,
        hellos_sent,
        hellos_received,
        hellos_duplicate,
        hellos_dropped_not_for_us,
        hellos_dropped_rate
    )
}

impl<'a> Sim<'a> {
    fn new(sc: &'a Scenario) -> Self {
        let mut secrets = [[0u8; 32]; 2];
        let mut key_rng = stream(sc.seed, 1);
        for k in &mut secrets {
            key_rng.fill_bytes(k);
        }
        let keys = secrets.map(|s| Identity::from_secret_bytes(&s).public_key());
        let nodes = (0..2)
            .map(|i| {
                let mut engine = Engine::new(
                    sc.config,
                    Identity::from_secret_bytes(&secrets[i]),
                    MemoryStorage::new(),
                    stream(sc.seed, 10 + i as u64),
                )
                .expect("valid scenario config");
                engine
                    .add_link(LINK, sc.link.engine_link())
                    .expect("valid profile link");
                let conv = avianlink_core::hashes::conversation_id(&keys[i], &keys[1 - i]);
                if !(i == 1 && sc.introduce) {
                    engine.add_contact(keys[1 - i]).expect("fresh contact");
                }
                Node {
                    secret: secrets[i],
                    engine: Some(engine),
                    wreck: None,
                    conv,
                    wake: None,
                    generation: 0,
                    crash_armed: false,
                    incarnation: 0,
                    retired: Stats::default(),
                    accept_requests: i == 1 && (sc.introduce || sc.wipe_at_ms.is_some()),
                }
            })
            .collect();

        let mut wl = stream(sc.seed, 2);
        let mut t = SIM_EPOCH_MS;
        let msgs: Vec<Msg> = (0..sc.messages)
            .map(|_| {
                t += exp_ms(&mut wl, sc.mean_interval_ms);
                let r = unit(&mut wl);
                let len = if r < sc.lengths.short {
                    5 + below(&mut wl, 76)
                } else if r < sc.lengths.short + sc.lengths.medium {
                    80 + below(&mut wl, 221)
                } else {
                    300 + below(&mut wl, 901)
                };
                let from = below(&mut wl, 2) as usize;
                Msg {
                    from: if sc.one_way { 0 } else { from },
                    text: random_text(&mut wl, len as usize),
                    scheduled_at: t,
                    sent_at: None,
                    id: None,
                    delivered_at: None,
                    acked_at: None,
                }
            })
            .collect();

        let mut sim = Self {
            sc,
            now: SIM_EPOCH_MS,
            order: 0,
            queue: BinaryHeap::new(),
            nodes,
            channels: [
                Channel::new(sc.link, stream(sc.seed, 3)),
                Channel::new(sc.link, stream(sc.seed, 4)),
            ],
            outages: Outages::new(sc.link.outage, stream(sc.seed, 5), SIM_EPOCH_MS),
            crash_rng: stream(sc.seed, 6),
            adv_rng: stream(sc.seed, 7),
            recorded: [Vec::new(), Vec::new()],
            injected: 0,
            msgs,
            by_id: BTreeMap::new(),
            delivered: 0,
            acked: 0,
            wire_bytes: 0,
            packets: 0,
            stalls: 0,
            outbox_full_retries: 0,
            duplicate_deliveries: 0,
            integrity_violations: 0,
            out_of_order: 0,
            crashes: 0,
            max_storage_bytes: 0,
            outage_wire_bytes: 0,
            outage_packets: 0,
            sync_anomalies: 0,
            wipes: 0,
            redelivered_after_wipe: 0,
            skipped_after_wipe: 0,
        };
        if let Some(at) = sc.wipe_at_ms {
            sim.schedule(SIM_EPOCH_MS + at, Ev::Wipe { node: 1 });
        }
        for &(start, len) in &sc.fixed_outages {
            let end = SIM_EPOCH_MS + start + len;
            sim.outages.add_fixed(SIM_EPOCH_MS + start, end);
            if sc.nudge_on_reconnect {
                for node in 0..2 {
                    sim.schedule(end, Ev::Nudge { node });
                }
            }
        }
        for i in 0..sim.msgs.len() {
            let at = sim.msgs[i].scheduled_at;
            sim.schedule(at, Ev::Send { msg: i });
        }
        for node in 0..2 {
            sim.schedule_crash(node);
        }
        sim
    }

    fn schedule(&mut self, at: u64, ev: Ev) {
        self.order += 1;
        self.queue.push(Reverse(Scheduled {
            at,
            order: self.order,
            ev,
        }));
    }

    fn schedule_crash(&mut self, node: usize) {
        if let Some(c) = self.sc.crashes {
            let at = self.now + exp_ms(&mut self.crash_rng, c.mean_interval_ms).max(1);
            self.schedule(at, Ev::Crash { node });
        }
    }

    fn done(&self) -> bool {
        self.delivered == self.msgs.len() && self.acked == self.msgs.len()
    }

    fn run(mut self) -> Report {
        let wall = Instant::now();
        let deadline = SIM_EPOCH_MS + self.sc.deadline_ms;
        while let Some(Reverse(s)) = self.queue.pop() {
            if s.at > deadline {
                self.now = deadline;
                break;
            }
            self.now = s.at;
            if let Some(node) = self.step(s.ev) {
                if self.nodes[node].crash_armed {
                    self.crash(node);
                } else {
                    self.pump(node);
                }
            }
            if self.done() {
                break;
            }
        }
        self.report(wall.elapsed().as_secs_f64() * 1000.0)
    }

    /// Applies one event; returns the node to pump afterwards, if any.
    fn step(&mut self, ev: Ev) -> Option<usize> {
        let now = Timestamp::from_millis(self.now);
        match ev {
            Ev::Send { msg } => {
                let from = self.msgs[msg].from;
                let n = &mut self.nodes[from];
                let Some(engine) = n.engine.as_mut() else {
                    // The app waits for its node to come back.
                    self.schedule(self.now + 1_000, Ev::Send { msg });
                    return None;
                };
                match engine.send_text(n.conv, &self.msgs[msg].text, now) {
                    Ok(q) => {
                        let m = &mut self.msgs[msg];
                        m.sent_at = Some(self.now);
                        m.id = Some(q.id);
                        self.by_id.insert(q.id, msg);
                    }
                    Err(Error::OutboxFull) => {
                        self.outbox_full_retries += 1;
                        self.schedule(self.now + 1_000, Ev::Send { msg });
                    }
                    // Not accepted the peer yet: the user waits.
                    Err(Error::UnknownConversation) => {
                        self.schedule(self.now + 1_000, Ev::Send { msg });
                    }
                    Err(e) => panic!("send_text failed: {e}"),
                }
                Some(from)
            }
            Ev::Arrive { node, bytes } => {
                let engine = self.nodes[node].engine.as_mut()?;
                engine.handle_packet(LINK, &bytes, now);
                Some(node)
            }
            Ev::Wake { node, generation } => {
                let n = &mut self.nodes[node];
                if generation != n.generation {
                    return None;
                }
                n.wake = None;
                n.engine.as_mut()?.handle_timeout(now);
                Some(node)
            }
            Ev::Crash { node } => {
                self.nodes[node].crash_armed = true;
                None
            }
            Ev::Restart { node } => {
                self.restart(node);
                Some(node)
            }
            Ev::Nudge { node } => {
                self.nodes[node].engine.as_mut()?.nudge(now);
                Some(node)
            }
            Ev::Wipe { node } => {
                self.wipe(node);
                Some(node)
            }
        }
    }

    /// Replaces the node with an empty engine: same identity, no contacts,
    /// nothing in storage.
    fn wipe(&mut self, node: usize) {
        let sc = self.sc;
        let n = &mut self.nodes[node];
        let Some(old) = n.engine.take() else {
            return;
        };
        self.wipes += 1;
        n.retired = add_stats(&n.retired, &old.stats());
        n.incarnation += 1;
        n.generation += 1;
        n.wake = None;
        let rng = stream(sc.seed, 100 + 2 * n.incarnation + node as u64);
        let identity = Identity::from_secret_bytes(&n.secret);
        let mut engine =
            Engine::new(sc.config, identity, MemoryStorage::new(), rng).expect("fresh engine");
        engine
            .add_link(LINK, sc.link.engine_link())
            .expect("valid profile link");
        n.engine = Some(engine);
    }

    /// Kills the node mid-call: queued events, timers and anything not
    /// committed are lost.
    fn crash(&mut self, node: usize) {
        let n = &mut self.nodes[node];
        n.crash_armed = false;
        let Some(engine) = n.engine.take() else {
            return;
        };
        self.crashes += 1;
        n.retired = add_stats(&n.retired, &engine.stats());
        n.wreck = Some(engine.storage().crash_snapshot());
        n.generation += 1;
        n.wake = None;
        let downtime = self.sc.crashes.map_or(0, |c| c.downtime_ms);
        self.schedule(self.now + downtime, Ev::Restart { node });
    }

    fn restart(&mut self, node: usize) {
        let sc = self.sc;
        let n = &mut self.nodes[node];
        let Some(storage) = n.wreck.take() else {
            return;
        };
        n.incarnation += 1;
        let rng = stream(sc.seed, 100 + 2 * n.incarnation + node as u64);
        let identity = Identity::from_secret_bytes(&n.secret);
        let mut engine = Engine::restore(sc.config, identity, storage, rng).expect("restore");
        engine
            .add_link(LINK, sc.link.engine_link())
            .expect("valid profile link");
        n.engine = Some(engine);
        self.schedule_crash(node);
    }

    fn pump(&mut self, node: usize) {
        let now = Timestamp::from_millis(self.now);
        let Some(engine) = self.nodes[node].engine.as_mut() else {
            return;
        };
        let mut sent = Vec::new();
        while let Some(tx) = engine.poll_transmit(now) {
            sent.push(tx.packet.into_vec());
        }
        let mut events = Vec::new();
        while let Some(ev) = engine.poll_event() {
            events.push(ev);
        }
        let next = engine.next_timeout().map(|t| t.as_millis());
        self.max_storage_bytes = self.max_storage_bytes.max(engine.storage().bytes());

        let in_outage = self.outages.in_fixed(self.now);
        for bytes in sent {
            self.packets += 1;
            self.wire_bytes += bytes.len() as u64;
            if in_outage {
                self.outage_packets += 1;
                self.outage_wire_bytes += bytes.len() as u64;
            }
            self.attack(node, &bytes);
            let copies = self.channels[node].send(self.now, bytes, &mut self.outages);
            for (at, mut bytes) in copies {
                if let Some(adv) = self.sc.adversary {
                    if unit(&mut self.adv_rng) < adv.tamper_prob && !bytes.is_empty() {
                        let bit = below(&mut self.adv_rng, bytes.len() as u64 * 8);
                        bytes[(bit / 8) as usize] ^= 1 << (bit % 8);
                        self.injected += 1;
                    }
                }
                self.schedule(
                    at,
                    Ev::Arrive {
                        node: 1 - node,
                        bytes,
                    },
                );
            }
        }
        let mut accepted = false;
        for ev in events {
            accepted |= self.on_event(node, ev);
        }
        if accepted {
            // The new contact has an answer to send at once.
            self.pump(node);
            return;
        }
        let next = next.map(|t| {
            if t <= self.now {
                // The engine claims work is due now but produced nothing.
                self.stalls += 1;
                self.now + 1
            } else {
                t
            }
        });
        let n = &mut self.nodes[node];
        if next != n.wake {
            n.generation += 1;
            n.wake = next;
            let generation = n.generation;
            if let Some(at) = next {
                self.schedule(at, Ev::Wake { node, generation });
            }
        }
    }

    /// Records `bytes` and maybe injects a replay or a forgery toward the
    /// other node. Injected packets bypass loss and outages.
    fn attack(&mut self, from: usize, bytes: &[u8]) {
        let Some(adv) = self.sc.adversary else {
            return;
        };
        let rec = &mut self.recorded[from];
        if rec.len() < 256 {
            rec.push(bytes.to_vec());
        } else {
            let i = below(&mut self.adv_rng, rec.len() as u64) as usize;
            rec[i] = bytes.to_vec();
        }
        let delay = 1 + below(&mut self.adv_rng, 600_000);
        if unit(&mut self.adv_rng) < adv.replay_prob {
            let i = below(&mut self.adv_rng, self.recorded[from].len() as u64) as usize;
            let old = self.recorded[from][i].clone();
            self.injected += 1;
            self.schedule(
                self.now + delay,
                Ev::Arrive {
                    node: 1 - from,
                    bytes: old,
                },
            );
        }
        if unit(&mut self.adv_rng) < adv.forge_prob {
            let mut forged = bytes.to_vec();
            for b in forged.iter_mut().skip(5) {
                *b = self.adv_rng.next_u32() as u8;
            }
            self.injected += 1;
            self.schedule(
                self.now + delay,
                Ev::Arrive {
                    node: 1 - from,
                    bytes: forged,
                },
            );
        }
    }

    /// Returns whether a contact request was accepted.
    fn on_event(&mut self, node: usize, ev: Event) -> bool {
        match ev {
            Event::MessageReceived(m) => {
                let Some(&i) = self.by_id.get(&m.id) else {
                    self.integrity_violations += 1;
                    return false;
                };
                let msg = &mut self.msgs[i];
                if msg.from == node || msg.text != m.text {
                    self.integrity_violations += 1;
                    return false;
                }
                if msg.delivered_at.is_some() {
                    // After a wipe the receiver has forgotten what it had.
                    if self.wipes > 0 {
                        self.redelivered_after_wipe += 1;
                    } else {
                        self.duplicate_deliveries += 1;
                    }
                    return false;
                }
                if m.missing_before > 0 {
                    self.out_of_order += 1;
                }
                msg.delivered_at = Some(self.now);
                self.delivered += 1;
            }
            Event::MessagesSkipped { count, .. } if self.wipes > 0 => {
                // Expected: the wiped node lost what it had received.
                self.skipped_after_wipe += count;
            }
            Event::MessagesSkipped { .. } | Event::SyncDiverged { .. } => {
                // Only state loss or rollback cause these; only `wipe` loses
                // state, so any other occurrence is a bug.
                self.sync_anomalies += 1;
            }
            Event::ContactRequest { public_key, .. } if self.nodes[node].accept_requests => {
                if let Some(e) = self.nodes[node].engine.as_mut() {
                    return e.add_contact(public_key).is_ok();
                }
            }
            Event::MessageDelivered { id, .. } => {
                let Some(&i) = self.by_id.get(&id) else {
                    self.integrity_violations += 1;
                    return false;
                };
                let msg = &mut self.msgs[i];
                if msg.from != node || msg.acked_at.is_some() {
                    self.integrity_violations += 1;
                    return false;
                }
                msg.acked_at = Some(self.now);
                self.acked += 1;
            }
            _ => {}
        }
        false
    }

    fn report(mut self, wall_ms: f64) -> Report {
        let mut latency: Vec<u64> = self
            .msgs
            .iter()
            .filter_map(|m| Some(m.delivered_at? - m.sent_at?))
            .collect();
        latency.sort_unstable();
        let mut ack_latency: Vec<u64> = self
            .msgs
            .iter()
            .filter_map(|m| Some(m.acked_at? - m.sent_at?))
            .collect();
        ack_latency.sort_unstable();
        let payload_bytes: u64 = self
            .msgs
            .iter()
            .filter(|m| m.delivered_at.is_some())
            .map(|m| m.text.len() as u64)
            .sum();
        let stats: Vec<Stats> = self
            .nodes
            .iter()
            .map(|n| {
                let live = n.engine.as_ref().map(|e| e.stats()).unwrap_or_default();
                add_stats(&n.retired, &live)
            })
            .collect();
        let duration = self.now - SIM_EPOCH_MS;
        // Convergence after the last scheduled outage: how long until every
        // message sent before it ended had been delivered.
        let converge_ms = self
            .sc
            .fixed_outages
            .iter()
            .map(|&(s, l)| SIM_EPOCH_MS + s + l)
            .max()
            .map(|end| {
                self.msgs
                    .iter()
                    .filter(|m| m.sent_at.is_some_and(|t| t < end))
                    .filter_map(|m| m.delivered_at)
                    .max()
                    .map_or(0, |d| d.saturating_sub(end))
            });
        let downtime = self.outages.downtime(SIM_EPOCH_MS, self.now);
        let n = self.msgs.len();
        Report {
            name: self.sc.name.clone(),
            seed: self.sc.seed,
            messages: n,
            delivered: self.delivered,
            acked: self.acked,
            latency_p50_ms: percentile(&latency, 50),
            latency_p95_ms: percentile(&latency, 95),
            latency_p99_ms: percentile(&latency, 99),
            latency_max_ms: latency.last().copied().unwrap_or(0),
            ack_p50_ms: percentile(&ack_latency, 50),
            ack_p95_ms: percentile(&ack_latency, 95),
            payload_bytes,
            wire_bytes: self.wire_bytes,
            packets: self.packets,
            sim_duration_ms: duration,
            downtime_ms: downtime,
            wall_ms,
            stalls: self.stalls,
            outbox_full_retries: self.outbox_full_retries,
            duplicate_deliveries: self.duplicate_deliveries,
            integrity_violations: self.integrity_violations,
            out_of_order: self.out_of_order,
            crashes: self.crashes,
            injected: self.injected,
            outage_wire_bytes: self.outage_wire_bytes,
            outage_packets: self.outage_packets,
            converge_ms,
            sync_anomalies: self.sync_anomalies,
            wipes: self.wipes,
            redelivered_after_wipe: self.redelivered_after_wipe,
            skipped_after_wipe: self.skipped_after_wipe,
            max_storage_bytes: self.max_storage_bytes,
            channels: [self.channels[0].stats, self.channels[1].stats],
            engines: [stats[0], stats[1]],
        }
    }
}

/// Sum of both directions' channel counters.
pub fn total_channel_stats(c: &[ChannelStats; 2]) -> ChannelStats {
    let [a, b] = c;
    ChannelStats {
        sent: a.sent + b.sent,
        sent_bytes: a.sent_bytes + b.sent_bytes,
        delivered: a.delivered + b.delivered,
        lost: a.lost + b.lost,
        lost_outage: a.lost_outage + b.lost_outage,
        lost_queue: a.lost_queue + b.lost_queue,
        corrupted: a.corrupted + b.corrupted,
        duplicated: a.duplicated + b.duplicated,
        oversize: a.oversize + b.oversize,
        duty_violations: a.duty_violations + b.duty_violations,
    }
}
