//! Discrete-event simulation of two peers over one impaired link.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::time::Instant;

use avianlink_core::{
    Config, ConversationId, Engine, Error, Event, LinkBudget, LinkConfig, LinkId, MemoryStorage,
    MessageId, PublicKey, Stats, Timestamp,
};
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;

use crate::impair::{below, unit, Channel, ChannelStats, LinkProfile, Outages};
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

impl Default for LengthMix {
    fn default() -> Self {
        Self {
            short: 0.80,
            medium: 0.15,
        }
    }
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
}

impl Scenario {
    /// Defaults for a named profile: 1000 messages, one every 30 s on
    /// average (every 10 min on `lora_like`, whose 1% duty cycle carries only
    /// ~3 KB/hour), 30-day deadline.
    pub fn new(profile: Profile, seed: u64) -> Self {
        let mean_interval_ms = match profile {
            Profile::LoraLike => 600_000,
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
        }
    }

    /// Runs the scenario to completion or deadline.
    pub fn run(&self) -> Report {
        Sim::new(self).run()
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Ev {
    Send { msg: usize },
    Arrive { node: usize, bytes: Vec<u8> },
    Wake { node: usize, generation: u64 },
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Scheduled {
    at: u64,
    order: u64,
    ev: Ev,
}

struct Node {
    engine: Engine<MemoryStorage, ChaCha20Rng>,
    conv: ConversationId,
    wake: Option<u64>,
    generation: u64,
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
    msgs: Vec<Msg>,
    by_id: BTreeMap<MessageId, usize>,
    delivered: usize,
    acked: usize,
    stalls: u64,
    outbox_full_retries: u64,
    duplicate_deliveries: u64,
    integrity_violations: u64,
}

fn stream(seed: u64, n: u64) -> ChaCha20Rng {
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

fn random_text(rng: &mut ChaCha20Rng, target: usize) -> String {
    let mut s = String::new();
    while s.len() < target {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(WORDS[below(rng, WORDS.len() as u64) as usize]);
    }
    s
}

impl<'a> Sim<'a> {
    fn new(sc: &'a Scenario) -> Self {
        let mut keys = [PublicKey([0; 32]); 2];
        let mut key_rng = stream(sc.seed, 1);
        for k in &mut keys {
            key_rng.fill_bytes(&mut k.0);
        }
        let nodes = (0..2)
            .map(|i| {
                let mut engine = Engine::new(
                    sc.config,
                    keys[i],
                    MemoryStorage::new(),
                    stream(sc.seed, 10 + i as u64),
                )
                .expect("valid scenario config");
                engine
                    .add_link(LINK, sc.link.engine_link())
                    .expect("valid profile link");
                let conv = engine.add_contact(keys[1 - i]).expect("fresh contact");
                Node {
                    engine,
                    conv,
                    wake: None,
                    generation: 0,
                }
            })
            .collect();

        let mut wl = stream(sc.seed, 2);
        let mut t = SIM_EPOCH_MS;
        let msgs: Vec<Msg> = (0..sc.messages)
            .map(|_| {
                t += (-(unit(&mut wl).max(f64::MIN_POSITIVE)).ln() * sc.mean_interval_ms as f64)
                    as u64;
                let r = unit(&mut wl);
                let len = if r < sc.lengths.short {
                    5 + below(&mut wl, 76)
                } else if r < sc.lengths.short + sc.lengths.medium {
                    80 + below(&mut wl, 221)
                } else {
                    300 + below(&mut wl, 901)
                };
                Msg {
                    from: below(&mut wl, 2) as usize,
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
            msgs,
            by_id: BTreeMap::new(),
            delivered: 0,
            acked: 0,
            stalls: 0,
            outbox_full_retries: 0,
            duplicate_deliveries: 0,
            integrity_violations: 0,
        };
        for i in 0..sim.msgs.len() {
            let at = sim.msgs[i].scheduled_at;
            sim.schedule(at, Ev::Send { msg: i });
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
            let now = Timestamp::from_millis(self.now);
            let node = match s.ev {
                Ev::Send { msg } => {
                    let m = &self.msgs[msg];
                    let n = &mut self.nodes[m.from];
                    match n.engine.send_text(n.conv, &m.text, now) {
                        Ok(id) => {
                            let m = &mut self.msgs[msg];
                            m.sent_at = Some(self.now);
                            m.id = Some(id);
                            self.by_id.insert(id, msg);
                        }
                        Err(Error::OutboxFull) => {
                            self.outbox_full_retries += 1;
                            self.schedule(self.now + 1_000, Ev::Send { msg });
                        }
                        Err(e) => panic!("send_text failed: {e}"),
                    }
                    self.msgs[msg].from
                }
                Ev::Arrive { node, bytes } => {
                    self.nodes[node].engine.handle_packet(LINK, &bytes, now);
                    node
                }
                Ev::Wake { node, generation } => {
                    if generation != self.nodes[node].generation {
                        continue;
                    }
                    self.nodes[node].wake = None;
                    self.nodes[node].engine.handle_timeout(now);
                    node
                }
            };
            self.pump(node);
            if self.done() {
                break;
            }
        }
        self.report(wall.elapsed().as_secs_f64() * 1000.0)
    }

    fn pump(&mut self, node: usize) {
        let now = Timestamp::from_millis(self.now);
        while let Some(tx) = self.nodes[node].engine.poll_transmit(now) {
            let copies =
                self.channels[node].send(self.now, tx.packet.into_vec(), &mut self.outages);
            for (at, bytes) in copies {
                self.schedule(
                    at,
                    Ev::Arrive {
                        node: 1 - node,
                        bytes,
                    },
                );
            }
        }
        while let Some(ev) = self.nodes[node].engine.poll_event() {
            self.on_event(node, ev);
        }
        let next = self.nodes[node].engine.next_timeout().map(|t| {
            let t = t.as_millis();
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

    fn on_event(&mut self, node: usize, ev: Event) {
        match ev {
            Event::MessageReceived(m) => {
                let Some(&i) = self.by_id.get(&m.id) else {
                    self.integrity_violations += 1;
                    return;
                };
                let msg = &mut self.msgs[i];
                if msg.from == node || msg.text != m.text {
                    self.integrity_violations += 1;
                    return;
                }
                if msg.delivered_at.is_some() {
                    self.duplicate_deliveries += 1;
                    return;
                }
                msg.delivered_at = Some(self.now);
                self.delivered += 1;
            }
            Event::MessageDelivered { id, .. } => {
                let Some(&i) = self.by_id.get(&id) else {
                    self.integrity_violations += 1;
                    return;
                };
                let msg = &mut self.msgs[i];
                if msg.from != node || msg.acked_at.is_some() {
                    self.integrity_violations += 1;
                    return;
                }
                msg.acked_at = Some(self.now);
                self.acked += 1;
            }
            _ => {}
        }
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
        let stats: Vec<Stats> = self.nodes.iter().map(|n| n.engine.stats()).collect();
        let wire_bytes: u64 = stats.iter().map(|s| s.bytes_sent).sum();
        let packets: u64 = stats.iter().map(|s| s.packets_sent).sum();
        let duration = self.now - SIM_EPOCH_MS;
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
            wire_bytes,
            packets,
            sim_duration_ms: duration,
            downtime_ms: downtime,
            wall_ms,
            stalls: self.stalls,
            outbox_full_retries: self.outbox_full_retries,
            duplicate_deliveries: self.duplicate_deliveries,
            integrity_violations: self.integrity_violations,
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
