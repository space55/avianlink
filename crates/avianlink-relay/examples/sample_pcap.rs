//! Writes a sample capture of every avianlink packet kind, for the
//! Wireshark dissector (`tools/wireshark/`):
//!
//! ```text
//! cargo run -p avianlink-relay --example sample_pcap -- avianlink-sample.pcap
//! ```
//!
//! Part 1: A and B talk directly (10.0.0.1:7000 ↔ 10.0.0.2:7000). B doesn't
//! know A, so A's first round is a Hello. Part 2: the same two through a
//! relay (10.0.0.9:7400), never online together. Part 3: B registers for
//! push notifications, Hellos included; C (10.0.0.3), a stranger, writes to
//! B through the relay, which notifies the push service (10.0.0.10:41001).

use std::io::Write;

use avianlink_core::push::{encode_service, AckCode, ServiceMsg};
use avianlink_core::{
    Config, Engine, Event, Identity, LinkBudget, LinkConfig, LinkId, MemoryStorage, Timestamp,
};
use avianlink_relay::{Notifier, PushConfig, Relay, RelayClient, RelayConfig};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

type E = Engine<MemoryStorage, ChaCha20Rng>;
const T0: u64 = 1_793_000_000_000;
const A: ([u8; 4], u16) = ([10, 0, 0, 1], 7000);
const B: ([u8; 4], u16) = ([10, 0, 0, 2], 7000);
const C: ([u8; 4], u16) = ([10, 0, 0, 3], 7000);
const R: ([u8; 4], u16) = ([10, 0, 0, 9], 7400);
const S: ([u8; 4], u16) = ([10, 0, 0, 10], 41_001);

struct Pcap(Vec<u8>);

impl Pcap {
    fn new() -> Self {
        let mut v = Vec::new();
        // Global header: magic, v2.4, tz 0, sigfigs 0, snaplen, LINKTYPE_RAW (101).
        v.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&0i32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&65_535u32.to_le_bytes());
        v.extend_from_slice(&101u32.to_le_bytes());
        Self(v)
    }

    fn udp(&mut self, ms: u64, from: ([u8; 4], u16), to: ([u8; 4], u16), payload: &[u8]) {
        let udp_len = 8 + payload.len();
        let total = 20 + udp_len;
        let mut ip = vec![
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0x40,
            0,
            64,
            17,
            0,
            0,
        ];
        ip.extend_from_slice(&from.0);
        ip.extend_from_slice(&to.0);
        let mut sum: u32 = ip
            .chunks(2)
            .map(|c| u32::from(c[0]) << 8 | u32::from(c[1]))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let check = !(sum as u16);
        ip[10] = (check >> 8) as u8;
        ip[11] = check as u8;
        let mut pkt = ip;
        pkt.extend_from_slice(&from.1.to_be_bytes());
        pkt.extend_from_slice(&to.1.to_be_bytes());
        pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 0]); // checksum optional over IPv4
        pkt.extend_from_slice(payload);
        let (s, us) = ((ms / 1000) as u32, ((ms % 1000) * 1000) as u32);
        for x in [s, us, pkt.len() as u32, pkt.len() as u32] {
            self.0.extend_from_slice(&x.to_le_bytes());
        }
        self.0.extend_from_slice(&pkt);
    }
}

fn engine(seed: u8, relay: bool) -> E {
    let mut e = Engine::new(
        Config::default(),
        Identity::from_secret_bytes(&[seed; 32]),
        MemoryStorage::new(),
        ChaCha20Rng::seed_from_u64(seed.into()),
    )
    .unwrap();
    let link = LinkConfig {
        mtu: if relay { 48 } else { 200 },
        budget: LinkBudget::Unlimited,
        cost: 1,
    };
    if relay {
        e.add_relay_link(LinkId(0), link).unwrap();
    } else {
        e.add_link(LinkId(0), link).unwrap();
    }
    e
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or("avianlink-sample.pcap".into());
    let mut pcap = Pcap::new();
    let ms = |t: u64| Timestamp::from_millis(t);

    // Part 1: direct, with an introduction.
    let (mut a, mut b) = (engine(1, false), engine(2, false));
    let ab = a.add_contact(b.local_key()).unwrap();
    a.send_text(ab, "Hello B, this is A over a direct link.", ms(T0))
        .unwrap();
    let mut now = T0;
    for _ in 0..40 {
        while let Some(tx) = a.poll_transmit(ms(now)) {
            pcap.udp(now, A, B, tx.packet.as_bytes());
            b.handle_packet(LinkId(0), tx.packet.as_bytes(), ms(now));
        }
        while let Some(ev) = b.poll_event() {
            if let Event::ContactRequest { public_key, .. } = ev {
                let ba = b.add_contact(public_key).unwrap();
                b.send_text(ba, "Hi A, request accepted.", ms(now)).unwrap();
            }
        }
        while let Some(tx) = b.poll_transmit(ms(now)) {
            pcap.udp(now, B, A, tx.packet.as_bytes());
            a.handle_packet(LinkId(0), tx.packet.as_bytes(), ms(now));
        }
        now += 250;
    }

    // Part 2: through a relay, one at a time.
    let config = RelayConfig {
        push: true,
        ..RelayConfig::default()
    };
    let mut relay: Relay<MemoryStorage, u8> = Relay::open(config, MemoryStorage::new()).unwrap();
    let (mut a, mut b) = (engine(3, true), engine(4, true));
    let ab = a.add_contact(b.local_key()).unwrap();
    let ba = b.add_contact(a.local_key()).unwrap();
    let mut notifier = Notifier::new();
    let mut session = |e: &mut E,
                       addr: ([u8; 4], u16),
                       id: u8,
                       text: Option<(_, &str)>,
                       push: Option<PushConfig>,
                       now: &mut u64| {
        let mut c = RelayClient::new(LinkId(0));
        c.set_push(push);
        if let Some((conv, t)) = text {
            e.send_text(conv, t, ms(*now)).unwrap();
        }
        c.connect(e, ms(*now));
        for _ in 0..80 {
            e.handle_timeout(ms(*now));
            c.handle_timeout(e, ms(*now));
            while let Some(tx) = e.poll_transmit(ms(*now)) {
                c.upload(e, tx, ms(*now));
            }
            while let Some(bytes) = c.poll_transmit() {
                pcap.udp(*now, addr, R, &bytes);
                relay.handle(id, &bytes, ms(*now));
            }
            while let Some((_, bytes)) = relay.poll_transmit() {
                pcap.udp(*now + 20, R, addr, &bytes);
                c.handle(e, &bytes, ms(*now + 20));
            }
            while let Some(p) = relay.poll_push() {
                notifier.push(p, 0x5eed_0000 + u64::from(id), ms(*now));
                while let Some(n) = notifier.poll_transmit() {
                    pcap.udp(*now + 5, R, S, &n);
                    let ack = encode_service(&ServiceMsg::Ack {
                        id: 0x5eed_0000 + u64::from(id),
                        code: AckCode::Ok,
                    });
                    pcap.udp(*now + 60, S, R, &ack);
                    notifier.handle(&ack);
                }
            }
            while e.poll_event().is_some() {}
            *now += 250;
            if e.relay_settled() && c.caught_up() {
                break;
            }
        }
        // Going offline: the LEAVE that ends this address's leases.
        c.disconnect();
        while let Some(bytes) = c.poll_transmit() {
            pcap.udp(*now, addr, R, &bytes);
            relay.handle(id, &bytes, ms(*now));
        }
    };
    now += 60_000;
    session(
        &mut a,
        A,
        1,
        Some((ab, "Through the relay: A writes, then goes offline.")),
        None,
        &mut now,
    );
    now += 3_600_000;
    let push = PushConfig {
        secret: [0xb5; 16],
        blob: b"(sealed to the push service)".to_vec(),
        hellos: true,
    };
    session(
        &mut b,
        B,
        2,
        Some((ba, "B collects and replies.")),
        Some(push.clone()),
        &mut now,
    );
    now += 3_600_000;
    session(&mut a, A, 1, None, None, &mut now);

    // Part 3: a stranger's Hello wakes B through the push service.
    now += 3_600_000;
    let mut c = engine(5, true);
    let cb = c.add_contact(b.local_key()).unwrap();
    session(
        &mut c,
        C,
        3,
        Some((cb, "C here: we haven't met.")),
        None,
        &mut now,
    );

    std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(&pcap.0))
        .unwrap();
    eprintln!("wrote {path}");
}
