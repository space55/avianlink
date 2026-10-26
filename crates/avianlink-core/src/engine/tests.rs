use super::*;
use crate::{AirtimeModel, LinkBudget, MemoryStorage};
use alloc::string::String;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

type E = Engine<MemoryStorage, ChaCha20Rng>;

const A: PublicKey = PublicKey([0xaa; 32]);
const B: PublicKey = PublicKey([0xbb; 32]);
const L: LinkId = LinkId(0);

fn link(mtu: u16) -> LinkConfig {
    LinkConfig {
        mtu,
        budget: LinkBudget::Unlimited,
        cost: 1,
    }
}

fn engine(key: PublicKey, peer: PublicKey, mtu: u16) -> (E, ConversationId) {
    let mut e = Engine::new(
        Config::default(),
        key,
        MemoryStorage::new(),
        ChaCha20Rng::seed_from_u64(u64::from(key.0[0])),
    )
    .unwrap();
    e.add_link(L, link(mtu)).unwrap();
    let conv = e.add_contact(peer).unwrap();
    (e, conv)
}

fn t(ms: u64) -> Timestamp {
    Timestamp::from_millis(ms)
}

fn drain_tx(e: &mut E, now: Timestamp) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(tx) = e.poll_transmit(now) {
        assert!(tx.packet.len() <= 64 * 1024);
        out.push(tx.packet.into_vec());
    }
    out
}

fn drain_events(e: &mut E) -> Vec<Event> {
    core::iter::from_fn(|| e.poll_event()).collect()
}

#[test]
fn conversation_ids_agree() {
    let (_, ca) = engine(A, B, 64);
    let (_, cb) = engine(B, A, 64);
    assert_eq!(ca, cb);
}

#[test]
fn idle_engine_is_quiet() {
    let (mut e, _) = engine(A, B, 64);
    e.handle_timeout(t(0));
    assert_eq!(e.poll_transmit(t(0)), None);
    assert_eq!(e.poll_event(), None);
    assert_eq!(e.next_timeout(), None);
}

#[test]
fn single_message_round_trip_with_delivery() {
    let (mut a, conv) = engine(A, B, 64);
    let (mut b, _) = engine(B, A, 64);
    let now = t(1_767_225_600_000);
    let id = a.send_text(conv, "hello", now).unwrap();
    assert_eq!(a.next_timeout(), Some(now));
    let pkts = drain_tx(&mut a, now);
    assert_eq!(pkts.len(), 1);
    assert!(pkts[0].len() <= 64);
    b.handle_packet(L, &pkts[0], now);
    let ev = drain_events(&mut b);
    let Event::MessageReceived(m) = &ev[0] else {
        panic!("{ev:?}")
    };
    assert_eq!(
        (m.id, m.seq, m.lamport, m.text.as_str()),
        (id, 0, 1, "hello")
    );
    assert_eq!(m.sender_time, Some(now));
    // ACK waits for ack_delay, then goes out alone.
    assert_eq!(b.poll_transmit(now), None);
    let ack_at = b.next_timeout().unwrap();
    assert_eq!(ack_at, t(now.as_millis() + 100));
    let acks = drain_tx(&mut b, ack_at);
    assert_eq!(acks.len(), 1);
    a.handle_packet(L, &acks[0], ack_at);
    assert_eq!(
        drain_events(&mut a),
        [Event::MessageDelivered {
            conversation: conv,
            id
        }]
    );
    assert_eq!(a.outbox_len(), 0);
    assert_eq!(a.next_timeout(), None);
}

#[test]
fn retransmits_until_acked_and_dedupes() {
    let (mut a, conv) = engine(A, B, 64);
    let (mut b, _) = engine(B, A, 64);
    a.send_text(conv, "lost once", t(0)).unwrap();
    let first = drain_tx(&mut a, t(0));
    assert_eq!(first.len(), 1); // dropped by the network
    let rto = a.next_timeout().unwrap();
    assert!(rto >= t(4000) && rto <= t(5000), "{rto:?}");
    assert!(drain_tx(&mut a, t(3999)).is_empty());
    let second = drain_tx(&mut a, rto);
    assert_eq!(second.len(), 1);
    b.handle_packet(L, &second[0], rto);
    b.handle_packet(L, &first[0], rto); // late duplicate
    assert_eq!(drain_events(&mut b).len(), 1);
    assert_eq!(b.stats().messages_duplicate, 1);
    assert_eq!(a.stats().retransmissions, 1);
}

#[test]
fn fragments_long_message_at_min_mtu() {
    let (mut a, conv) = engine(A, B, 48);
    let (mut b, _) = engine(B, A, 48);
    let text: String = "ünïcødé ".repeat(60);
    let id = a.send_text(conv, &text, t(0)).unwrap();
    let mut pkts = drain_tx(&mut a, t(0));
    assert!(pkts.len() > 10);
    assert!(pkts.iter().all(|p| p.len() <= 48));
    pkts.reverse();
    for p in &pkts {
        b.handle_packet(L, p, t(1));
    }
    let ev = drain_events(&mut b);
    let Event::MessageReceived(m) = &ev[0] else {
        panic!("{ev:?}")
    };
    assert_eq!((m.id, &m.text), (id, &text));
}

#[test]
fn ack_piggybacks_on_data() {
    let (mut a, ca) = engine(A, B, 128);
    let (mut b, cb) = engine(B, A, 128);
    a.send_text(ca, "ping", t(0)).unwrap();
    for p in drain_tx(&mut a, t(0)) {
        b.handle_packet(L, &p, t(0));
    }
    b.send_text(cb, "pong", t(0)).unwrap();
    let pkts = drain_tx(&mut b, t(0));
    assert_eq!(pkts.len(), 1, "ack and data share one packet");
    a.handle_packet(L, &pkts[0], t(0));
    let ev = drain_events(&mut a);
    assert_eq!(ev.len(), 2);
    assert_eq!(b.stats().acks_sent, 1);
}

#[test]
fn garbage_and_tampering_are_counted_not_fatal() {
    let (mut a, conv) = engine(A, B, 64);
    let (mut b, _) = engine(B, A, 64);
    a.send_text(conv, "x", t(0)).unwrap();
    let pkt = drain_tx(&mut a, t(0)).remove(0);
    let mut flipped = pkt.clone();
    flipped[6] ^= 0x10;
    b.handle_packet(L, &flipped, t(0));
    b.handle_packet(L, &pkt[..pkt.len() - 1], t(0));
    b.handle_packet(L, &[0xff; 300], t(0));
    b.handle_packet(L, &[], t(0));
    let mut v2 = pkt.clone();
    v2[0] = 2;
    b.handle_packet(L, &v2, t(0));
    b.handle_packet(LinkId(9), &pkt, t(0));
    let s = b.stats();
    assert_eq!(s.packets_received, 6);
    assert_eq!(s.packets_dropped_unauthenticated, 2);
    assert_eq!(s.packets_dropped_malformed, 1);
    assert_eq!(s.packets_dropped_version, 2);
    assert_eq!(s.packets_dropped_unknown_link, 1);
    assert!(drain_events(&mut b).is_empty());
}

#[test]
fn rate_budget_paces_and_reports_timeout() {
    let mut a = Engine::new(
        Config::default(),
        A,
        MemoryStorage::new(),
        ChaCha20Rng::seed_from_u64(1),
    )
    .unwrap();
    a.add_link(
        L,
        LinkConfig {
            mtu: 100,
            budget: LinkBudget::BytesPerSecond(100),
            cost: 1,
        },
    )
    .unwrap();
    let conv = a.add_contact(B).unwrap();
    for _ in 0..5 {
        a.send_text(conv, &"z".repeat(80), t(0)).unwrap();
    }
    // Capacity = 1 s of rate = 100 bytes = one MTU-sized admission.
    assert_eq!(drain_tx(&mut a, t(0)).len(), 1);
    let next = a.next_timeout().unwrap();
    assert!(next > t(0) && next <= t(1000), "{next:?}");
    assert_eq!(drain_tx(&mut a, next).len(), 1);
}

#[test]
fn duty_cycle_link_must_fit_one_packet() {
    let mut a = Engine::new(
        Config::default(),
        A,
        MemoryStorage::new(),
        ChaCha20Rng::seed_from_u64(1),
    )
    .unwrap();
    let cfg = LinkConfig {
        mtu: 255,
        budget: LinkBudget::DutyCycle {
            permille: 1,
            window_ms: 1000,
            airtime: AirtimeModel {
                per_packet_us: 10_000,
                per_byte_us: 1000,
            },
        },
        cost: 1,
    };
    assert_eq!(a.add_link(L, cfg), Err(Error::InvalidLinkConfig));
}

#[test]
fn limits_are_enforced() {
    let cfg = Config {
        max_outbox_messages: 2,
        max_contacts: 1,
        ..Config::default()
    };
    let mut a = Engine::new(cfg, A, MemoryStorage::new(), ChaCha20Rng::seed_from_u64(1)).unwrap();
    assert_eq!(a.add_contact(A), Err(Error::InvalidContact));
    let conv = a.add_contact(B).unwrap();
    assert_eq!(a.add_contact(B), Err(Error::InvalidContact));
    assert_eq!(
        a.add_contact(PublicKey([1; 32])),
        Err(Error::TooManyContacts)
    );
    assert_eq!(
        a.send_text(conv, &"x".repeat(5000), t(0)),
        Err(Error::TextTooLong)
    );
    a.send_text(conv, "1", t(0)).unwrap();
    a.send_text(conv, "2", t(0)).unwrap();
    assert_eq!(a.send_text(conv, "3", t(0)), Err(Error::OutboxFull));
    assert_eq!(
        a.send_text(ConversationId([0; 16]), "x", t(0)),
        Err(Error::UnknownConversation)
    );
}

#[test]
fn new_smaller_link_triggers_refragmentation() {
    let (mut a, conv) = engine(A, B, 200);
    let (mut b, _) = engine(B, A, 200);
    let cheap_small = LinkConfig {
        cost: 0,
        ..link(48)
    };
    b.add_link(LinkId(1), cheap_small).unwrap();
    let text = "r".repeat(300);
    a.send_text(conv, &text, t(0)).unwrap();
    let big = drain_tx(&mut a, t(0));
    b.handle_packet(L, &big[0], t(0)); // partial at the old plan
    a.add_link(LinkId(1), cheap_small).unwrap();
    let rto = a.next_timeout().unwrap();
    let small = drain_tx(&mut a, rto);
    assert!(small.iter().all(|p| p.len() <= 48));
    for p in &small {
        b.handle_packet(L, p, rto);
    }
    let ev = drain_events(&mut b);
    assert!(matches!(&ev[..], [Event::MessageReceived(m)] if m.text == text));
}

#[test]
fn no_wall_clock_omits_timestamp() {
    let cfg = Config {
        wall_clock: false,
        ..Config::default()
    };
    let mut a = Engine::new(cfg, A, MemoryStorage::new(), ChaCha20Rng::seed_from_u64(1)).unwrap();
    a.add_link(L, link(64)).unwrap();
    let conv = a.add_contact(B).unwrap();
    let (mut b, _) = engine(B, A, 64);
    a.send_text(conv, "boot+5s", t(5000)).unwrap();
    for p in drain_tx(&mut a, t(5000)) {
        b.handle_packet(L, &p, t(5000));
    }
    let ev = drain_events(&mut b);
    assert!(matches!(&ev[..], [Event::MessageReceived(m)] if m.sender_time.is_none()));
}
