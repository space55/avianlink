use super::*;
use crate::crypto::PairKeys;
use crate::{AirtimeModel, LinkBudget, MemoryStorage};
use alloc::string::String;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

type E = Engine<MemoryStorage, ChaCha20Rng>;

/// Identity seeds of the two test peers.
const A: u8 = 0xaa;
const B: u8 = 0xbb;

fn id(who: u8) -> Identity {
    Identity::from_secret_bytes(&[who; 32])
}

fn pk(who: u8) -> PublicKey {
    id(who).public_key()
}

fn who(key: PublicKey) -> u8 {
    [A, B, 0xcc].into_iter().find(|&w| pk(w) == key).unwrap()
}
const L: LinkId = LinkId(0);

fn link(mtu: u16) -> LinkConfig {
    LinkConfig {
        mtu,
        budget: LinkBudget::Unlimited,
        cost: 1,
    }
}

fn rng(who: u8) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(u64::from(who))
}

fn engine_with(cfg: Config, key: u8, peer: u8, mtu: u16) -> (E, ConversationId) {
    let mut e = Engine::new(cfg, id(key), MemoryStorage::new(), rng(key)).unwrap();
    e.add_link(L, link(mtu)).unwrap();
    let conv = e.add_contact(pk(peer)).unwrap();
    (e, conv)
}

/// Tests of the core mechanics run without Hellos; `hello_*` tests cover
/// them (D-044).
fn base() -> Config {
    Config {
        hello: crate::HelloMode::Off,
        ..Config::default()
    }
}

fn engine(key: u8, peer: u8, mtu: u16) -> (E, ConversationId) {
    engine_with(base(), key, peer, mtu)
}

/// Simulates a crash: rebuild from what storage had committed.
fn crash_and_restore(e: &E, mtu: u16) -> E {
    let storage = e.storage().crash_snapshot();
    let w = who(e.local_key());
    let mut r = Engine::restore(*e.config(), id(w), storage, rng(w)).unwrap();
    r.add_link(L, link(mtu)).unwrap();
    r
}

fn t(ms: u64) -> Timestamp {
    Timestamp::from_millis(ms)
}

fn drain_tx(e: &mut E, now: Timestamp) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(tx) = e.poll_transmit(now) {
        out.push(tx.packet.into_vec());
    }
    out
}

/// Pending events, minus the best-effort `MessageTransmitted` notices
/// (tested separately).
fn drain_events(e: &mut E) -> Vec<Event> {
    core::iter::from_fn(|| e.poll_event())
        .filter(|e| !matches!(e, Event::MessageTransmitted { .. }))
        .collect()
}

fn deliver(to: &mut E, pkts: &[Vec<u8>], now: Timestamp) {
    for p in pkts {
        to.handle_packet(L, p, now);
    }
}

fn received(evs: &[Event]) -> Vec<(u64, String)> {
    evs.iter()
        .filter_map(|e| match e {
            Event::MessageReceived(m) => Some((m.seq, m.text.clone())),
            _ => None,
        })
        .collect()
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
    let q = a.send_text(conv, "hello", now).unwrap();
    assert_eq!((q.seq, q.lamport), (0, 1));
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
        (q.id, 0, 1, "hello")
    );
    assert_eq!((m.sender_time, m.missing_before), (Some(now), 0));
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
            id: q.id
        }]
    );
    assert_eq!(a.outbox_len(), 0);
    assert_eq!(a.next_timeout(), None);
    assert_eq!(a.stats().rtt_samples, 1);
}

#[test]
fn retransmits_until_acked_and_dedupes() {
    let (mut a, conv) = engine(A, B, 64);
    let (mut b, _) = engine(B, A, 64);
    a.send_text(conv, "lost once", t(0)).unwrap();
    let first = drain_tx(&mut a, t(0));
    assert_eq!(first.len(), 1); // dropped by the network
    let rto = a.next_timeout().unwrap();
    assert!(rto >= t(3000) && rto <= t(3375), "{rto:?}");
    assert!(drain_tx(&mut a, t(2999)).is_empty());
    let second = drain_tx(&mut a, rto);
    assert_eq!(second.len(), 1);
    b.handle_packet(L, &second[0], rto);
    b.handle_packet(L, &first[0], rto); // late duplicate
    assert_eq!(drain_events(&mut b).len(), 1);
    assert_eq!(b.stats().messages_duplicate, 1);
    assert_eq!(a.stats().retransmissions, 1);
}

#[test]
fn rto_adapts_to_measured_rtt() {
    let (mut a, conv) = engine(A, B, 64);
    let (mut b, _) = engine(B, A, 64);
    // Ten exchanges with a 20 ms network RTT (+100 ms ACK delay, which the
    // ACK reports and the sender subtracts).
    let mut now = 0;
    for i in 0..10 {
        a.send_text(conv, "x", t(now)).unwrap();
        deliver(&mut b, &drain_tx(&mut a, t(now)), t(now + 10));
        let at = b.next_timeout().unwrap().as_millis();
        deliver(&mut a, &drain_tx(&mut b, t(at)), t(at + 10));
        drain_events(&mut a);
        drain_events(&mut b);
        now = at + 1000 + i;
    }
    a.send_text(conv, "y", t(now)).unwrap();
    drain_tx(&mut a, t(now));
    // RTO is clamped to min_rto (1 s) rather than the 3 s initial value.
    let next = a.next_timeout().unwrap().as_millis() - now;
    assert!((1000..1200).contains(&next), "{next}");
}

#[test]
fn unreachable_peer_gets_doubling_probes_then_full_resend_on_contact() {
    let (mut a, conv) = engine(A, B, 64);
    let (mut b, cb) = engine(B, A, 64);
    for i in 0..8 {
        a.send_text(conv, &alloc::format!("m{i} {}", "z".repeat(20)), t(0))
            .unwrap();
    }
    let burst = drain_tx(&mut a, t(0));
    assert!(burst.len() >= 4);
    // Everything is lost. Record when packets go out over 20 minutes.
    let mut sends = Vec::new();
    let mut now = 0;
    while now < 20 * 60_000 {
        now = a.next_timeout().unwrap().as_millis();
        let n = drain_tx(&mut a, t(now)).len();
        assert!(n <= 1, "probe mode sends one packet per interval");
        sends.push(now);
    }
    let gaps: Vec<u64> = sends.windows(2).map(|w| w[1] - w[0]).collect();
    let cap = a.config().max_rto_ms;
    // Grace probes at the plain RTO, then doubling up to the cap.
    assert!(gaps.windows(2).all(|g| g[1] + 500 >= g[0]), "{gaps:?}");
    assert!(
        gaps.iter().any(|&g| g >= cap),
        "capped at max_rto: {gaps:?}"
    );
    // Within the first minutes the cap holds; after that the interval
    // follows 1/16 of the silence (it began when the first probe went out).
    let start = sends[0];
    for (w, &g) in sends.windows(2).zip(&gaps) {
        let silence = w[0] - start + 3_000;
        assert!(g <= (cap + cap / 8).max(silence / 64 + 1_000), "{gaps:?}");
    }
    assert!(a.stats().probes_sent as usize >= sends.len() - 1);

    // The peer speaks: A leaves backoff and resends everything at once.
    b.send_text(cb, "hello?", t(now)).unwrap();
    deliver(&mut a, &drain_tx(&mut b, t(now)), t(now + 5));
    let resend = drain_tx(&mut a, t(now + 5));
    deliver(&mut b, &resend, t(now + 10));
    let mut got = received(&drain_events(&mut b)).len();
    assert!(got >= 7, "{got}");
    // The last probe went out just before B spoke; it is resent at its
    // normal timer.
    while got < 8 {
        let at = a.next_timeout().unwrap();
        assert!(at.as_millis() - now < 5_000, "resend within one RTO");
        deliver(&mut b, &drain_tx(&mut a, at), at);
        got += received(&drain_events(&mut b)).len();
    }
}

#[test]
fn frag_ack_limits_retransmission_to_missing_fragments() {
    let (mut a, conv) = engine(A, B, 48);
    let (mut b, _) = engine(B, A, 48);
    let text: String = "fragment me ".repeat(30);
    a.send_text(conv, &text, t(0)).unwrap();
    let pkts = drain_tx(&mut a, t(0));
    let n = pkts.len();
    assert!(n > 8);
    // Deliver even-numbered packets only; B reports what it holds.
    for p in pkts.iter().step_by(2) {
        b.handle_packet(L, p, t(10));
    }
    let at = b.next_timeout().unwrap();
    deliver(&mut a, &drain_tx(&mut b, at), at);
    assert!(b.stats().frag_acks_sent >= 1);
    // Hearing from B also keeps A out of backoff; only the missing half
    // goes out again (each at its own jittered time at this MTU).
    let mut resent = 0;
    while received(&drain_events(&mut b)).is_empty() {
        let at = a.next_timeout().unwrap();
        let again = drain_tx(&mut a, at);
        resent += again.len();
        deliver(&mut b, &again, at);
        assert!(resent <= n / 2 + 1, "{resent} of {n}");
    }
    assert_eq!(a.stats().probes_sent, 0);
    let _ = text;
}

#[test]
fn reports_out_of_order_arrival() {
    let (mut a, conv) = engine(A, B, 128);
    let (mut b, _) = engine(B, A, 128);
    let mut pkts = Vec::new();
    for i in 0..3 {
        a.send_text(conv, &alloc::format!("{i}"), t(0)).unwrap();
        pkts.extend(drain_tx(&mut a, t(0)));
    }
    assert_eq!(pkts.len(), 3);
    b.handle_packet(L, &pkts[2], t(1));
    b.handle_packet(L, &pkts[0], t(2));
    let missing: Vec<(u64, u64)> = drain_events(&mut b)
        .into_iter()
        .filter_map(|e| match e {
            Event::MessageReceived(m) => Some((m.seq, m.missing_before)),
            _ => None,
        })
        .collect();
    assert_eq!(missing, [(2, 2), (0, 0)]);
}

#[test]
fn restore_resumes_outbox_without_loss_or_duplication() {
    let (mut a, conv) = engine(A, B, 64);
    let (mut b, _) = engine(B, A, 64);
    let ids: Vec<MessageId> = (0..3)
        .map(|i| {
            a.send_text(conv, &alloc::format!("msg {i}"), t(0))
                .unwrap()
                .id
        })
        .collect();
    let first = drain_tx(&mut a, t(0));
    let only_first = {
        // Rebuild a packet carrying just message 0 by sending it from a
        // twin engine with identical state.
        let (mut twin, c) = engine(A, B, 64);
        twin.send_text(c, "msg 0", t(0)).unwrap();
        drain_tx(&mut twin, t(0)).remove(0)
    };
    assert_eq!(first.len(), 1, "all three share a packet");
    // B gets message 0 only, queues its event, then crashes before the host
    // polls it.
    b.handle_packet(L, &only_first, t(5));
    let mut b = crash_and_restore(&b, 64);
    assert_eq!(
        received(&drain_events(&mut b)),
        [(0, String::from("msg 0"))]
    );

    // A crashes with all three undelivered; the restored A resends them
    // with fresh counters.
    let mut a = crash_and_restore(&a, 64);
    assert_eq!(a.outbox_len(), 3);
    assert_eq!(a.contacts().collect::<Vec<_>>(), [(conv, pk(B))]);
    let resent = drain_tx(&mut a, t(100));
    let counter = |p: &[u8]| wire::parse_header(p).unwrap().1;
    assert!(resent.iter().all(|p| counter(p) >= 1024));
    deliver(&mut b, &resent, t(105));
    // Message 0 is a duplicate; 1 and 2 are new.
    assert_eq!(
        received(&drain_events(&mut b)),
        [(1, String::from("msg 1")), (2, String::from("msg 2"))]
    );
    let at = b.next_timeout().unwrap();
    deliver(&mut a, &drain_tx(&mut b, at), at);
    let delivered: Vec<MessageId> = drain_events(&mut a)
        .into_iter()
        .filter_map(|e| match e {
            Event::MessageDelivered { id, .. } => Some(id),
            _ => None,
        })
        .collect();
    assert_eq!(delivered, ids);
    // Both sides drained: nothing left in storage but metadata.
    let a2 = crash_and_restore(&a, 64);
    assert_eq!(a2.outbox_len(), 0);
}

#[test]
fn storage_failure_changes_nothing() {
    let (mut a, conv) = engine(A, B, 64);
    let (mut b, _) = engine(B, A, 64);
    // Fail inside send_text's batch.
    a.storage.fail_after(Some(1));
    assert_eq!(a.send_text(conv, "x", t(0)), Err(Error::Storage));
    assert_eq!(a.outbox_len(), 0);
    let q = a.send_text(conv, "x", t(0)).unwrap();
    assert_eq!(q.seq, 0, "failed send consumed no seq");

    // Fail while B persists the received message: no event, no ACK. (The
    // first two writes record that A is confirmed.)
    let pkts = drain_tx(&mut a, t(0));
    b.storage.fail_after(Some(2));
    deliver(&mut b, &pkts, t(1));
    assert!(drain_events(&mut b).is_empty());
    assert_eq!(b.stats().storage_errors, 1);
    // Re-delivering the same packet is a replay now; A's retransmission
    // (fresh counter) gets through.
    deliver(&mut b, &pkts, t(2));
    assert!(drain_events(&mut b).is_empty());
    let rto = a.next_timeout().unwrap();
    deliver(&mut b, &drain_tx(&mut a, rto), rto);
    assert_eq!(received(&drain_events(&mut b)).len(), 1);
}

#[test]
fn new_and_restore_check_storage() {
    let (a, _) = engine(A, B, 64);
    let used = a.storage().crash_snapshot();
    assert_eq!(
        Engine::new(Config::default(), id(A), used.clone(), rng(A)).err(),
        Some(Error::StorageNotEmpty)
    );
    assert_eq!(
        Engine::restore(Config::default(), id(B), used, rng(B)).err(),
        Some(Error::IdentityMismatch)
    );
    assert_eq!(
        Engine::restore(Config::default(), id(A), MemoryStorage::new(), rng(A)).err(),
        Some(Error::StateMissing)
    );
}

#[test]
fn fragments_long_message_at_min_mtu() {
    let (mut a, conv) = engine(A, B, 48);
    let (mut b, _) = engine(B, A, 48);
    let text: String = "ünïcødé ".repeat(60);
    let q = a.send_text(conv, &text, t(0)).unwrap();
    let mut pkts = drain_tx(&mut a, t(0));
    assert!(pkts.len() > 10);
    assert!(pkts.iter().all(|p| p.len() <= 48));
    pkts.reverse();
    deliver(&mut b, &pkts, t(1));
    let ev = drain_events(&mut b);
    let Event::MessageReceived(m) = &ev[0] else {
        panic!("{ev:?}")
    };
    assert_eq!((m.id, &m.text), (q.id, &text));
}

#[test]
fn ack_piggybacks_on_data() {
    let (mut a, ca) = engine(A, B, 128);
    let (mut b, cb) = engine(B, A, 128);
    a.send_text(ca, "ping", t(0)).unwrap();
    deliver(&mut b, &drain_tx(&mut a, t(0)), t(0));
    b.send_text(cb, "pong", t(0)).unwrap();
    let pkts = drain_tx(&mut b, t(0));
    assert_eq!(pkts.len(), 1, "ack and data share one packet");
    a.handle_packet(L, &pkts[0], t(0));
    assert_eq!(drain_events(&mut a).len(), 2);
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
    v2[0] = 3; // 2 is a Hello
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
    let mut a = Engine::new(Config::default(), id(A), MemoryStorage::new(), rng(A)).unwrap();
    a.add_link(
        L,
        LinkConfig {
            mtu: 100,
            budget: LinkBudget::BytesPerSecond(100),
            cost: 1,
        },
    )
    .unwrap();
    let conv = a.add_contact(pk(B)).unwrap();
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
    let mut a = Engine::new(Config::default(), id(A), MemoryStorage::new(), rng(A)).unwrap();
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
    let mut a = Engine::new(cfg, id(A), MemoryStorage::new(), rng(A)).unwrap();
    assert_eq!(a.add_contact(pk(A)), Err(Error::InvalidContact));
    assert_eq!(a.add_contact(not_a_point()), Err(Error::InvalidContact));
    let conv = a.add_contact(pk(B)).unwrap();
    assert_eq!(a.add_contact(pk(B)), Err(Error::InvalidContact));
    assert_eq!(a.add_contact(pk(0xcc)), Err(Error::TooManyContacts));
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
    // B's FRAG_ACK reaches A over the small link, so A is not in backoff
    // and now routes over that link.
    let at = b.next_timeout().unwrap();
    for p in drain_tx(&mut b, at) {
        a.handle_packet(LinkId(1), &p, at);
    }
    let rto = a.next_timeout().unwrap();
    let small = drain_tx(&mut a, rto);
    assert!(small.iter().all(|p| p.len() <= 48));
    deliver(&mut b, &small, rto);
    let ev = drain_events(&mut b);
    assert!(matches!(&ev[..], [Event::MessageReceived(m)] if m.text == text));
}

#[test]
fn no_wall_clock_omits_timestamp() {
    let cfg = Config {
        wall_clock: false,
        ..Config::default()
    };
    let (mut a, conv) = engine_with(cfg, A, B, 64);
    let (mut b, _) = engine(B, A, 64);
    a.send_text(conv, "boot+5s", t(5000)).unwrap();
    deliver(&mut b, &drain_tx(&mut a, t(5000)), t(5000));
    let ev = drain_events(&mut b);
    assert!(matches!(&ev[..], [Event::MessageReceived(m)] if m.sender_time.is_none()));
}

/// Regression (found by fuzzing): a FRAG_ACK too large to fit beside the
/// ACK kept the ACK timer re-armed at "now", so `poll_transmit` produced
/// ACK-only packets forever.
#[test]
fn oversized_frag_ack_does_not_livelock() {
    let (mut b, _) = engine(B, A, 48);
    // One byte of a long message, then its last byte at 4000: the FRAG_ACK
    // bitmap (1-byte blocks) is far larger than a 48-byte packet.
    let keys = PairKeys::derive(&id(A), &pk(B)).unwrap();
    let mut pkt = Vec::new();
    begin_packet(&mut pkt, keys.tx_tag, 0);
    put_msg_frame(
        &mut pkt,
        0,
        Some(wire::Part {
            offset: 0,
            last: false,
        }),
        b"x",
    );
    put_msg_frame(
        &mut pkt,
        0,
        Some(wire::Part {
            offset: 3999,
            last: true,
        }),
        b"y",
    );
    keys.seal(&mut pkt, header_len(0), 0).unwrap();
    b.handle_packet(L, &pkt, t(1));
    let at = b.next_timeout().unwrap();
    let mut n = 0;
    while let Some(tx) = b.poll_transmit(at) {
        assert!(tx.packet.len() <= 48);
        n += 1;
        assert!(n < 10, "poll_transmit never ran dry");
    }
    assert!(b.next_timeout().is_none_or(|t| t > at));
}

/// Sends one message A→B and returns the packet.
fn one_packet() -> (E, E, Vec<u8>) {
    let (mut a, conv) = engine(A, B, 128);
    let (b, _) = engine(B, A, 128);
    a.send_text(conv, "secret text", t(0)).unwrap();
    let pkt = drain_tx(&mut a, t(0)).remove(0);
    (a, b, pkt)
}

#[test]
fn packets_are_encrypted() {
    let (_, _, pkt) = one_packet();
    assert!(!pkt.windows(6).any(|w| w == b"secret"));
}

#[test]
fn every_tampered_byte_is_rejected() {
    let (_, mut b, pkt) = one_packet();
    for i in 0..pkt.len() {
        for bit in [0x01, 0x80] {
            let mut bad = pkt.clone();
            bad[i] ^= bit;
            b.handle_packet(L, &bad, t(1));
        }
    }
    assert!(drain_events(&mut b).is_empty());
    let s = b.stats();
    assert_eq!(s.messages_received, 0);
    assert_eq!(
        s.packets_dropped_unauthenticated + s.packets_dropped_version + s.packets_dropped_malformed,
        2 * pkt.len() as u64
    );
    // The genuine packet still gets through afterwards.
    b.handle_packet(L, &pkt, t(2));
    assert_eq!(received(&drain_events(&mut b)).len(), 1);
}

#[test]
fn every_truncation_is_rejected() {
    let (_, mut b, pkt) = one_packet();
    for n in 0..pkt.len() {
        b.handle_packet(L, &pkt[..n], t(1));
    }
    let mut long = pkt.clone();
    long.push(0);
    b.handle_packet(L, &long, t(1));
    assert!(drain_events(&mut b).is_empty());
    assert_eq!(b.stats().messages_received, 0);
}

#[test]
fn replays_are_rejected_even_after_restore() {
    let (_, mut b, pkt) = one_packet();
    b.handle_packet(L, &pkt, t(1));
    b.handle_packet(L, &pkt, t(2));
    assert_eq!(received(&drain_events(&mut b)).len(), 1);
    assert_eq!(b.stats().packets_dropped_replay, 1);
    let mut b = crash_and_restore(&b, 128);
    b.handle_packet(L, &pkt, t(3));
    assert!(drain_events(&mut b).is_empty());
    assert_eq!(b.stats().packets_dropped_replay, 1);
}

#[test]
fn misrouted_and_forged_packets_are_rejected() {
    let (_, _, pkt) = one_packet();
    // C knows A but the packet was for B.
    let (mut c, _) = engine(0xcc, A, 128);
    c.handle_packet(L, &pkt, t(1));
    // A B that knows only C: A's packet matches no tag.
    let (mut b_other, _) = engine(B, 0xcc, 128);
    b_other.handle_packet(L, &pkt, t(1));
    for e in [&mut c, &mut b_other] {
        assert!(drain_events(e).is_empty());
        assert_eq!(e.stats().packets_dropped_unauthenticated, 1);
    }
    // A forger who copies a real header but knows no secret.
    let (mut b, _) = engine(B, A, 128);
    let mut forged = pkt.clone();
    for x in forged[5..].iter_mut() {
        *x = 0x5a;
    }
    b.handle_packet(L, &forged, t(1));
    assert_eq!(b.stats().packets_dropped_unauthenticated, 1);
}

#[test]
fn transmitted_event_fires_once_per_message() {
    let (mut a, conv) = engine(A, B, 64);
    let q = a.send_text(conv, "hi", t(0)).unwrap();
    assert_eq!(a.poll_event(), None);
    drain_tx(&mut a, t(0));
    assert_eq!(
        a.poll_event(),
        Some(Event::MessageTransmitted {
            conversation: conv,
            id: q.id
        })
    );
    let rto = a.next_timeout().unwrap();
    drain_tx(&mut a, rto);
    assert_eq!(a.poll_event(), None, "retransmission is not re-announced");
    let st = a.outgoing(conv).unwrap();
    assert_eq!(
        (st[0].id, st[0].transmissions, st[0].fragments),
        (q.id, 2, 1)
    );
    // Transient events are never persisted; a restored engine announces
    // its first transmission again.
    let mut r = crash_and_restore(&a, 64);
    assert_eq!(r.poll_event(), None);
    drain_tx(&mut r, t(rto.as_millis() + 1));
    assert!(matches!(
        r.poll_event(),
        Some(Event::MessageTransmitted { .. })
    ));
}

#[test]
fn remove_contact_abandons_outbox_and_persists() {
    let (mut a, conv) = engine(A, B, 64);
    let ids: Vec<MessageId> = (0..3)
        .map(|i| a.send_text(conv, &alloc::format!("{i}"), t(0)).unwrap().id)
        .collect();
    assert_eq!(a.contact_key(conv), Some(pk(B)));
    assert_eq!(a.remove_contact(conv), Ok(ids));
    assert_eq!(a.outbox_len(), 0);
    assert_eq!(a.contact_key(conv), None);
    assert_eq!(a.remove_contact(conv), Err(Error::UnknownConversation));
    assert_eq!(a.poll_transmit(t(0)), None);
    let r = crash_and_restore(&a, 64);
    assert_eq!(r.contacts().count(), 0);
    assert_eq!(r.outbox_len(), 0);
    // B's packets are now unauthenticated for A.
    let (mut b, cb) = engine(B, A, 64);
    b.send_text(cb, "anyone?", t(0)).unwrap();
    deliver(&mut a, &drain_tx(&mut b, t(0)), t(1));
    assert_eq!(a.stats().packets_dropped_unauthenticated, 1);
    // And A can add B again.
    assert_eq!(a.add_contact(pk(B)), Ok(conv));
}

#[test]
fn link_and_contact_status_queries() {
    let mut a = Engine::new(Config::default(), id(A), MemoryStorage::new(), rng(A)).unwrap();
    let rate = LinkConfig {
        mtu: 100,
        budget: LinkBudget::BytesPerSecond(100),
        cost: 1,
    };
    a.add_link(L, rate).unwrap();
    let conv = a.add_contact(pk(B)).unwrap();
    let (mut b, cb) = engine(B, A, 100);
    assert_eq!(a.link_stats(LinkId(7)), None);
    let st = a.contact_status(conv).unwrap();
    assert_eq!(
        (st.last_heard, st.srtt_ms, st.unreachable),
        (None, None, false)
    );
    assert_eq!(st.rto_ms, 3000);

    a.send_text(conv, &"z".repeat(70), t(0)).unwrap();
    let sent = drain_tx(&mut a, t(0));
    let ls = a.link_stats(L).unwrap();
    assert_eq!(ls.packets_sent, 1);
    assert_eq!(ls.bytes_sent, sent[0].len() as u64);
    assert!(ls.budget_blocked_until.is_some_and(|t0| t0 > t(0)));

    b.send_text(cb, "hello", t(0)).unwrap();
    let from_b = drain_tx(&mut b, t(0));
    a.handle_packet(L, &from_b[0], t(50));
    a.handle_packet(L, &from_b[0], t(51)); // a duplicate
    let ls = a.link_stats(L).unwrap();
    assert_eq!((ls.packets_received, ls.packets_dropped), (2, 1));
    let st = a.contact_status(conv).unwrap();
    assert_eq!((st.last_heard, st.outbox_len), (Some(t(50)), 1));
}

/// A 32-byte string that is not a valid Ed25519 point encoding.
fn not_a_point() -> PublicKey {
    (0u8..=255)
        .map(|b| {
            let mut k = [0u8; 32];
            k[0] = b;
            PublicKey(k)
        })
        .find(|k| ed25519_dalek::VerifyingKey::from_bytes(&k.0).is_err())
        .unwrap()
}

/// Delivers every packet from `from` to `to` except those `drop` selects
/// (by position), and returns how many were sent.
fn deliver_except(from: &mut E, to: &mut E, now: Timestamp, drop: impl Fn(usize) -> bool) -> usize {
    let pkts = drain_tx(from, now);
    for (i, p) in pkts.iter().enumerate() {
        if !drop(i) {
            to.handle_packet(L, p, now);
        }
    }
    pkts.len()
}

/// Runs A→B traffic with every third A packet lost until B has reported
/// loss and A has turned FEC on. Returns the engines and A's conversation.
fn lossy_until_fec() -> (E, E, ConversationId) {
    let (mut a, ca) = engine(A, B, 128);
    let (mut b, cb) = engine(B, A, 128);
    let mut n = 0usize;
    let mut now = 0;
    while a
        .contact_status(ca)
        .unwrap()
        .loss_out_permille
        .is_none_or(|p| p < 20)
    {
        a.send_text(ca, "tick", t(now)).unwrap();
        let sent = drain_tx(&mut a, t(now));
        for p in &sent {
            n += 1;
            if !n.is_multiple_of(3) {
                b.handle_packet(L, p, t(now));
            }
        }
        let at = b.next_timeout().unwrap_or(t(now)).max(t(now));
        deliver(&mut a, &drain_tx(&mut b, at), at);
        drain_events(&mut a);
        drain_events(&mut b);
        now = at.as_millis() + 1000;
        assert!(now < 3_600_000, "FEC never activated");
    }
    let _ = cb;
    (a, b, ca)
}

#[test]
fn loss_reports_turn_fec_on_and_repairs_recover_without_retransmission() {
    let (mut a, mut b, ca) = lossy_until_fec();
    let st = b.contact_status(b.contacts().next().unwrap().0).unwrap();
    assert!(st.loss_in_permille.is_some_and(|p| p > 200), "{st:?}");
    // Two packet-sized messages share a window (k = 2 earns 1.5 repairs of
    // credit at ~33% loss). The first source is lost; the XOR repair and the
    // second source recover it.
    let before = b.stats().fec_recovered;
    let now = 10_000_000;
    let q = a.send_text(ca, &"saved by FEC ".repeat(6), t(now)).unwrap();
    a.send_text(ca, &"second source ".repeat(6), t(now))
        .unwrap();
    let sent = deliver_except(&mut a, &mut b, t(now), |i| i == 0);
    assert_eq!(sent, 2, "one packet per message");
    let flush = a.next_timeout().unwrap();
    assert!(
        flush <= t(now + a.config().fec_flush_ms),
        "window flush timer"
    );
    let sent = deliver_except(&mut a, &mut b, flush, |_| false);
    assert!(sent >= 1, "repair sent at window close");
    let got = drain_events(&mut b);
    assert!(
        got.iter()
            .any(|e| matches!(e, Event::MessageReceived(m) if m.id == q.id)),
        "{got:?}"
    );
    assert_eq!(b.stats().fec_recovered, before + 1);
    assert!(a.stats().fec_repairs_sent > 0);
}

#[test]
fn fec_stays_off_on_budget_poor_links_and_in_backoff() {
    // A 1%-duty LoRa-like link: one MTU packet costs ~37 s of budget.
    let lora = LinkConfig {
        mtu: 51,
        budget: LinkBudget::DutyCycle {
            permille: 10,
            window_ms: 3_600_000,
            airtime: AirtimeModel {
                per_packet_us: 160_000,
                per_byte_us: 4_100,
            },
        },
        cost: 1,
    };
    let mut a = Engine::new(Config::default(), id(A), MemoryStorage::new(), rng(A)).unwrap();
    a.add_link(L, lora).unwrap();
    let ca = a.add_contact(pk(B)).unwrap();
    let (mut b, _) = engine(B, A, 51);
    // B claims 50% loss.
    let keys = PairKeys::derive(&id(B), &pk(A)).unwrap();
    let mut pkt = Vec::new();
    begin_packet(&mut pkt, keys.tx_tag, 0);
    wire::put_loss_frame(&mut pkt, 500);
    keys.seal(&mut pkt, header_len(0), 0).unwrap();
    a.handle_packet(L, &pkt, t(0));
    assert_eq!(a.contact_status(ca).unwrap().loss_out_permille, Some(500));
    for i in 0..5 {
        a.send_text(ca, "x", t(i)).unwrap();
        drain_tx(&mut a, t(i));
    }
    drain_tx(&mut a, t(10_000));
    assert_eq!(a.stats().fec_sources, 0);
    assert_eq!(a.stats().fec_repairs_sent, 0);
    let _ = &mut b;

    // On a rich link, backoff suspends FEC too.
    let (mut a, _b, ca) = lossy_until_fec();
    let now = 20_000_000;
    a.send_text(ca, "into the void", t(now)).unwrap();
    drain_tx(&mut a, t(now));
    // Nothing comes back: retransmission timers fire into silence.
    let mut at = a.next_timeout().unwrap();
    for _ in 0..3 {
        drain_tx(&mut a, at);
        at = a.next_timeout().unwrap();
    }
    assert!(a.contact_status(ca).unwrap().unreachable);
    let repairs = a.stats().fec_repairs_sent;
    for _ in 0..5 {
        drain_tx(&mut a, at);
        at = a.next_timeout().unwrap();
    }
    assert_eq!(
        a.stats().fec_repairs_sent,
        repairs,
        "no repairs into an outage"
    );
}

/// Exchanges packets between `a` and `b` (losslessly) until both are quiet
/// or `until` is reached; returns the time reached.
fn converse(a: &mut E, b: &mut E, mut now: u64, until: u64) -> u64 {
    while now < until {
        let pa = drain_tx(a, t(now));
        deliver(b, &pa, t(now));
        let pb = drain_tx(b, t(now));
        deliver(a, &pb, t(now));
        let next = [a.next_timeout(), b.next_timeout()]
            .into_iter()
            .flatten()
            .min();
        match next {
            Some(n) if n.as_millis() < until => now = n.as_millis().max(now + 1),
            _ if pa.is_empty() && pb.is_empty() => break,
            _ => now += 1,
        }
    }
    now
}

#[test]
fn wiped_receiver_skips_unrecoverable_gap_instead_of_stalling() {
    let cfg = Config {
        max_reorder_window: 64,
        ..Config::default()
    };
    let (mut a, ca) = engine_with(cfg, A, B, 256);
    let (mut b, _) = engine_with(cfg, B, A, 256);
    for i in 0..100 {
        a.send_text(ca, &alloc::format!("old {i}"), t(i)).unwrap();
    }
    let now = converse(&mut a, &mut b, 0, 600_000);
    assert_eq!(a.outbox_len(), 0, "all 100 delivered to the old install");
    // B reinstalls: same identity, empty storage.
    let (mut b, _) = engine_with(cfg, B, A, 256);
    let q = a.send_text(ca, "after reinstall", t(now)).unwrap();
    assert_eq!(q.seq, 100);
    converse(&mut a, &mut b, now, now + 3_600_000);
    let ev = drain_events(&mut b);
    assert!(
        ev.iter().any(|e| matches!(
            e,
            Event::MessagesSkipped {
                first_seq: 0,
                count: 100,
                ..
            }
        )),
        "{ev:?}"
    );
    assert!(ev
        .iter()
        .any(|e| matches!(e, Event::MessageReceived(m) if m.id == q.id)));
    assert_eq!(a.outbox_len(), 0);
}

#[test]
fn storage_rollback_is_detected_as_divergence() {
    let (mut a, ca) = engine(A, B, 256);
    let (mut b, _) = engine(B, A, 256);
    a.send_text(ca, "original 0", t(0)).unwrap();
    let now = converse(&mut a, &mut b, 0, 600_000);
    // The backup postdates a counter reservation, so the restored engine's
    // packets get past B's replay window (an earlier backup would reuse
    // counters and be rejected outright, security.md §4).
    let backup = a.storage().crash_snapshot();
    for i in 1..64 {
        a.send_text(ca, &alloc::format!("original {i}"), t(now + i))
            .unwrap();
    }
    let now = converse(&mut a, &mut b, now, now + 600_000);
    assert_eq!(received(&drain_events(&mut b)).len(), 64);
    // A restores the old backup and writes different messages under the
    // same seqs; B dedupes them by seq, and only the digest can tell.
    let mut a = Engine::restore(*a.config(), id(A), backup, rng(A)).unwrap();
    a.add_link(L, link(256)).unwrap();
    for i in 1..64 {
        a.send_text(ca, &alloc::format!("rewritten {i}"), t(now + i))
            .unwrap();
    }
    converse(&mut a, &mut b, now, now + 600_000);
    let ev = drain_events(&mut b);
    assert!(received(&ev).is_empty(), "duplicates by seq, as feared");
    assert!(
        ev.iter().any(|e| matches!(
            e,
            Event::SyncDiverged {
                first_seq: 0,
                last_seq: 63,
                ..
            }
        )),
        "{ev:?}"
    );
}

#[test]
fn a_week_of_silence_costs_little_and_nudge_wakes_probing() {
    let (mut a, ca) = engine(A, B, 256);
    a.send_text(ca, &"into the void ".repeat(10), t(0)).unwrap();
    let week = 7 * 24 * 3_600_000u64;
    let (mut packets, mut bytes, mut late_max) = (0u64, 0u64, 0usize);
    let mut now = 0;
    while now < week {
        for p in drain_tx(&mut a, t(now)) {
            packets += 1;
            bytes += p.len() as u64;
            if now > 2 * 3_600_000 {
                late_max = late_max.max(p.len());
            }
        }
        now = a.next_timeout().unwrap().as_millis().max(now + 1);
    }
    // Phase 4 behaviour: ~20,000 MTU-sized probes (3.4 MB). Now an hour of
    // data probes, then bare SYNCs at 1/64 of the silence.
    assert!(packets < 700, "{packets} packets");
    assert!(bytes < 64 * 1024, "{bytes} bytes");
    assert!(
        late_max < 40,
        "deep probes are SYNC-only, got {late_max} bytes"
    );
    let st = a.contact_status(ca).unwrap();
    assert!(st.unreachable);
    drain_tx(&mut a, t(now)); // the probe due at the end of the week
    let next = a.next_timeout().unwrap();
    assert!(
        next.as_millis() > now + 60_000,
        "deep backoff: next probe far away"
    );
    a.nudge(t(now));
    assert_eq!(a.next_timeout(), Some(t(now)), "nudge probes now");
    assert_eq!(drain_tx(&mut a, t(now)).len(), 1);
}

#[test]
fn sync_reveals_tail_loss() {
    let (mut a, ca) = engine(A, B, 256);
    let (mut b, _) = engine(B, A, 256);
    for i in 0..3 {
        a.send_text(ca, &alloc::format!("m{i} {}", "x".repeat(180)), t(0))
            .unwrap();
    }
    assert_eq!(drain_tx(&mut a, t(0)).len(), 3); // all lost
                                                 // A's probe carries the oldest message plus a SYNC; B learns from it
                                                 // that two newer messages exist and ACKs at once, so A resends them.
    let mut now = a.next_timeout().unwrap().as_millis();
    let probe = drain_tx(&mut a, t(now));
    deliver(&mut b, &probe, t(now));
    assert_eq!(b.next_timeout(), Some(t(now)), "reply is immediate");
    now = converse(&mut a, &mut b, now, now + 60_000);
    assert_eq!(received(&drain_events(&mut b)).len(), 3);
    assert!(b.stats().syncs_received >= 1);
    let _ = now;
}

#[test]
fn handle_packet_reports_the_authenticated_sender() {
    let (_, mut b, pkt) = one_packet();
    let conv_b = b.contacts().next().unwrap().0;
    assert_eq!(b.handle_packet(L, &pkt, t(1)), Received::Contact(conv_b));
    assert_eq!(b.handle_packet(L, &pkt, t(2)), Received::Ignored, "replay");
    assert_eq!(
        b.handle_packet(L, &[0u8; 40], t(3)),
        Received::Ignored,
        "garbage"
    );
    let mut bad = pkt.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(b.handle_packet(L, &bad, t(4)), Received::Ignored, "forged");
}

// ---------------------------------------------------------------------
// Hello (D-044)

/// An engine with Hellos on (the default) and no contacts.
fn bare(key: u8) -> E {
    let mut e = Engine::new(Config::default(), id(key), MemoryStorage::new(), rng(key)).unwrap();
    e.add_link(L, link(64)).unwrap();
    e
}

fn is_hello(p: &[u8]) -> bool {
    p.first() == Some(&wire::HELLO_KIND)
}

fn requests(evs: &[Event]) -> Vec<PublicKey> {
    evs.iter()
        .filter_map(|e| match e {
            Event::ContactRequest { public_key, .. } => Some(*public_key),
            _ => None,
        })
        .collect()
}

#[test]
fn hello_introduces_an_unknown_sender() {
    let mut a = bare(A);
    let ab = a.add_contact(pk(B)).unwrap();
    let mut b = bare(B);
    assert!(!a.contact_status(ab).unwrap().confirmed);
    a.send_text(ab, "hi, you don't know me yet", t(0)).unwrap();

    // One probe round: the Hello first, then one data packet.
    let round = drain_tx(&mut a, t(0));
    assert_eq!(round.len(), 2, "Hello plus one probe");
    assert!(is_hello(&round[0]) && round[0].len() == wire::HELLO_LEN);
    assert!(!is_hello(&round[1]));
    assert_eq!(a.stats().hellos_sent, 1);

    assert_eq!(
        b.handle_packet(L, &round[0], t(10)),
        Received::ContactRequest(pk(A))
    );
    assert_eq!(b.handle_packet(L, &round[1], t(10)), Received::Ignored);
    assert_eq!(
        b.stats().packets_dropped_unauthenticated,
        1,
        "data before acceptance"
    );
    let evs = drain_events(&mut b);
    assert_eq!(requests(&evs), [pk(A)]);
    assert!(matches!(
        evs[0],
        Event::ContactRequest { link: L, received_at, .. } if received_at == t(10)
    ));

    // Acceptance: the contact starts confirmed and answers at once.
    let ba = b.add_contact(pk(A)).unwrap();
    assert!(b.contact_status(ba).unwrap().confirmed);
    let answer = drain_tx(&mut b, t(20));
    assert_eq!(answer.len(), 1);
    assert!(!is_hello(&answer[0]), "no Hello back: A knows B");
    assert_eq!(a.handle_packet(L, &answer[0], t(30)), Received::Contact(ab));
    let st = a.contact_status(ab).unwrap();
    assert!(st.confirmed && !st.unreachable);

    // A's message now flows; no more Hellos.
    let mut now = 30;
    for _ in 0..20 {
        deliver(&mut b, &drain_tx(&mut a, t(now)), t(now));
        deliver(&mut a, &drain_tx(&mut b, t(now)), t(now));
        now += 500;
    }
    assert_eq!(
        received(&drain_events(&mut b)),
        [(0, String::from("hi, you don't know me yet"))]
    );
    assert_eq!(a.outbox_len(), 0);
    assert_eq!(a.stats().hellos_sent, 1);
}

#[test]
fn introduction_with_nothing_queued_confirms_and_goes_quiet() {
    // Both added each other out of band; neither has anything to say.
    let mut a = bare(A);
    let ab = a.add_contact(pk(B)).unwrap();
    let mut b = bare(B);
    let ba = b.add_contact(pk(A)).unwrap();
    let from_a = drain_tx(&mut a, t(0));
    assert_eq!(from_a.len(), 2);
    assert!(is_hello(&from_a[0]));
    deliver(&mut b, &from_a, t(5));
    assert!(
        drain_events(&mut b).is_empty(),
        "a known key raises no request"
    );
    assert!(b.contact_status(ba).unwrap().confirmed);
    for now in [5, 10, 15] {
        deliver(&mut a, &drain_tx(&mut b, t(now)), t(now));
        deliver(&mut b, &drain_tx(&mut a, t(now)), t(now));
    }
    assert!(a.contact_status(ab).unwrap().confirmed);
    assert!(b.contact_status(ba).unwrap().confirmed);
    // Quiet afterwards.
    let later = t(1_000_000);
    assert!(drain_tx(&mut a, later).is_empty() && drain_tx(&mut b, later).is_empty());
    assert_eq!(a.next_timeout(), None);
    assert_eq!(b.next_timeout(), None);
}

#[test]
fn hello_from_a_known_contact_draws_one_sync_per_rto() {
    let mut a = bare(A);
    a.add_contact(pk(B)).unwrap();
    let hello = drain_tx(&mut a, t(0)).remove(0);
    let (mut b, _) = engine_with(Config::default(), B, A, 64);
    drain_tx(&mut b, t(0)); // b's own introduction round
    assert_eq!(b.handle_packet(L, &hello, t(100)), Received::Ignored);
    assert_eq!(b.stats().hellos_received, 1);
    assert_eq!(b.link_stats(L).unwrap().packets_dropped, 0);
    let reply = drain_tx(&mut b, t(100));
    assert_eq!(reply.len(), 1, "an ACK + SYNC asking for a reply");
    // A replay within the RTO is verified but not answered again.
    b.handle_packet(L, &hello, t(200));
    assert!(drain_tx(&mut b, t(200)).is_empty());
    assert_eq!(b.stats().hellos_received, 2);
    // A Hello never confirms (it can be replayed).
    assert!(
        !b.contact_status(hash::conversation_id(&pk(A), &pk(B)))
            .unwrap()
            .confirmed
    );
}

#[test]
fn replayed_hellos_raise_one_request() {
    let mut a = bare(A);
    a.add_contact(pk(B)).unwrap();
    let hello = drain_tx(&mut a, t(0)).remove(0);
    let mut b = bare(B);
    assert_eq!(
        b.handle_packet(L, &hello, t(1)),
        Received::ContactRequest(pk(A))
    );
    for i in 2..10 {
        assert_eq!(b.handle_packet(L, &hello, t(i)), Received::Ignored);
    }
    assert_eq!(requests(&drain_events(&mut b)), [pk(A)]);
    assert_eq!(b.stats().hellos_duplicate, 8);
}

#[test]
fn hello_verification_is_rate_limited() {
    let cfg = Config {
        hello_verify_burst: 2,
        hello_verify_per_minute: 60,
        ..Config::default()
    };
    let mut b = Engine::new(cfg, id(B), MemoryStorage::new(), rng(B)).unwrap();
    b.add_link(L, link(64)).unwrap();
    let hellos: Vec<Vec<u8>> = (1..=5u8)
        .map(|s| {
            let mut x = bare(s);
            x.add_contact(pk(B)).unwrap();
            drain_tx(&mut x, t(0)).remove(0)
        })
        .collect();
    let got: Vec<Received> = hellos.iter().map(|h| b.handle_packet(L, h, t(0))).collect();
    assert_eq!(
        got.iter()
            .filter(|r| matches!(r, Received::ContactRequest(_)))
            .count(),
        2
    );
    assert_eq!(b.stats().hellos_dropped_rate, 3);
    // One token per second refills.
    assert!(matches!(
        b.handle_packet(L, &hellos[2], t(1_000)),
        Received::ContactRequest(_)
    ));
    assert_eq!(b.handle_packet(L, &hellos[3], t(1_000)), Received::Ignored);
    // A rate of 0 ignores unknown keys entirely.
    let off = Config {
        hello_verify_per_minute: 0,
        ..Config::default()
    };
    let mut c = Engine::new(off, id(B), MemoryStorage::new(), rng(B)).unwrap();
    c.add_link(L, link(64)).unwrap();
    assert_eq!(c.handle_packet(L, &hellos[0], t(0)), Received::Ignored);
    assert_eq!(c.stats().hellos_dropped_rate, 1);
}

#[test]
fn bad_hellos_are_dropped_and_counted() {
    let mut a = bare(A);
    a.add_contact(pk(B)).unwrap();
    let hello = drain_tx(&mut a, t(0)).remove(0);
    let mut b = bare(B);
    let mut c = bare(0xcc);
    // Meant for B, not C.
    assert_eq!(c.handle_packet(L, &hello, t(0)), Received::Ignored);
    assert_eq!(c.stats().hellos_dropped_not_for_us, 1);
    // Wrong lengths.
    b.handle_packet(L, &hello[..46], t(0));
    let mut long = hello.clone();
    long.push(0);
    b.handle_packet(L, &long, t(0));
    assert_eq!(b.stats().packets_dropped_malformed, 2);
    // A forged MAC, and a key swapped in (MAC no longer matches).
    let mut forged = hello.clone();
    forged[46] ^= 1;
    assert_eq!(b.handle_packet(L, &forged, t(0)), Received::Ignored);
    let mut swapped = hello.clone();
    swapped[3..35].copy_from_slice(&pk(0xcc).0);
    assert_eq!(b.handle_packet(L, &swapped, t(0)), Received::Ignored);
    // B's own key.
    let mut own = hello.clone();
    own[3..35].copy_from_slice(&pk(B).0);
    b.handle_packet(L, &own, t(0));
    assert_eq!(b.stats().packets_dropped_unauthenticated, 3);
    assert!(drain_events(&mut b).is_empty() && drain_events(&mut c).is_empty());
    // The genuine one still works afterwards.
    assert_eq!(
        b.handle_packet(L, &hello, t(0)),
        Received::ContactRequest(pk(A))
    );
}

#[test]
fn contact_requests_survive_restore() {
    let mut a = bare(A);
    a.add_contact(pk(B)).unwrap();
    let hello = drain_tx(&mut a, t(0)).remove(0);
    let mut b = bare(B);
    b.handle_packet(L, &hello, t(7));
    let mut r = crash_and_restore(&b, 64);
    assert_eq!(requests(&drain_events(&mut r)), [pk(A)]);
    // The recent-requests set is not persisted: accepting after a restart
    // starts unconfirmed and introduces itself instead.
    let ra = r.add_contact(pk(A)).unwrap();
    assert!(!r.contact_status(ra).unwrap().confirmed);
    assert!(is_hello(&drain_tx(&mut r, t(8))[0]));
}

#[test]
fn unconfirmed_contacts_stay_unconfirmed_across_restore() {
    let mut a = bare(A);
    let ab = a.add_contact(pk(B)).unwrap();
    drain_tx(&mut a, t(0));
    let mut r = crash_and_restore(&a, 64);
    assert!(!r.contact_status(ab).unwrap().confirmed);
    let round = drain_tx(&mut r, t(1));
    assert!(is_hello(&round[0]), "introduction resumes");
}

#[test]
fn schema_3_storage_migrates_as_confirmed() {
    let (a, ab) = engine(A, B, 64);
    let mut storage = a.storage().crash_snapshot();
    // Rewrite as schema 3: version byte 3, contact record without the flag.
    let mut contact = storage.load(&contact_key(&ab)).unwrap().unwrap();
    contact.pop();
    let mut version = version_record(&pk(A));
    version[0] = 3;
    storage.begin().unwrap();
    storage.store(KEY_VERSION, &version).unwrap();
    storage.store(&contact_key(&ab), &contact).unwrap();
    storage.commit().unwrap();
    let mut r = Engine::restore(Config::default(), id(A), storage, rng(A)).unwrap();
    r.add_link(L, link(64)).unwrap();
    assert!(r.contact_status(ab).unwrap().confirmed);
    assert!(drain_tx(&mut r, t(0)).iter().all(|p| !is_hello(p)));
    let v = r
        .storage()
        .crash_snapshot()
        .load(KEY_VERSION)
        .unwrap()
        .unwrap();
    assert_eq!(v[0], SCHEMA, "rewritten as the current schema");
}

#[test]
fn hello_mode_off_sends_none() {
    let (mut a, ab) = engine(A, B, 64);
    a.send_text(ab, "x", t(0)).unwrap();
    let mut now = 0;
    for _ in 0..50 {
        drain_tx(&mut a, t(now));
        now += 30_000;
    }
    assert_eq!(a.stats().hellos_sent, 0);
    assert!(a.stats().probes_sent > 0);
}

#[test]
fn silent_confirmed_contact_gets_hellos_after_the_grace_probes() {
    let (mut a, ab) = engine_with(Config::default(), A, B, 64);
    let (mut b, _) = engine_with(Config::default(), B, A, 64);
    // Introduce both ways, then B goes silent with a message outstanding.
    for now in [0, 5, 10] {
        deliver(&mut b, &drain_tx(&mut a, t(now)), t(now));
        deliver(&mut a, &drain_tx(&mut b, t(now)), t(now));
    }
    assert!(a.contact_status(ab).unwrap().confirmed);
    let before = a.stats().hellos_sent;
    a.send_text(ab, "into the void", t(20)).unwrap();
    let mut now = 20;
    let mut probes_without_hello = 0;
    while a.stats().hellos_sent == before {
        let pkts = drain_tx(&mut a, t(now));
        if !pkts.is_empty() && a.contact_status(ab).unwrap().unreachable {
            probes_without_hello += 1;
        }
        now = a.next_timeout().unwrap().as_millis().max(now + 1);
        assert!(now < 3_600_000, "no Hello within an hour");
    }
    assert_eq!(
        probes_without_hello,
        usize::from(Config::default().backoff_grace),
        "the grace probes go without Hellos"
    );
}

// ---------------------------------------------------------------------
// Tombstones (D-046)

/// Runs both engines against each other until quiet.
fn settle(a: &mut E, b: &mut E, now: &mut u64) {
    for _ in 0..40 {
        deliver(b, &drain_tx(a, t(*now)), t(*now));
        deliver(a, &drain_tx(b, t(*now)), t(*now));
        *now += 500;
    }
}

#[test]
fn readded_contact_resumes_instead_of_restarting() {
    let (mut a, ab) = engine(A, B, 128);
    let (mut b, _) = engine(B, A, 128);
    let mut now = 0;
    for i in 0..3 {
        a.send_text(ab, &alloc::format!("before {i}"), t(now))
            .unwrap();
    }
    settle(&mut a, &mut b, &mut now);
    assert_eq!(received(&drain_events(&mut b)).len(), 3);
    drain_events(&mut a);
    let old_counter = a.contacts[&ab].tx_counter;

    a.remove_contact(ab).unwrap();
    assert_eq!(a.add_contact(pk(B)).unwrap(), ab);
    assert!(
        a.contacts[&ab].tx_counter > old_counter,
        "no counter restart"
    );
    let q = a.send_text(ab, "after re-add", t(now)).unwrap();
    assert_eq!(q.seq, 3, "seqs continue");
    settle(&mut a, &mut b, &mut now);
    // Delivered for real, not "acknowledged" by a stale ACK.
    assert_eq!(
        received(&drain_events(&mut b)),
        [(3, String::from("after re-add"))]
    );
    assert!(drain_events(&mut a)
        .iter()
        .any(|e| matches!(e, Event::MessageDelivered { id, .. } if *id == q.id)));
    assert_eq!(b.stats().packets_dropped_replay, 0);
    // B's messages still flow to the re-added A, and old ones aren't
    // redelivered.
    b.send_text(ab, "hello again", t(now)).unwrap();
    settle(&mut a, &mut b, &mut now);
    assert_eq!(
        received(&drain_events(&mut a)),
        [(0, String::from("hello again"))]
    );
}

#[test]
fn abandoned_messages_are_skipped_not_waited_for() {
    let (mut a, ab) = engine(A, B, 128);
    let (mut b, _) = engine(B, A, 128);
    let mut now = 0;
    a.send_text(ab, "delivered", t(now)).unwrap();
    settle(&mut a, &mut b, &mut now);
    // Queued but never sent, then abandoned by the removal.
    a.send_text(ab, "abandoned", t(now)).unwrap();
    assert_eq!(a.remove_contact(ab).unwrap().len(), 1);
    a.add_contact(pk(B)).unwrap();
    a.send_text(ab, "fresh", t(now)).unwrap();
    settle(&mut a, &mut b, &mut now);
    let evs = drain_events(&mut b);
    assert_eq!(
        received(&evs),
        [(0, String::from("delivered")), (2, String::from("fresh"))]
    );
    assert!(evs.iter().any(|e| matches!(
        e,
        Event::MessagesSkipped {
            first_seq: 1,
            count: 1,
            ..
        }
    )));
}

#[test]
fn tombstones_survive_restore() {
    let (mut a, ab) = engine(A, B, 128);
    let (mut b, _) = engine(B, A, 128);
    let mut now = 0;
    a.send_text(ab, "one", t(now)).unwrap();
    settle(&mut a, &mut b, &mut now);
    a.remove_contact(ab).unwrap();
    let mut r = crash_and_restore(&a, 128);
    assert_eq!(r.contacts().count(), 0);
    r.add_contact(pk(B)).unwrap();
    let q = r.send_text(ab, "two", t(now)).unwrap();
    assert_eq!(q.seq, 1);
    settle(&mut r, &mut b, &mut now);
    assert_eq!(
        received(&drain_events(&mut b)),
        [(0, String::from("one")), (1, String::from("two"))]
    );
}
