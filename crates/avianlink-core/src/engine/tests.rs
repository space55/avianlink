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

fn rng(key: PublicKey) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(u64::from(key.0[0]))
}

fn engine_with(cfg: Config, key: PublicKey, peer: PublicKey, mtu: u16) -> (E, ConversationId) {
    let mut e = Engine::new(cfg, key, MemoryStorage::new(), rng(key)).unwrap();
    e.add_link(L, link(mtu)).unwrap();
    let conv = e.add_contact(peer).unwrap();
    (e, conv)
}

fn engine(key: PublicKey, peer: PublicKey, mtu: u16) -> (E, ConversationId) {
    engine_with(Config::default(), key, peer, mtu)
}

/// Simulates a crash: rebuild from what storage had committed.
fn crash_and_restore(e: &E, mtu: u16) -> E {
    let storage = e.storage().crash_snapshot();
    let key = e.local_key();
    let mut r = Engine::restore(*e.config(), key, storage, rng(key)).unwrap();
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

fn drain_events(e: &mut E) -> Vec<Event> {
    core::iter::from_fn(|| e.poll_event()).collect()
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
    assert!(gaps.iter().all(|&g| g <= cap + cap / 8), "{gaps:?}");
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
    assert_eq!(a.contacts().collect::<Vec<_>>(), [(conv, B)]);
    let resent = drain_tx(&mut a, t(100));
    let counter = |p: &[u8]| wire::split_verified(p).unwrap().0;
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

    // Fail while B persists the received message: no event, no ACK.
    let pkts = drain_tx(&mut a, t(0));
    b.storage.fail_after(Some(0));
    deliver(&mut b, &pkts, t(1));
    assert!(drain_events(&mut b).is_empty());
    assert_eq!(b.stats().storage_errors, 1);
    deliver(&mut b, &pkts, t(2)); // the retransmission succeeds
    assert_eq!(received(&drain_events(&mut b)).len(), 1);
}

#[test]
fn new_and_restore_check_storage() {
    let (a, _) = engine(A, B, 64);
    let used = a.storage().crash_snapshot();
    assert_eq!(
        Engine::new(Config::default(), A, used.clone(), rng(A)).err(),
        Some(Error::StorageNotEmpty)
    );
    assert_eq!(
        Engine::restore(Config::default(), B, used, rng(B)).err(),
        Some(Error::IdentityMismatch)
    );
    assert_eq!(
        Engine::restore(Config::default(), A, MemoryStorage::new(), rng(A)).err(),
        Some(Error::CorruptStorage)
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
    let mut a = Engine::new(Config::default(), A, MemoryStorage::new(), rng(A)).unwrap();
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
    let mut a = Engine::new(Config::default(), A, MemoryStorage::new(), rng(A)).unwrap();
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
    let mut a = Engine::new(cfg, A, MemoryStorage::new(), rng(A)).unwrap();
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
    // One fragment of a 250-fragment message: its FRAG_ACK bitmap is 32
    // bytes, which cannot share a 48-byte packet with an ACK.
    let mut pkt = Vec::new();
    begin_packet(&mut pkt, hash::pair_tag(&A, &B), 0);
    put_msg_frame(&mut pkt, 0, 250, 0, b"x");
    seal_packet(&mut pkt, &A, &B);
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
