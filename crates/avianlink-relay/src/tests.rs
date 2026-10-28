use super::*;
use avianlink_core::mailbox::{anchor, proof};
use avianlink_core::MemoryStorage;

type R = Relay<MemoryStorage, u8>;

fn relay(cfg: RelayConfig) -> R {
    Relay::open(cfg, MemoryStorage::new()).unwrap()
}

fn t(ms: u64) -> Timestamp {
    Timestamp::from_millis(ms)
}

/// A pair's mailbox for one direction: tag and chain seeds.
struct Mb {
    tag: PairTag,
    up: Proof,
    down: Proof,
    up_k: u32,
    down_k: u32,
}

impl Mb {
    fn new(tag: PairTag, seed: u8) -> Self {
        Self {
            tag,
            up: [seed; 16],
            down: [seed ^ 0xff; 16],
            up_k: 0,
            down_k: 0,
        }
    }
    fn register(&self) -> Vec<u8> {
        encode_relay(&RelayMsg::Register {
            tag: self.tag,
            up: anchor(&self.up),
            down: anchor(&self.down),
        })
    }
    fn open(&mut self) -> Vec<u8> {
        self.up_k += 1;
        encode_relay(&RelayMsg::Open {
            tag: self.tag,
            proof: proof(&self.up, self.up_k).unwrap(),
        })
    }
    fn fetch(&mut self, since: u64) -> Vec<u8> {
        self.down_k += 1;
        encode_relay(&RelayMsg::Fetch {
            tag: self.tag,
            proof: proof(&self.down, self.down_k).unwrap(),
            since,
            release: since,
            max: 0,
        })
    }
}

/// A plausible data packet: kind, tag, counter, filler, 16-byte tag.
fn packet(tag: PairTag, n: u8) -> Vec<u8> {
    let mut p = vec![VERSION];
    p.extend_from_slice(&tag);
    p.push(n & 0x7f);
    p.extend(std::iter::repeat_n(n, 24));
    p
}

fn drain(r: &mut R) -> Vec<(u8, Vec<u8>)> {
    std::iter::from_fn(|| r.poll_transmit()).collect()
}

fn msgs(out: &[(u8, Vec<u8>)]) -> Vec<RelayMsg> {
    out.iter()
        .filter(|(_, b)| wire::is_relay_kind(b[0]))
        .map(|(_, b)| parse_relay(b).unwrap())
        .collect()
}

fn packets(out: &[(u8, Vec<u8>)]) -> Vec<Vec<u8>> {
    out.iter()
        .filter(|(_, b)| !wire::is_relay_kind(b[0]))
        .map(|(_, b)| b.clone())
        .collect()
}

fn code_of(m: &RelayMsg) -> RelayCode {
    match m {
        RelayMsg::Reply { code, .. } | RelayMsg::Receipt { code, .. } => *code,
        _ => panic!("not a reply: {m:?}"),
    }
}

fn last_cursor(out: &[(u8, Vec<u8>)]) -> (RelayCode, u64) {
    msgs(out)
        .into_iter()
        .rev()
        .find_map(|m| match m {
            RelayMsg::Reply { code, cursor, .. } => Some((code, cursor)),
            _ => None,
        })
        .unwrap()
}

const A: u8 = 1;
const B: u8 = 2;
const EVE: u8 = 9;
const TAG: PairTag = [7, 7, 7];

#[test]
fn upload_fetch_and_release() {
    let mut r = relay(RelayConfig::default());
    let mut mb = Mb::new(TAG, 1);
    r.handle(A, &mb.register(), t(0));
    r.handle(A, &mb.open(), t(0));
    assert!(msgs(&drain(&mut r))
        .iter()
        .all(|m| code_of(m) == RelayCode::Ok));
    for n in 0..3 {
        r.handle(A, &packet(TAG, n), t(10));
    }
    let receipts = msgs(&drain(&mut r));
    assert_eq!(receipts.len(), 3);
    assert!(receipts.iter().all(|m| matches!(m,
        RelayMsg::Receipt { code: RelayCode::Ok, hashes } if hashes.len() == 1)));
    // B fetches everything, then proves it has it: the relay releases it.
    r.handle(B, &mb.fetch(0), t(20));
    let out = drain(&mut r);
    assert_eq!(
        packets(&out),
        (0..3).map(|n| packet(TAG, n)).collect::<Vec<_>>()
    );
    assert_eq!(last_cursor(&out), (RelayCode::Ok, 3));
    assert!(out.iter().all(|(to, _)| *to == B));
    let used = r.used_bytes();
    assert!(used > 0);
    r.handle(B, &mb.fetch(3), t(30));
    assert!(packets(&drain(&mut r)).is_empty());
    assert_eq!(r.used_bytes(), 0);
    assert_eq!(r.stats().released, 3);
}

#[test]
fn uploads_need_a_session() {
    let mut r = relay(RelayConfig::default());
    let mb = Mb::new(TAG, 1);
    r.handle(A, &mb.register(), t(0));
    drain(&mut r);
    r.handle(A, &packet(TAG, 1), t(1));
    assert_eq!(code_of(&msgs(&drain(&mut r))[0]), RelayCode::NoSession);
    assert_eq!(r.used_bytes(), 0);
}

#[test]
fn colliding_tags_keep_separate_mailboxes() {
    let mut r = relay(RelayConfig::default());
    let (mut ab, mut cd, mut eve) = (Mb::new(TAG, 1), Mb::new(TAG, 2), Mb::new(TAG, 3));
    for (who, mb) in [(A, &ab), (3, &cd), (EVE, &eve)] {
        r.handle(who, &mb.register(), t(0));
    }
    assert_eq!(r.mailbox_count(), 3, "nobody refused");
    r.handle(A, &ab.open(), t(1));
    r.handle(3, &cd.open(), t(1));
    r.handle(A, &packet(TAG, 1), t(2));
    r.handle(3, &packet(TAG, 2), t(2));
    drain(&mut r);
    r.handle(B, &ab.fetch(0), t(3));
    assert_eq!(packets(&drain(&mut r)), [packet(TAG, 1)]);
    r.handle(4, &cd.fetch(0), t(3));
    assert_eq!(packets(&drain(&mut r)), [packet(TAG, 2)]);
    // Eve registered the same tag with anchors of her own: empty mailbox.
    r.handle(EVE, &eve.fetch(0), t(3));
    assert!(packets(&drain(&mut r)).is_empty());
}

#[test]
fn proofs_are_one_time_and_tolerate_losses() {
    let mut r = relay(RelayConfig::default());
    let mut mb = Mb::new(TAG, 1);
    r.handle(A, &mb.register(), t(0));
    let first = mb.fetch(0);
    r.handle(B, &first, t(1));
    assert_eq!(last_cursor(&drain(&mut r)).0, RelayCode::Ok);
    // A recorded proof is useless the second time.
    r.handle(EVE, &first, t(2));
    assert_eq!(last_cursor(&drain(&mut r)).0, RelayCode::BadProof);
    // Ten proofs lost on the way: the next one still verifies.
    for _ in 0..10 {
        mb.fetch(0);
    }
    r.handle(B, &mb.fetch(0), t(3));
    assert_eq!(last_cursor(&drain(&mut r)).0, RelayCode::Ok);
    // A guess, and an up proof used as a down proof, fail.
    let wrong = encode_relay(&RelayMsg::Fetch {
        tag: TAG,
        proof: proof(&mb.up, 1).unwrap(),
        since: 0,
        release: 0,
        max: 0,
    });
    r.handle(EVE, &wrong, t(4));
    assert_eq!(last_cursor(&drain(&mut r)).0, RelayCode::BadProof);
    let unknown = encode_relay(&RelayMsg::Open {
        tag: [1, 2, 3],
        proof: [0; 16],
    });
    r.handle(EVE, &unknown, t(4));
    assert_eq!(last_cursor(&drain(&mut r)).0, RelayCode::UnknownMailbox);
}

#[test]
fn a_full_relay_refuses_and_never_evicts() {
    let cfg = RelayConfig {
        mailbox_quota_bytes: 100,
        total_quota_bytes: 100,
        ..RelayConfig::default()
    };
    let mut r = relay(cfg);
    let mut mb = Mb::new(TAG, 1);
    r.handle(A, &mb.register(), t(0));
    r.handle(A, &mb.open(), t(0));
    drain(&mut r);
    let codes: Vec<RelayCode> = (0..5)
        .map(|n| {
            r.handle(A, &packet(TAG, n), t(1));
            code_of(&msgs(&drain(&mut r))[0])
        })
        .collect();
    assert_eq!(codes[..3], [RelayCode::Ok; 3]);
    assert_eq!(codes[3..], [RelayCode::Full; 2]);
    r.handle(B, &mb.fetch(0), t(2));
    assert_eq!(packets(&drain(&mut r)).len(), 3, "the first three kept");
}

#[test]
fn duplicates_are_stored_once() {
    let mut r = relay(RelayConfig::default());
    let mut mb = Mb::new(TAG, 1);
    r.handle(A, &mb.register(), t(0));
    r.handle(A, &mb.open(), t(0));
    for _ in 0..4 {
        r.handle(A, &packet(TAG, 1), t(1));
    }
    let receipts = msgs(&drain(&mut r));
    assert!(receipts[1..].iter().all(|m| code_of(m) == RelayCode::Ok));
    assert_eq!(r.stats().stored, 1);
    assert_eq!(r.stats().duplicates, 3);
}

#[test]
fn packets_and_idle_mailboxes_expire_at_retention() {
    let day = 24 * 3_600_000;
    let cfg = RelayConfig {
        retention_ms: 2 * day,
        ..RelayConfig::default()
    };
    let mut r = relay(cfg);
    let mut mb = Mb::new(TAG, 1);
    r.handle(A, &mb.register(), t(0));
    r.handle(A, &mb.open(), t(0));
    r.handle(A, &packet(TAG, 1), t(0));
    drain(&mut r);
    assert_eq!(r.next_timeout(), Some(t(2 * day)));
    r.handle_timeout(t(2 * day - 1));
    assert_eq!(r.stats().expired, 0, "not a millisecond early");
    r.handle_timeout(t(2 * day));
    assert_eq!(r.stats().expired, 1);
    assert_eq!(r.mailbox_count(), 0, "idle for a retention period");
    assert_eq!(r.used_bytes(), 0);
    // Every reply advertises the retention.
    let mut fresh = Mb::new(TAG, 5);
    r.handle(A, &fresh.register(), t(3 * day));
    r.handle(A, &fresh.open(), t(3 * day));
    assert!(msgs(&drain(&mut r)).iter().all(|m| matches!(m,
        RelayMsg::Reply { retention_s, .. } if *retention_s == 2 * day / 1000)));
}

#[test]
fn hellos_are_filed_openly_by_hint() {
    let mut r = relay(RelayConfig::default());
    let mut hello = vec![HELLO_KIND, 0xab, 0xcd];
    hello.extend_from_slice(&[5; 44]);
    r.handle(A, &hello, t(0));
    r.handle(A, &hello, t(1));
    assert!(msgs(&drain(&mut r))
        .iter()
        .all(|m| code_of(m) == RelayCode::Ok));
    assert_eq!(r.stats().stored, 1, "repeats are byte-identical");
    let fetch = encode_relay(&RelayMsg::FetchHello {
        hint: [0xab, 0xcd],
        since: 0,
    });
    r.handle(B, &fetch, t(2));
    let out = drain(&mut r);
    assert_eq!(packets(&out), [hello.clone()]);
    assert_eq!(last_cursor(&out), (RelayCode::Ok, 1));
    // Fetching Hellos releases nothing: anyone may ask.
    let again = encode_relay(&RelayMsg::FetchHello {
        hint: [0xab, 0xcd],
        since: 1,
    });
    r.handle(EVE, &again, t(3));
    assert!(packets(&drain(&mut r)).is_empty());
    assert_eq!(r.used_bytes(), hello.len() as u64);
}

#[test]
fn fetches_are_paged() {
    let cfg = RelayConfig {
        page_packets: 4,
        ..RelayConfig::default()
    };
    assert!(
        !RelayConfig {
            page_packets: 7,
            ..RelayConfig::default()
        }
        .is_valid(),
        "a REPLY lists at most 6 hashes"
    );
    let mut r = relay(cfg);
    let mut mb = Mb::new(TAG, 1);
    r.handle(A, &mb.register(), t(0));
    r.handle(A, &mb.open(), t(0));
    for n in 0..10 {
        r.handle(A, &packet(TAG, n), t(1));
    }
    drain(&mut r);
    let mut since = 0;
    let mut got = Vec::new();
    loop {
        r.handle(B, &mb.fetch(since), t(2));
        let out = drain(&mut r);
        got.extend(packets(&out));
        let (code, cursor) = last_cursor(&out);
        since = cursor;
        if code == RelayCode::Ok {
            break;
        }
        assert_eq!(code, RelayCode::More);
    }
    assert_eq!(got.len(), 10);
}

#[test]
fn live_forwarding_during_a_lease() {
    let mut r = relay(RelayConfig::default());
    let mut mb = Mb::new(TAG, 1);
    r.handle(A, &mb.register(), t(0));
    r.handle(A, &mb.open(), t(0));
    r.handle(B, &mb.fetch(0), t(0));
    drain(&mut r);
    r.handle(A, &packet(TAG, 1), t(1_000));
    let out = drain(&mut r);
    assert!(out.contains(&(B, packet(TAG, 1))), "forwarded live");
    r.handle(A, &packet(TAG, 2), t(700_000));
    let out = drain(&mut r);
    assert!(!out.iter().any(|(to, _)| *to == B), "lease over");
}

#[test]
fn state_survives_restart_and_receipts_follow_commits() {
    let mut r = relay(RelayConfig::default());
    let mut mb = Mb::new(TAG, 1);
    r.handle(A, &mb.register(), t(0));
    r.handle(A, &mb.open(), t(0));
    r.handle(A, &packet(TAG, 1), t(1));
    drain(&mut r);
    // A failed commit refuses the upload instead of losing it.
    let mut storage = r.storage().crash_snapshot();
    storage.fail_after(Some(0));
    let mut r2: R = Relay::open(RelayConfig::default(), storage).unwrap();
    r2.handle(A, &mb.open(), t(2));
    drain(&mut r2);
    r2.handle(A, &mb.open(), t(2));
    r2.handle(A, &packet(TAG, 2), t(3));
    let codes: Vec<RelayCode> = msgs(&drain(&mut r2)).iter().map(code_of).collect();
    assert_eq!(codes.last(), Some(&RelayCode::Ok));
    let mut r3: R = Relay::open(RelayConfig::default(), r2.storage().crash_snapshot()).unwrap();
    r3.handle(B, &mb.fetch(0), t(4));
    assert_eq!(packets(&drain(&mut r3)), [packet(TAG, 1), packet(TAG, 2)]);
}

#[test]
fn requests_are_rate_limited_per_address() {
    let cfg = RelayConfig {
        requests_per_minute: 4,
        ..RelayConfig::default()
    };
    let mut r = relay(cfg);
    let mut mb = Mb::new(TAG, 1);
    r.handle(A, &mb.register(), t(0));
    let codes: Vec<RelayCode> = (0..10)
        .map(|_| {
            r.handle(EVE, &mb.fetch(0), t(0));
            last_cursor(&drain(&mut r)).0
        })
        .collect();
    assert!(codes.contains(&RelayCode::RateLimited));
    // Another address is unaffected.
    r.handle(B, &mb.fetch(0), t(0));
    assert_ne!(last_cursor(&drain(&mut r)).0, RelayCode::RateLimited);
}

#[test]
fn everything_the_relay_sends_fits_48_bytes_except_stored_packets() {
    let mut r = relay(RelayConfig::default());
    let mut mb = Mb::new(TAG, 1);
    r.handle(A, &mb.register(), t(0));
    r.handle(A, &mb.open(), t(0));
    r.handle(A, &packet(TAG, 1), t(0));
    r.handle(B, &mb.fetch(1 << 34), t(0));
    for (_, b) in drain(&mut r) {
        if wire::is_relay_kind(b[0]) {
            assert!(b.len() <= 48, "{} bytes", b.len());
        }
    }
}

#[test]
fn garbage_is_dropped() {
    let mut r = relay(RelayConfig::default());
    for g in [
        &[][..],
        &[0x00],
        &[0x10, 1, 2],
        &[0x01, 1],
        &[0x02; 10],
        &[0xff; 50],
    ] {
        r.handle(EVE, g, t(0));
    }
    assert!(drain(&mut r).is_empty());
    assert_eq!(r.stats().dropped, 6);
}
