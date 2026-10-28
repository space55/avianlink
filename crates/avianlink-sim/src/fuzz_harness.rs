//! Fuzz harnesses, shared by `fuzz/` (cargo-fuzz, nightly) and by ordinary
//! tests so they cannot rot (`docs/decisions.md` D-019).
//!
//! Random bytes never authenticate, so the harness can also encrypt fuzzer
//! bytes as a genuine packet from a known contact (it holds the contact's
//! identity). That exercises the frame, fragment and record paths behind the
//! AEAD.

use avianlink_core::crypto::PairKeys;
use avianlink_core::wire::{self, begin_packet, header_len};
use avianlink_core::{
    Config, Engine, Event, Identity, LinkBudget, LinkConfig, LinkId, MemoryStorage, PublicKey,
    Timestamp,
};
use rand_chacha::ChaCha20Rng;

use crate::seeded_rng;

const PEER_SEED: [u8; 32] = [0xa1; 32];
const LOCAL_SEED: [u8; 32] = [0xb2; 32];

fn peer() -> Identity {
    Identity::from_secret_bytes(&PEER_SEED)
}

fn local() -> Identity {
    Identity::from_secret_bytes(&LOCAL_SEED)
}

fn local_key() -> PublicKey {
    local().public_key()
}
const MTUS: [u16; 2] = [48, 1200];

/// Runs every standalone parser over `data`.
pub fn decode(data: &[u8]) {
    let _ = wire::peek_tag(data);
    let _ = wire::parse_hello(data);
    let _ = wire::parse_header(data);
    let _ = wire::validate_frames(data);
    for f in wire::Frames::new(data) {
        match f {
            Ok(wire::Frame::Ack(a)) => {
                let _ = (a.covers(0), a.covers(u64::MAX), a.horizon());
            }
            Ok(wire::Frame::Sync(s)) => {
                let _ = s.digests();
            }
            Ok(wire::Frame::Repair(r)) => {
                let _ = r.sources();
            }
            _ => {}
        }
    }
    let _ = wire::decode_record(data, 4096);
}

/// Drives an engine with a script decoded from `data`, checking invariants
/// after every step:
///
/// - every transmitted packet fits its link's MTU;
/// - after draining `poll_transmit`, `next_timeout` is never at or before
///   the current time (that would be a busy-loop for the host);
/// - received messages have the ID the content implies.
///
/// Script: repeated `[op] [len] [len bytes]`. `op & 3` selects raw packet /
/// sealed frames from the peer / `send_text` / time advance; bit 2 picks the
/// link; bits 3.. scale the time step. A raw packet of exactly one byte `b`
/// is replaced by a genuine Hello: from the known peer if `b` is even, else
/// from a stranger whose key derives from `b`. Link 1 is a relay link
/// (`relay.md` §6); a time step whose chunk is non-empty also feeds a
/// relay receipt, with the code `chunk[0]` picks, for the packets the
/// engine sent most recently.
pub fn handle_packet(data: &[u8]) {
    let mut e: Engine<MemoryStorage, ChaCha20Rng> = Engine::new(
        Config::default(),
        local(),
        MemoryStorage::new(),
        seeded_rng(0),
    )
    .expect("default config");
    for (i, mtu) in MTUS.iter().enumerate() {
        let link = LinkConfig {
            mtu: *mtu,
            budget: LinkBudget::Unlimited,
            cost: i as u16,
        };
        if i == 1 {
            e.add_relay_link(LinkId(1), link).expect("relay link");
        } else {
            e.add_link(LinkId(0), link).expect("link");
        }
    }
    let conv = e.add_contact(peer().public_key()).expect("contact");
    let keys = PairKeys::derive(&peer(), &local_key()).expect("valid keys");

    let mut now = crate::SIM_EPOCH_MS;
    let mut counter = 0u64;
    let mut recent: Vec<wire::ReceiptHash> = Vec::new();
    let mut rest = data;
    while let [op, len, tail @ ..] = rest {
        let n = usize::from(*len).min(tail.len());
        let (chunk, tail) = tail.split_at(n);
        rest = tail;
        let link = LinkId(u16::from((op >> 2) & 1));
        now += u64::from(op >> 3) * 250;
        let t = Timestamp::from_millis(now);
        match op & 3 {
            0 if chunk.len() == 1 => {
                let b = chunk[0];
                let from = if b % 2 == 0 {
                    peer()
                } else {
                    Identity::from_secret_bytes(&[b; 32])
                };
                if let Some(hello) = PairKeys::derive(&from, &local_key())
                    .and_then(|k| k.hello(&from.public_key(), &local_key()))
                {
                    e.handle_packet(link, &hello, t);
                }
            }
            0 => {
                e.handle_packet(link, chunk, t);
            }
            1 => {
                let mut pkt = Vec::new();
                begin_packet(&mut pkt, keys.tx_tag, counter);
                pkt.extend_from_slice(chunk);
                keys.seal(&mut pkt, header_len(counter), counter)
                    .expect("seal");
                counter += 1;
                e.handle_packet(link, &pkt, t);
            }
            2 => {
                let _ = e.send_text(conv, &String::from_utf8_lossy(chunk), t);
            }
            _ => {
                if let Some(&c) = chunk.first() {
                    let code = match c % 4 {
                        0 => wire::RelayCode::Ok,
                        1 => wire::RelayCode::Full,
                        2 => wire::RelayCode::NoSession,
                        _ => wire::RelayCode::Unknown(c),
                    };
                    let take = recent.len().min(usize::from(c >> 2).max(1));
                    let hashes = recent.split_off(recent.len() - take);
                    e.handle_receipt(LinkId(1), code, &hashes, t);
                }
                e.handle_timeout(t)
            }
        }
        let mut sent = 0;
        while let Some(tx) = e.poll_transmit(t) {
            let mtu = MTUS[usize::from(tx.link.0)];
            assert!(tx.packet.len() <= usize::from(mtu), "packet exceeds MTU");
            if tx.link == LinkId(1) {
                recent.push(avianlink_core::hashes::receipt_hash(tx.packet.as_bytes()));
                if recent.len() > 64 {
                    recent.remove(0);
                }
            }
            sent += 1;
            // Turn a livelock into a crash the fuzzer can report. The most
            // one call can owe is every queued fragment once.
            assert!(sent < 100_000, "poll_transmit never runs dry");
        }
        while let Some(ev) = e.poll_event() {
            if let Event::MessageReceived(m) = ev {
                assert_eq!(m.conversation, conv);
            }
        }
        if let Some(next) = e.next_timeout() {
            assert!(
                next > t,
                "engine would busy-loop: next_timeout {next:?} <= now"
            );
        }
        assert_eq!(e.stats().transmit_stalls, 0, "due work could not be sent");
    }
}

/// Restores an engine from fuzzer-chosen storage contents, then drives it
/// briefly. Storage belongs to the host and may be corrupted or tampered
/// with, so restore must fail cleanly, never panic.
///
/// Input: repeated `[key_len] [val_len_lo] [val_len_hi] [key] [value]`
/// entries, preceded implicitly by a valid version record (so the fuzzer
/// gets past the first check). A leading `0xff` byte omits it.
pub fn restore(data: &[u8]) {
    use avianlink_core::Storage;
    let mut storage = MemoryStorage::new();
    let (with_version, mut rest) = match data {
        [0xff, tail @ ..] => (false, tail),
        _ => (true, data),
    };
    storage.begin().expect("batch");
    if with_version {
        let mut v = vec![2u8];
        v.extend_from_slice(&local_key().0);
        storage.store(b"v", &v).expect("store");
    }
    while let [klen, lo, hi, tail @ ..] = rest {
        let klen = usize::from(*klen).min(tail.len());
        let (k, tail) = tail.split_at(klen);
        let vlen = usize::from(u16::from_le_bytes([*lo, *hi])).min(tail.len());
        let (v, tail) = tail.split_at(vlen);
        storage.store(k, v).expect("store");
        rest = tail;
    }
    storage.commit().expect("commit");
    let Ok(mut e) = Engine::restore(Config::default(), local(), storage, seeded_rng(0)) else {
        return;
    };
    let link = LinkConfig {
        mtu: 64,
        budget: LinkBudget::Unlimited,
        cost: 0,
    };
    e.add_link(LinkId(0), link).expect("link");
    for step in 0..4u64 {
        let t = Timestamp::from_millis(crate::SIM_EPOCH_MS + step * 60_000);
        e.handle_timeout(t);
        let mut sent = 0;
        while let Some(tx) = e.poll_transmit(t) {
            assert!(tx.packet.len() <= 64, "packet exceeds MTU");
            sent += 1;
            assert!(sent < 100_000, "poll_transmit never runs dry");
        }
        while e.poll_event().is_some() {}
        if let Some(next) = e.next_timeout() {
            assert!(next > t, "engine would busy-loop after restore");
        }
    }
    let convs: Vec<_> = e.contacts().map(|(c, _)| c).collect();
    for c in convs {
        let _ = e.send_text(
            c,
            "after restore",
            Timestamp::from_millis(crate::SIM_EPOCH_MS),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::Rng;

    /// Smoke-runs both harnesses on random scripts (the real fuzzing runs
    /// under `scripts/fuzz.sh`).
    #[test]
    fn harnesses_survive_random_scripts() {
        let mut rng = seeded_rng(99);
        for _ in 0..2_000 {
            let mut buf = vec![0u8; (rng.next_u32() % 600) as usize];
            rng.fill_bytes(&mut buf);
            decode(&buf);
            handle_packet(&buf);
            restore(&buf);
        }
    }

    /// Restoring real, then mangled, engine state never panics.
    #[test]
    fn restore_survives_mangled_real_state() {
        let mut e: Engine<MemoryStorage, ChaCha20Rng> = Engine::new(
            Config::default(),
            local(),
            MemoryStorage::new(),
            seeded_rng(1),
        )
        .unwrap();
        let link = LinkConfig {
            mtu: 64,
            budget: LinkBudget::Unlimited,
            cost: 0,
        };
        e.add_link(LinkId(0), link).unwrap();
        let conv = e.add_contact(peer().public_key()).unwrap();
        let now = Timestamp::from_millis(crate::SIM_EPOCH_MS);
        for i in 0..5 {
            e.send_text(conv, &"y".repeat(i * 40), now).unwrap();
        }
        let mut entries = Vec::new();
        use avianlink_core::Storage;
        e.storage()
            .crash_snapshot()
            .scan_prefix(b"", &mut |k, v| entries.push((k.to_vec(), v.to_vec())))
            .unwrap();
        let mut rng = seeded_rng(5);
        for _ in 0..500 {
            let mut script = vec![0xff];
            for (k, v) in &entries {
                let mut v = v.clone();
                if !v.is_empty() && rng.next_u32().is_multiple_of(2) {
                    let i = (rng.next_u32() as usize) % v.len();
                    v[i] ^= 1 << (rng.next_u32() % 8);
                }
                if rng.next_u32().is_multiple_of(8) {
                    v.truncate((rng.next_u32() as usize) % (v.len() + 1));
                }
                script.push(k.len() as u8);
                script.extend_from_slice(&(v.len() as u16).to_le_bytes());
                script.extend_from_slice(k);
                script.extend_from_slice(&v);
            }
            restore(&script);
        }
    }

    /// Regression (fuzzer, Phase 6): after draining `poll_transmit`,
    /// `next_timeout` still reported "now", a busy loop for the host.
    #[test]
    fn regression_busy_loop_after_drain() {
        handle_packet(&[
            0x2d, 0x30, 0x00, 0x01, 0xff, 0x01, 0x0f, 0x25, 0x01, 0xff, 0xff, 0xef, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xf9, 0xff, 0x01, 0x09, 0x00, 0x06, 0x08, 0x93, 0x01, 0x01, 0x05,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x7e, 0x00, 0x16, 0x00, 0x2a, 0x1e,
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x34, 0x01, 0x00, 0x2d,
            0x00, 0x0d, 0x30, 0x00, 0xbf, 0xff, 0xff, 0x01, 0x09, 0x00, 0x00, 0x00, 0x00, 0x2a,
            0x00, 0x97, 0x2d, 0x00, 0xf6, 0x00, 0x81, 0x81,
        ]);
    }

    /// A hand-made script that delivers a message via sealed frames.
    #[test]
    fn sealed_script_reaches_frame_handling() {
        let mut frames = Vec::new();
        let mut rec = Vec::new();
        wire::encode_record(
            &mut rec,
            &wire::Record {
                lamport: 1,
                timestamp: None,
                text: "hi",
            },
        );
        wire::put_msg_frame(&mut frames, 0, None, &rec);
        let mut script = vec![1u8, frames.len() as u8];
        script.extend_from_slice(&frames);
        script.extend_from_slice(&[3 | (8 << 3), 0]);
        handle_packet(&script);
    }
}
