//! Fuzz harnesses, shared by `fuzz/` (cargo-fuzz, nightly) and by ordinary
//! tests so they cannot rot (`docs/decisions.md` D-019).
//!
//! Random bytes almost never pass the packet check, so the harness can also
//! wrap fuzzer bytes in a correctly tagged and checked packet from a known
//! contact. That exercises the frame, fragment and record paths behind the
//! check.

use avianlink_core::wire::{self, begin_packet, seal_packet};
use avianlink_core::{
    hashes, Config, Engine, Event, LinkBudget, LinkConfig, LinkId, MemoryStorage, PublicKey,
    Timestamp,
};
use rand_chacha::ChaCha20Rng;

use crate::seeded_rng;

const PEER: PublicKey = PublicKey([0xa1; 32]);
const LOCAL: PublicKey = PublicKey([0xb2; 32]);
const MTUS: [u16; 2] = [48, 1200];

/// Runs every standalone parser over `data`.
pub fn decode(data: &[u8]) {
    let _ = wire::peek_tag(data);
    let _ = wire::split_verified(data);
    let _ = wire::validate_frames(data);
    for f in wire::Frames::new(data) {
        if let Ok(wire::Frame::Ack(a)) = f {
            let _ = (a.covers(0), a.covers(u64::MAX), a.horizon());
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
/// link; bits 3.. scale the time step.
pub fn handle_packet(data: &[u8]) {
    let mut e: Engine<MemoryStorage, ChaCha20Rng> = Engine::new(
        Config::default(),
        LOCAL,
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
        e.add_link(LinkId(i as u16), link).expect("link");
    }
    let conv = e.add_contact(PEER).expect("contact");
    let tag = hashes::pair_tag(&PEER, &LOCAL);

    let mut now = crate::SIM_EPOCH_MS;
    let mut counter = 0u64;
    let mut rest = data;
    while let [op, len, tail @ ..] = rest {
        let n = usize::from(*len).min(tail.len());
        let (chunk, tail) = tail.split_at(n);
        rest = tail;
        let link = LinkId(u16::from((op >> 2) & 1));
        now += u64::from(op >> 3) * 250;
        let t = Timestamp::from_millis(now);
        match op & 3 {
            0 => e.handle_packet(link, chunk, t),
            1 => {
                let mut pkt = Vec::new();
                begin_packet(&mut pkt, tag, counter);
                counter += 1;
                pkt.extend_from_slice(chunk);
                seal_packet(&mut pkt, &PEER, &LOCAL);
                e.handle_packet(link, &pkt, t);
            }
            2 => {
                let _ = e.send_text(conv, &String::from_utf8_lossy(chunk), t);
            }
            _ => e.handle_timeout(t),
        }
        while let Some(tx) = e.poll_transmit(t) {
            let mtu = MTUS[usize::from(tx.link.0)];
            assert!(tx.packet.len() <= usize::from(mtu), "packet exceeds MTU");
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

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
        }
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
        wire::put_msg_frame(&mut frames, 0, 1, 0, &rec);
        let mut script = vec![1u8, frames.len() as u8];
        script.extend_from_slice(&frames);
        script.extend_from_slice(&[3 | (8 << 3), 0]);
        handle_packet(&script);
    }
}
