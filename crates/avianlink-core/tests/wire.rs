//! Property tests for the wire codec, and the overhead table in
//! `docs/wire-format.md` §6.

use avianlink_core::wire::{
    self, decode_record, encode_record, frame_space, msg_frame_len, plan_fragments, put_ack_frame,
    put_frag_ack_frame, put_msg_frame, put_varint, record_len, AckFrame, FragAckFrame, Frame,
    Frames, MsgFrame, Part, Reader, Record,
};
use proptest::prelude::*;

fn relay_msg() -> impl Strategy<Value = wire::RelayMsg> {
    use wire::{RelayCode, RelayMsg};
    let code = prop_oneof![
        Just(RelayCode::Ok),
        Just(RelayCode::Full),
        Just(RelayCode::More),
        (7u8..).prop_map(RelayCode::Unknown)
    ];
    prop_oneof![
        (any::<[u8; 3]>(), any::<[u8; 16]>(), any::<[u8; 16]>())
            .prop_map(|(tag, up, down)| RelayMsg::Register { tag, up, down }),
        (any::<[u8; 3]>(), any::<[u8; 16]>())
            .prop_map(|(tag, proof)| RelayMsg::Open { tag, proof }),
        (
            any::<[u8; 3]>(),
            any::<[u8; 16]>(),
            0u64..1 << 35,
            0u64..1 << 35
        )
            .prop_map(|(tag, proof, since, release)| RelayMsg::Fetch {
                tag,
                proof,
                since,
                release
            }),
        (any::<[u8; 2]>(), 0u64..1 << 35)
            .prop_map(|(hint, since)| RelayMsg::FetchHello { hint, since }),
        (
            any::<u8>(),
            code.clone(),
            any::<[u8; 3]>(),
            (0u64..1 << 28, 0u64..1 << 35),
            prop::collection::vec(any::<[u8; 4]>(), 0..=wire::MAX_PAGE)
        )
            .prop_map(|(request, code, key, (retention_s, cursor), page)| {
                RelayMsg::Reply {
                    request,
                    code,
                    key,
                    retention_s,
                    cursor,
                    page,
                }
            }),
        (code, prop::collection::vec(any::<[u8; 4]>(), 0..=10))
            .prop_map(|(code, hashes)| RelayMsg::Receipt { code, hashes }),
    ]
}

proptest! {
    #[test]
    fn relay_messages_round_trip_within_48_bytes(m in relay_msg()) {
        let bytes = wire::encode_relay(&m);
        prop_assert_eq!(wire::parse_relay(&bytes), Ok(m.clone()));
        prop_assert!(wire::is_relay_kind(bytes[0]));
        prop_assert!(bytes.len() <= 48, "{} bytes", bytes.len());
    }

    #[test]
    fn relay_parse_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let _ = wire::parse_relay(&bytes);
    }

    #[test]
    fn hello_round_trips(hint in any::<[u8; 2]>(), key in any::<[u8; 32]>(), mac in any::<[u8; 12]>()) {
        let sender = avianlink_core::PublicKey(key);
        let signed = wire::hello_signed(hint, &sender);
        let bytes = wire::encode_hello(&signed, &mac);
        prop_assert_eq!(bytes.len(), wire::HELLO_LEN);
        let h = wire::parse_hello(&bytes).unwrap();
        prop_assert_eq!((h.hint, h.sender, h.mac), (hint, sender, mac));
        prop_assert_eq!(h.signed, &signed[..]);
    }

    #[test]
    fn hello_parse_accepts_only_exact_kind_and_length(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let ok = wire::parse_hello(&bytes).is_ok();
        prop_assert_eq!(ok, bytes.len() == wire::HELLO_LEN && bytes[0] == wire::HELLO_KIND);
    }

    #[test]
    fn varint_round_trips(v in any::<u64>()) {
        let mut out = Vec::new();
        put_varint(&mut out, v);
        prop_assert_eq!(out.len(), wire::varint_len(v));
        let mut r = Reader::new(&out);
        prop_assert_eq!(r.varint(), Ok(v));
        prop_assert!(r.is_empty());
    }

    #[test]
    fn varint_decode_is_canonical(bytes in prop::collection::vec(any::<u8>(), 0..12)) {
        let mut r = Reader::new(&bytes);
        if let Ok(v) = r.varint() {
            let consumed = bytes.len() - r.remaining();
            let mut out = Vec::new();
            put_varint(&mut out, v);
            prop_assert_eq!(&out[..], &bytes[..consumed]);
        }
    }

    #[test]
    fn record_round_trips(
        lamport in any::<u64>(),
        timestamp in proptest::option::of(any::<u64>()),
        text in ".{0,200}",
    ) {
        let rec = Record { lamport, timestamp, text: &text };
        let mut out = Vec::new();
        encode_record(&mut out, &rec);
        prop_assert_eq!(out.len(), record_len(&rec));
        prop_assert_eq!(decode_record(&out, 4096), Ok(rec));
    }

    #[test]
    fn frames_round_trip(frames in prop::collection::vec(arb_frame(), 0..8)) {
        let mut out = Vec::new();
        for f in &frames {
            match f {
                OwnedFrame::Msg { seq, part, data } => put_msg_frame(&mut out, *seq, *part, data),
                OwnedFrame::Ack { cum, largest, delay, bitmap } =>
                    put_ack_frame(&mut out, *cum, *largest, *delay, bitmap),
                OwnedFrame::FragAck { seq, unit, bitmap } =>
                    put_frag_ack_frame(&mut out, *seq, *unit, bitmap),
            }
        }
        let parsed: Vec<Frame<'_>> = Frames::new(&out).collect::<Result<_, _>>().unwrap();
        prop_assert_eq!(parsed.len(), frames.len());
        for (p, f) in parsed.iter().zip(&frames) {
            let expected = match f {
                OwnedFrame::Msg { seq, part, data } => Frame::Msg(MsgFrame {
                    seq: *seq, part: *part, data,
                }),
                OwnedFrame::Ack { cum, largest, delay, bitmap } => Frame::Ack(AckFrame {
                    cum: *cum, largest: *largest, ack_delay: *delay, bitmap,
                }),
                OwnedFrame::FragAck { seq, unit, bitmap } => Frame::FragAck(FragAckFrame {
                    seq: *seq, unit: *unit, bitmap,
                }),
            };
            prop_assert_eq!(*p, expected);
        }
    }

    #[test]
    fn parsers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = wire::peek_tag(&bytes);
        let _ = wire::parse_header(&bytes);
        let _ = wire::validate_frames(&bytes);
        let _ = Frames::new(&bytes).count();
        let _ = decode_record(&bytes, 4096);
    }

    #[test]
    fn fragment_plans_cover_record_and_fit(
        mtu in 48usize..1500,
        seq in any::<u64>(),
        len in 1usize..5000,
    ) {
        let space = frame_space(mtu);
        let plan = plan_fragments(space, seq, len).unwrap();
        let mut covered = 0;
        for i in 0..plan.count {
            let r = plan.range(i, len);
            prop_assert_eq!(r.start, covered);
            prop_assert!(!r.is_empty());
            prop_assert!(msg_frame_len(seq, plan.part(i, len), r.len()) <= space);
            covered = r.end;
        }
        prop_assert_eq!(covered, len);
    }
}

#[derive(Debug, Clone)]
enum OwnedFrame {
    Msg {
        seq: u64,
        part: Option<Part>,
        data: Vec<u8>,
    },
    Ack {
        cum: u64,
        largest: u64,
        delay: u64,
        bitmap: Vec<u8>,
    },
    FragAck {
        seq: u64,
        unit: u64,
        bitmap: Vec<u8>,
    },
}

fn arb_frame() -> impl Strategy<Value = OwnedFrame> {
    let part = proptest::option::of(
        (0u64..(1 << 62), any::<bool>()).prop_map(|(offset, last)| Part { offset, last }),
    );
    prop_oneof![
        (
            any::<u64>(),
            part,
            prop::collection::vec(any::<u8>(), 0..64)
        )
            .prop_map(|(seq, part, data)| OwnedFrame::Msg { seq, part, data }),
        (
            any::<u64>(),
            any::<u64>(),
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..16)
        )
            .prop_map(|(cum, largest, delay, bitmap)| OwnedFrame::Ack {
                cum,
                largest,
                delay,
                bitmap
            }),
        (
            any::<u64>(),
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..16)
        )
            .prop_map(|(seq, unit, bitmap)| OwnedFrame::FragAck { seq, unit, bitmap }),
    ]
}

/// Most text that fits in one unfragmented packet with `space` frame bytes:
/// seq < 128, Lamport < 16384, timestamp present (4 bytes).
fn single_packet_text(space: usize) -> usize {
    (0..space)
        .rev()
        .find(|&t| {
            let rec = 1 + 2 + 4 + t;
            msg_frame_len(100, None, rec) <= space
        })
        .unwrap_or(0)
}

/// Fragment payload per packet: seq < 128, record of 128–16383 bytes.
fn fragment_payload(space: usize) -> usize {
    let part = Some(Part {
        offset: 1000,
        last: false,
    });
    (0..space)
        .rev()
        .find(|&d| msg_frame_len(100, part, d) <= space)
        .unwrap_or(0)
}

fn overhead_rows() -> String {
    let mut out = String::from(
        "| MTU | text₁ | frag | eff | text₁ (P2) | frag (P2) | eff (P2) |\n\
         |---|--:|--:|--:|--:|--:|--:|\n",
    );
    for mtu in [48usize, 51, 64, 128, 222, 255, 512, 1200] {
        let now = frame_space(mtu);
        // Phase 2's 4-byte placeholder check left 12 more bytes.
        let p2 = now + 12;
        let (t1, f1) = (single_packet_text(now), fragment_payload(now));
        let (t2, f2) = (single_packet_text(p2), fragment_payload(p2));
        out.push_str(&format!(
            "| {mtu} | {t1} | {f1} | {}% | {t2} | {f2} | {}% |\n",
            f1 * 100 / mtu,
            f2 * 100 / mtu
        ));
    }
    out
}

#[test]
fn overhead_table_matches_spec() {
    let doc = include_str!("../../../docs/wire-format.md");
    let start = "<!-- overhead-table:start -->\n";
    let end = "<!-- overhead-table:end -->";
    let a = doc.find(start).expect("start marker") + start.len();
    let b = doc.find(end).expect("end marker");
    let rows = overhead_rows();
    assert_eq!(
        &doc[a..b],
        rows,
        "docs/wire-format.md §6 is stale; replace the table rows with:\n{rows}"
    );
}
