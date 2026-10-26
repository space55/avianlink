//! Property tests for the wire codec, and the overhead table in
//! `docs/wire-format.md` §6.

use avianlink_core::wire::{
    self, decode_record, encode_record, frame_space, msg_frame_len, plan_fragments, put_ack_frame,
    put_frag_ack_frame, put_msg_frame, put_varint, record_len, AckFrame, FragAckFrame, Frame,
    Frames, MsgFrame, Reader, Record,
};
use proptest::prelude::*;

proptest! {
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
                OwnedFrame::Msg { seq, count, index, data } =>
                    put_msg_frame(&mut out, *seq, *count, *index, data),
                OwnedFrame::Ack { cum, largest, delay, bitmap } =>
                    put_ack_frame(&mut out, *cum, *largest, *delay, bitmap),
                OwnedFrame::FragAck { seq, count, bitmap } =>
                    put_frag_ack_frame(&mut out, *seq, *count, bitmap),
            }
        }
        let parsed: Vec<Frame<'_>> = Frames::new(&out).collect::<Result<_, _>>().unwrap();
        prop_assert_eq!(parsed.len(), frames.len());
        for (p, f) in parsed.iter().zip(&frames) {
            let expected = match f {
                OwnedFrame::Msg { seq, count, index, data } => Frame::Msg(MsgFrame {
                    seq: *seq, count: *count, index: if *count > 1 { *index } else { 0 }, data,
                }),
                OwnedFrame::Ack { cum, largest, delay, bitmap } => Frame::Ack(AckFrame {
                    cum: *cum, largest: *largest, ack_delay: *delay, bitmap,
                }),
                OwnedFrame::FragAck { seq, count, bitmap } => Frame::FragAck(FragAckFrame {
                    seq: *seq, count: *count, bitmap,
                }),
            };
            prop_assert_eq!(*p, expected);
        }
    }

    #[test]
    fn parsers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = wire::peek_tag(&bytes);
        let _ = wire::split_verified(&bytes);
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
            prop_assert!(msg_frame_len(seq, plan.count, i, r.len()) <= space);
            covered = r.end;
        }
        prop_assert_eq!(covered, len);
    }
}

#[derive(Debug, Clone)]
enum OwnedFrame {
    Msg {
        seq: u64,
        count: u64,
        index: u64,
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
        count: u64,
        bitmap: Vec<u8>,
    },
}

fn arb_frame() -> impl Strategy<Value = OwnedFrame> {
    prop_oneof![
        (
            any::<u64>(),
            1u64..300,
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..64)
        )
            .prop_map(|(seq, count, index, data)| OwnedFrame::Msg {
                seq,
                count,
                index,
                data
            }),
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
            .prop_map(|(seq, count, bitmap)| OwnedFrame::FragAck { seq, count, bitmap }),
    ]
}

/// Most text that fits in one unfragmented packet with `space` frame bytes:
/// seq < 128, Lamport < 16384, timestamp present (4 bytes).
fn single_packet_text(space: usize) -> usize {
    (0..space)
        .rev()
        .find(|&t| {
            let rec = 1 + 2 + 4 + t;
            msg_frame_len(100, 1, 0, rec) <= space
        })
        .unwrap_or(0)
}

/// Fragment payload per packet: seq < 128, fewer than 128 fragments.
fn fragment_payload(space: usize) -> usize {
    (0..space)
        .rev()
        .find(|&d| msg_frame_len(100, 127, 126, d) <= space)
        .unwrap_or(0)
}

fn overhead_rows() -> String {
    let mut out = String::from(
        "| MTU | text₁ (P1) | frag (P1) | eff (P1) | text₁ (P3, +12) | frag (P3) | eff (P3) |\n\
         |---|--:|--:|--:|--:|--:|--:|\n",
    );
    for mtu in [48usize, 51, 64, 128, 222, 255, 512, 1200] {
        let p1 = frame_space(mtu);
        let p3 = p1 - 12;
        let (t1, f1) = (single_packet_text(p1), fragment_payload(p1));
        let (t3, f3) = (single_packet_text(p3), fragment_payload(p3));
        out.push_str(&format!(
            "| {mtu} | {t1} | {f1} | {}% | {t3} | {f3} | {}% |\n",
            f1 * 100 / mtu,
            f3 * 100 / mtu
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
