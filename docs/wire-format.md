# avianlink wire format

> **Status: v1 (Phase 3).** The version byte stays `0x01` until the first
> release. Before then, peers are assumed to run the same build.

## 1. Conventions

- Byte order: varints are little-endian groups (LEB128). Fixed-width fields
  are byte strings and have no byte order.
- **varint**: unsigned LEB128, at most 10 bytes, value ≤ `u64::MAX`.
  Decoders **must** reject non-minimal encodings (a final byte of `0x00`
  after the first byte) and overflow (10th byte > `0x01`). Canonical
  encodings matter because message IDs are hashes of encoded bytes.
- `H(x)` is SHA-256. `H_n(x)` is its first `n` bytes. `||` is concatenation.
  Domain-separation labels are ASCII, with no terminator.
- `PK_s` / `PK_r` are the sender's and recipient's 32-byte public keys.
- "Drop" means discard silently and count it in `Stats`. Network input never
  causes an error, an event, or a panic.

## 2. Packet

```
packet  = header  ciphertext  aead_tag:[16]
header  = version:u8  tag:[3]  counter:varint
ciphertext = ChaCha20-Poly1305(frame*)   (same length as the frames)
```

| Field   | Size  | Meaning |
|---------|-------|---------|
| version | 1     | `0x01`. `0x00` is never valid. Other values: drop (`packets_dropped_version`). |
| tag     | 3     | Routing tag of the (sender → recipient) direction (§2.2). |
| counter | 1–5   | Per-direction packet counter, strictly increasing, never reused. It gives the AEAD nonce (§2.3). Fragment sizing assumes ≤ 5 bytes (counter < 2³⁵). |
| frame*  | rest  | Zero or more frames (§3), encrypted. Zero frames is a valid keep-alive. |
| aead_tag| 16    | Poly1305 tag over header (associated data) and ciphertext. |

A packet is never larger than the MTU of the link it is sent on. The smallest
valid packet is 21 bytes.

### 2.1 Processing order

1. Length ≥ 21, else drop (`packets_dropped_malformed`).
2. Version byte, else drop.
3. Look up the tag among known contacts. No match: drop
   (`packets_dropped_unauthenticated`).
4. Parse the counter. For each candidate contact: skip it if the counter is
   a replay for that contact (`security.md` §6). Otherwise try to decrypt
   with its key, and the first success identifies the sender. No success:
   drop (`packets_dropped_unauthenticated`, or `packets_dropped_replay` if
   every candidate rejected the counter).
5. Mark the counter as seen.
6. Parse **all** frames. A structural error anywhere (a bad varint, or a
   frame length past the end) drops the whole packet, so frames are applied
   all-or-nothing.
7. Apply the frames in order.

### 2.2 Routing tag

```
tag(S→R) = HKDF-Expand(prk(S,R), "tag" ‖ PK_S ‖ PK_R, 3)
```

`prk` is the pairwise key-derivation secret (`security.md` §3). The tag
identifies the ordered pair to the recipient, who precomputes one tag per
contact. Outsiders can't compute it even when they know both public keys.
Collisions (about 3% among 1000 contacts) are resolved by trial decryption.

### 2.3 Nonce

```
nonce = counter (u64, little-endian, 8 bytes) ‖ 00 00 00 00
key   = key(S→R) = HKDF-Expand(prk(S,R), "key" ‖ PK_S ‖ PK_R, 32)
```

Each direction has its own key, so the counter alone makes nonces unique.

### 2.4 AEAD

ChaCha20-Poly1305 (RFC 8439), with the encoded header as associated data
and the concatenated frames as plaintext. See `security.md` §4 for why
there is no separate checksum and the tag is not truncated.

## 3. Frames

```
frame = type:varint  len:varint  body:[len]
```

Every frame is length-prefixed, so a receiver can skip frame types it doesn't
know. A frame type whose meaning would be unsafe to ignore can never be
added this way; it needs a new version byte.

| Type | Name    | Phase | Body |
|------|---------|-------|------|
| 0x00 | PADDING | 1     | Ignored. |
| 0x01 | MSG     | 1     | Message fragment (§3.1). |
| 0x02 | ACK     | 1     | Selective acknowledgement (§3.2). |
| 0x03 | REPAIR  | 4     | Reserved: FEC repair symbol. |
| 0x04 | SYNC    | 5     | Reserved: reconciliation summary. |
| 0x05 | FRAG_ACK| 2     | Per-fragment acknowledgement (§3.3). |
| other| —       |       | Skipped and counted (`frames_unknown`). |

### 3.1 MSG

```
body = seq:varint  count:varint  [index:varint if count > 1]  data:rest
```

- `seq`: the sender's per-conversation message sequence number, dense and
  starting at 0.
- `count`: the number of fragments, ≥ 1. `count = 1` means unfragmented, and
  `index` is omitted.
- `index`: < `count`.
- `data`: the fragment's slice of the encoded message record (§4).
  Fragments are contiguous and in index order; only the last may be shorter.

Semantic errors (`count = 0`, `index ≥ count`, `count > max_fragments`,
inconsistent sizes) drop **that frame** only.

**Reassembly.** The receiver keys partial messages by (contact, seq). If a
fragment arrives with a different `count` than the stored partial, the
sender has re-fragmented (for example because a link with a smaller MTU
appeared). The stored partial is discarded and reassembly restarts. Memory
is bounded by `Config::max_reassembly_bytes`. When that limit is hit, the
least recently updated partials belonging to *other* messages are evicted
first. If the fragment still doesn't fit, it is dropped
(`fragments_dropped_reassembly_full`), and the sender's retransmission
recovers it.

**Receive window.** A `seq` ≥ `cum + max_reorder_window` (§3.2) is dropped
unacknowledged. This bounds receiver state, and the sender keeps
retransmitting. A `seq` already received is acknowledged again but not
redelivered.

### 3.2 ACK

```
body = cum:varint  largest:varint  ack_delay:varint  bitmap:rest
```

- `cum`: all of the receiver's inbound seqs `< cum` have been received.
- `largest`: the largest packet counter received from the peer so far.
- `ack_delay`: milliseconds between that packet's arrival and this ACK being
  sent. Together with `largest`, this gives the peer an RTT sample that isn't
  confused by retransmission (`reliability.md` §3).
- Bit `i` of `bitmap` (byte `i / 8`, LSB first) set means seq `cum + 1 + i`
  was received. Seq `cum` itself is by definition missing.
- Trailing zero bytes are omitted. The sender may cap the bitmap
  (`max_ack_bitmap_bytes`).

An ACK covers the conversation implied by the packet's tag. Seqs the sender
never used are ignored. Senders piggyback an ACK on any packet to the peer
while one is pending, and otherwise send an ACK-only packet after
`ack_delay_ms`.

### 3.3 FRAG_ACK

```
body = seq:varint  count:varint  bitmap:rest
```

Fragments of the partially reassembled message `seq` (fragmented into
`count` pieces) that have arrived. Bit `i` set means fragment `i` is held.
A FRAG_ACK is advisory. The receiver may still evict the partial, so the
sender treats acknowledged fragments as "not needed for now", not "never
needed" (`reliability.md` §2). A sender whose plan for `seq` has a different
`count` ignores the frame.

## 4. Message record

A message's plaintext, carried in MSG fragment data:

```
record = flags:varint  lamport:varint  [timestamp:varint]  [ext_len:varint ext:[ext_len]]  text:rest
```

| Flag bit | Meaning |
|----------|---------|
| 0 | `timestamp` present: the sender's wall clock, in seconds since **2025-01-01T00:00:00Z** (Unix 1735689600). Absent if the sender has no wall clock. |
| 1 | Extension block present. v1 receivers skip `ext` entirely. Its future contents are a TLV list (`type:varint len:varint value`). |
| 2.. | Reserved. Senders set 0, receivers ignore. |

- `lamport`: the per-conversation Lamport clock (§5).
- `text`: UTF-8 that must validate, else the record is malformed. It may be
  empty. Its length is `Config::max_text_len` (default 4096 bytes); a longer
  `text` makes the record malformed.
- A malformed record is dropped **and not acknowledged**. Since the AEAD
  authenticates every fragment, only a buggy or hostile peer can produce
  one. Not acknowledging it keeps the receiver's state unchanged.

The custom epoch keeps timestamps at 4 bytes until 2033 (2²⁸ s).

## 5. Identity, ordering, IDs

```
ConversationId = H_16("avianlink/v1/conv" || min(PK_a, PK_b) || max(PK_a, PK_b))
MessageId      = H_16("avianlink/v1/msg" || PK_s || PK_r || varint(seq) || record)
```

- Message IDs are never sent. Both sides compute them from content, so
  resends and duplicates are idempotent.
- **Ordering** is causal, never by timestamp. On send, `L ← L + 1` and the
  message carries `L`. On receive, `L ← max(L, lamport)`. Messages are
  delivered to the application **in arrival order**, with their Lamport value
  and (seq, sender), so the UI can sort honestly. Ties are broken by sender
  public key.

## 6. Header-overhead budget

Fixed per-packet cost: version 1 + routing tag 3 + counter (typically 2,
5 in the worst case assumed for sizing) + AEAD tag 16 = **22 bytes
typical**. Phase 1–2's placeholder check was 4 bytes, 12 fewer.

The engine sizes fragments for the worst case (5-byte counter). Columns:
`text₁` is the most text that fits in one unfragmented packet (seq < 128,
Lamport < 16384, with a timestamp). `frag` is the fragment payload per packet
for a fragmented message (seq < 128, < 128 fragments). `eff` is
`frag / MTU`. The Phase 2 columns used the 4-byte placeholder check, for
comparison. Generated by the `overhead_table` test in
`avianlink-core/tests/wire.rs`.

<!-- overhead-table:start -->
| MTU | text₁ | frag | eff | text₁ (P2) | frag (P2) | eff (P2) |
|---|--:|--:|--:|--:|--:|--:|
| 48 | 12 | 18 | 37% | 24 | 30 | 62% |
| 51 | 15 | 21 | 41% | 27 | 33 | 64% |
| 64 | 28 | 34 | 53% | 40 | 46 | 71% |
| 128 | 92 | 98 | 76% | 104 | 110 | 85% |
| 222 | 185 | 191 | 86% | 197 | 203 | 91% |
| 255 | 218 | 224 | 87% | 230 | 236 | 92% |
| 512 | 475 | 481 | 93% | 487 | 493 | 96% |
| 1200 | 1163 | 1169 | 97% | 1175 | 1181 | 98% |
<!-- overhead-table:end -->

At 48 bytes the AEAD tag costs a third of the packet. See
`security.md` §4 for why it isn't truncated.
