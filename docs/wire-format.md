# avianlink wire format

> **Status: v1 (Phase 5; Hello added after Phase 7).** Byte 0 values stay
> as listed here until the first release. Before then, peers are assumed to
> run the same build.

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

**Byte 0 is the packet kind.** It selects the whole format of the packet,
including the protocol version: a later, incompatible data format gets a
new kind value, not a version field inside the old one. Receivers drop
kinds they don't know (`packets_dropped_version`), so new kinds are safe to
introduce.

| Kind | Packet |
|------|--------|
| `0x00` | Never valid. |
| `0x01` | v1 data packet (this section). |
| `0x02` | v1 Hello (§2.5). |
| other | Reserved. Drop. |

A v1 data packet:

```
packet  = header  ciphertext  aead_tag:[16]
header  = kind:u8  tag:[3]  counter:varint
ciphertext = ChaCha20-Poly1305(frame*)   (same length as the frames)
```

| Field   | Size  | Meaning |
|---------|-------|---------|
| kind    | 1     | `0x01`. |
| tag     | 3     | Routing tag of the (sender → recipient) direction (§2.2). |
| counter | 1–5   | Per-direction packet counter, strictly increasing, never reused. It gives the AEAD nonce (§2.3). Fragment sizing assumes ≤ 5 bytes (counter < 2³⁵). |
| frame*  | rest  | Zero or more frames (§3), encrypted. Zero frames is a valid keep-alive. |
| aead_tag| 16    | Poly1305 tag over header (associated data) and ciphertext. |

A packet is never larger than the MTU of the link it is sent on. The smallest
valid packet is 21 bytes.

### 2.1 Processing order

1. Length ≥ 21, else drop (`packets_dropped_malformed`).
2. Kind byte: `0x01` continues here, `0x02` goes to §2.5, anything else
   is dropped.
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

### 2.5 Hello

A Hello introduces the sender to a recipient who may not know the sender's
key. It is **not encrypted**, but it is authenticated: only the holder of
the sender's (or the recipient's) secret key can produce it. It always
travels as a datagram of its own, never combined with a data packet.

```
hello = kind:u8 = 0x02  hint:[2]  sender_key:[32]  mac:[12]      (47 bytes)
hint  = H_2("avianlink-hello-hint-v1" ‖ PK_R)
key   = hello_key(S→R) = HKDF-Expand(prk(S,R), "hello" ‖ PK_S ‖ PK_R, 32)
mac   = HMAC-SHA256(hello_key(S→R), kind ‖ hint ‖ sender_key)[..12]
```

| Field | Size | Meaning |
|-------|------|---------|
| kind | 1 | `0x02`. |
| hint | 2 | Identifies the recipient to triage with: the recipient itself, or a relay holding mail for it. About 1 in 65,536 other keys share it. |
| sender_key | 32 | `PK_S`, the sender's public key, in the clear. |
| mac | 12 | Truncated HMAC (`security.md` §2.1). The key binds both public keys, so the MAC also authenticates `PK_R`, which isn't sent. |

47 bytes fits the smallest supported MTU (48). A Hello for a given pair is
the same 47 bytes every time: it has no counter or nonce. That is what makes
it safe to repeat and to replay (`security.md` §6). In v1 a Hello is exactly
47 bytes; any other length is dropped (`packets_dropped_malformed`).
Extensions get a new kind.

**Receiving** (each step drops on failure; the counters are in `Stats`):

1. Length is exactly 47 (`packets_dropped_malformed`).
2. `hint` matches our own (`hellos_dropped_not_for_us`). This is the only
   cost a stray Hello imposes.
3. `sender_key` isn't our own key.
4. **If `sender_key` is a contact:** verify `mac` with the cached
   `hello_key`. That's one HMAC, with no Diffie-Hellman. On success the
   peer is telling us it thinks we don't know it, or that it hasn't heard
   from us, so we answer with an immediate SYNC asking for a reply, at
   most once per RTO per contact (`reliability.md` §7). The Hello does not
   count as a fresh packet: it doesn't end backoff or confirm anything,
   because it can be a replay.
5. **If `sender_key` already has a verified request outstanding** (a
   bounded recent-requests set, which holds only verified keys): drop as a
   duplicate (`hellos_duplicate`). No cryptography.
6. Take a token from the Hello verification bucket (`Config`), else drop
   (`hellos_dropped_rate`).
7. Decode `sender_key` as a point, rejecting invalid and weak keys. Compute
   the X25519 shared secret and `hello_key`, then verify `mac` in constant
   time (`packets_dropped_unauthenticated`).
8. Queue `Event::ContactRequest { public_key, link, received_at }` and add
   the key to the recent-requests set. If the event queue is full, drop
   without recording the key, so a later Hello can retry.

**Sending:** `reliability.md` §3 says when.

## 3. Frames

```
frame = type:varint  len:varint  body:[len]
```

Every frame is length-prefixed, so a receiver can skip frame types it doesn't
know. **Zero bytes after the last frame are padding.** When every byte left at
a frame boundary is zero, parsing ends successfully. FEC (§3.4) relies on
this: a recovered packet keeps the zero padding of its coded symbol. A frame type whose meaning would be unsafe to ignore can never be
added this way; it needs a new kind byte (§2).

| Type | Name    | Phase | Body |
|------|---------|-------|------|
| 0x00 | PADDING | 1     | Ignored. |
| 0x01 | MSG     | 1     | Message fragment (§3.1). |
| 0x02 | ACK     | 1     | Selective acknowledgement (§3.2). |
| 0x03 | REPAIR  | 4     | FEC repair symbol (§3.4). |
| 0x04 | SYNC    | 5     | Reconciliation summary (§3.6). |
| 0x05 | FRAG_ACK| 2     | Per-fragment acknowledgement (§3.3). |
| 0x06 | LOSS    | 4     | Receiver's measured packet loss (§3.5). |
| other| —       |       | Skipped and counted (`frames_unknown`). |

### 3.1 MSG

```
body = seq:varint  frag:varint  data:rest
```

- `seq`: the sender's per-conversation message sequence number, dense and
  starting at 0.
- `frag = 0`: unfragmented. `data` is the whole message record (§4).
- `frag = 1 + (offset << 1 | last)`: `data` is bytes
  `[offset, offset + len)` of the record. `last = 1` marks the final
  fragment, whose end is the record's length.

Fragments are addressed **by byte offset**, so a receiver can combine
fragments from different fragmentations of the same message. That happens
when the sender re-plans: a smaller-MTU link appears, FEC changes the space
available, or the sender restarts. The record's bytes are the same in
every plan. (Phases 1–3 used `count, index`, and fragments from two plans
with equal counts but different sizes spliced into a corrupt record.
D-037.)

Semantic errors drop **that frame** only:
- an empty fragment;
- an end beyond the record limit;
- a final fragment that disagrees with a known length, or with data already
  held beyond it;
- a non-final fragment that reaches the known length.

**Reassembly.** The receiver keys partial messages by (contact, seq). It
copies each fragment to its offset, growing the buffer as needed;
overlaps are harmless. The message completes once the final fragment has
fixed the length and `[0, length)` is covered. Memory is bounded by
`Config::max_reassembly_bytes`, charged at the buffer size. When that
limit is hit, the least recently updated partials belonging to *other*
messages are evicted first. If the fragment still doesn't fit, it is
dropped (`fragments_dropped_reassembly_full`), and the sender's
retransmission recovers it.

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
body = seq:varint  unit:varint  bitmap:rest
```

Which bytes of the partially reassembled message `seq` the receiver holds,
in blocks of `unit` bytes. Bit `i` set means bytes
`[i·unit, (i+1)·unit)` are all held, truncated at the record's length
when it is known. `unit` is the length of
the most recent non-final fragment received, normally the sender's current
fragment size, so the blocks line up with its fragments.

The sender treats fragment `[a, b)` as held when every block that
intersects it is set. That rule is correct for any `unit`. FRAG_ACK is
advisory. The receiver may still evict the partial, so the sender treats
held fragments as "not needed for now", not "never needed"
(`reliability.md` §2).

### 3.4 REPAIR

```
body = base:varint  mask:varint  shape:u8  data:rest
```

A repair symbol for a window of the sender's earlier packets in this
direction (`reliability.md` §6).

- **Sources:** packet counters `base + i` for every bit `i` set in `mask`
  (LSB first). Bit 0 must be set. There are at most 16 sources, and
  `mask < 2³²`.
- **`shape`:** `(m − 1) << 4 | j`. The window has `m` repairs (1–16) and
  this is repair `j < m`.
- **`data`:** `Σᵢ c(m, j, i) · sᵢ` over GF(2⁸), using the polynomial
  `x⁸+x⁴+x³+x²+1` (0x11d).
  - `sᵢ` is the *plaintext* (decrypted frames) of the i-th source, in
    counter order, zero-padded to the length of `data`.
  - `c(1, 0, i) = 1`, so a single repair is plain XOR.
  - For `m > 1`, `c(m, j, i) = (j ⊕ (16 + i))⁻¹`. This is a Cauchy matrix,
    and every square submatrix of a Cauchy matrix is invertible. So any `e`
    missing sources can be recovered from any `e` repairs of the window.
- **Packets:** a packet carrying REPAIR carries nothing else and is never
  itself a source.
- **Recovery:** a recovered source is processed exactly like a received
  packet with that counter. It goes through the replay check, frame
  validation and frame application. Trailing zero bytes are padding (§3).
- **Invalid fields** (bit 0 clear, too many sources, `j ≥ m`) drop the
  frame.

### 3.5 LOSS

```
body = loss_permille:varint
```

Loss the receiver measured on packets from the sender, in parts per
thousand. It counts gaps in the packet counter, before any FEC recovery,
over the most recent ~256 counters. The sender uses it to size FEC
(`reliability.md` §6). It is advisory, and values above 1000 are clamped.

### 3.6 SYNC

```
body   = flags:varint  floor:varint  next:varint  n:varint  digest{n}
digest = block:varint  hash:[8]
```

The sender's view of what it has sent to the recipient in this
conversation (`reliability.md` §7):

- `flags` bit 0: **reply wanted**. The recipient should answer promptly
  with its ACK and a SYNC of its own (without this bit). Other bits are
  reserved and ignored.
- `floor`: the lowest seq the sender can still deliver. Everything below
  has been acknowledged or abandoned and will never be sent again.
- `next`: the sender's next unused seq. Seqs in `[floor, next)` exist.
  `floor ≤ next`, else the frame is dropped.
- `digest`: for up to 4 completed blocks of 64 seqs
  (`[64·block, 64·block + 64)`, all below `next`), the XOR of the first 8
  bytes of the message IDs in the block.

**On receipt:**
- **Floor.** If `floor` is above the receiver's `cum`, the seqs in
  `[cum, floor)` that it doesn't hold are reported once as skipped
  (`Event::MessagesSkipped`), and `cum` jumps to `floor`.
- **Next.** If `next` reveals seqs the receiver hasn't seen, it
  acknowledges at once, so the sender learns exactly what is missing.
- **Digests.** For each digest of a block the receiver holds completely,
  it compares its own. A mismatch is reported once
  (`Event::SyncDiverged`). It means both sides hold different messages
  under the same seqs, for example after a storage rollback.

Each SYNC is self-contained, so any one that arrives makes progress.

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

Fixed per-packet cost: kind 1 + routing tag 3 + counter (typically 2,
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

A Hello (§2.5) is always 47 bytes, whatever the MTU.

At 48 bytes the AEAD tag costs a third of the packet. See
`security.md` §4 for why it isn't truncated.
