# Decision log

Each entry records a significant choice, the alternatives rejected, and why.
Entries are append-only; a reversed decision gets a new entry that references
the old one.

---

## D-001: Sans-IO, `no_std` + `alloc` core (Phase 0)

**Decision.** `avianlink-core` is a deterministic state machine with no I/O,
no clock, no threads, no async. It is `#![no_std]` and uses `alloc`. The host
drives it through `handle_packet` / `send_text` / `handle_timeout` and drains
it through `poll_transmit` / `poll_event` / `next_timeout`.

**Rejected.**
- *Async core (`async fn` over a transport trait).* Ties the core to an
  executor model, makes deterministic simulation harder, and is awkward over
  a C ABI and on bare-metal targets.
- *Heapless core (no `alloc`).* Possible later via fixed-capacity
  collections, but it would push every limit into const generics before we
  know the right shapes. Bounded memory is enforced by configured limits
  instead (see `Config`). We can revisit this once the data structures settle.

## D-002: Dependency: `rand_core` 0.6 (Phase 0)

**Decision.** Randomness is injected as `R: rand_core::CryptoRngCore`, using
`rand_core = "0.6.4"` with default features off.

**Why.** The spec names `CryptoRngCore`. It exists in `rand_core` 0.6, which
is also the version `x25519-dalek` 2.x, `ed25519-dalek` 2.x and the current
RustCrypto AEAD crates use. `rand_core` 0.9 drops `CryptoRngCore` and isn't
yet supported across that stack, so picking it now would mean two copies of
`rand_core` and adapter glue. It's `no_std`, has no dependencies with default
features off, and is maintained by the rust-random org.

**Revisit** when the dalek and RustCrypto crates move to `rand_core` 0.9+.

## D-003: Dependency: `rand_chacha` 0.3 in the simulator (Phase 0)

**Decision.** `avianlink-sim` uses `rand_chacha::ChaCha20Rng` as its seeded
RNG, both for impairments and as the engine's injected CSPRNG in tests.

**Why.** It produces the same stream on every platform for a given seed, which
is what "reproducible from its seed" needs. It also implements `CryptoRng` for
rand_core 0.6 (D-002). The `rand` crate isn't needed. It's a sim-only
dependency and never enters core.

## D-004: Edition 2021, MSRV 1.88 (Phase 0; raised in Phases 1 and 4)

**Decision.** Edition 2021, `rust-version = "1.88"`. It was raised from 1.81
to 1.82 in Phase 1 for `Option::is_none_or`, then to 1.88 in Phase 4 because
`sha2` 0.11 requires it (D-035).

**Why.** 1.81 stabilised `core::error::Error`, so the core can implement the
error trait without `std`. Edition 2021 keeps us buildable on older embedded
and vendor toolchains. Edition 2024 gains us little in a crate like this.

## D-005: Panic-freedom enforced by lints (Phase 0)

**Decision.** Outside `#[cfg(test)]`, the core denies `clippy::unwrap_used`,
`expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`,
`float_arithmetic`, `unreachable`, `todo` and `unimplemented`.
`unsafe_code` is forbidden.

**Why.** Rule 3 ("never panic on network input") is hard to check by review
alone. The lints make every slice index and every `+` on a parsed value a CI
failure unless it uses `get`, `checked_*`, `saturating_*` or `wrapping_*`.
Tests may use `unwrap` freely. Fuzzing (Phase 1+) is the second line of defence.

**Cost.** `arithmetic_side_effects` is noisy for trivially safe arithmetic.
We accept that. A local `#[allow]` with a justification comment is fine where
the bound is clear.

## D-006: API refinements to the spec's signatures (Phase 0)

- `send_text(conversation, text, now)` takes `now`. The message carries a
  timestamp, and core can't read a clock (D-001).
- `poll_transmit` returns `Option<Transmit>` (a struct with `link` and
  `packet` fields), not a bare tuple, so fields can be added later (for
  example a priority hint for the host's radio driver) without breaking
  callers.
- `Timestamp` is a newtype over `u64` milliseconds, not a bare `u64`, so
  durations and instants can't be confused.

## D-007: Clock semantics (Phase 0, open)

**Decision.** Hosts should supply `now` as Unix-epoch milliseconds. The
engine never relies on that for correctness:
- Timers use saturating differences, so a clock that goes backwards
  behaves as "no time has passed" and can't underflow.
- Message timestamps are sender-asserted display metadata. Ordering is
  causal (Lamport/parents), never by timestamp.

**Open question.** Microcontrollers without an RTC can only supply
time-since-boot. Their message timestamps will be meaningless to the peer.
Option: a wire flag "timestamp is not wall-clock" so receivers can display
the time they received the message instead. To be decided in the Phase 1 wire
format.

## D-008: Link budgets modelled as rate or duty cycle with an airtime model (Phase 0)

**Decision.** `LinkBudget` is `Unlimited`, `BytesPerSecond(n)`, or
`DutyCycle { permille, window_ms, airtime }`. The airtime model is
`per_packet_us + per_byte_us * len`.

**Why.** Duty-cycle regulation (for example EU868 at 1%) limits *time on air*,
not bytes. LoRa airtime has a large fixed preamble cost per packet, so a
per-packet + per-byte linear model captures the important behaviour. Small
packets are expensive, which pushes the scheduler to batch. Exact LoRa
symbol math belongs in the host's link adapter, which can pick the
coefficients.

## D-009: Dependency: `sha2` 0.10 (SHA-256) for hashing (Phase 1)

**Decision.** Message IDs, conversation IDs, pair tags and the Phase 1 check
use domain-separated SHA-256 from RustCrypto `sha2 = "0.10"`, with default
features off.

**Why.** Content-addressed IDs need a hash from Phase 1, and Phase 3's HKDF
needs one too. `sha2` 0.10 is `no_std`, audited, and already a transitive
dependency of `ed25519-dalek` 2.x, so it adds nothing to the Phase 3 tree.
SHA-256 is often hardware-accelerated on microcontrollers.
**Rejected:** BLAKE2s/BLAKE3, which are faster in software but would be an
extra hash implementation alongside the SHA-512 that Ed25519 already pulls in.

## D-010: Pair routing tag instead of a recipient-only tag (Phase 1, proposal)

**Spec said:** "a few bytes of a hash of the recipient's key".
**Decision:** `tag = H_3(label || PK_sender || PK_recipient)`.

**Why.** With a recipient-only tag, the recipient must try every contact's
pairwise key on every packet, because the tag says nothing about the sender.
That costs O(contacts) per packet, a real DoS lever on a microcontroller. A
pair tag narrows the candidates to about one. It also leaks less: an
observer who knows someone's public key can't spot packets addressed to
them without also knowing the sender's key. Collisions are resolved exactly
as the spec intended, by trial verification/decryption. The cost is
identical (3 bytes).

**Phase 3 follow-up:** derive the tag from the pairwise secret, so that
knowing both public keys doesn't let an observer link packets to the pair.

## D-011: Keyed 4-byte check as a Phase 1 stand-in for the AEAD tag (Phase 1)

Phase 1 is plaintext, but the simulator flips bits, so packets need
integrity. A 4-byte `H(label || PK_s || PK_r || packet)` fills the AEAD
tag's slot. It catches corruption and resolves tag collisions the same way
trial decryption will. It is explicitly **not** authentication.

## D-012: Packets are sequences of length-prefixed frames (Phase 1)

QUIC-style frames (`type, len, body`) let ACKs piggyback on data, let
several small messages share a packet, and let old peers skip new frame
types. The extra length byte per frame is the price of forward
compatibility. **Rejected:** a fixed packet-type byte with a type-specific
layout, which would mean one message or ACK per packet and no skipping of
unknown content.

## D-013: Dense per-sender sequence numbers plus a Lamport clock (Phase 1)

Each sender numbers its messages densely per conversation. Dense numbers
make ACKs a cumulative value plus a bitmap, and bound receiver state with a
window. A content hash can't give us either. The Lamport clock carries
causality across both directions. Message IDs stay content-addressed and
are computed rather than sent (16 bytes saved per message).

## D-014: Timestamps are optional, in seconds since 2025-01-01 (Phase 1)

This resolves D-007. Seconds are enough for display. The custom epoch keeps
the varint at 4 bytes until 2033. A host without a wall clock sets
`Config::wall_clock = false`, and its messages omit the timestamp entirely.

## D-015: Pacing admits a packet only if a worst-case (MTU-sized) packet fits the budget (Phase 1)

The engine checks the budget for an MTU-sized packet, then charges the
actual size. This keeps the budget check side-effect free (no "build, then
un-build"). It guarantees compliance and wastes at most one MTU of budget
headroom. Byte-rate budgets use a token bucket. Its capacity is
max(MTU, one second of rate).

Duty-cycle budgets use an **exact sliding log** of (time, airtime), not a
token bucket. A token bucket with capacity C and refill C/T admits up to 2C
in a window T, which would break regulations such as EU868's 1%/hour. The
log is bounded by `max_duty_log_entries`. When it is full, the link is
treated as out of budget until the oldest entry ages out.

The duty pacer also models the radio being busy. Each packet is logged at
its on-air *start*, `max(now, busy_until)`, and is not admitted before then.
Without this, a burst admitted at one instant is serialized over many
seconds, and the on-air times can creep past the window the engine checked.

## D-016: Dependency: `proptest` (dev-only) (Phase 1)

`proptest = "1"` is a dev-dependency for property tests (encode/decode
round-trips, reassembly under arbitrary order/duplication). It never enters
the `no_std` build graph.

## D-017: Fragment once, at the minimum registered MTU, on first transmission (Phase 1)

Retransmitted fragments must line up with what the receiver already holds,
so a message is split once, sized for the smallest MTU among the registered
links. It is re-split only if a link that can't carry the existing fragments
is added. The receiver detects the change (a different `count`) and
restarts reassembly. **Rejected:** per-link fragmentation, which would
discard partial progress every time the route changes.

## D-018: Phase 1 ACKs are per message, not per fragment (Phase 1)

When an RTO fires, the sender resends every fragment of an unacked message.
The receiver keeps partials across rounds, so delivery still converges, but
long messages waste bandwidth under loss. Phase 2 should either add
per-fragment acknowledgement for multi-fragment messages, or leave the
problem to Phase 4 FEC. This will be decided from simulator data.

## D-019: Fuzzing on nightly, outside `ci.sh` (Phase 1)

`cargo-fuzz` needs a nightly toolchain. The fuzz crate lives in `fuzz/`,
outside the workspace, and runs via `scripts/fuzz.sh`, so the stable CI gate
stays stable-only. `ci.sh` builds the fuzz targets' shared harness code as
an ordinary test (`fuzz_harness` in avianlink-core's tests), so it can't rot.

## D-020: Due fragments are served oldest-due first, not in seq order (Phase 1)

The first simulator run found congestion collapse on `lora_like`. With
fragments chosen in seq order and an RTO (4 s) shorter than one duty-cycle
slot (~37 s), the lowest seqs were due again at every slot. They starved
everything behind them: 143 packets per message, about 3% delivered in 30
days. Ordering by `next_send` makes the backlog a round-robin, and new
fragments inherit their message's queue time. The same overloaded run now
delivers everything. Phase 2's adaptive RTO attacks the root cause
(spurious retransmission). This ordering stays as the fairness rule.

## D-021: Simulator workloads respect link capacity by default (Phase 1)

Default scenarios send 1000 messages, one every 30 s on average.
`lora_like` uses one every 10 minutes: its 1% duty cycle carries roughly
3 KB/hour, about 1/30 of the default offered load. Overload still has its
own test (`overloaded_lora_drains`), which checks that the backlog drains
rather than collapses.

## D-022: Packet-level RTT samples via `largest` + `ack_delay` in ACK (Phase 2)

ACKs name the largest packet counter received and how long ago it arrived,
in QUIC style. Every ACK yields an unambiguous RTT sample, even for
messages that were retransmitted. Karn's algorithm would discard those
samples, and under 35–50% loss most messages are retransmitted at least
once. Cost: about 2–4 bytes per ACK.

## D-023: Per-contact backoff with probes instead of per-fragment backoff (Phase 2)

Phase 1 resent every outstanding fragment each RTO, straight into outages.
Phase 2 tells loss (progress continues) from unreachability (no progress
since the send). When the peer looks unreachable, the contact sends one
probe packet per doubling interval, capped at `max_rto_ms`, and leaves
backoff on the first authenticated packet from the peer. **Rejected:**
independent exponential backoff per fragment. It still sends N fragments per
interval, and each fragment backs off on a different clock, so recovery
after an outage is slow and ragged.

## D-024: Soft per-fragment acknowledgement (FRAG_ACK) (Phase 2)

This resolves D-018. Message-level ACKs alone resend every fragment of a
long message each round. At a 64-byte MTU a 1200-byte message is about 26
fragments, and at 50% loss that means roughly 6 rounds × 26 sends. FRAG_ACK
reports which fragments the receiver holds. It is advisory, because the
receiver's reassembly memory is bounded and may evict. The sender therefore
re-arms acknowledged fragments after `max_rto_ms`, so eviction costs
latency, never liveness.

## D-025: Storage batches are required trait methods; the engine owns its durable state (Phase 2)

`Storage` gains `begin`/`commit`/`rollback` and `scan_prefix`. All of them
are required; none has a no-op default. A host without transactions has to
decide, visibly, what atomicity it offers. The engine persists contacts,
outbox, receive windows, Lamport clocks, counter reservations and pending
events, and `Engine::restore` rebuilds from them. Hosts no longer need to
replay `add_contact` after a restart, and `contacts()` lists what was
restored. (This overlaps desktop-app requests AR-006 and AR-008.) Links
stay host-owned and are re-registered after restore.

## D-026: Events are persisted until polled (Phase 2)

An event is committed in the same batch as the state change that causes
it, and removed when the host polls it. Without this, either side of a
crash loses something. Acknowledge, then crash before the host sees the
message: the message is lost. Redeliver after the crash: duplicates. The
remaining window, between `poll_event` returning and the host persisting
the event, is documented as the host's responsibility.

## D-027: `send_text` returns `Queued { id, seq, lamport }` (Phase 2)

The application has to interleave its own messages with received ones by
Lamport value, and only the engine knows the value it assigned. This is
part of Phase 2's causal-ordering work, and also satisfies desktop request
AR-001. `ReceivedMessage` gains `missing_before`, so out-of-order arrival is
visible rather than hidden.

## D-028: Retransmission timer defaults tuned in the simulator (Phase 2)

The first Phase 2 build used RFC 6298 as written (`srtt + 4·rttvar`) with a
120 s backoff cap. It cut `disaster_cellular` traffic 6.5× but more than
doubled its latency. Pareto-tailed delay inflates `rttvar`. And at one
message every 30 s, a single loss looks like silence, so the sender dropped
into backoff during uptime too. Sweep over 10 seeds × 1000 messages
(medians of per-seed values):

| variant | p50 | p95 | p99 | wire/payload |
|---|--:|--:|--:|--:|
| Phase 1 (fixed 4 s RTO, no backoff) | 5.3s | 6.5m | 10.6m | 23.9 |
| RFC: 4·var, cap 120 s, no grace | 39.1s | 13.2m | 19.1m | 3.65 |
| cap 30 s | 17.1s | 7.5m | 11.6m | 4.45 |
| 2·var | 33.1s | 13.1m | 24.7m | 3.87 |
| 2 grace probes | 25.2s | 11.4m | 21.2m | 3.78 |
| **2·var, cap 30 s, 2 grace probes (chosen)** | **8.4s** | **7.5m** | **11.3m** | **4.75** |
| 1·var, cap 30 s, 3 grace | 7.2s | 7.2m | 12.0m | 5.04 |
| 2·var, cap 15 s, 3 grace | 7.2s | 7.1m | 11.2m | 5.95 |
| 1·var, cap 10 s, 3 grace | 5.5s | 6.5m | 11.3m | 7.04 |

The chosen point keeps p95/p99 within about 15% of Phase 1 at a fifth of
the bytes. It is also the knee: going further buys little latency for a
lot of bandwidth. On the other profiles it is neutral or better (see the
Phase 2 report). All three knobs are `Config` fields
(`rttvar_multiplier`, `max_rto_ms`, `backoff_grace`) for hosts with
different priorities.

**Link-aware probe floor.** A 30 s probe interval would spend more than a
1% duty cycle's entire budget on a LoRa link. So the probe interval is
never below 10× the budget time one MTU-sized packet costs on the
contact's link: probing uses at most about 10% of the budget.

## D-029: Cryptography dependencies (Phase 3)

| Crate | Version | Why |
|---|---|---|
| `ed25519-dalek` | 2.x | Identity keys; `VerifyingKey::to_montgomery` and `SigningKey::to_scalar_bytes` give the X25519 form without custom math. |
| `curve25519-dalek` | 4.x | `MontgomeryPoint::mul_clamped` for X25519 on converted keys. Already a dependency of `ed25519-dalek`. |
| `chacha20poly1305` | 0.10 | RFC 8439 AEAD, constant-time, `no_std`, audited (NCC 2020). |
| `hkdf` | 0.12 | RFC 5869 over the `sha2` 0.10 already in the tree. |
| `zeroize` | 1.x | Wipes derived keys and identity secrets on drop. |

All are `default-features = false`. **Rejected:** `x25519-dalek`, which
can't consume Ed25519 secrets without re-implementing the conversion that
`ed25519-dalek` already exposes. XChaCha20-Poly1305 is unnecessary because
nonces come from counters and are never random. `ring` is not `no_std`.

## D-030: One Ed25519 identity, used for X25519 too (Phase 3)

See `security.md` §2. Identities are shared once, out of band, and are
expensive to change. Choosing Ed25519 now keeps signatures available later
without a new identity format.

## D-031: Routing tags derived from the shared secret (Phase 3)

This is the D-010 follow-up. Outsiders who know both public keys can't
compute the tag. Tags stay static per direction (linkable). Rotating tags
per counter epoch is possible later, because the receiver could precompute
a small window. It is deferred until there is a metadata requirement worth
the complexity.

## D-032: The full 16-byte Poly1305 tag; no pre-decryption checksum (Phase 3)

See `security.md` §4. At a 48-byte MTU this costs 12 bytes more per packet
than Phase 2's placeholder. The overhead table in `wire-format.md` §6 shows
the result.

## D-033: Sequence numbers capped at 2³⁵, `max_fragments` raised to 512 (Phase 3)

With a 16-byte tag, the frame space at a 48-byte MTU drops to 23 bytes.
Config validation sized fragments for a worst-case 10-byte seq varint. That
made a 4096-byte message need over 600 fragments, so defaults that fit the
spec failed validation. Seqs are now capped at 2³⁵−1 per conversation
(`send_text` returns `Exhausted` beyond it; at one message per second that
is over a thousand years), which bounds the seq varint at 5 bytes. The
fragment limit becomes 512, and reassembly bounds memory regardless.

## D-034: Desktop API requests taken up in Phase 3

- **AR-002, accepted with changes.** `Event::MessageTransmitted { conversation, id }`
  fires once per message per engine incarnation, on its first
  transmission. It is **not persisted**, because one storage write per
  transmission is too costly. If the event queue is full it is skipped.
  Retry counts come from a query instead: `Engine::outgoing(conv)` returns
  per-message transmission counts and the fragments the peer holds. That
  avoids an event per retransmission.
- **AR-003, declined as specified.** There is no age-based give-up, because
  silence for days is normal and a "failed" state would usually be a lie.
  `remove_contact` abandons a contact's undelivered messages explicitly and
  returns their IDs, so the host can mark them. An opt-in age limit can be
  added if a host shows it needs one.
- **AR-004, accepted unchanged:** `PublicKey::fingerprint` and
  `format_fingerprint`, as defined by desktop DA-009.
- **AR-005, accepted.** `remove_contact(conv) -> Result<Vec<MessageId>, Error>`
  deletes the contact and its outbox, receive window and reassembly
  partials in one batch. `contacts()` already existed (Phase 2), and
  `contact_key(conv)` is added.
- **AR-007, accepted as queries:** `link_stats(link)` (packets and bytes
  in/out, drops, `budget_blocked_until`) and `contact_status(conv)`
  (`last_heard`, smoothed RTT, `unreachable`, outbox size). `last_heard`
  counts every authenticated packet, ACK-only packets included.

## D-035: Upgrade to the rand_core 0.10 / RustCrypto 0.11 generation (Phase 4)

This supersedes the "revisit" note in D-002. Library crates now use
`rand_core` 0.10, `rand_chacha` 0.10, `sha2` 0.11, `ed25519-dalek` 3,
`curve25519-dalek` 5, `chacha20poly1305` 0.11 (`AeadInOut`), `hkdf` 0.13,
`zeroize` 1.9 and `proptest` 1.12. The engine's RNG bound changes from
`CryptoRngCore` to `rand_core::CryptoRng`.

**Verification.** The 20-seed sweep over all scenarios is unchanged.
Profiles that took no Phase 3 follow-up fixes reproduce bit-for-bit, so
the RNG streams and key derivations are identical. The `no_std` tree has
one copy of each crate.

**Workspace coupling.** `apps/desktop` inherits `rand_core`, `rand_chacha`
and `sha2` from `[workspace.dependencies]`, with `rand_core`'s `getrandom`
feature, which 0.10 removed. Changing those shared entries would break
dependency resolution for the whole workspace. So they stay at the old
versions, and the library crates pin their own. When the desktop app
migrates, the shared entries should move to the new versions and the
per-crate pins can go. Until then the lockfile carries both generations of
those three crates, but never inside the library's graph.

*Resolved (Phase 5):* the desktop app moved to its own repository, and the
shared entries are back in `[workspace.dependencies]` at the new versions.

## D-036: FEC codes decrypted packet plaintexts, with Cauchy Reed-Solomon over GF(2⁸) (Phase 4)

**What is coded.** Packet plaintexts (frames) are coded, not ciphertexts or
message bytes. A recovered plaintext then enters the normal frame path,
and the repair itself is authenticated like any packet, so FEC adds no
trust assumptions. **Rejected:** coding ciphertexts. A repair would then
have to be a raw, unauthenticated packet type, and a recovered packet
would need a second AEAD pass. Coding message bytes would not help the
common single-packet message.

**The code.** A single repair uses the all-ones row, which is plain XOR, as
the spec's "start with parity" asks. Multiple repairs use a Cauchy matrix:
every square submatrix is nonsingular, so *any* `e` repairs recover *any*
`e` losses. A Vandermonde code has to be made systematic to give that
guarantee. GF(2⁸) arithmetic is a 300-line integer module with log/exp
tables built at compile time, so no dependency is needed.

**Trailing zeros are padding** (wire §3), so symbols need no length prefix.
That saves 2 bytes per repair.

**Loss is measured by the receiver** from counter gaps and reported in a
LOSS frame. The sender can't see packet loss directly: ACKs are per
message. Losses are counted *before* FEC recovery. Otherwise FEC would hide
the loss that justifies it and switch itself off.

**Rejected:** a fountain code (the spec defers it); interleaving windows
across time, which adds latency at sparse traffic and should only be
reconsidered if burst losses dominate in measurements.

## D-037: Fragments addressed by byte offset (Phase 4; fixes a latent Phase 1 bug)

**Bug.** MSG fragments carried `(count, index)`. The receiver detected
re-fragmentation only when `count` changed (D-017). Two plans with
different fragment sizes can share a count: a 30-byte record splits as
19+11 or as 29+1. The receiver then spliced fragments from both into a
corrupt record. It was usually still valid UTF-8, so it was delivered
under a wrong ID and *acknowledged*, and the real message was lost.

**Exposure.** In Phases 1–3 it needed a new, smaller-MTU link while a long
message was in flight, and no test did that. Phase 4 made it reachable,
because FEC changes the planning space and a restarted sender re-plans
without it. The simulator caught it as integrity violations in
`harsh_64_crashy` with FEC on (7 lost messages in 20,000).

**Fix.** Fragments carry their byte offset, plus a flag on the final one
(wire §3.1). The receiver copies bytes to their offsets, so any mix of
plans reassembles correctly. The final fragment fixes the length, so
`total` needn't be repeated: the encoding is no larger than the old
`count, index`. Unfragmented messages keep a single `0` byte. FRAG_ACK
reports coverage in byte blocks. **Rejected:**
always planning with the FEC reserve, which would only hide this instance
and cost about 8 bytes per fragment on every link; adding a plan ID, which
would still discard partial progress on every re-plan.

## D-038: FEC policy: budget gates, repair credit, Reed-Solomon by default (Phase 4)

These are the measurements behind the policy in `reliability.md` §6. All
use `bursty_loss` (`disaster_cellular`'s ~35% Gilbert-Elliott loss,
heavy-tailed delay, no outages) unless noted. Values are medians over 10–20
seeds.

**1. Gate on link budget.** The first version used FEC wherever loss was
reported. On `lora_like` (1% duty) p95 went from 9 minutes to 2.5 hours,
because repairs spent airtime that data needed. On `geo_satellite` it cost
+38% for no gain. FEC now requires one MTU-sized packet to cost at most
`fec_max_packet_cost_ms` (2 s) of the link's budget, which rules out
duty-cycled LoRa.

**2. Repair credit.** Rounding every window up to at least one repair
meant a full duplicate per lone packet at any loss rate. Windows now
accrue `k·1.5·p/(1−p)` of credit and send whole repairs out of it. That
brought `geo_satellite`'s cost from +38% to +5%. A factor of 1.0 or 0.7
instead of 1.5 saved under 10% of bytes but lost 10–15% of the p95 gain.

**3. Spare budget only.** On a near-saturated link (one long message per
second, about 75% load), both codes made p95 *worse* than no FEC (XOR 1.8m
vs 1.4m off), because repairs queued ahead of data. Repairs are now
dropped unless a further MTU packet would fit straight after. With that
gate, Reed-Solomon improves the saturated case (p95 1.2m vs 1.4m).

**4. Reed-Solomon vs XOR depends on fragments per message.**

| workload | p95 off | p95 XOR | p95 RS | bytes, RS vs XOR |
|---|--:|--:|--:|--:|
| chat mix (mean ~100 B), MTU 256 | 51.0s | 33.0s | 36.8s | +3% |
| ~190 B messages, MTU 51 | 1.2m | 32.4s | **24.4s** | +16% |
| ~190 B messages, MTU 64 | 1.2m | 43.1s | **26.2s** | +20% |
| ~190 B messages, MTU 128 | 1.2m | 52.8s | **42.8s** | +18% |
| ~190 B messages, MTU 256 | 1.1m | 39.2s | 38.5s | +9% |
| 300–1200 B bulk, MTU 256 | 21.9s | 17.2s | **15.5s** | +2% |

When one message spans several packets, a window often loses two or more,
and only Reed-Solomon recovers that. The expected workload is messages
averaging 200 bytes or more over small-MTU links, so **Reed-Solomon is
the default**. XOR stays available for short-message chat over larger
MTUs.

**Not done:** interleaving windows over time. In this simulator,
Gilbert-Elliott bursts take out a window's sources and its repairs
together. Real fading is time-correlated, and spacing repairs out could
help there. It needs a time-based burst model to evaluate.

## D-039: Sync as floor/next/cum/bitmap plus block digests, not general set reconciliation (Phase 5)

**Spec said:** reconcile via compact summaries, starting with
per-conversation hash ranges, with range-based set reconciliation later.

**Decision.** In a pairwise conversation each sender's seqs are dense, so
one direction's state *is* the four values (floor, next, cum, bitmap).
That is an exact summary, smaller than any hash structure. The ACK
already carried the receiver's half. SYNC now carries the sender's half,
plus XOR digests over 64-seq blocks. Those are the "per-conversation hash
ranges": cheap, and they detect what the dense summary can't, namely two
sides holding *different* messages under the same seqs.

**Why not set reconciliation now.** It earns its complexity when there is
no shared order: groups with many senders, multi-device histories. Those
aren't v1 features. The SYNC frame and `Event::SyncDiverged` leave room for
it: a future frame type can carry range summaries for group conversations
without changing pairwise sync.

**Divergence is detected, not repaired.** Repair needs both sides to keep
message histories (v1 deletes delivered messages from the outbox) and a
way to re-sequence. Both are outside v1.

## D-040: Bounding the cost of long silence: probe interval follows the silence; deep probes are bare SYNCs (Phase 5)

Phase 2–4 probes resent the oldest data fragment every `max_rto_ms` (30 s)
forever. A week offline cost one contact 20,165 packets (3.43 MB, measured
through the public API on commit 8be22d8), and the done criterion asks for
bounded bytes.

**Now.**
- Once a silence outlasts the short-term doubling, the probe interval is
  1/64 of the silence so far, between `max_rto_ms` and
  `max_probe_interval_ms` (1 h).
- After `deep_backoff_after_ms` (1 h) of silence, probes carry only a bare
  SYNC (reply wanted) instead of data.
- Data probes append a SYNC when there is room left after the data.

**How this was chosen.** The tests were the simulator, 60 paired seeds
against the Phase 4 build, plus `week_offline`.

| variant | harsh_64 p95 (P4: 46.4m) | week offline, bytes while down (both peers; P4 ≈ 6.8 MB) |
|---|--:|--:|
| fixed: 30 s for 1 h, then doubling to 1 h | 102m, days on some seeds | ~26 KB |
| interval = silence/16 | 102m | 20–26 KB |
| **interval = silence/64** | **47.0m** | **47–80 KB** |
| interval = silence/128 | 46.4m | 67–105 KB |

The fixed schedule failed badly on `harsh_64`, whose link is up 13% of the
time in 90-second windows. After one rare outage over an hour, both peers
probed hourly. Each probe had about a 6% chance of landing in an up window
and surviving 50% loss, so reconnecting took hours and on some seeds days.
Probing in proportion to the silence keeps flaky links found quickly and
dead links cheap.

**Probe content, measured:**
- *SYNC-only probes from early backoff:* +25% `bursty_loss` p95. Recovery
  from two consecutive losses waited a round trip for the peer's reply.
- *SYNC in every data probe:* hurt `lora_like`, because at a 51-byte MTU it
  halved the data per probe. Appending it only when there is room keeps
  both.

**Rejected:** unbounded doubling. Bytes would be logarithmic in the outage
length, but return latency could reach days. `nudge()` lets hosts that
know connectivity changed skip the wait entirely.

## D-041: Simulator workload re-based to ~200-byte messages (after Phase 5)

**Decision.** The default message mix is now 45% short (5–80 B), 42%
medium (80–300 B) and 13% long (300–1200 B). The measured mean is 199.6
bytes, the expected real workload. The old mix (80/15/5, about 100 B) is
kept as `LengthMix::LEGACY`. `Scenario::legacy_workload()` restores it,
and the Phase 3 overhead-regression test uses it, because it pins seed-1
numbers from that time.

**LoRa interval.** At the old 10-minute interval, 200-byte messages
overload a 1% duty cycle: about 10 fragments each at a 51-byte MTU, and p95
over a day. `lora_like` now sends one message every 25 minutes, which
keeps its airtime utilization where it was. Measured p95: 22.9m at 20 min,
11.1m at 25 min, 6.2m at 30 min.

**FEC default re-checked** on the new workload, with 60 paired seeds, XOR
vs Reed-Solomon:

| scenario | p95 XOR → RS | p50 XOR → RS | bytes RS vs XOR |
|---|--:|--:|--:|
| bursty_loss, MTU 64 | 42.9s → 31.5s (RS better on 50/60) | 3.3s → 1.6s (60/60) | +15% |
| bursty_loss, MTU 51 | 35.9s → 26.3s (47/60) | 5.1s → 3.6s (60/60) | +14% |
| bursty_loss, MTU 256 | 38.3s → 40.7s (tie) | 1.0s → 1.0s | +4% |
| disaster_cellular, harsh_64 | tie | tie | +2–4% |

Reed-Solomon stays the default (D-038). It is clearly better where
messages span several packets, and within a few percent elsewhere.

**New baseline** (20 seeds, medians of per-seed values, default config):

| scenario | delivered | p50 | p95 | p99 | wire/payload | pkts/msg |
|---|--:|--:|--:|--:|--:|--:|
| clean | 100% | 5ms | 5ms | 5ms | 1.31 | 2.00 |
| geo_satellite | 100% | 318ms | 428ms | 23.9s | 1.49 | 2.17 |
| edge_2g | 100% | 414ms | 1.8s | 38.6s | 2.02 | 3.13 |
| disaster_cellular | 100% | 7.3s | 6.8m | 11.6m | 5.14 | 8.00 |
| lora_like | 100% | 3.1s | 11.1m | 49.2m | 5.04 | 24.64 |
| harsh_64 | 100% | 12.1m | 57.5m | 1.2h | 8.64 | 32.20 |
| harsh_64_crashy | 100% | 10.7m | 53.4m | 1.2h | 9.71 | 34.81 |
| disaster_hostile | 100% | 9.0s | 7.2m | 12.4m | 5.61 | 9.06 |
| bursty_loss | 100% | 1.0s | 43.5s | 2.0m | 4.51 | 8.23 |
| week_offline | 100% | 2.5d | 6.6d | 6.9d | 1.94 | 2.08 |

Wire bytes per payload byte drop on every profile compared with the
100-byte workload: fixed per-packet and per-ACK costs are spread over
more payload. Packets per message rise with fragmentation.

## D-042: Host-side choices for the UDP adapter and CLI (Phase 6)

- **Dependency: `getrandom` 0.4,** used only to seed ChaCha20 (rand_chacha,
  already in the tree) from the OS. **Rejected:** `rand::rngs::OsRng`. That
  is the whole `rand` crate for one function.
- **`FileStorage` is a write-ahead log in one file** (`hosting.md` §2):
  one checksummed record per batch, `fsync` on commit, truncate the tail on
  recovery, and compact by rename. That is atomic batches with no
  dependency. **Rejected:** `sled`, which is large and its future is
  uncertain; SQLite, a C dependency and too much for a demo. Hosts with a
  database should implement `Storage` over it.
- **`Engine::handle_packet` now returns the authenticated sender's
  `ConversationId`,** or `None` for a dropped packet. Hosts on
  point-to-point transports need it to keep the address book current under
  NAT rebinding, and only authenticated packets may move an address.
  Returning a value is non-breaking for callers that ignore it.
- **The CLI depends on `avianlink-sim`** for named profiles
  (`Profile::link().engine_link()`), so a chat over netem uses the same MTU
  and budget the simulator was tuned with.
- **Desktop request AR-009 accepted.** `impair::Channel` and `Outages` are
  public, with `Jitter::sample`, because `udp-impair` needs exactly what the
  desktop app asked for: the simulator's impairment model, driven in real
  time.

## D-043: The C ABI wraps the sans-IO engine; `unsafe` is confined to `avianlink-ffi` (Phase 7)

- **Why the engine, not `UdpHost`.** The C ABI is the basis for iOS and
  other mobile bindings. Those hosts own their transports and their
  database, and the engine's sans-IO shape is what lets them. `UdpHost` is
  a convenience for desktop demos.
- **Storage across the boundary.** File (the Phase 6 write-ahead log),
  memory, or a callback vtable, so an app can use its own encrypted store.
  Callbacks must give the same atomicity and durability guarantees as Rust
  `Storage` implementations.
- **`unsafe`.** The workspace denies `unsafe_code`. `avianlink-ffi` allows
  it, because dereferencing C pointers needs it. Every unsafe block states
  its precondition. `avianlink-core` keeps `forbid(unsafe_code)`.
- **Errors and panics.** Status codes plus a thread-local detail, and
  `catch_unwind` on every entry point, so unwinding never crosses into C.
- **Tooling.** `cbindgen` (a CLI, not a build dependency) generates
  `include/avianlink.h`, and CI fails if the checked-in header is stale. The
  C example and the Swift smoke test link against the real static library.
- **Scope (per the user).** The microcontroller example is deferred. The
  core's `thumbv7em-none-eabihf` build stays in CI meanwhile.
- **Enums from C are integers.** `AvlConfig.fec` and `AvlLinkConfig.budget`
  are `uint8_t`, validated on the Rust side. A `repr(C)` enum field written
  by C with an unknown value would be undefined behaviour in Rust before any
  check could run. Enums Rust only returns stay C enums.
- **`size_t`, not `uintptr_t`.** cbindgen's default maps `usize` to
  `uintptr_t`, which Swift imports as `UInt` and every `count` would need a
  cast. `usize_is_size_t` gives `Int`.
- **XCFramework without `xcodebuild`.** The build script falls back to
  writing the bundle (slice directories plus `Info.plist`) when
  `xcodebuild -create-xcframework` fails. The development machine's Xcode
  could not load its simulator plug-in, and Command Line Tools installs
  have no `xcodebuild` at all. The Swift smoke test consumes the result
  through SwiftPM's `binaryTarget`, which validates the bundle either way.

## D-044: Hello: unencrypted, authenticated contact requests (after Phase 7, proposal)

**Problem.** Pairwise keys need no exchange, since each side derives them
from the other's public key. But a receiver that doesn't know the sender's
key can't find a routing tag for it and drops everything silently. Relays
and gateways coming online must register clients, and each other, without
every pair having swapped keys first. Specified in `wire-format.md` §2.5,
`security.md` §2.1, §6, §8 and §9, and `reliability.md` §3, §4 and §7.

**Decisions.**
- **Byte 0 is the packet kind** (`0x01` data, `0x02` Hello). Old receivers
  already drop unknown values. **Rejected:** a reserved routing-tag value
  (real tags would collide with it, and it special-cases the lookup); a
  Hello frame inside a data packet (the receiver can't decrypt it without
  the key the Hello is meant to deliver).
- **A Hello always travels alone.** **Rejected:** prepending it to a data
  packet in the same datagram. That saves a round trip on UDP but couples
  the two formats, and it doesn't work on small links anyway.
- **Unencrypted, MAC-authenticated, 47 bytes:** kind, a 2-byte recipient
  hint, the sender's key, and a 12-byte truncated HMAC-SHA256 under a key
  from the existing static Diffie-Hellman. It fits the 48-byte minimum MTU,
  per the user's requirement. **Rejected:** an Ed25519 signature (+64 bytes);
  a Noise-`X` sealed Hello (~97 bytes) that hides the sender (doesn't fit
  small links, and the user's goal is reliability over metadata privacy,
  §8); a 4-byte hint (53 bytes, over LoRa's MTU).
- **Dependency: `hmac` 0.13,** already in the tree as a dependency of
  `hkdf`, so no new code. It is used directly for its constant-time
  truncated verify. **Rejected:** truncating a Poly1305 tag (the audited
  AEAD crate doesn't verify truncated tags, and composing the parts
  ourselves is out, D-032).
- **No counter, so replayable on purpose.** Hellos are idempotent: a
  replay can only re-raise a request or draw one SYNC. Consequently **a
  Hello never moves an address.**
- **Unconfirmed contacts start in backoff,** sending a Hello plus one probe
  packet per round until the peer answers. Accepting a recent request
  sends an immediate SYNC that ends the peer's backoff. (Implementation
  note: the spec first sent that SYNC on every `add_contact`. That was
  redundant, because an unconfirmed contact already probes at once, and
  wasted with Hellos off. So it is now limited to contacts that start
  confirmed.)
  **Rejected:** buffering unknown-tag packets at the receiver and replaying
  them after acceptance. It saves about one RTT, but the buffer is memory
  any attacker can fill.
- **Hellos in backoff too** (default), so a relay that restarts empty
  relearns its clients within one probe interval.
- **The engine reports requests; the host decides.** No auto-accept in the
  engine.

**API (proposed; breaking).**
- `Engine::handle_packet` returns a new `Received` enum instead of
  `Option<ConversationId>`:
  - `None`;
  - `Contact(ConversationId)`, an authenticated data packet, after which
    the address may be updated;
  - `Hello(PublicKey)`, a verified Hello from an unknown key, whose
    address is a candidate only.
- `Event::ContactRequest { public_key, link, received_at }`, persisted
  until polled like other events.
- `Config`:
  - `hello: HelloMode` (`Off`, `Unconfirmed`, `UnconfirmedAndBackoff`;
    default `UnconfirmedAndBackoff`);
  - `hello_verify_per_minute` (default 60; 0 disables receiving Hellos
    from unknown keys);
  - `hello_verify_burst` (default 8);
  - `hello_dedupe_entries` (default 64).
- `Stats`: `hellos_sent`, `hellos_received`, `hellos_duplicate`,
  `hellos_dropped_not_for_us`, `hellos_dropped_rate`. Bad MACs count in
  `packets_dropped_unauthenticated`. `packets_dropped_version` keeps its
  name and now counts unknown kinds.
- `ContactStatus::confirmed: bool`.
- Storage schema 3 → 4 (`reliability.md` §4).
- C ABI: `avl_engine_handle_packet` gains a public-key output and returns
  a new `AVL_STATUS_HELLO` for verified Hellos, plus an
  `AVL_EVENT_KIND_CONTACT_REQUEST` event. `UdpHost` keeps candidate
  addresses for pending requests. The CLI prints requests and gains
  `/accept`.
- The desktop app (`avianlink-desktop`) breaks on the `handle_packet`
  return type and the new event. It must be told.

**Tests and done criteria.**
- Wire: round-trip and proptests for Hello encoding. The fuzz targets'
  harness gains a "valid Hello" mode.
- Engine:
  - each receive step's drop counter;
  - replays don't move addresses or duplicate requests;
  - the verification bucket bounds X25519 operations;
  - requests survive restore;
  - migration from schema 3.
- New simulator scenarios:
  - `introduction`: Bob doesn't know Alice and auto-accepts; on
    `disaster_cellular` and `lora_like`;
  - `relay_restart`: one peer loses all state mid-run and auto-accepts.

  Done when both deliver 100%, and the time to first delivery after
  acceptance stays within about one RTT plus the link's pacing.

**Implementation results.** Simulator, 10 seeds per scenario. Wire bytes
per payload byte, then median p50 and median p95 latency:

| Scenario | Hellos off | `Unconfirmed` | `UnconfirmedAndBackoff` (default) |
|---|---|---|---|
| `edge_2g` | 2.03, 414 ms, 1.7 s | 2.02, 412 ms, 1.7 s | 2.07, 417 ms, 1.7 s |
| `disaster_cellular` | 5.14, 7.8 s, 6.9 min | 5.11, 7.5 s, 6.9 min | 5.45, 5.5 s, 6.5 min |
| `lora_like` | 5.06, 3.0 s, 10.5 min | 5.03, 3.0 s, 11.3 min | 5.08, 2.9 s, 7.1 min |
| `bursty_loss` | 4.50, 1.1 s, 45.6 s | 4.52, 1.0 s, 44.6 s | 4.53, 982 ms, 20.2 s |
| `harsh_64` | 8.76, 12.1 min, 1.1 h | 8.72, 11.6 min, 55.5 min | 9.53, 10.6 min, 1.0 h |
| `week_offline` | 1.92, 2.6 d, 6.6 d | 1.94, 2.6 d, 6.6 d | 2.05, 2.6 d, 6.5 d |
| `introduction` | n/a (can't deliver) | 5.12, 7.5 s, 6.7 min | 5.42, 5.8 s, 6.7 min |
| `introduction_lora` | n/a | 5.03, 3.0 s, 9.3 min | 5.09, 3.0 s, 6.6 min |

- Introductions cost about nothing: `Unconfirmed` is within about 1% of
  Hellos off everywhere.
- Hellos in backoff cost 0–9% more bytes (most on `harsh_64` and
  `week_offline`, where Hellos replace ~35-byte SYNC probes during long
  outages). But they shorten recovery: a
  Hello to a known contact draws an immediate SYNC, so it acts as a cheap
  probe that solicits a reply. Median p95 fell from 45.6 s to 20.2 s on
  `bursty_loss` and from 10.5 to 7.1 min on `lora_like`.
- **Change from the spec:** in deep backoff the Hello replaces the bare
  SYNC probe instead of preceding it. A Hello plus a SYNC every round
  pushed `week_offline` past its 128 KiB outage budget (12% more bytes than
  Hellos off), and the SYNC added nothing. That brought it to 7%.
- The Phase 3 overhead-regression test now runs with Hellos off, as it
  already did with FEC, because it measures header overhead against Phase 2.

**Open problem: counter reuse after state loss** (resolved by D-046 and by
identity-less relays; kept for the record). The `relay_restart`
scenario (the relay is wiped mid-run and relearns its client from Hellos)
delivers everything, but recovery takes about 1.8 days. The cause is not
the Hello. The rebuilt relay restarts its packet counter for the client at
0 under the same pair key. The client rejects those packets as replays
until the counter passes the old high-water mark. Worse, every such packet
reuses a nonce (`security.md` §4, "Known issue"). `remove_contact` then
`add_contact` does the same. This predates D-044, but Hellos make losing
and relearning a peer routine, so it needs fixing before relays rely on
it. `relay_restart` is kept out of `Scenario::NAMES` (the default sweep)
until then. Options, for the user to decide:
1. Persist a counter tombstone per removed contact. That fixes path 2
   only, and the storage grows with churn.
2. Mix a per-incarnation random value into each direction's key, sent in
   the Hello. It fixes both paths, but the Hello grows past the 48-byte
   minimum MTU.
3. The epoch extension (§7 of `security.md`), which also gives forward
   secrecy per epoch. It's the principled fix and the largest change.

## D-046: Tombstones for removed contacts; lost state means a new identity

**Problem** (found while testing D-044). Removing and re-adding a contact,
or losing storage but keeping the identity, restarted that pair's packet
counter and message sequence numbers at 0 under the same key:
- **nonces were reused;**
- **messages were silently lost.** The peer's ACK for the old seqs
  "acknowledged" the new seq 0 before it arrived. A test confirmed it: the
  sender saw "delivered", and the peer never received the message;
- **traffic stalled**, because the peer dropped the reused counters as
  replays.

**Decisions** (with the user):
- **`remove_contact` leaves a tombstone** in storage, about 60 bytes per
  key and never deleted: counter reservation, next seq, Lamport, confirmed
  flag, replay floor, and the receive window's `cum`. `add_contact` of the
  same key resumes from it, then announces its floor and next with a SYNC.
  Messages abandoned by the removal are reported to the peer as skipped,
  not waited for. **Rejected:** a cap on tombstones. An evicted tombstone
  brings the bug back for that key; 60 bytes × 1 million removals is
  60 MB, acceptable even for a large host.
- **Lost state means a new identity.** The engine can't detect that its
  own state was lost, so state is created only together with a new
  identity:
  - `Engine::restore` on empty storage returns the new `Error::StateMissing`
    (it used to be `CorruptStorage`);
  - `UdpHost::open` only restores, and the new `init_node` creates identity
    and state together. `load_or_create_identity` is gone, because it made
    the unsafe pairing easy;
  - `avl_engine_open` takes an explicit `create` flag.

  **Rejected:** an incarnation marker in the Hello. It doesn't fit the
  48-byte minimum MTU, which the user requires. Key epochs (`security.md`
  §7) could let a reinstall keep its identity later.
- **Relays have no identity** (user decision, D-045), so none of this
  applies to them.

**Breaking:** `remove_contact` now keeps a tombstone instead of deleting
everything; `Engine::restore` returns a new error;
`avianlink_udp::load_or_create_identity` is replaced by `load_identity`
and `init_node`; and `avl_engine_open` takes a new argument.

## D-045: Identity-less relays with hash-chain mailboxes (proposal, after Phase 7)

**Use case** (user): A and B are never online at the same time. A relay is
the only path, and in a disaster everyone uses one relay at once.
Specified in `relay.md`.

**User requirements:**
- relays have no identity;
- relays are untrusted: delivery is confirmed only by B's end-to-end ACK;
- traffic for a tag goes only to a client that has proven control of it;
- colliding tags must not lock anyone out;
- accepted packets are never dropped;
- retention is set by the relay, at most 30 days;
- Hellos are stored as open copies;
- every message is ≤ 48 bytes.

**Decisions:**
- **The relay is a link,** with no keys and no pair state. A rebuilt relay
  costs only buffered packets, which the endpoints resend.
- **Mailboxes per (tag, anchors), filed by proven upload session.** Hash
  chains from the pair secret: one-time 16-byte proofs, a 256-step window
  for lost proofs, and 16384 proofs per 30-day **epoch**. Chains renew from
  the clock with no messages. (Implementation note: the first draft had a
  REKEY message. It was dropped because each side tracks generations only
  for its own roles, so after a re-key the two can disagree on a mailbox's
  anchors and lock each other out when re-registering.)
  **Rejected:**
  - tag-only subscriptions: anyone could read anyone's traffic metadata
    and copies;
  - exclusive first-come registration: breaks colliding pairs, and the
    user wants none refused;
  - longer tags on every packet: +5 bytes per packet, −28% payload at
    48 bytes;
  - Ed25519-signed requests: 64-byte signatures don't fit 48 bytes.
- **Whichever side first uses the relay registers both directions,** so a
  tag is pinned before it is on the wire. This closes the
  trust-on-first-use window, including for introductions.
- **Receipts** (stored / FULL / NO_SESSION), sent only once the packet is
  durable. They make hop reliability possible and tell "refused" from
  "lost". They are never authenticated and never mean delivery.
- **Space:** no eviction before expiry, except below a proved fetch
  cursor, which shows the recipient has the packets. Otherwise refuse when
  full, with a per-mailbox share.
- **Engine store-and-forward mode** (`relay.md` §6):
  - hop retransmission until receipted;
  - end-to-end resend at half the advertised retention;
  - no probes, backoff or FEC;
  - hop-reliable ACKs;
  - a transient `MessageStored` event.
