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
