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

## D-004: Edition 2021, MSRV 1.82 (Phase 0; MSRV raised in Phase 1)

**Decision.** Edition 2021, `rust-version = "1.82"` (raised from 1.81 in
Phase 1 for `Option::is_none_or`).

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
