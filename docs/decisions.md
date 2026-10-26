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

## D-004: Edition 2021, MSRV 1.81 (Phase 0)

**Decision.** Edition 2021, `rust-version = "1.81"`.

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
