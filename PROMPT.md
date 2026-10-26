# Build `avianlink`: a lossy-link text messaging library in Rust

## What you are building

A Rust library for end-to-end encrypted **text messaging over extremely poor packet links**: high latency (seconds to hours), high packet loss (up to 50%+, bursty), bit corruption, duplication, reordering, tiny MTUs (as low as ~50 bytes), and links that disappear for long periods.

The library does not assume IP, UDP, or sockets. It sits on top of *any* packet transport (UDP today; LoRa, serial radios, BLE or satellite modems later). It treats the network as a store-and-forward postal service, not a live connection.

The same core code must run on macOS/Linux now and on iOS and microcontrollers later. Portability is a day-one constraint, not a later port.

## Non-negotiable architecture rules

1. **Sans-IO core.** The core crate never opens sockets, reads a clock, touches a filesystem, spawns threads, or uses async. It is a deterministic state machine driven by the host:
   - Inputs: `handle_packet(link_id, bytes, now)`, `send_text(conversation, text)`, `handle_timeout(now)`, link registration.
   - Outputs: `poll_transmit(now) -> Option<(LinkId, Packet)>`, `poll_event() -> Option<Event>`, `next_timeout() -> Option<Timestamp>`.
   - Time is a plain `u64` of milliseconds supplied by the caller. Randomness comes from an injected `rand_core::CryptoRngCore`. Persistence goes through a `Storage` trait the host implements.
2. **`#![no_std]` core with `alloc`.** A `std` feature may add conveniences, but the core must build for `thumbv7em-none-eabihf` at every commit. Prefer integer math; no floating point in core logic.
3. **Never panic on input from the network.** Every byte from a packet is untrusted. No `unwrap`, `expect`, indexing that can go out of bounds, or unchecked arithmetic on parsed values. Use `#![forbid(unsafe_code)]` in core.
4. **Bounded memory.** Every queue, buffer, reassembly table and cache has a configurable limit, with documented behavior when it is full.
5. **Minimal, `no_std`-compatible dependencies.** Use audited RustCrypto/dalek crates for cryptography. Never implement cryptographic primitives yourself. Justify every new dependency in `docs/decisions.md`.
6. **Links are first-class.** The host registers each link with its MTU, a rate or duty-cycle budget (airtime is often legally limited), and a relative cost. The engine fragments, paces and schedules per link. It does not infer congestion from loss.

## Workspace layout

```
avianlink/
  crates/
    avianlink-core/    # no_std sans-IO engine: wire format, reliability, crypto, FEC, sync
    avianlink-sim/     # deterministic network simulator + test harness (std)
    avianlink-udp/     # UDP link adapter + driver loop (std)
    avianlink-cli/     # demo: two peers chatting over UDP from the terminal
    avianlink-ffi/     # C ABI (later phase), basis for iOS/Swift bindings
  docs/
    wire-format.md
    security.md
    decisions.md
  scripts/
    netem/        # tc netem profiles for real-device testing
```

## Core design

**Messages**
- A message is small UTF-8 text with a sender, conversation, causal metadata and timestamp.
- Message IDs are content-addressed (a truncated hash), so duplicates are detected for free and resends are idempotent.
- Ordering is causal (Lamport clock per conversation, or parent references). Messages arrive out of order and the API exposes that honestly.

**Wire format (write `docs/wire-format.md` before implementing it)**
- First byte is a version. Peers will run mismatched versions for years, so unknown versions and unknown fields must be handled gracefully.
- Headers are minimal: varints, short routing tags (a few bytes of a hash of the recipient's key, with collisions resolved by trial decryption), and nonces derived from counters rather than sent in full.
- Message fragmentation and reassembly must work at any MTU from 48 bytes upward.
- Include a header-overhead budget table per MTU in the spec.

**Reliability**
- Persistent outbox via `Storage`. "Sent" means durably queued; delivery is a separate event.
- Compact selective acknowledgements (bitmaps), piggybacked on data when possible. Receipts are the lowest priority traffic.
- Adaptive retransmission timers with capped exponential backoff, and no fixed connection timeouts. A peer silent for days is normal.

**Cryptography (document honestly in `docs/security.md`)**
- Identity is an X25519/Ed25519 keypair. Contacts are added from a known public key (out-of-band, e.g. a QR code). There is no handshake.
- Every packet is independently decryptable with an AEAD (ChaCha20-Poly1305 or XChaCha20-Poly1305). Pairwise keys are derived from static keys via HKDF, with counter-derived nonces.
- v1 does not provide forward secrecy. State that clearly, and leave a documented extension point for a ratchet that tolerates heavy reordering and skipped messages.
- Run a cheap integrity check before decryption only if it measurably saves work; the AEAD tag is the real integrity guarantee.

**Forward error correction**
- Most messages fit in one packet, so code *across* messages: batch outbound packets into a sliding window and emit repair packets (start with systematic XOR parity, then Reed-Solomon), so one repair packet can recover any one lost packet in its window.
- The repair rate adapts per link based on measured loss.
- Multi-fragment payloads may use a fountain code later. Do not add one in v1.

**Sync**
- Peers reconcile which messages each has via compact summaries (start with per-conversation hash ranges; range-based set reconciliation later), rather than "send everything since X".
- Sync must make progress even if only a fraction of its packets arrive.

## Simulator (`avianlink-sim`)

This is the primary test environment and must be as good as the engine.
- Virtual time and a seeded RNG. Any failing run is reproducible exactly from its seed.
- Per-link impairments: fixed and heavy-tailed delay, Gilbert-Elliott bursty loss, random bit flips, duplication, reordering, MTU, rate/duty-cycle limits, and scheduled outages (e.g. up 90 s, down 10 min).
- Named profiles: `clean`, `geo_satellite`, `edge_2g`, `disaster_cellular`, `lora_like`.
- Metrics per run: delivery ratio, time-to-delivery p50/p95/p99, bytes on the wire per delivered byte, and packets sent per message.
- Runs thousands of simulated hours per minute of wall time.

## Phases

Work through these in order. At the end of each phase, stop and report: what was built, test results, metrics from the simulator, open questions, and anything you deviated from in this prompt and why.

**Phase 0: Skeleton**
- Workspace, crates, empty APIs, `docs/` stubs.
- CI script (`scripts/ci.sh`) running `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, and builds of `avianlink-core` for `thumbv7em-none-eabihf` and `aarch64-apple-ios`.
- Done when: CI passes on all targets.

**Phase 1: Framing and the simulator**
- Wire format spec, packet encode/decode, fragmentation/reassembly, the `Engine` API with plaintext messages and naive retransmission.
- Simulator with all impairments.
- Done when: two simulated peers exchange 1,000 messages over `disaster_cellular` with 100% eventual delivery, and a fuzz target on `handle_packet` runs without panics.

**Phase 2: Reliability**
- Selective acks, adaptive RTO, `Storage`-backed outbox, dedupe, causal ordering, bounded queues.
- Done when: 100% eventual delivery at a 64-byte MTU with 50% bursty loss and outages, and the engine can be restored from `Storage` mid-run without losing or duplicating messages.

**Phase 3: Cryptography**
- Identities, contacts, per-packet AEAD, routing tags, `docs/security.md`.
- Done when: tampered, replayed, truncated or misrouted packets are rejected without panics, and Phase 2 metrics regress by no more than the documented header overhead.

**Phase 4: FEC**
- Cross-message parity, adaptive repair rate.
- Done when: simulator metrics show improved p95 time-to-delivery under bursty loss versus Phase 3, with a reported bandwidth cost.

**Phase 5: Sync**
- Summary-based reconciliation, so a peer returning after a long outage catches up efficiently.
- Done when: a peer offline for a simulated week converges with bounded bytes exchanged.

**Phase 6: Real network**
- `avianlink-udp` adapter and driver loop, `avianlink-cli` demo, `scripts/netem/` profiles matching the simulator's.
- Done when: two CLI peers on separate machines chat through a netem box running `disaster_cellular`.

**Phase 7: Portability (only when asked)**
- `avianlink-ffi` with a C header generated by `cbindgen`, an iOS XCFramework build script, and an embedded example on a real microcontroller target.

## Working style

- Write the spec or doc section before the code it describes.
- Small, focused commits with clear messages.
- Tests alongside every feature: unit tests, `proptest` property tests for encode/decode round-trips and invariants, simulator scenarios, and `cargo-fuzz` targets for every parser.
- Record significant choices and rejected alternatives in `docs/decisions.md`.
- If a requirement here turns out to be wrong or impractical, say so and propose an alternative rather than quietly working around it.