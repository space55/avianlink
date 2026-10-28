# avianlink

End-to-end encrypted text messaging for packet links that barely work.

avianlink is a Rust library for getting short messages through links with
some or all of these properties:
- latency from seconds to hours;
- 50% or more packet loss, arriving in bursts;
- bit corruption, duplication and reordering;
- packets as small as 48 bytes;
- links that disappear for days.

It treats the network as a **postal service, not a connection**:
- every packet stands on its own;
- nothing ever times out;
- a peer that has been silent for a week is a normal case, not an error.

The core doesn't assume IP, UDP or sockets. It runs over any packet
transport, such as UDP, LoRa, serial radios, BLE or satellite modems. The
same code builds for macOS, Linux, iOS and bare-metal microcontrollers.

> **Status: pre-release (0.0.0).** Wire format v1 is specified and
> implemented, and the test suite and simulator results below are real. The
> cryptography uses audited crates but **has not been independently
> reviewed**, and v1 has **no forward secrecy** (see [Security](#security)).
> Don't rely on it where lives depend on it yet.

## Goals

1. **Deliver every message eventually**, however bad the link, without
   flooding it. Throughput on a clean link is secondary.
2. **Run anywhere.** The core is `#![no_std]` + `alloc`, and
   [sans-IO](#how-it-works). It never touches a socket, clock, file or
   thread, so the same engine runs in a terminal app, an iPhone app or on a
   radio's microcontroller.
3. **Never crash on network input.** Every byte is untrusted. The core
   forbids `unsafe`, denies `unwrap`, indexing and unchecked arithmetic by
   lint, and every parser is fuzzed.
4. **Bounded memory.** Every queue, buffer and table has a configurable
   limit, with documented behaviour when it is full.
5. **Respect the link.** Each link is registered with its MTU, its rate or
   legal duty-cycle budget, and a cost. The engine paces itself to the
   budget and doesn't mistake loss for congestion.
6. **Be honest.** The API says what actually happened:
   - *queued* means stored durably;
   - *transmitted* means it went out for the first time;
   - *delivered* means the peer acknowledged it.

   Messages that arrive out of order are marked as such.
   [`docs/security.md`](docs/security.md) lists what the cryptography does
   not protect.
7. **Minimal dependencies.** Cryptography comes from audited
   RustCrypto/dalek crates and is never hand-rolled. Every dependency is
   justified in [`docs/decisions.md`](docs/decisions.md).

### Non-goals (v1)

- Large payloads. Messages are text of a few hundred bytes. Long messages
  work but are fragmented.
- Forward secrecy and post-compromise security. There is an extension point
  for a ratchet that tolerates reordering.
- Group chats, anonymity, routing or mesh networking. avianlink is
  point-to-point over whatever links the host provides.
- Encrypting data at rest. That is the host's job.

## How it works

```
        your app / host                          avianlink-core (sans-IO)
 ┌───────────────────────────┐   send_text      ┌──────────────────────────┐
 │ UI, sockets, radio, clock,│ ───────────────▶ │ outbox, reliability, FEC,│
 │ database                  │   handle_packet  │ sync, crypto, pacing     │
 │                           │ ───────────────▶ │                          │
 │                           │   handle_timeout │ deterministic state      │
 │                           │ ───────────────▶ │ machine: no I/O, no      │
 │                           │ ◀─────────────── │ clock, no threads        │
 │                           │   poll_transmit  │                          │
 │                           │   poll_event     │                          │
 │                           │   next_timeout   │                          │
 └─────────────┬─────────────┘                  └────────────┬─────────────┘
               │ Storage trait (atomic batches)              │
               └─────────────────────────────────────────────┘
```

The host feeds packets, timer ticks and wall-clock time (`u64`
milliseconds) into the engine. It takes out packets to send, events for the
UI, and when it next wants to be woken. The host supplies randomness (any
`rand_core::CryptoRng`) and persistence (the `Storage` trait).

The engine is built from these parts:

- **Wire format v1** ([`docs/wire-format.md`](docs/wire-format.md)).
  - A packet is a version byte, a 3-byte routing tag, a varint counter,
    encrypted frames and a 16-byte tag. That's 22 bytes of fixed overhead.
  - Nonces come from the counter, so they are never sent.
  - Frames are type-length-value records: message fragments, selective
    ACKs, repairs, sync summaries and loss reports. Unknown versions and
    frame types are skipped, not fatal.
  - Fragmentation works at any MTU from 48 bytes up, and is addressed by
    byte offset.
- **Reliability** ([`docs/reliability.md`](docs/reliability.md)).
  - The outbox is persistent.
  - Message IDs are content-addressed, so duplicates are free to detect and
    resends are idempotent.
  - ACKs are selective bitmaps piggybacked on data, plus per-fragment ACKs.
  - Retransmission timers are adaptive (RFC 6298-style).
  - There are no connection timeouts. A silent peer gets probes whose
    spacing grows with the silence, so a week offline costs a bounded
    number of bytes.
  - Ordering is causal (a Lamport clock per conversation).
  - Every state change is one atomic storage batch, so a crash at any point
    loses and duplicates nothing.
- **Cryptography** ([`docs/security.md`](docs/security.md)).
  - An identity is an Ed25519 keypair, also used for X25519.
  - Contacts are added by public key. Only one side needs the other's key
    in advance: the other learns it from a **Hello**, a 47-byte
    unencrypted but authenticated contact request that the app or relay
    decides whether to accept. Fingerprints are still checked out of band.
    There is no handshake.
  - Per-direction keys and routing tags come from static-static
    Diffie-Hellman through HKDF-SHA256.
  - Every packet is independently decryptable with ChaCha20-Poly1305.
  - Replay protection uses a sliding window with a persisted floor.
- **Forward error correction.** It codes *across* messages, because most
  messages fit in a few packets:
  - outgoing packets form windows, and Cauchy Reed-Solomon repairs let the
    receiver rebuild lost packets without a round trip;
  - the repair rate follows the loss the peer reports;
  - repairs are sent only from budget that would otherwise go unused.
- **Relays** ([`docs/relay.md`](docs/relay.md)), for peers that are never
  online at the same time: A sends and goes offline, B comes online later,
  collects, replies and leaves.
  - The relay has **no identity and no keys**: it stores packets it can't
    read, in mailboxes that only the pair can prove control of, using
    one-time hash-chain proofs.
  - It never drops what it accepted: it refuses when full, and keeps
    packets until its configured retention expires (at most 30 days).
  - Delivery is still confirmed only by the recipient's end-to-end ACK,
    which the relay carries like any packet.
  - Every relay message fits in 48 bytes.
- **Sync.** After an outage, peers exchange compact summaries (a floor, a
  receive bitmap and 8-byte digests of 64-message blocks) instead of
  "everything since X". It makes progress even when most sync packets are
  lost.

## Results

These numbers are from the deterministic simulator (`avianlink-sim`). Each
scenario sends 1,000 messages averaging ~200 bytes between two peers, both
ways. Times are from send to first delivery. Bytes and packets count
everything on the wire: headers, retransmissions, ACKs, repairs and sync.
Seed 1 is shown; **all 120 runs (12 scenarios × 10 seeds) delivered every
message.**

| Scenario | Conditions | p50 | p95 | wire bytes / payload byte | packets / message |
|---|---|--:|--:|--:|--:|
| `clean` | 1200 B MTU, 5 ms, no loss | 5 ms | 5 ms | 1.33 | 2.0 |
| `geo_satellite` | 550 ms RTT, 8 kB/s, rain fades | 318 ms | 422 ms | 1.48 | 2.2 |
| `edge_2g` | 512 B MTU, 4 kB/s, spiky delay, outages | 417 ms | 3.1 s | 2.22 | 3.4 |
| `disaster_cellular` | 256 B, 1 kB/s, ~35% bursty loss, corruption, 3-min outages | 5.7 s | 7.0 min | 5.66 | 9.7 |
| `lora_like` | 51 B MTU, 1% duty cycle, ~10% loss | 2.8 s | 6.3 min | 5.04 | 23.7 |
| `bursty_loss` | `disaster_cellular` without outages | 951 ms | 17.5 s | 4.56 | 8.6 |
| `harsh_64` | 64 B MTU, ~50% bursty loss, up 90 s / down 10 min | 13.1 min | 1.1 h | 9.46 | 34.3 |
| `harsh_64_crashy` | `harsh_64`, both nodes crash every ~30 min | 13.6 min | 1.2 h | 10.11 | 35.8 |
| `disaster_hostile` | `disaster_cellular` plus 20% replayed, 20% forged, 10% tampered packets | 6.7 s | 7.1 min | 6.30 | 11.5 |
| `week_offline` | `edge_2g`, link down for 7 days, 1,000 messages over 9 days | 2.6 d | 6.6 d | 2.05 | 2.4 |
| `introduction` | `disaster_cellular`, but B starts without A's key and accepts A's contact request | 7.7 s | 7.0 min | 5.74 | 9.8 |
| `introduction_lora` | the same on `lora_like` | 3.1 s | 6.5 min | 5.07 | 23.8 |

Single-seed rows move noticeably between seeds. [`docs/decisions.md`](docs/decisions.md)
D-044 has 10-seed medians, with and without Hellos.

At small MTUs a 200-byte message needs several packets: 6–10 at a 64-byte
MTU, 10 or more on LoRa. That, more than retransmission, is why packets per
message climbs there.
[`docs/wire-format.md`](docs/wire-format.md) §6 has the per-MTU overhead
table.

The simulator runs 3,000–1,000,000 simulated hours per wall-clock minute,
depending on the scenario. Reproduce the table with:

```sh
cargo run --release -p avianlink-sim --bin simrun -- --profile everything --seeds 10
```

On real networks, two CLI peers chatting through Linux `tc netem` running
the `disaster_cellular` profile delivered 20/20 messages each way across two
outages ([`docs/hosting.md`](docs/hosting.md) §7).

**Through a relay, with A and B never online together**
(`simrun --profile turns_all --seeds 10`, [`docs/relay.md`](docs/relay.md)
§8). Over 50 runs, **no message was lost**:
- clean, satellite and 2G hops: every message arrived in the recipient's
  very next session;
- disaster-grade and LoRa hops: 95–98% arrived by the end of each run, and
  the rest were still queued by their senders.

The cost on the worst links is about 20 wire bytes per payload byte, the
main open item.

## Workspace

| Crate | What it is |
|---|---|
| [`avianlink-core`](crates/avianlink-core) | The engine: wire format, reliability, crypto, FEC, sync. `no_std` + `alloc`, `forbid(unsafe_code)`. |
| [`avianlink-sim`](crates/avianlink-sim) | Deterministic network simulator and test harness. Every run reproduces exactly from its seed. Also has `udp-impair` (a userspace impairment proxy) and `netem-gen`. |
| [`avianlink-udp`](crates/avianlink-udp) | UDP host for `std` platforms: `UdpHost` driver loop (direct or through a relay), `FileStorage` (a crash-safe write-ahead log), identity files, and the `avianlink-relay` server binary. |
| [`avianlink-cli`](crates/avianlink-cli) | `avianlink`: a terminal chat demo. |
| [`avianlink-relay`](crates/avianlink-relay) | The identity-less relay (`Relay`) and its client (`RelayClient`), both sans-IO. |
| [`avianlink-ffi`](crates/avianlink-ffi) | C ABI with a generated header, plus an Apple XCFramework, for iOS and Swift. |

Other directories:
- [`docs/`](docs) holds the specifications and the decision log.
- [`tools/wireshark/`](tools/wireshark) holds a Wireshark dissector:
  packet headers, Hellos with sender fingerprints, the full relay protocol,
  and receipt hashes that tie each upload to the relay's receipt.
- [`scripts/`](scripts) holds CI, fuzzing, netem profiles and the
  XCFramework and Swift builds.
- [`fuzz/`](fuzz) holds the `cargo-fuzz` targets.

## Getting started

Requires Rust 1.88 or later.

### Chat from two terminals

```sh
cargo build --release -p avianlink-cli
alias avianlink=target/release/avianlink

avianlink init /tmp/alice      # prints alice's address and fingerprint
avianlink init /tmp/bob

avianlink chat /tmp/alice --bind 127.0.0.1:7001 --peer <BOB_ADDRESS>@127.0.0.1:7002
avianlink chat /tmp/bob   --bind 127.0.0.1:7002 --peer <ALICE_ADDRESS>@127.0.0.1:7001
```

Every line you type is a message. `/status` shows RTT, measured loss and
reachability, and `/nudge` probes immediately. Leave out `--peer` on one
side to wait for a contact request instead: compare the fingerprint it
prints with the sender, then type `/accept`. Add `--profile lora_like`
(or any profile name) to give the engine that profile's MTU and budget.

To make the link actually bad, run the chat through `udp-impair` or real
netem. `scripts/local-chat-test.sh disaster_cellular` does the whole thing
on loopback. `scripts/netem/docker-test.sh` does it with real `tc netem` in
Docker. See [`docs/hosting.md`](docs/hosting.md).

### Embed the engine in Rust

```rust
use avianlink_core::{
    Config, Engine, Event, Identity, LinkBudget, LinkConfig, LinkId, MemoryStorage, Timestamp,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

let mut rng = ChaCha20Rng::from_seed([7; 32]); // use an OS-seeded RNG in real code
let alice_id = Identity::generate(&mut rng);
let bob_id = Identity::generate(&mut rng);
let (alice_key, bob_key) = (alice_id.public_key(), bob_id.public_key());

let mut alice = Engine::new(Config::default(), alice_id, MemoryStorage::new(), rng.clone())?;
let mut bob = Engine::new(Config::default(), bob_id, MemoryStorage::new(), rng)?;

// A 64-byte radio link, at most 100 bytes/s.
let radio = LinkConfig { mtu: 64, budget: LinkBudget::BytesPerSecond(100), cost: 1 };
alice.add_link(LinkId(0), radio)?;
bob.add_link(LinkId(0), radio)?;

let to_bob = alice.add_contact(bob_key)?;
bob.add_contact(alice_key)?;

let mut now = Timestamp::from_millis(0);
alice.send_text(to_bob, "Water at the north gate. Need 20 litres.", now)?;

// The host loop: move packets, fire timers, read events.
for _ in 0..200 {
    while let Some(tx) = alice.poll_transmit(now) {
        bob.handle_packet(tx.link, tx.packet.as_bytes(), now);
    }
    while let Some(tx) = bob.poll_transmit(now) {
        alice.handle_packet(tx.link, tx.packet.as_bytes(), now);
    }
    while let Some(event) = bob.poll_event() {
        if let Event::MessageReceived(m) = event {
            println!("bob got: {}", m.text);
        }
    }
    now = Timestamp::from_millis(now.as_millis() + 100);
    alice.handle_timeout(now);
    bob.handle_timeout(now);
}
```

A real host would make these changes:
- send `tx.packet` over its transport to the address of contact `tx.to`;
- sleep until `next_timeout()` or the next packet;
- use durable `Storage`, either `avianlink_udp::FileStorage` or its own
  encrypted database;
- keep `Identity::secret_bytes()` in the OS keychain.

`avianlink_udp::UdpHost` is a complete example of all of this.

### Use it from C or Swift

```sh
scripts/c-example.sh          # builds the static library, compiles and runs examples/c/loopback.c
scripts/build-xcframework.sh  # target/Avianlink.xcframework (iOS device, simulator, macOS)
scripts/swift-smoke-test.sh   # imports it from Swift via SwiftPM and exchanges a message
```

The header is
[`crates/avianlink-ffi/include/avianlink.h`](crates/avianlink-ffi/include/avianlink.h).
Ownership, buffer and threading rules are in [`docs/ffi.md`](docs/ffi.md).

## Testing

```sh
scripts/ci.sh      # fmt, clippy -D warnings, all tests, no_std builds for
                   # thumbv7em-none-eabihf and aarch64-apple-ios, header
                   # freshness, the C example
scripts/fuzz.sh    # cargo-fuzz (nightly): decode, handle_packet, restore
```

The tests are:
- unit tests;
- `proptest` round-trip and invariant tests for every encoder and decoder;
- simulator scenarios with pass/fail delivery criteria, crash and restore
  injection, and an on-path attacker;
- fuzz targets that also check the engine can't stall or busy-loop;
- end-to-end UDP tests through the impairment proxy.

`scripts/netem/` holds `tc netem` versions of every simulator profile.
They're generated from the same definitions, and a test fails if they drift.

## Security

[`docs/security.md`](docs/security.md) is the full threat model. In brief:

**Protected:**
- message contents, sequence numbers, timestamps and ACKs are confidential;
- every packet is authenticated as coming from the contact it claims;
- replayed, forged, truncated, tampered and misrouted packets are rejected.
  The `disaster_hostile` scenario runs this continuously.
- an attacker can only cause a bounded amount of work per packet.

**Rule for hosts:** a node that has lost its stored state must start over
with a new identity. Reusing the old one would reuse nonces. The engine
reports this as `Error::StateMissing` (`docs/security.md` §4).

**Not protected in v1:**
- **No forward secrecy.** Keys come from the two long-term identities, so
  anyone who later steals either secret key can decrypt recorded traffic.
- No post-compromise security.
- Key-compromise impersonation is possible, which is inherent to
  static-static Diffie-Hellman.
- Metadata is visible: packet sizes, timing, counters, and a per-direction
  routing tag that links a pair's packets together without naming them.
  Hellos also show the sender's public key and 16 bits of a hash of the
  recipient's key (`HelloMode::Off` turns them off).
- Data at rest isn't encrypted by the engine.

Verify fingerprints out of band when you add a contact.

## Documentation

| Document | Contents |
|---|---|
| [`docs/wire-format.md`](docs/wire-format.md) | Byte-level packet and frame format, versioning rules, overhead per MTU |
| [`docs/reliability.md`](docs/reliability.md) | ACKs, timers and backoff, persistence and crash semantics, ordering, FEC, sync |
| [`docs/security.md`](docs/security.md) | Goals and non-goals, key schedule, replay protection, metadata, DoS, dependencies |
| [`docs/hosting.md`](docs/hosting.md) | `FileStorage`, `UdpHost`, the CLI, netem profiles, real-network results |
| [`docs/ffi.md`](docs/ffi.md) | The C ABI and Apple packaging |
| [`docs/decisions.md`](docs/decisions.md) | Every significant design choice, with the alternatives rejected and why |

## Roadmap

- An embedded example on a real microcontroller. The core already builds
  for `thumbv7em-none-eabihf` in CI.
- Cut the relay protocol's overhead on the worst links, and expose relays
  through the C ABI.
- A ratchet for forward secrecy that tolerates heavy reordering and skipped
  messages (`docs/security.md` §7).
- Swift-friendly wrappers on top of the C ABI.

## License

MIT. See [LICENSE](LICENSE).
