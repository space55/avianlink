# Hosting avianlink on a real network

> **Status: Phase 6.** How the `std` crates turn the sans-IO engine into a
> running node: the UDP adapter, durable storage, the CLI demo, and the
> netem profiles used to test over real links.

## 1. Pieces

| Crate / tool | Role |
|---|---|
| `avianlink-udp::FileStorage` | Durable `Storage`: a write-ahead log in one file, with atomic batches. |
| `avianlink-udp::UdpHost` | Driver loop. Owns the engine, a UDP socket, the wall clock and the peer address book. Talks to a UI thread over channels. |
| `avianlink` (`avianlink-cli`) | Terminal demo: `init`, `whoami`, `chat`. |
| `udp-impair` (`avianlink-sim`) | Userspace impairment proxy. Applies a simulator profile to real UDP traffic between two hosts, for testing without netem. |
| `netem-gen` (`avianlink-sim`) | Generates `scripts/netem/*.sh` from the simulator profiles, so the two can't drift. |

## 2. `FileStorage`

The file `state.log` is a sequence of records:

```
record = len:u32le  check:[8]  payload:[len]
payload = op*
op     = 0x01 key_len:varint key value_len:varint value   (store)
       | 0x02 key_len:varint key                           (remove)
check  = SHA-256(payload)[..8]
```

- **`commit`** appends one record (the whole batch), then `fsync`s. A batch
  is durable once `commit` returns, and atomic because a record is applied
  only when it is complete and its check verifies.
- **Recovery.** On open, records are replayed in order. The first truncated
  or corrupt record ends the log, and the file is truncated there. This is
  a crash mid-append, so the torn batch never happened.
- **Compaction.** When the log grows past 4× the live data plus 64 KiB, the
  live state is written as one record to `state.log.tmp`, `fsync`ed, and
  renamed over `state.log`, and the directory is `fsync`ed. A crash at any
  point leaves either the old log or the new one.
- **Not encrypted.** The engine stores message plaintext (outbox, pending
  events), and `security.md` §1 makes encryption at rest the host's job. The
  CLI is a demo and leaves the file readable only by its owner (`0600`).
  It doesn't encrypt.

The identity secret lives in a separate file, `identity` (`0600`), never in
`Storage`.

## 3. `UdpHost`

One thread runs the loop:

1. Receive from the socket, with a timeout of `min(next_timeout − now,
   50 ms)`. The 50 ms bound keeps commands from the UI responsive.
2. Each datagram goes to `Engine::handle_packet`:
   - `Received::Contact(conv)`: an authenticated data packet. The contact's
     address is updated to the datagram's source, so NAT rebinding and
     roaming just work;
   - `Received::ContactRequest(key)`: a verified Hello from an unknown key.
     Its source is kept as a *candidate* address (at most 64), used only if
     the request is accepted (`Command::Accept`). Hellos can be replayed,
     so this never moves an existing contact's address.
3. Commands from the UI (send, accept, nudge, status, quit) are applied.
4. Pump: drain `poll_transmit`, sending each packet to its contact's
   address, then drain `poll_event` to the UI.

`now` is the wall clock in Unix milliseconds, and the engine tolerates it
going backwards (D-007). The RNG is ChaCha20 seeded from the OS
(`getrandom`).

Addresses come from the command line (`KEY@HOST:PORT`) and are then
learned from authenticated traffic. Unauthenticated packets never change
an address, so an attacker can't redirect traffic by spoofing a source.

## 4. CLI

```
avianlink init   DIR                 # new identity and its state; prints address and fingerprint
avianlink whoami DIR
avianlink chat   DIR --bind HOST:PORT [--peer KEY@HOST:PORT]
                 [--profile NAME | --mtu N [--rate BYTES_PER_S]]
```

`init` creates the identity and the engine state together. `chat`
refuses to start if the identity is there but the state is gone (D-046):
re-`init` in a new directory and re-share the address.

Without `--peer`, `chat` waits for a contact request: it prints the
requester's fingerprint, and `/accept` adds it, reachable at the address
its Hello came from.

`--profile` sets the engine's link to the same MTU and budget as the named
simulator profile. Use it with the matching netem script. In `chat`, each
line typed is a message, and `/status`, `/nudge` and `/quit` are
commands. Output lines show the engine's view honestly: queued,
transmitted, delivered, and received (with any `missing_before`).

## 5. netem profiles

`scripts/netem/<profile>.sh DEV [DEV…]` applies a profile on the egress of
each device, typically both interfaces of a box routing between two
hosts. Run it as root on Linux. `scripts/netem/clear.sh DEV…` removes
the qdiscs.

| Simulator model | netem | Fidelity |
|---|---|---|
| Base delay + uniform jitter | `delay B J distribution uniform`, approximated as normal | close |
| Base delay + Pareto jitter (scale, α, cap) | `delay B+median J distribution pareto` | approximate: netem's Pareto table has a fixed shape, and the cap is not enforced |
| Gilbert-Elliott (p, r, loss_bad, loss_good) | `loss gemodel p r loss_bad loss_good` | exact model, per packet |
| Bit flips (per packet) | `corrupt P` | netem flips one bit; sim flips 1–3 |
| Duplication | `duplicate P` | exact |
| Reordering (extra hold-back) | `reorder P 50%` with the base delay | different mechanism, similar effect |
| Rate (serialization) | `rate R`, plus `limit` for the queue | close |
| Duty cycle + airtime (LoRa) | `rate` with per-packet overhead (`rate R OVERHEAD`) | airtime modelled; the 1% budget is enforced by the engine itself, not netem |
| Outages (exponential up/down) | a background loop toggling `loss 100%` | same distribution, shared by all devices |
| MTU | not enforced (the engine never exceeds `--mtu`) | n/a |

The scripts are generated by `netem-gen` and checked by a test, so
changing a profile without regenerating them fails CI.

## 6. Running it

**Locally, through the userspace proxy.** No root and no Linux needed:

```
scripts/local-chat-test.sh [PROFILE] [MESSAGES] [TIMEOUT_S]
```

This starts `udp-impair` and two `avianlink chat` processes on loopback,
exchanges messages both ways, and fails unless every message is received
and acknowledged. `cargo test -p avianlink-udp` runs the same path
in-process with `UdpHost`.

**In Docker, through real netem.** On any machine with Docker:

```
scripts/netem/docker-test.sh [PROFILE] [MESSAGES] [INTERVAL_S] [TIMEOUT_S]
```

This builds Linux binaries in a `rust` container. It then puts alice and bob
on two separate bridge networks whose only route to each other goes through
a router container running the generated `scripts/netem/PROFILE.sh` on both
of its interfaces: real `tc netem`, both directions, with shared outages.
It exchanges messages through `avianlink chat` and fails unless every
message is received and acknowledged. (Docker's `--internal` networks drop
routed traffic, so plain bridge networks are used.)

**Two machines through a netem box (the Phase 6 acceptance setup).**

```
 alice ── eth0 [ Linux router ] eth1 ── bob
              netem on eth0 and eth1 egress
```

1. On the router (Linux, IP forwarding on, routes between the two
   subnets):

   ```
   sudo scripts/netem/disaster_cellular.sh eth0 eth1   # Ctrl-C clears it
   ```

   Both directions get independent impairments and shared outages.
2. On each end:

   ```
   avianlink init ~/.avianlink            # once; prints address + fingerprint
   avianlink chat ~/.avianlink --bind 0.0.0.0:7000 \
       --peer <OTHER_ADDRESS>@<other-host>:7000 --profile disaster_cellular
   ```

3. Type messages. Expect what the simulator predicts for
   `disaster_cellular`: seconds to minutes per message, nothing lost,
   out-of-order arrivals marked, and silence during outages followed by
   catch-up. `/status` shows RTT, measured loss and reachability.
   `/nudge` probes at once after you know the link is back.

**Without a router:** run the netem script on each end host's own
interface (`sudo scripts/netem/disaster_cellular.sh eth0` on both). Each
direction is impaired once, at its sender. The two outage schedules are
then independent rather than shared.

## 7. Acceptance results (Phase 6)

| Run | Link | Result |
|---|---|---|
| `scripts/netem/docker-test.sh disaster_cellular 20 30` | Real `tc netem` on a router container. Two outages (28 s, 4.5 min); measured loss 34–47% | 20/20 each way received and acknowledged in 773 s. Slowest delivery 4m42s (sent into the 4.5-minute outage). 0 unauthenticated drops. |
| `scripts/local-chat-test.sh disaster_cellular 20 1800 45` | `udp-impair`, the simulator's model in real time. About 12 minutes of outages; 63 packets lost to them | 20/20 each way in 245 s after the last send. Slowest delivery 7m38s. |
| `cargo test -p avianlink-udp` (in-process `UdpHost` through the proxy) | `edge_2g`, and `disaster_cellular` without outages | 20 messages in 4.9 s and 9.8 s. |

The two-machine setup in §6 is the same topology with physical hosts.
