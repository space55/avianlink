# avianlink reliability

> **Status: Phase 2.** How the engine decides what to (re)send and when, and
> what survives a crash. The wire encodings referenced here are in
> `wire-format.md`.

## 1. Model

The network is a postal service, not a connection. There is no handshake,
no connection state to time out, and no assumption that silence means
failure. A peer silent for days is normal. Reliability is end-to-end, per
message:

- **Sent** means durably queued. `send_text` returns only after the message
  is committed to `Storage`.
- **Delivered** means the peer acknowledged it. The sender then sees
  `Event::MessageDelivered`.
- A message is retried until delivered. The engine never gives up on its
  own.

## 2. Acknowledgements

Two frame types:

- **ACK** (per message): `cum` + bitmap over seqs, plus the largest packet
  counter seen from the peer and how long ago it arrived (`ack_delay`). The
  sender uses those two for RTT samples that are unaffected by
  retransmission ambiguity, because they name a *packet*, not a message.
- **FRAG_ACK** (per fragment): for a partially reassembled message, which
  fragments have arrived. The sender stops resending those, so a 25-fragment
  message under 50% loss converges in about 2× its size on the wire instead
  of resending everything each round.

FRAG_ACK is *soft*. The receiver may still evict the partial (bounded
memory). An acknowledged fragment therefore becomes due again after
`max_rto_ms`, if the whole message is still unacknowledged by then.

**Priority.** ACK frames ride along with data whenever a packet is going to
the peer anyway. When a link has budget for only some packets, contacts
with data are served before ACK-only packets ("receipts are the lowest
priority traffic"). An ACK-only packet waits at most `ack_delay_ms` for data
to piggyback on.

## 3. Retransmission timers

Per contact, an RFC 6298-style estimator in integer milliseconds:

```
first sample:  srtt = r,  rttvar = r / 2
then:          rttvar = 3/4·rttvar + 1/4·|srtt − r|,   srtt = 7/8·srtt + 1/8·r
rto            = clamp(srtt + max(100 ms, k·rttvar), min_rto_ms, max_rto_ms)
                 (k = rttvar_multiplier, default 2; RFC 6298 uses 4, see D-028)
               = initial_rto_ms before the first sample
```

A sample is `now − sent_at(largest_counter) − ack_delay`. If the ACK delay
exceeds the raw sample, the raw sample is used, because a peer's report
can't make the RTT negative. The sender keeps send times for its recent
packets in a bounded log; ACKs naming a packet that has left the log give
no sample.

**Normal mode.** A fragment never sent is due immediately. A sent fragment
is due `rto` after its last send, with up to `rto/8` random jitter. Due
fragments go out oldest-first (D-020). A packet that is going out anyway
also carries fragments due within the next `rto/4`, so jittered timers of
one message still share packets.

**Backoff mode** (the peer looks unreachable). The contact enters backoff
when a retransmission timer fires and no fresh packet (new highest counter)
has arrived from the peer since that fragment was last sent. A loss among other successful
deliveries is just a loss. Silence after a send means the path is down.

In backoff:

- the contact sends **one probe packet** (its oldest due fragments) per
  interval;
- the first `backoff_grace` probes (default 2) go out at the plain RTO.
  After that the interval doubles each time, capped at `max_rto_ms`
  (default 30 s). It is never shorter than 10× the budget time one
  MTU-sized packet costs on the link, so probing uses at most ~10% of a
  duty-cycled link's airtime. There is no limit on the number of probes and
  no connection timeout;
- the contact **leaves backoff immediately** on any authenticated packet
  from the peer that carries a new highest counter. Everything outstanding
  is then due again and drains at the link's pace. An older packet, such as
  a late reorder or an attacker's replay of a lost original, doesn't count
  (`security.md` §9).

This bounds the cost of a long outage to one packet per `max_rto_ms` per
contact. Without it, Phase 1 spent 17–32 wire bytes per payload byte on
`disaster_cellular`, almost all of it lost to outages.

## 4. Persistence

The engine owns its durable state and writes it through `Storage` in
**atomic batches** (`begin`, writes, `commit`; `rollback` on failure). Every
batch is written *before* the matching in-memory change. A failed batch
leaves the engine exactly as it was.

| Key | Value | Written when |
|-----|-------|--------------|
| `"v"` | schema version | `Engine::new` |
| `"c" ‖ conv` | peer key, next seq, Lamport, counter reservation | `add_contact`, `send_text`, receive (Lamport), counter reservation |
| `"o" ‖ conv ‖ seq(be64)` | queue time, encoded record | `send_text`; removed on delivery |
| `"i" ‖ conv` | receive window: `cum` + bitmap | each newly received message |
| `"e" ‖ n(be64)` | a pending event | when the event is queued; removed when the host polls it |

Not persisted, because it is rebuilt or soft: RTT estimates, backoff,
fragment send times, partial reassemblies (the peer retransmits), and pacer
state.

**Packet counters** are reserved in blocks of `counter_reservation`
(default 1024). A restored engine resumes at the reservation, so a counter
value is never reused. Phase 3 derives nonces from it.

### Crash semantics

A crash may happen between any two engine calls. After `Engine::restore`:

- every message whose `send_text` returned `Ok` and that was not yet
  delivered is in the outbox, and is resent;
- no message is delivered to the host twice. The receive window is
  committed together with the event that announces the message, and the
  event is removed from storage only when the host polls it;
- an event that was queued but not yet polled is queued again. Events are
  handed over **exactly once**, provided the host has processed an event
  before its next engine call. The engine can't see past `poll_event`'s
  return;
- the peer may receive retransmissions it already has. They are deduped by
  seq and re-acknowledged.

The engine does not persist the host's links. Hosts re-register them after
`restore`.

## 5. Ordering

Each message carries a per-conversation Lamport value, and `send_text`
returns the value assigned. `ReceivedMessage::missing_before` counts earlier
seqs from the same sender that have not arrived yet. So the application can
tell "this arrived out of order, and two earlier messages are still on
their way" from "this is the latest", and sort its thread by (Lamport,
sender key).
