# avianlink reliability

> **Status: Phase 5.** How the engine decides what to (re)send and when, and
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

**Long silences.** Once a silence outlasts the short-term doubling, the
probe interval follows it: 1/64 of the time since backoff began, at least
`max_rto_ms` and at most `max_probe_interval_ms` (default 1 h). A flaky
link with brief up-windows keeps being probed every 30–60 s for the first
hour. A dead one is probed less and less often, so a week costs a few
hundred packets. After `deep_backoff_after_ms` (default 1 h) of silence,
probes shrink from data to a bare SYNC frame (§7) asking for a reply.

**Hints.** `Engine::nudge(now)` tells the engine that connectivity may have
changed, for example the OS reports a new network or the app comes to the
foreground. Every contact in backoff then probes at once. Without a hint,
a returning peer is noticed at the next probe in either direction. Without it, Phase 1 spent 17–32 wire bytes per payload byte on
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

## 6. Forward error correction

Most messages fit in one packet, so FEC codes **across packets**, not
within a message. One repair packet can stand in for any one lost packet
of its window. That saves a retransmission timeout, which on these links
means seconds to minutes.

**Sender, per contact:**
- **When FEC is on.** All three must hold:
  - the peer's latest LOSS report is at least `fec_min_loss_permille`
    (default 20 ‰);
  - the contact is not in backoff, so repairs are never sent into an
    outage;
  - the link is budget-rich: one MTU-sized packet costs at most
    `fec_max_packet_cost_ms` (default 2 s) of its rate or duty-cycle
    budget. On a 1%-duty LoRa link a packet costs about 37 s of budget, and
    redundancy would crowd out data.
- **Sources.** Every packet built while FEC is on is a source, ACK-only
  packets included. Its plaintext frames are kept until the window closes.
  Packets are built `fec_reserve` bytes short of the MTU so a repair
  (frame header plus the longest source) always fits in one packet. New
  messages are fragmented with that reserve. Packets built before FEC
  turned on are simply not coded.
- **Windows** close at `fec_max_sources` sources (default 8), or
  `fec_flush_ms` (default 200 ms) after the first source, whichever comes
  first. On close, the engine computes `m` repairs and queues them. Repairs
  are sent after due data and before ACK-only packets.
- **Repair count.** For window size `k` and reported loss `p` (as a
  fraction), each closing window adds `k · 1.5 · p/(1−p)` (at most `k`) to
  a per-contact *repair credit*. The window then gets `m` whole repairs out
  of that credit: at most 1 with `fec = Xor`, at most `k` with
  `fec = ReedSolomon` (the default, D-038). The rest of the credit carries
  over.
- **Spare budget only.** A repair is sent only if the link could still
  send an MTU-sized packet straight afterwards. Otherwise the window's
  pending repairs are dropped (`fec_repairs_dropped`). On a busy link,
  redundancy would delay the data it is meant to protect, and the
  retransmission timer covers the loss.
  This targets about 1.5× the expected losses on average, without
  rounding every lone packet up to a full duplicate at low loss.

**Receiver:**
- **Plaintexts kept** of recently received sources, bounded by
  `max_fec_rx_bytes` (default 32 KiB across all contacts, oldest evicted
  first).
- **Pending repairs** until their window decodes or they are evicted, at
  most `max_fec_pending_repairs` (default 64).
- **Decoding** happens when a window's missing sources number no more than
  its repairs received. It is Gaussian elimination over GF(2⁸) on an
  `e × e` system, where `e ≤ 16`.
- **Loss measurement.** Counter gaps over a separate arrivals bitmap, so
  FEC recoveries don't hide loss from the sender, which would make FEC
  turn itself off. Reported in a LOSS frame with an ACK whenever the
  estimate moves by ≥ 20 ‰, or every 64 packets.

**Cost model.** With FEC on, every packet gives up the `fec_reserve` bytes
(about 7–9 at small MTUs), plus `m/k` extra packets. Sparse traffic means
small windows: a lone packet's single repair is a duplicate, which is the
right code for a lone packet. The simulator reports the bandwidth this
costs against the latency it saves (Phase 4 report, D-037).

## 7. Sync

Reconciliation answers "which messages does each side have?" with a
summary rather than by resending. In a pairwise conversation with dense
per-sender seqs, a direction's state is fully described by four values:
- the sender's `floor`, the lowest seq it can still deliver;
- the sender's `next`, its next unused seq;
- the receiver's `cum`;
- the receiver's bitmap of seqs above `cum`.

The ACK carries the receiver's half and SYNC (wire §3.6) the sender's.
Each frame stands alone, so reconciliation makes progress with whatever
fraction of packets arrives. There is no handshake to complete.

**When SYNC is sent:**
- in every SYNC-only backoff probe, with *reply wanted*;
- in answer to a SYNC that asked for one, together with an ACK;
- after `Engine::restore`, to announce the restored floor and next;
- when a block of 64 sent seqs completes, so its digest reaches the peer.

SYNC rides along with any packet that is going out anyway.

**What it fixes:**
- **Tail loss.** If every packet of the newest messages is lost, the
  receiver learns from `next` that they exist, and asks via its ACK.
- **Lost or reset receiver state.** A fresh install with the same identity,
  or a restore from old storage, has a `cum` far below anything the sender
  can still deliver. Without `floor`, its receive window would stall, and
  after `max_reorder_window` seqs it would drop everything. With `floor` it
  skips the unrecoverable gap and reports it (`Event::MessagesSkipped`),
  so the application can say "N earlier messages were delivered to a
  previous install".
- **Divergence.** If a sender's storage was rolled back (forbidden, see
  `security.md` §4, but it happens), it reuses seqs for new messages. The
  receiver would dedupe those away. Block digests detect this and raise
  `Event::SyncDiverged`, so the host can warn instead of silently losing
  messages. Repairing divergence would need message histories that v1
  doesn't keep.

**Persisted:**
- the last 4 sent-block digests, in the contact record;
- the last 4 received-block digests, with their message counts, in the
  receive-window record (so only completely received blocks are compared).

**Not done:** range-based set reconciliation (Minsky–Trachtenberg, IBLTs,
RBSR). It solves sets without a dense order, such as group conversations
with many senders or multi-device histories. In a pairwise conversation
the dense seq order makes (floor, next, cum, bitmap) a complete summary at
O(1) size plus the reorder window. Range reconciliation is the extension
point for groups (D-039).
