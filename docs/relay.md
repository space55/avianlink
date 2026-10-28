# avianlink relays

> **Status: D-045 (after Phase 7).** A store-and-forward relay for peers that
> are never online at the same time. The relay is untrusted and has no
> identity.

## 1. Model

The use case: A comes online, sends to B and goes offline. Later B comes
online, collects A's messages, replies and goes offline. Then A comes back,
and so on. In a disaster, everyone connects to the same relay at once.

- **The relay is a link, not a peer.** It stores and forwards packets it
  can't read, like a slow, lossy radio. It has no identity, no keys and no
  conversation state, so restarting it, or rebuilding it empty, never
  touches the endpoints' cryptography.
- **The relay is untrusted.** Delivery is confirmed only by the recipient's
  end-to-end ACK, an ordinary encrypted packet that the relay stores like
  any other. A relay that loses, withholds or delays packets is a bad link,
  and the sender resends (§6). A relay can't read, forge or alter traffic.
- **The relay never drops accepted packets.** It keeps them until the
  retention it is configured with (at most 30 days) expires, or until the
  recipient proves it has them (§4.3). When full, it refuses new uploads
  rather than evicting old ones, and says so (§4.4). The sender's outbox is
  durable, so a refused packet is retried, never lost.
- **Every relay message fits in 48 bytes,** the smallest MTU, so clients
  behind a LoRa gateway can use the relay.

## 2. Mailboxes

Every direction of every pair (A→B, and separately B→A) has its own
**mailbox** at the relay. The relay knows a mailbox by:
- the direction's **routing tag** (3 bytes, `wire-format.md` §2.2), the tag
  on every data packet A sends to B;
- an **upload anchor** and a **fetch anchor** (16 bytes each): the public
  ends of two hash chains that only A and B can compute.

### 2.1 Hash chains

Both members of the pair derive, for direction S→R, role
`r` ∈ {`up`, `down`} and **mailbox epoch** `e`:

```
e          = floor(unix_ms / 30 days)
seed(r, e) = HKDF-Expand(prk(S,R), "mailbox" ‖ r ‖ varint(e) ‖ PK_S ‖ PK_R, 16)
v_0        = seed(r, e)
v_{i+1}    = SHA-256("avianlink-chain-v1" ‖ v_i)[..16]
anchor     = v_N,   N = 16384
```

`prk` is the pair's key-derivation secret (`security.md` §3), so nobody
else can compute a seed. The *k*-th proof a client makes is `v_{N-k}`. A
proof is a one-time password: the relay keeps the last value it accepted,
`L` (initially the anchor), and accepts `p` if `H^j(p) = L` for some
1 ≤ *j* ≤ 256, then sets `L = p`. The window of 256 tolerates proofs lost
on the way. A recorded proof is useless once used, and the next one
can't be computed from it.

- **Up proofs** open upload sessions (§4.2). Only the sender S uses them.
- **Down proofs** fetch (§4.3). Only the recipient R uses them.

Each user keeps its own position in its own chain, so the two never
collide. Positions are persisted with the contact. A client whose state is
lost gets a new identity (D-046), and with it new mailboxes.

**Epochs renew the chains** with no coordination: both members compute
`e` from the clock, so each epoch has fresh mailboxes. 16384 proofs per
role per epoch is about 550 a day. Senders upload to the current epoch's
mailbox. Recipients fetch the current and the previous epoch, since the
previous one can hold packets for up to the retention period, until each
is empty. Near a boundary a client registers both epochs, so a sender
whose clock is ahead and a recipient whose clock is behind still meet.
Idle old-epoch mailboxes expire like any other (§4.4). Relay use
therefore needs a roughly correct wall clock (within days).

### 2.2 Shared tags

Routing tags are 3 bytes, so on a busy relay distinct pairs sometimes share
one. **The relay keeps a separate mailbox for each (tag, anchors) pair.**
Packets are filed into a mailbox by the proven upload session they arrive
in, and only a matching fetch proof reads them. So colliding pairs never
see each other's traffic, and someone who registers a tag they have seen,
with anchors of their own, gets an empty mailbox. Registration is never
refused because of a collision.

### 2.3 Hellos

A Hello (`wire-format.md` §2.5) for a recipient that doesn't know the
sender can't use a mailbox: the recipient can't compute the pair secret
yet. Hellos are filed **openly by their 2-byte hint**. Anyone can fetch the
Hellos for a hint, and they expire like everything else. Hellos are
unauthenticated to outsiders anyway, and repeats are byte-identical, so
the relay stores each one once.

## 3. Who registers

Whichever member of the pair first uses the relay registers **both
directions** of the pair. It can, because it derives all four anchors.
Registering again with the same anchors is harmless: it refreshes the
mailbox's activity time. So the tags are pinned before any packet carrying
them is on the wire. When A introduces itself to B through the relay, A
registers B's incoming mailbox before uploading its Hello and first
message. B, after accepting the request, derives the same anchors and
fetches.

## 4. Protocol

Relay messages travel in their own datagrams, beside data packets and
Hellos, and are told apart by byte 0 (`wire-format.md` §2). All fields as in
`wire-format.md` §1. **Every relay message ends with a 4-byte checksum**,
`SHA-256("avianlink-relay-v1" ‖ message)[..4]`, and is dropped if it doesn't
match. Relay messages have no AEAD, and these links flip bits: one flipped
bit in a REPLY cursor once made a simulated client release 250 packets it
had never read. The checksum detects corruption, not forgery; the relay has
no keys (§5). Sizes below include it.

| Kind | Name | Body (then `check[4]`) | Size |
|------|------|------|------|
| `0x10` | REGISTER | `tag[3] up_anchor[16] down_anchor[16]` | 40 |
| `0x11` | OPEN | `tag[3] up_proof[16]` | 24 |
| `0x12` | FETCH | `tag[3] down_proof[16] since:varint release:varint max:u8` | 27–35 |
| `0x13` | FETCH_HELLO | `hint[2] since:varint` | 8–12 |
| `0x18` | REPLY | `request:u8 code:u8 key[3] retention_s:varint cursor:varint n:u8 hash[4]×n` (n ≤ 6) | 14–44 |
| `0x19` | RECEIPT | `code:u8 count:u8 hash[4]×count` (count ≤ 10) | 7–47 |

All fit in 48 bytes while the retention is under 2²⁸ seconds and sequence
numbers are under 2³⁵.

`key` is the request's tag, or its hint padded with a zero byte. Codes:

| Code | Meaning |
|------|---------|
| 0 | OK |
| 1 | BAD_PROOF |
| 2 | UNKNOWN_MAILBOX |
| 3 | FULL: refused for lack of space; retry later or elsewhere |
| 4 | NO_SESSION: a data packet with no upload session for its tag from this address |
| 5 | RATE_LIMITED |
| 6 | MORE: a FETCH page ended and more is waiting |

Every REPLY carries the relay's **retention** in seconds, so clients learn
it without configuring it (§6). Malformed messages are dropped.

### 4.1 REGISTER
Creates the mailbox (tag, up_anchor, down_anchor) if it doesn't exist, and
otherwise refreshes it. REPLY `OK`, or `FULL` if the relay can't take more
mailboxes.

### 4.2 OPEN, then upload
OPEN proves the up chain of a mailbox for that tag. If several mailboxes
share the tag, the relay tries each, so the proof also selects the mailbox.
It then binds **(source address, tag) → mailbox** for 10 minutes, renewed by
every upload. Each data packet that then arrives from that address with
that tag is stored in the mailbox. The relay answers each stored packet
with a RECEIPT: `OK` with the packet's hash, or `FULL`, or `NO_SESSION`
when no session matches.

```
hash = SHA-256("avianlink-receipt-v1" ‖ packet)[..4]
```

A Hello uploaded to the relay needs no session: it's filed by its hint
(§2.3) and receipted the same way.

A receipt is sent only after the packet is **durable** at the relay.

### 4.3 FETCH
FETCH proves the down chain. The relay first deletes the mailbox's packets
below `release` (≤ `since`): the client is proving it has them. That frees
space in a spike without dropping anything undelivered. Then it sends, as
plain datagrams exactly as uploaded, up to `max` packets (0: the relay's
page size, at most 6) whose relay sequence number is ≥ `since`. Then a
REPLY with:
- `cursor`, the sequence number after the page;
- the page's receipt hashes in order. They had sequence numbers
  `cursor − n .. cursor`;
- code `MORE` if packets remain, or `OK` if not.

**Reading and releasing are separate.** From the hashes, the client knows
exactly which sequence numbers it now holds, including page packets that
arrive after their REPLY. It keeps reading forward (`since` = the highest
seen), and records the ones that never arrived. Once at the end, it re-reads
from the first gap, asking with `max` for just the span covering its gaps.
`release` is always the first sequence number it still lacks, so loss slows
reading but never makes the relay delete something unread. (A first design
advanced only when a whole page arrived. On a 35%-loss link a 6–16 packet
page rarely does, and the client never got past page one.)
- **Lease.** For 10 minutes after a FETCH, renewed by each fetch, new
  uploads to the mailbox are also forwarded to the fetcher's address at
  once. Online clients re-fetch every 5 minutes, which keeps the lease
  alive and costs about 290 proofs a day, within an epoch's budget. If both ends happen to be online, traffic flows live. Forwarded
  packets are still stored and fetched normally.

FETCH_HELLO works the same for a hint, without proof and without deletion.

### 4.4 Relay policy
These are relay-side settings; clients only learn the retention.
- **Retention:** at most 30 days. Packets and Hellos are evicted at expiry
  and not before, except packets below a proved fetch cursor.
- **Mailboxes expire** after one retention period with no REGISTER, OPEN or
  FETCH.
- **Capacity:** a per-mailbox share and a total. Uploads beyond either are
  refused with `FULL`; nothing stored is evicted early.
- **Durability:** packets, mailboxes and cursors are committed to durable
  storage before they are acknowledged.
- **Rate limits** per source address on proof checks (each costs up to 256
  hashes) and registrations.

## 5. Threats

- **Reading or forging traffic:** impossible. Everything stored is
  end-to-end encrypted and authenticated between the endpoints.
- **Fetching someone else's mail:** needs their down chain, i.e. the pair
  secret. Recorded proofs are one-time.
- **Spoofed source addresses (UDP):** an attacker spoofing A's address
  during A's upload session can file junk into A's mailbox. B discards it,
  because it doesn't decrypt. The cost is A's share of space, the same
  damage as flooding.
- **Metadata:** the relay and anyone watching it see each mailbox's tag,
  sizes and timing, which client addresses upload and fetch, and the
  sender keys in Hellos (`security.md` §8). Tags don't name users; Hellos
  do.
- **A malicious relay** can drop, delay, or withhold packets, or send false
  receipts. False `OK` receipts delay a message until the next end-to-end
  resend (§6). Delivery is never falsely confirmed.
- **Forged replies.** Anyone able to spoof the relay's address can send a
  REPLY. The checksum doesn't stop that, because it isn't keyed. A forged
  page could make a client release packets it hasn't read. The sender
  still holds every message until the recipient's end-to-end ACK and
  resends it (§6), so the damage is delay, as with any packet dropped on
  the way. Nothing is lost for good.

## 6. The engine on a relay

A link registered with `Engine::add_relay_link` is a relay. Traffic routed
over it follows these rules instead of `reliability.md` §3:

- **Hop reliability by receipt.** The host passes each RECEIPT's hashes to
  `Engine::handle_receipt`. A fragment is *stored* once a packet carrying
  it is receipted `OK`. Until then it is retransmitted at the RTO, with RTT
  sampled from receipts, so the RTO tracks the relay hop. A `FULL` refusal
  delays the retry by `max_rto_ms`.
- **End-to-end by ACK, on a slow timer.** A stored fragment is next due
  only after **half the relay's retention**. The host passes the retention
  from any REPLY to `Engine::set_link_retention`; it defaults to 7 days
  until known. That's often enough that some copy is always held, however
  long the recipient stays away, and it costs about two copies of each
  undelivered message.
- **No backoff, no probes, no FEC.** On a relay, silence from the peer is
  normal. `ContactStatus::unreachable` stays false.
- **ACKs are hop-reliable too.** If the packet carrying our latest ACK isn't
  receipted within the RTO, the ACK goes out again. Otherwise B's
  confirmation could wait days for a resend.
- **Hellos:** an unconfirmed contact's Hello is uploaded once and receipted
  like a packet, then again every half-retention until the contact
  confirms.
- **Events:** `Event::MessageStored` (transient) fires when every fragment
  of a message is stored: "safe to go offline". `MessageDelivered` still
  means only the peer's ACK. `OutgoingStatus::fragments_stored` counts
  progress.
- **Mailbox material:** `Engine::mailbox_register`, `mailbox_open` and
  `mailbox_fetch` build the relay messages. Each proof's position is
  persisted before the message is returned, so a proof is never reused.
  `Engine::hello_fetch` builds the Hello fetch.
- **When to go offline:** `Engine::relay_settled()` is true once every
  fragment, ACK and Hello owed to a relay contact is stored there.

## 7. Hosts

- **`avianlink_relay::RelayClient`** (sans-IO) runs the protocol next to an
  engine:
  - registers both directions per epoch (the next one too, near a
    boundary);
  - opens upload sessions and holds packets until they open;
  - reads the previous then the current epoch, one fetch in flight per
    contact, with gaps re-read;
  - fetches Hellos;
  - retries unanswered requests with fresh proofs;
  - passes receipts and the retention to the engine.

  `caught_up()` is true once nothing is outstanding and every mailbox is
  read to the end with nothing missing. **A host should go offline only
  when both `relay_settled()` and `caught_up()` hold.**
- **`avianlink_relay::Relay`** is the relay itself, sans-IO: datagrams in,
  datagrams out, a `Storage` for durability.
- **`avianlink-relay`** (binary, in `avianlink-udp`) runs it on a UDP
  socket with `FileStorage`:

  ```
  avianlink-relay --bind 0.0.0.0:7400 --dir /var/lib/avianlink-relay \
                  [--retention-days 7] [--mailbox-quota-kib 1024] [--total-quota-mib 1024]
  ```
- **`UdpHost`** with `HostConfig::relay` sends and receives everything
  through the relay, and reports `HostEvent::Settled` ("safe to go
  offline").
- **The CLI:** `avianlink chat DIR --bind HOST:PORT --relay HOST:PORT
  [--peer KEY]`.

## 8. Results

`simrun --profile turns_all --seeds 10`. Per run, A and B alternate 40
sessions each, never online together, about 2 h apart (exponential).
Sessions last 30 s to 5 min: a node leaves once settled and caught up, or at
the cap regardless. Each session writes 0–2 messages from the ~200-byte
mix. Both hops (client→relay, relay→client) apply the named profile.
Packets that arrive while a node is offline are lost. "Sessions" counts the
recipient's sessions until the message arrived; 1 means its very next
session.

| Hops | Delivered by end of run | Still queued by sender | Lost | Sessions p95 (median) / max | Wire bytes / payload byte (median) |
|---|--:|--:|--:|--:|--:|
| `clean` | 818/818 | 0 | 0 | 1 / 1 | 3.8 |
| `geo_satellite` | 818/818 | 0 | 0 | 1 / 1 | 4.1 |
| `edge_2g` | 818/818 | 0 | 0 | 1 / 1 | 5.4 |
| `disaster_cellular` | 774/818 (94.6%) | 44 | 0 | 2 / 15 | 18.7 |
| `lora_like` | 805/818 (98.4%) | 13 | 0 | 1 / 2 | 21.4 |

**No message was ever lost.** Anything undelivered at the end of a run is
still in its sender's outbox, being resent. The cost on the worst links is
overhead: about 20 bytes on the wire per payload byte, mostly relay
protocol (polls, re-reads, page overlap) and retransmission over 35–60%
bursty loss. That is the main thing to optimise next (D-045,
"Open").
