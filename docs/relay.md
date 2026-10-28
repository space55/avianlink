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
  rather than evicting old ones, and says so (§4.5). The sender's outbox is
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

Both members of the pair derive, for direction S→R and role
`r` ∈ {`up`, `down`}, at generation `g` (starting at 0):

```
seed(r, g) = HKDF-Expand(prk(S,R), "mailbox" ‖ r ‖ varint(g) ‖ PK_S ‖ PK_R, 16)
v_0        = seed(r, g)
v_{i+1}    = SHA-256("avianlink-chain-v1" ‖ v_i)[..16]
anchor     = v_N,   N = 4096
```

`prk` is the pair's key-derivation secret (`security.md` §3), so nobody
else can compute a seed. The *k*-th proof a client makes is `v_{N-k}`. A
proof is a one-time password: the relay keeps the last value it accepted,
`L` (initially the anchor), and accepts `p` if `H^j(p) = L` for some
1 ≤ *j* ≤ 64, then sets `L = p`. The window of 64 tolerates proofs lost
on the way. A recorded proof is useless once used, and the next one
can't be computed from it.

- **Up proofs** open upload sessions (§4.2). Only the sender S uses them.
- **Down proofs** fetch (§4.3). Only the recipient R uses them.

Each user keeps its own position in its own chain, so the two never
collide. Positions are persisted with the contact. A client whose state is
lost gets a new identity (D-046), and with it new mailboxes. When a chain
runs low (fewer than 64 proofs left), the client re-keys to generation
`g + 1` (§4.4).

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
`wire-format.md` §1.

| Kind | Name | Body | Size |
|------|------|------|------|
| `0x10` | REGISTER | `tag[3] up_anchor[16] down_anchor[16]` | 36 |
| `0x11` | OPEN | `tag[3] up_proof[16]` | 20 |
| `0x12` | FETCH | `tag[3] down_proof[16] since:varint` | 21–30 |
| `0x13` | FETCH_HELLO | `hint[2] since:varint` | 4–13 |
| `0x14` | REKEY | `tag[3] role:u8 proof[16] new_anchor[16]` | 37 |
| `0x18` | REPLY | `request:u8 code:u8 key[3] retention_s:varint cursor:varint` | 8–25 |
| `0x19` | RECEIPT | `code:u8 count:u8 hash[4]×count` (count ≤ 10) | 3–43 |

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
FETCH proves the down chain. The relay sends, as plain datagrams exactly as
uploaded, the mailbox's packets whose relay sequence number is ≥ `since`,
up to one page. Then it sends REPLY with `cursor` = the next sequence
number, and code `MORE` if packets remain or `OK` if not. The client
fetches again with `since = cursor`.

- **A proved `since` means the recipient has everything below it,** so the
  relay deletes those packets. That frees space in a spike without ever
  dropping anything undelivered.
- **Lease.** For 60 seconds after a FETCH, renewed by each fetch, new
  uploads to the mailbox are also forwarded to the fetcher's address at
  once. If both ends happen to be online, traffic flows live. Forwarded
  packets are still stored and fetched normally.

FETCH_HELLO works the same for a hint, without proof and without deletion.

### 4.4 REKEY
Proves the current chain of one role (`0` up, `1` down) and replaces its
anchor with `new_anchor` (generation `g + 1`). REPLY `OK` or `BAD_PROOF`.

### 4.5 Relay policy
These are relay-side settings; clients only learn the retention.
- **Retention:** at most 30 days. Packets and Hellos are evicted at expiry
  and not before, except packets below a proved fetch cursor.
- **Mailboxes expire** after one retention period with no REGISTER, OPEN or
  FETCH.
- **Capacity:** a per-mailbox share and a total. Uploads beyond either are
  refused with `FULL`; nothing stored is evicted early.
- **Durability:** packets, mailboxes and cursors are committed to durable
  storage before they are acknowledged.
- **Rate limits** per source address on proof checks (each costs up to 64
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

## 6. The engine on a relay

A link registered with `store_and_forward: true` is a relay. Traffic routed
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
- **Mailbox material:** `Engine::mailbox(conv)` returns both directions'
  tags and anchors, and `Engine::mailbox_proof(conv, role)` returns the next
  proof, persisting the position. The host runs the relay protocol itself
  (registration, sessions, fetch paging, Hello fetches for
  `Engine::hello_hint()`).

`avianlink-udp`'s `UdpHost` does all of this when configured with a relay
address.
