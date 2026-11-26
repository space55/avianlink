# Push notifications

> **Status: D-052.** Lets a relay wake an offline phone through APNs or FCM
> when something arrives for it. Optional at every layer: a relay without a
> push service configured, and a client that never registers, behave
> exactly as in `relay.md`.

## 1. Model

```
client ──PUSH_REGISTER / PUSH_BIND──▶ relay ──NOTIFY──▶ avianlink-push ──▶ APNs / FCM ──▶ client
```

- **Only the app's publisher can push to it.** APNs and FCM accept
  notifications only from whoever holds the app's credentials. Relays are
  run by anyone (`relay.md` §1), so they never hold those credentials. A
  separate **push service**, `avianlink-push`, holds them; it is run by the
  app's publisher, and any relay can forward to it.
- **Nobody sees more than its part.** The client seals its device token to
  the push service's key (§2). The relay stores an opaque blob, and learns
  neither the provider, the app nor the token. The push service learns the
  token, but never sees a tag, a mailbox or a packet. Apple and Google see a
  content-free wake-up.
- **A push is a hint.** It carries no content, and the relay is untrusted
  (`relay.md` §5). A push that never comes only delays a message until the
  app next runs and fetches; a forged one costs a wasted fetch. Delivery is
  still confirmed only end to end.
- **On the phone,** the notification is a visible alert with
  `mutable-content`. The Notification Service Extension wakes, runs the
  engine, fetches from the relay with the ordinary `RelayClient`, decrypts,
  and rewrites the alert. Silent background pushes are throttled by iOS and
  not delivered to an app the user has closed, so they are not used.
- **Provider-neutral.** The provider is a byte inside the sealed blob (§2).
  Adding a provider changes only the push service.

## 2. The sealed registration

The push service has an avianlink identity, `PK_G`, printed by
`avianlink-push init`; apps ship it. The app seals the token from the OS:

```
pt   = provider:u8  app:u8  token:rest
blob = version:u8 = 1  eph[32]  ct
k    = HKDF-SHA256(salt = eph ‖ PK_G, ikm = X25519(e, PK_G), info = "avianlink-push-seal-v1", 32)
ct   = ChaCha20-Poly1305(k, nonce = 0¹², aad = version ‖ eph, pt)
```

`e` is a fresh identity (its public key is `eph`), used once, so the zero
nonce is safe. `X25519` is the same Ed25519→X25519 agreement as
`security.md` §3.

| provider | Meaning |
|---|---|
| 1 | APNs, production |
| 2 | APNs, sandbox (development builds) |
| 3 | FCM |

`app` selects one of the apps configured on the push service (a bundle ID
or an FCM project). Blobs are at most 512 bytes. A blob is sealed once per
token and kept; the app re-seals only when the OS hands it a new token.

## 3. Handles

A client chooses a random 16-byte **push secret**, once, and keeps it with
its state. The relay names the registration by

```
handle = SHA-256("avianlink-push-handle-v1" ‖ secret)[..8]
```

Only PUSH_REGISTER carries the secret. The bindings (§4) carry the handle,
so knowing a handle (from a PUSH_BIND on the wire) is not enough to point
it at a different blob.

## 4. Protocol

Five more relay message kinds, in the format of `relay.md` §4: byte 0 is
the kind, and the 4-byte checksum ends the message. The relay answers the
first three with a REPLY (`relay.md` §4) naming the request; the notes
have no answer.

| Kind | Name | Body (then `check[4]`) | Size |
|------|------|------|------|
| `0x14` | PUSH_REGISTER | `secret[16] blob[..]` | 21–533 |
| `0x15` | PUSH_BIND | `tag[3] down_proof[16] handle[8]` | 32 |
| `0x16` | PUSH_BIND_HELLO | `key[32] handle[8] on:u8 sig[64]` | 110 |
| `0x17` | HELLO_NOTE | `hello_hash[4] detect[8]` | 17 |
| `0x1a` | PUSH_NOTE | `tag[3]` | 8 |

**PUSH_REGISTER and PUSH_BIND_HELLO are over 48 bytes.** They are sent
only by a client that can reach a push provider, which is on IP. Every
message a sender on a LoRa link needs still fits in 48 bytes.

### 4.1 PUSH_REGISTER

Creates the handle with `blob`, or replaces its blob and refreshes it.
An empty blob deletes the handle and all its bindings. REPLY `OK` with
`key = handle[..3]` and `cursor` 1 if the handle already existed, 0 if it
was created. A client seeing 0 binds everything again: the relay lost or
expired it. `FULL` if the relay holds too many handles.

### 4.2 PUSH_BIND

Proves the down chain of the mailbox for `tag`, exactly as FETCH does
(`relay.md` §4.3), and binds that mailbox to the handle. **The proof is
the point:** without it, anyone could bind a mailbox they have seen to
their own device and learn when its owner receives mail. REPLY `OK`,
`BAD_PROOF`, `UNKNOWN_MAILBOX` (or the handle is unknown), or `FULL` if
the handle has too many bindings. Clients bind each contact's incoming
mailbox once per epoch (and the next epoch near a boundary, as for
REGISTER), the first time they connect with push set.

### 4.3 Hellos

A Hello names its recipient only by a 2-byte hint (`wire-format.md`
§2.5), and the relay can't check its MAC. Pushing on the hint alone would
wake every registered recipient sharing it: about one in 65,536 of them,
which on a busy relay in a spike is many. Two more messages make the match
exact:

- **HELLO_NOTE**, from the sender: whenever a client uploads a Hello to a
  relay, it also uploads the note, with
  `hello_hash = receipt_hash(hello)` and
  `detect = SHA-256("avianlink-hello-push-v1" ‖ PK_R)[..8]`.
  It fits in 48 bytes, so senders behind LoRa send it too.
- **PUSH_BIND_HELLO**, from the recipient: binds its key to the handle,
  proved by `sig = Ed25519(identity, "avianlink-push-hello-v1" ‖ handle ‖
  on)` against `key`. With `on = 0` it removes the binding. The signature
  stops anyone binding somebody else's key to their own device. Replaying
  a recorded one only re-sends what its owner asked for.

The relay pushes for a Hello when it holds both the Hello and a note with
its hash, the note's `detect` matches a bound key, and the Hello's hint is
that key's hint. Whichever arrives second triggers the check. A false
match needs 96 bits to collide by chance. Notes without a stored Hello are
kept 10 minutes, at most 65,536 of them, oldest first out.

**The privacy cost.** Anyone can compute `detect` from a public key. So
someone watching the relay who already knows your key can tell which
Hellos are for you; the 2-byte hint alone left that ambiguous. And the
relay operator learns which push handle belongs to which key, which
mailbox bindings never reveal. That is why Hello pushes are a separate
opt-in (`on`), and why notes carry no more than a hash of the key.

### 4.4 When the relay pushes

- **Messages:** when an upload session that is marked by a **PUSH_NOTE**
  stores a packet in a mailbox bound to a handle. Unless that mailbox's
  fetch lease (`relay.md` §4.3) is live: then its owner is online and gets
  the packet forwarded at once.

  The relay can't tell a message from an acknowledgement, since both are
  encrypted, and the recipient's own ACKs land in its mailbox after every
  turn. Pushing on every stored packet would show a false "New message"
  for each. So the sender says which uploads carry a message: after a
  burst of uploads that included one, the client sends PUSH_NOTE with the
  session's tag (8 bytes, so LoRa senders send it too). It's honoured only
  from the address holding that upload session, like the uploads
  themselves. A note covers what the session stored since its last push,
  or, arriving first, the next packet it stores. ACK-only uploads are never
  noted. The relay learns which uploads are messages, which their sizes and
  timing mostly showed anyway.
- **Hellos:** on a match (§4.3), unless a FETCH_HELLO for that hint came
  from anywhere in the last 10 minutes.
- **Coalescing:** at most one push per handle per minute. Anything that
  arrives in between is covered by one more push when the minute ends. A
  burst of 500 packets is one or two pushes, not 500.
- **Expiry:** handles expire after the relay's retention without a
  PUSH_REGISTER; bindings go with their handle or their mailbox.
- **Durable:** handles and bindings are committed to storage before they
  are acknowledged, like mailboxes.
- PUSH_REGISTER and PUSH_BIND take a rate-limit token (`relay.md` §4.4),
  and PUSH_BIND_HELLO two (it verifies a signature).

## 5. Relay → push service

The relay sends NOTIFY datagrams over UDP to its configured push service.
Fields and checksum as in `relay.md` §4, with the label
`"avianlink-push-v1"` instead of `"avianlink-relay-v1"`.

| Kind | Name | Body (then `check[4]`) |
|------|------|------|
| `0x20` | NOTIFY | `id:u64 kind:u8 blob[..]` |
| `0x21` | NOTIFY_ACK | `id:u64 code:u8` |

`id` is random per NOTIFY. `kind` is 0 for messages and 1 for Hellos; the
app learns it from the push, so it knows whether to fetch mailboxes or
Hellos. The relay re-sends a NOTIFY not acknowledged within 2 s, up to 3
times, then gives up: a lost push is a delay. Codes:

| Code | Meaning |
|------|---------|
| 0 | OK: handed to the provider |
| 1 | GONE: the provider says the token is dead. The relay deletes the handle. |
| 2 | BAD_BLOB: not sealed to this push service |
| 3 | RATE_LIMITED: too many pushes to this token |
| 4 | FAILED: the provider refused or was unreachable |

**The push service is open to any relay.** That is the point, since relays
are run by anyone. A recorded blob can be replayed to it, though, by
anyone who saw a PUSH_REGISTER. So the push service limits pushes per
token (default: 1 a minute, bursts of 5), which bounds what a replayer can
do to one device to that rate.

## 6. Payloads

The push service sends no content, only the kind:

- **APNs:** `{"aps":{"alert":{"title":"avianlink","body":"New message"},
  "mutable-content":1},"avl":"m"}`, `apns-push-type: alert`,
  `apns-priority: 10`, with `"avl":"h"` and body "New contact request"
  for Hellos. The app's extension replaces the text once it has fetched.
- **FCM:** a high-priority data message, `{"avl":"m"}` or `{"avl":"h"}`.
  The app fetches and posts its own notification.

## 7. Library and hosts

- **`avianlink_core::push`:** `seal` and `open` for blobs, `handle`,
  `detect`, and the NOTIFY codec.
- **`Engine`** builds the messages that need its keys:
  `mailbox_push_bind` (consumes a down proof), `push_bind_hello` (signs),
  and `hello_note`.
- **`RelayClient::set_push`** takes the secret, the blob and whether to
  push Hellos. In each session the client sends PUSH_REGISTER, then binds
  every incoming mailbox not yet bound by this process, uploads a
  HELLO_NOTE with every Hello, and sends a PUSH_NOTE after each burst of
  uploads that carried a message (`Transmit::carries_message`).
- **`Relay`** keeps handles and bindings, and queues pushes;
  `poll_push` hands them to the host, and `push_gone` deletes a handle.
- **`avianlink-relay --push-service HOST:PORT`** sends NOTIFY datagrams and
  handles acknowledgements. Without the flag, the relay refuses
  PUSH_REGISTER with `FULL`, so clients don't spend proofs on bindings that
  can never fire.
- **C ABI:** `avl_push_seal` and `avl_relay_set_push` (`ffi.md` §4).
- **`avianlink-push`** (its own repository) is the push service, on UDP
  41001 by default: `init` prints its key, and `run` reads a TOML file
  naming the APNs key (`.p8`, team and key ID, bundle ID) and FCM service
  account per app.
