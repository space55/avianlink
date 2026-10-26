# IPC contract

Everything that crosses the Tauri boundary. Each type is defined **once**, in
`src-tauri/src/ipc.rs`, and the TypeScript in `src/lib/ipc/bindings.ts` is
generated from it with `ts-rs` (DA-006). This document is the prose that the
generated file cannot carry: units, invariants, error behaviour, and which
field the UI is allowed to believe.

If this document and `ipc.rs` disagree, `ipc.rs` is right and this document
is a bug.

## Conventions

**Binary values are lowercase hex strings.** `PublicKey` is 64 characters
(32 bytes), `ConversationId` and `MessageId` are 32 characters (16 bytes).
They are strings rather than byte arrays because they are used as object keys
and in URLs, and because `number[]` across JSON is both larger and easy to
mutate by accident. Decoding rejects uppercase, odd lengths and wrong
lengths.

**Times are integer milliseconds since the Unix epoch**, as `number`. A
double holds integer milliseconds exactly until the year 287396, so `number`
is safe here. Fields that are a _duration_ are named `*_ms`.

**`null` means "not known", never "zero".** `delivered_at: null` on a
delivered message would be a bug; `delivered_at: null` on a queued message is
correct and expected.

**Sequence and Lamport values are `number`.** They are `u64` in Rust and so
can in principle exceed `Number.MAX_SAFE_INTEGER`. They cannot in practice: a
`u64` sequence counter at one message per millisecond takes 285,000 years to
reach 2^53. The frontend uses them only for ordering and never does
arithmetic that would lose precision. Noted because it is the one place the
JSON boundary is lossy in theory.

**Secrets never appear here.** There is no IPC type with a private key,
seed, or keychain handle in it. The frontend cannot ask for one; no command
returns one. `get_identity` returns a public key and a fingerprint.

## Errors

Every command returns `Result<T, IpcError>`. On the TypeScript side a
rejected `invoke` promise carries the serialised `IpcError`.

```
IpcError {
  kind: IpcErrorKind,
  message: string,          // human-readable, safe to show in UI
}

IpcErrorKind =
  | "bad_request"      // malformed argument: bad hex, empty text, unknown enum
  | "not_found"        // no such conversation, contact, link or message
  | "conflict"         // contact already exists, link id in use
  | "limit"            // engine limit hit: outbox full, text too long, too many contacts
  | "storage"          // SQLite or keychain failure
  | "engine"           // the engine rejected the call for another reason
  | "internal"         // a bug in the app; the message is a diagnostic
```

`kind` is what the UI branches on; `message` is what it shows. The split
exists so that a new error cause does not need a frontend change to be
displayed, while the cases the UI genuinely handles differently (`limit` on
send must not clear the composer; `not_found` should drop the conversation
from the sidebar) stay machine-checkable.

**Notably, `send_message` must not fail for link reasons.** Sending is a
local durable write. The only errors it can return are `bad_request` (empty
or oversized text), `not_found` (unknown conversation), `limit` (outbox
full), and `storage`. It never waits for a link and never reports one.

## Core types

### `Identity`

```
Identity {
  public_key: string,         // 64 hex
  fingerprint: string,        // "a1b2-c3d4-e5f6-7890-abcd"
  display_name: string | null // what we call ourselves; local only, never sent
}
```

The fingerprint is `hex(SHA-256("avianlink-fingerprint-v1" || pk)[..10])` in
five groups of four (DA-009, AR-004). It is derived, never stored, so it
cannot disagree with `public_key`.

### `Contact`

```
Contact {
  conversation_id: string,          // 32 hex; the stable identifier for a peer
  public_key: string,               // 64 hex
  fingerprint: string,
  display_name: string,             // local label; never leaves this machine
  verified: boolean,                // the user asserts they compared the fingerprint
  added_at: number,                 // unix ms
  last_packet_at: number | null,    // last packet attributed to this peer, unix ms
  last_message_at: number | null    // last message received from this peer, unix ms
}
```

`conversation_id`, not `public_key`, is the identifier used everywhere else:
it is what the engine routes on, and it is the same value on both sides of a
conversation.

`verified` is the user's own claim, stored locally and shown as a quiet
marker. The app never treats an unverified contact as unusable — on these
links, out-of-band verification may legitimately take days.

`last_packet_at` is best-effort; see AR-007 for why it can lag behind
reality by one ACK-only packet.

### `MessageStatus`

```
MessageStatus = "queued" | "sent" | "delivered" | "failed"
```

| value       | means                                       | reached when                                                                      |
| ----------- | ------------------------------------------- | --------------------------------------------------------------------------------- |
| `queued`    | durably saved locally, nothing has gone out | `send_message` returns                                                            |
| `sent`      | at least one transmission left this machine | a `Transmit` carrying it was flushed to a link (currently over-reported — AR-002) |
| `delivered` | the recipient acknowledged it               | `Event::MessageDelivered`                                                         |
| `failed`    | the engine gave up                          | never, with the real engine (AR-003)                                              |

Incoming messages have no status; the field is `null` for them. The
progression is monotonic: the backend never moves a message from `delivered`
back to `sent`.

### `Message`

```
Message {
  id: string,                      // 32 hex
  conversation_id: string,         // 32 hex
  outgoing: boolean,
  text: string,

  lamport: number,                 // causal order key
  seq: number,                     // per-sender sequence within the conversation
  order_key: string,               // opaque; sort messages by this, ascending

  sent_at: number | null,          // sender-asserted wall clock, unix ms
  received_at: number | null,      // when our engine got it, unix ms; incoming only
  status: MessageStatus | null,    // outgoing only
  delivered_at: number | null,     // outgoing only
  attempts: number | null,         // transmissions so far; outgoing only
  arrived_late: boolean,           // see below
  missing_before: number           // earlier messages not yet arrived
}
```

`order_key` is the contract the UI relies on. It is
`<lamport as 16 hex digits> + ":" + <id>`, so lexicographic string order is
`(lamport, id)` order: causal order, with a deterministic tiebreak between
genuinely concurrent messages. The frontend sorts by this string and never
re-derives the ordering rule, so changing the tiebreak is a backend-only
change. It is also the pagination cursor (see `get_messages`).

**Two times.** `sent_at` is when the sender says they wrote it; `received_at`
is when it got here. For outgoing messages `sent_at` is our own queue time
and `received_at` is `null`. For incoming messages `sent_at` may be `null`
(the sender has no wall clock — library D-014) in which case the UI shows
`received_at` alone. The UI shows `sent_at` by default and surfaces
`received_at` as well only when the gap is large enough to matter; the
threshold is a frontend display decision, not part of this contract.

`arrived_late` is set by the backend when the message was inserted into
history _behind_ messages that were already stored — that is, a strictly
greater `order_key` already existed in the conversation when this one
arrived. It is computed once, at insert time, and stored. It is deliberately
not recomputed: it records "this appeared out of order while you were
watching", which is a fact about history, not about the current sort.

### `Link`

```
Link {
  id: number,                            // u16 LinkId
  label: string,
  kind: LinkKind,                        // "udp" | "fake"
  enabled: boolean,                      // user intent
  status: LinkStatus,
  mtu: number,
  config: LinkSettings,                  // tagged union, see below
  packets_sent: number,
  packets_received: number,
  bytes_sent: number,
  bytes_received: number,
  recent_loss_permille: number | null,   // 0..=1000, null when unmeasurable
  last_sent_at: number | null,           // unix ms
  last_received_at: number | null,       // unix ms
  budget_blocked_until: number | null    // unix ms; pacing, not a fault
}

LinkStatus = "up" | "down" | "disabled"
LinkKind = "udp" | "fake"

LinkSettings =
  | { kind: "udp", local_port: number, peers: UdpPeer[] }
  | { kind: "fake", profile: string }

UdpPeer { conversation_id: string, address: string }   // "host:port"
```

`status` is observed; `enabled` is intended. A link the user switched off is
`disabled`, not `down`, because those two deserve very different tones in the
UI. `down` means the app tried and could not (socket bind failed, interface
gone). A link that is `up` but has heard nothing for two days is still `up` —
silence is not a fault on these links, and `last_received_at` is where that
information lives.

`recent_loss_permille` is populated by `FakeEngine`, which knows exactly what
it dropped, and is `null` against the real engine, which cannot observe loss
from one end. `null` must render as "not measured", never as 0 — claiming a
perfect link because nothing measured it is the worst available failure.

`budget_blocked_until` comes from `LinkStats::budget_blocked_until`: the
pacer is the only thing that knows when a duty-cycled radio will next have
airtime.

`budget_blocked_until` is a duty-cycle or rate limit, not an error. It is
separate from `status` so the UI can say "out of airtime until 14:02" while
still showing the link as up.

### `ConversationSummary`

```
ConversationSummary {
  conversation_id: string,
  contact: Contact,
  last_message: MessagePreview | null,
  unread_count: number,
  undelivered_count: number          // outgoing, not yet delivered
}

MessagePreview {
  text: string,                      // truncated to 160 chars by the backend
  outgoing: boolean,
  at: number,                        // unix ms; sent_at ?? received_at
  status: MessageStatus | null
}
```

Truncation happens in the backend so that listing conversations never loads
full message bodies.

## Commands

Argument objects are named `<Command>Args` in Rust and are passed as a single
`args` object, so adding an optional field is never a breaking change.

### `get_identity() -> Identity`

Cheap, idempotent. Creates the identity on first call if none exists (and
persists the private key to the keychain — app Phase 2).

### `list_contacts() -> Contact[]`

Sorted by `display_name`, case-insensitive.

### `add_contact(args: { public_key: string, display_name: string, verified: boolean }) -> Contact`

Registers the key with the engine and stores the local label. Errors:
`bad_request` (not 64 hex characters), `conflict` (already a contact, or it
is our own key), `limit` (`Error::TooManyContacts`), `storage`.

Emits `contact_changed`.

`display_name` may be empty, in which case the backend uses the first group
of the fingerprint. `verified` is whether the user ticked "I compared the
fingerprint" while adding; it can be changed later with
`set_contact_verified`.

### `list_conversations() -> ConversationSummary[]`

One entry per contact, including contacts with no messages yet, so a new
contact appears in the sidebar immediately. Sorted by
`last_message.at` descending, with never-used conversations last, ordered by
`display_name`.

### `get_messages(args: { conversation_id: string, before: string | null, limit: number }) -> MessagePage`

```
MessagePage {
  messages: Message[],      // ascending order_key
  has_more: boolean,        // older messages exist before this page
  oldest_order_key: string | null  // pass as `before` for the next page
}
```

Returns the `limit` newest messages with `order_key < before`, or the newest
`limit` messages when `before` is `null`, and returns them in ascending
order. `limit` is clamped to 1..=500.

**Why an `order_key` cursor and not an offset.** A late-arriving message
inserts into the middle of the conversation. With `LIMIT/OFFSET`, that insert
shifts every page boundary below it and the UI either duplicates or skips a
message while the user scrolls. A cursor on the sort key is stable under
inserts anywhere. This is the whole reason `order_key` is in the wire type.

Errors: `not_found`, `bad_request` (bad hex or non-positive limit).

### `send_message(args: { conversation_id: string, text: string }) -> Message`

Writes the message to history with status `queued` and hands it to the
engine, then returns it. The returned `Message` is what the UI appends
optimistically; its `order_key` is final.

This command does not block on a link and cannot fail because of one. See
"Errors" above for the exhaustive list of what it can return.

`text` is rejected if empty after trimming, or longer than
`Config::max_text_len` (4096 bytes) — `bad_request` and `limit` respectively.

### `list_links() -> Link[]`

Sorted by `id`.

### `configure_link(args: { id: number, config: LinkSettings }) -> Link`

Replaces a link's settings. For a UDP link, rebinds the socket if
`local_port` changed. Returns the link's new state. Errors: `not_found`,
`bad_request` (port out of range, unparseable peer address), `engine`
(`Error::InvalidLinkConfig`).

Emits `link_status_changed`.

### `set_link_enabled(args: { id: number, enabled: boolean }) -> Link`

Disabling removes the link from the engine so nothing is paced onto it;
queued messages stay queued. Emits `link_status_changed`.

## Commands added beyond the brief

The brief's command list is a minimum. These four are required by screens it
also specifies (Settings, and the read/unread state the sidebar shows).

### `mark_conversation_read(args: { conversation_id: string, through_order_key: string }) -> void`

Clears `unread_count` up to a point the user has actually seen. Takes an
`order_key` rather than "all", so a late message that arrives above the read
point stays unread. Emits `contact_changed`.

### `set_contact_verified(args: { conversation_id: string, verified: boolean }) -> Contact`

The "I compared the fingerprint" toggle. Emits `contact_changed`.

### `get_settings() -> Settings` / `set_settings(args: { settings: Settings }) -> Settings`

```
Settings {
  display_name: string | null,
  show_receive_time_threshold_ms: number,   // default 300000 (5 min)
  fake_engine: FakeEngineSettings | null    // present only on FakeEngine
}

FakeEngineSettings {
  profile: string,                 // active impairment profile
  available_profiles: string[],    // every profile that can be selected
  reply_delay_ms: number,          // before a scripted contact begins answering
  reply_jitter_ms: number,         // uniform jitter on top
  scripted_replies: boolean,
  outages: boolean                 // run the profile's link outages
}
```

The packet-level impairments — delay, jitter, bursty loss, corruption,
duplication, reordering, MTU, airtime budget and outage schedule — all come
from the named `profile`, whose parameters are `avianlink-sim`'s and are
shared with `scripts/netem/`. Only knobs with no equivalent in the simulator
are exposed separately. Changing `profile` re-aims the links without
discarding packets already in flight.

`show_receive_time_threshold_ms` is the gap above which the UI shows both
times. It is a setting rather than a constant because the right value
depends entirely on the link the user is on.

### `add_simulated_contact(args: { display_name: string, history: number }) -> Contact`

Adds a contact backed by a simulated device that answers. Only meaningful on
`FakeEngine`; on the real engine it fails with `bad_request` rather than
silently creating a contact nothing will ever answer.

It exists because the interface cannot be reviewed, screenshotted or driven
through its states without a peer, and inventing a key by hand to paste into
the add-contact dialog is a pointless ritual. `history` seeds that many
scripted messages, which travel the real simulated link and so arrive over the
following seconds rather than appearing at once.

### `reset_local_data() -> void`

Deletes all history, contacts, settings and the identity key, then
reinitialises. Destructive and confirmed in the UI. Returns after the new
empty state is durable.

## Events

Emitted with `app.emit(name, payload)` and received with
`listen<Payload>(name, ...)`. Names are the brief's, unchanged.

| event                    | payload                | when                                                                                  |
| ------------------------ | ---------------------- | ------------------------------------------------------------------------------------- |
| `message_received`       | `Message`              | a new incoming message was stored                                                     |
| `message_status_changed` | `MessageStatusChanged` | an outgoing message moved to `sent`, `delivered` or `failed`                          |
| `link_status_changed`    | `Link`                 | a link went up or down, was configured, or its counters crossed a reporting threshold |
| `contact_changed`        | `Contact`              | a contact was added, renamed, verified, or its last-heard-from time moved             |

```
MessageStatusChanged {
  conversation_id: string,
  message_id: string,
  status: MessageStatus,
  delivered_at: number | null,
  attempts: number
}
```

**Event payloads are complete, not deltas.** `link_status_changed` carries
the whole `Link`, not the field that changed. The frontend can therefore
replace its copy without merge logic, and a dropped event self-heals on the
next one. The exception is `message_status_changed`, which is a delta because
re-sending a whole `Message` to change one field would be wasteful at the
rates retransmission produces.

**Events are a cache-coherence mechanism, not a transport.** The frontend is
correct if it ignores every event and re-runs the commands; events exist so
it does not have to poll. Any state the UI shows must be reachable by a
command, which is also what makes the Playwright suite able to drive the UI
with events mocked.

**Ordering and loss.** Events for one conversation are emitted in the order
the backend processed them. The frontend must not assume an event arrives
before the command result that caused it — `send_message` returns a `Message`
with status `queued`, and a `message_status_changed` for `sent` can arrive
first if a link was fast. Status is monotonic (`queued` < `sent` <
`delivered`), so the frontend keeps the furthest-along value it has seen
rather than the most recent.

## Throttling

`message_status_changed` is the only event a retransmission storm could
produce at a high rate, and it is kept quiet structurally rather than by a
timer: the backend emits it only when the status actually _moves_. Status is
monotonic over four values, so a message can produce at most three of these
events in its entire life, however many times it is retransmitted.

Retransmissions still increment `attempts` in the store; they just do not
generate an event. The thread's hover detail re-reads `attempts` with
`get_messages` when the user asks for it.

An earlier draft of this document specified a 100 ms coalescing window. It was
dropped rather than implemented: with "no status change, no event" in place,
the window would never have had two events to coalesce, and it would have
added latency to the one transition the user is actually waiting for.
