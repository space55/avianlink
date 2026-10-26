# Requests to `avianlink-core`

Things the desktop app needs from the library that it does not yet provide.
The app does not edit `crates/`; each entry states what is needed, why, a
proposed signature, and the workaround the app uses in the meantime.

Status values: **open**, **accepted**, **declined**, **done**.

Observed against `avianlink-core` as of the library's Phase 2 work in
progress (`Queued`, `ReceivedMessage::missing_before`, `MemoryStorageError`).

---

## AR-001 — `send_text` should return the message's Lamport value

**Status: done.** The library adopted the proposed shape:

```rust
pub struct Queued { pub id: MessageId, pub seq: u64, pub lamport: u64 }
pub fn send_text(&mut self, conversation: ConversationId, text: &str, now: Timestamp)
    -> Result<Queued, Error>
```

The app re-exports `avianlink_core::Queued` from `engine::Queued` rather than
declaring its own, and the mirrored-Lamport workaround described here is gone.

_Original request, for the record:_ the app has to interleave its own
outgoing messages with incoming ones in one thread, and ordering outgoing
messages by local queue time while ordering incoming ones by Lamport does not
compose — a reply written in response to our message can sort above it. The
workaround was for the app to mirror the engine's Lamport rule in its own
store, which it could not verify and which would have broken silently if the
library ever added a frame type that advanced the clock.

## AR-001a — `ReceivedMessage::missing_before` should have a counterpart for history

**Status:** open. **Severity:** low; a refinement, not a gap.

The library added

```rust
/// Earlier messages from this sender not yet received. Non-zero means
/// this one overtook them in the network.
pub missing_before: u64,
```

which is genuinely useful: it lets the thread say "two earlier messages are
still on their way" rather than leaving a silent gap, and the app will use it
in Phase 1.

It answers the _forward_ question (what is still missing below this message).
The app also needs the _backward_ one: did this message land behind messages
the user was already looking at? That is what the "arrived later" marker
means, and only the host can answer it, because it depends on what the host
had already displayed. No library change is needed — this entry exists so the
distinction is written down and `missing_before` is not mistaken for the
same thing.

## AR-002 — No signal that a message has actually been transmitted

**Status:** open. **Blocks:** the _sent_ message state.

The UI distinguishes **queued** (saved locally) from **sent** (at least one
transmission went out) from **delivered** (acknowledged). The engine reports
delivery (`Event::MessageDelivered`) but nothing for transmission.
`poll_transmit` returns

```rust
pub struct Transmit { pub link: LinkId, pub to: ConversationId, pub packet: Packet }
```

which names the conversation but not the messages inside the packet, and a
packet may carry several messages (library D-012) or only ACKs.

**Proposed.** Either add the carried messages to `Transmit`:

```rust
pub struct Transmit {
    pub link: LinkId,
    pub to: ConversationId,
    pub packet: Packet,
    /// Messages with at least one fragment in this packet. Empty for a
    /// packet that carries only acknowledgements.
    pub contains: Vec<MessageId>,
}
```

or emit an event the first time a message leaves:

```rust
Event::MessageTransmitted { conversation: ConversationId, id: MessageId, attempt: u32 }
```

The event form is cheaper for a host that only wants the state change, and
`attempt` would let the UI show "retried 4 times" on hover, which on these
links is the information a user actually wants. The `Transmit` form avoids an
event-queue slot per transmission.

**Workaround.** The driver marks _every_ not-yet-sent outgoing message in a
conversation as _sent_ when any `Transmit` for that conversation is flushed.
This over-reports: an ACK-only packet, or a packet carrying the first of
three queued messages, promotes all three. The app's status display is
therefore optimistic in exactly the direction the brief says not to be.

## AR-003 — No "gave up" event, so _failed_ is unreachable

**Status:** open. **Blocks:** the _failed_ message state.

The brief specifies _failed_ "only if the library gives up". Phase 1
retransmits on a fixed interval forever, and there is no event for
abandoning a message. `Config` has `max_outbox_messages` but reaching it
fails the _new_ `send_text` rather than giving up on an old message.

**Proposed.**

```rust
Event::MessageAbandoned {
    conversation: ConversationId,
    id: MessageId,
    reason: AbandonReason, // OutboxEvicted, RetryLimit, ContactRemoved
}
```

plus a `Config` field for the policy. Note that the right default for
avianlink is probably _never give up_: a peer silent for days is normal
(library spec, "Reliability"), so an app that shows _failed_ after an hour
would be lying. A host-chosen `max_message_age_ms` with no default limit
seems right.

**Workaround.** The app never shows _failed_ from the real engine. The state
exists in the IPC enum, the UI renders it, and `FakeEngine` can produce it on
demand so the state is designed and tested — but against the real engine it
will not occur until this lands.

## AR-004 — Fingerprint derivation belongs in the library

**Status:** open. **Severity:** medium (correctness is fine; interop is not).

Adding a contact is the app's only authentication step, and it rests on a
human comparing a short fingerprint out of band. If the desktop app, the CLI
demo and a future mobile app each derive that string differently, users
comparing across clients will see a mismatch and learn to ignore mismatches.

**Proposed.** One derivation in core, with the hash already present:

```rust
impl PublicKey {
    /// 80-bit domain-separated fingerprint for out-of-band comparison.
    pub fn fingerprint(&self) -> [u8; 10];
}

/// Canonical rendering: five groups of four lowercase hex characters.
pub fn format_fingerprint(fp: &[u8; 10]) -> alloc::string::String;
```

**Workaround.** `apps/desktop/src-tauri/src/identity.rs` computes
`SHA-256("avianlink-fingerprint-v1" || pk)[..10]` with the same grouping, so
the library can adopt the app's definition unchanged (desktop DA-009).

## AR-005 — No contact enumeration or removal

**Status:** open. **Severity:** low (the app owns this state anyway).

`add_contact(key) -> ConversationId` is the only contact API. There is no
`contacts()`, no `remove_contact`, and no way to recover the `PublicKey` for
a `ConversationId`. After a restart the host must re-add every contact in
order to repopulate the engine.

**Proposed.**

```rust
pub fn contacts(&self) -> impl Iterator<Item = (ConversationId, PublicKey)> + '_;
pub fn contact_key(&self, conversation: ConversationId) -> Option<PublicKey>;
pub fn remove_contact(&mut self, conversation: ConversationId) -> Result<(), Error>;
```

`remove_contact` needs a documented answer for the contact's outbox and
partial reassemblies.

**Workaround.** The app's SQLite store is the source of truth for contacts
and replays `add_contact` for each one at startup. This is not really a
workaround — the app needs display names and verification state that the
library should not know about — so only `remove_contact` is genuinely
missing, for the "delete contact" action.

## AR-006 — `Storage` needs atomic batches to keep its durability promise

**Status:** open. **Severity:** high for the app's Phase 2/3.

The trait is three independent calls:

```rust
fn load(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
fn store(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;
fn remove(&mut self, key: &[u8]) -> Result<(), Self::Error>;
```

with the documented contract that a `store` returning `Ok` is durable. The
library already marks this provisional and plans prefix iteration for its
Phase 2. The missing piece for a crash-safe host is **atomicity across
keys**: queueing a message updates both the outbox entry and the sequence
counter, and a crash between the two leaves the engine with a counter that
has outrun its outbox.

Per-call durability is also expensive done literally — one `fsync` per key
means several fsyncs per queued message.

**Proposed.** Let the engine delimit a set of writes that must land together:

```rust
pub trait Storage {
    type Error: core::fmt::Debug;
    fn load(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;
    /// Writes within a batch become durable together or not at all. The
    /// engine calls `begin`/`commit` around any group of writes that must
    /// not be observed partially. Calls do not nest.
    fn begin(&mut self) -> Result<(), Self::Error> { Ok(()) }
    fn commit(&mut self) -> Result<(), Self::Error> { Ok(()) }
    fn store(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;
    fn remove(&mut self, key: &[u8]) -> Result<(), Self::Error>;
}
```

Default bodies keep `MemoryStorage` and existing hosts working. A prefix
scan (`iter_prefix`) is the library's own Phase 2 item and is also needed.

**Workaround.** None available at Phase 1: the engine does not persist yet,
so the app's SQLite `Storage` implementation has nothing to be
non-atomic about. The app's _own_ history and outbox-mirror writes use
SQLite transactions. This becomes blocking at the app's Phase 3.

## AR-007 — Per-link and per-contact statistics for the link-health display

**Status:** open. **Severity:** medium.

`Stats` is a flat set of global counters. The UI needs, per link: up/down,
packets in and out, recent loss, and time since the last packet. Per contact
it needs time since the last packet _from that contact_, which is the single
most useful number on a link where silence for a day is normal.

**Proposed.**

```rust
pub struct LinkStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_dropped: u64,
    pub budget_blocked_until: Option<Timestamp>,
}
pub fn link_stats(&self, link: LinkId) -> Option<LinkStats>;
pub fn last_packet_from(&self, conversation: ConversationId) -> Option<Timestamp>;
```

`budget_blocked_until` matters for duty-cycled links: "nothing is wrong, the
radio is out of airtime until 14:02" is a calm and true thing to show, and
the engine's pacer is the only thing that knows it.

**Workaround.** The driver counts packets per link itself (it is the one
handing them to the engine) and records `last_packet_from` by watching which
conversation each inbound packet resolved to — which it can only do for
packets that produced an event, so a packet carrying only an ACK does not
update the contact's "last heard from" time. Loss is not observable to the
host at all; the UI shows loss only for `FakeEngine`, where the fake knows
what it dropped.

## AR-008 — Restoring an engine from `Storage`

**Status:** open. **Severity:** blocking for the app's Phase 3, not before.

`Engine::new(config, local, storage, rng)` takes storage but there is no
documented "resume from what is in storage" path, so a restart loses the
outbox. This is the library's own Phase 2 goal ("the engine can be restored
from `Storage` mid-run without losing or duplicating messages"), listed here
only so the app's dependency on it is written down. A constructor that makes
the intent explicit, e.g.

```rust
pub fn restore(config: Config, local: PublicKey, storage: S, rng: R)
    -> Result<Self, Error>
```

would be clearer than making `new` implicitly resume.
