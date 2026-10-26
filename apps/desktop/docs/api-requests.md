# Requests to `avianlink-core`

Things the desktop app needs from the library that it does not yet provide.
The app does not edit `crates/`; each entry states what is needed, why, a
proposed signature, and the workaround the app uses in the meantime.

Status values: **open**, **accepted**, **declined**, **done**.

Observed against `avianlink-core` after the library's Phase 3 (cryptography).

**Nine of the eleven entries below are now done.** The library adopted the
proposed shapes closely enough that the app's workarounds were deletions
rather than migrations. What is left is AR-003 (which may be the right answer
already) and AR-006/AR-009, neither of which blocks the app's Phase 1.

---

## AR-001 — `send_text` should return the message's Lamport value

**Status: done.** The library adopted the proposed shape:

```rust
pub struct Queued { pub id: MessageId, pub seq: u64, pub lamport: u64 }
```

The app re-exports `avianlink_core::Queued` from `engine::Queued` rather than
declaring its own.

_Why it mattered:_ the app interleaves its own outgoing messages with incoming
ones in one thread. Ordering outgoing messages by local queue time while
ordering incoming ones by Lamport does not compose — a reply written in
response to our message can sort above it.

## AR-002 — A signal that a message has actually been transmitted

**Status: done.** `Event::MessageTransmitted { conversation, id }`, with retry
counts from `Engine::outgoing(conversation) -> Vec<OutgoingStatus>`.

This removed the app's worst workaround. The driver used to promote _every_
still-queued message in a conversation to `sent` whenever any packet for that
conversation was flushed, because `Transmit` names a conversation and not the
messages inside it. That over-reported in exactly the direction the brief says
not to be optimistic about. Both the workaround and the
`EngineHandle::reports_transmissions` flag that gated it are gone.

**A note worth recording**, since it shaped the app's design before the event
landed: while `wire` was public and packets were plaintext, the host could
parse an outgoing packet and read the sequence numbers out of its MSG frames,
which was exact. Phase 3's encryption closed that door — an outgoing packet is
now AEAD-sealed and the host cannot read its own frames back without
decrypting. So the event is not merely more convenient than parsing; after
Phase 3 it is the only way a host can know.

## AR-003 — No "gave up" event, so _failed_ is unreachable

**Status:** open, and possibly correctly so.

The brief specifies _failed_ "only if the library gives up". The engine still
has no abandonment event, and the right default for avianlink is probably
**never give up**: a peer silent for days is normal, and an app that showed
_failed_ after an hour would be lying.

Phase 3 added `ContactStatus::unreachable` — "the engine currently believes
the contact unreachable and is only probing" — which is a _better_ answer for
the common case than a terminal failure, because it is reversible and is
about the peer rather than the message.

What is still missing is the genuinely terminal case: a message evicted
because the outbox filled.

```rust
Event::MessageAbandoned {
    conversation: ConversationId,
    id: MessageId,
    reason: AbandonReason, // OutboxEvicted, ContactRemoved
}
```

**Workaround.** The state exists in the IPC enum, the UI renders it, and
`FakeEngine::abandon` produces it on demand so it is designed and tested
rather than designed blind. Against the real engine it will not occur.

**Suggestion for the library:** if abandonment stays out, consider surfacing
`unreachable` as an event rather than only as a polled field, so a host does
not have to ask about every contact on every pump to notice it changed.

## AR-004 — Fingerprint derivation belongs in the library

**Status: done.** `PublicKey::fingerprint() -> [u8; FINGERPRINT_LEN]` and
`format_fingerprint`, with the same domain-separation label and the same
five-groups-of-four rendering the app had been using. Fingerprints did not
change when the app switched over, which is how it should be.

`apps/desktop/src-tauri/src/identity.rs` is now a one-line delegation. This is
the entry that mattered most for correctness-in-the-large: two avianlink
clients showing _different_ fingerprints for the same key would teach users to
ignore mismatches.

## AR-005 — Contact enumeration and removal

**Status: done.** `Engine::contacts()`, `Engine::contact_key()` and
`Engine::remove_contact() -> Result<Vec<MessageId>, Error>` — the last of
which answers the question the original request raised about the removed
contact's outbox by returning the abandoned message ids.

## AR-006 — `Storage` needs atomic batches to keep its durability promise

**Status:** open. **Severity:** high for the app's Phase 2/3.

The trait is still three independent calls with a documented promise that a
`store` returning `Ok` is durable. The missing piece for a crash-safe host is
**atomicity across keys**: queueing a message updates both the outbox entry
and the sequence counter, and a crash between the two leaves the engine with a
counter that has outrun its outbox. Per-call durability is also expensive done
literally — one `fsync` per key means several per queued message.

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

Default bodies keep `MemoryStorage` and existing hosts working.

**Workaround.** None needed yet: the app's store is still in memory. This
becomes blocking when the app implements `Storage` on SQLite in its Phase 2,
and it is the one entry here that should be settled before then.

## AR-007 — Per-link and per-contact statistics

**Status: done.** `Engine::link_stats(link) -> LinkStats` and
`Engine::contact_status(conversation) -> ContactStatus`.

Both landed with the fields the link-health display needed, including the two
that mattered most:

- `LinkStats::budget_blocked_until` — "nothing is wrong, the radio is out of
  airtime until 14:02" is a calm and true thing to show, and the pacer is the
  only thing that knows it.
- `ContactStatus::last_heard` — explicitly including acknowledgement-only
  packets. The app previously had to infer this from messages, so a peer that
  was acknowledging but not talking looked silent. The thread header's "heard
  from Rook 3h ago" is now true rather than merely plausible.

## AR-008 — Restoring an engine from `Storage`

**Status: done.** `Engine::restore(config, identity, storage, rng)`, explicit
rather than making `new` implicitly resume. The app will use it in Phase 3.

## AR-009 — The simulator's impairment engine is not reachable from a host

**Status:** open. **Severity:** low; a convenience, with a real duplication
cost.

`avianlink-sim` exposes its tuned impairment _parameters_ publicly
(`Profile::link() -> LinkProfile`, with `DelayModel`, `GilbertElliott`,
`OutageModel` and friends all public) but keeps the thing that _applies_ them
private: `impair::Channel` is `pub(crate)`, and `Jitter::sample` is a private
method on a public enum with public fields.

The only public way to drive impairments is `Scenario::run()`, which executes
a whole batch over virtual time. That is the right shape for the library's
metrics and the wrong shape for a GUI advancing in real time, one pump at a
time.

**Proposed.** Make the per-direction channel public and drivable:

```rust
impl Channel {
    pub fn new(profile: LinkProfile, rng: ChaCha20Rng) -> Self;
    /// Hands a packet to the link at `now`.
    pub fn send(&mut self, now: u64, bytes: &[u8], link_down: bool);
    /// Packets due at or before `now`, in arrival order.
    pub fn take_due(&mut self, now: u64) -> Vec<Vec<u8>>;
    pub fn next_arrival(&self) -> Option<u64>;
    pub fn stats(&self) -> ChannelStats;
}
```

plus `pub fn Jitter::sample(&self, rng: &mut ChaCha20Rng) -> u64`.

**Workaround.** `apps/desktop/src-tauri/src/engine/channel.rs` reimplements
the ~150 lines of "roll a die, drop or delay the packet" against the
library's public parameters. Reusing the numbers and not the code is the
better half to duplicate — the numbers are what was tuned against real links
— but the two will drift, and the app's channel does not implement rate
serialisation or the duty log, so it is a strictly weaker model than the
simulator's.

## AR-010 — `ReceivedMessage::missing_before` has no counterpart for history

**Status:** open. **Severity:** low; a note, not a gap.

`missing_before` is genuinely useful and the app uses it: the thread shows
"2 earlier messages are still on their way" above a message that overtook
others. It answers the _forward_ question — what is still missing below this
message.

The app also needs the _backward_ one: did this message land behind messages
the user was already looking at? That is what the "arrived out of order"
marker means. No library change is needed — only the host knows what it had
already displayed — and this entry exists so the two are not confused.

## AR-011 — `Identity::secret_bytes` is exactly the right keychain hook

**Status: done**, recorded as confirmation rather than as a request.

```rust
pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]>;
pub fn from_secret_bytes(secret: &[u8; 32]) -> Self;
```

A 32-byte seed, zeroized on drop, documented as never written to `Storage` by
the engine. That is precisely the shape the app's Phase 2 needs for the OS
keychain: small enough for every keychain's value limits, with the engine
explicitly disclaiming responsibility for persisting it.
