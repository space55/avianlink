# avianlink security model

> **Status: v1 (Phase 3).** This describes what avianlink protects, what it
> does not, and why. If something here and the code disagree, the code has
> a bug.

## 1. Goals and non-goals

**Goals (v1).** For each packet between two contacts who exchanged public
keys out of band:

- **Confidentiality** of everything except the header (§4): message text,
  sequence numbers, Lamport values, timestamps, ACKs.
- **Integrity and sender authenticity.** A packet accepted as coming from
  contact B was produced by someone holding B's or our own static secret
  key.
- **Replay rejection.** A captured packet is not accepted twice (§6).
- **Robustness.** No input crashes the engine, and the work an attacker can
  cause per packet is bounded (§9).

**Non-goals (v1), stated plainly:**

- **No forward secrecy.** All traffic between two contacts is protected by
  keys derived from their two long-term keys. Anyone who later obtains
  either secret key, and has recorded the traffic, can decrypt all of it,
  past and future. See §7.
- **No post-compromise security.** A stolen key stays useful until both
  sides switch identities.
- **No protection against key-compromise impersonation.** Whoever steals
  *your* secret key can impersonate *any* of your contacts *to you*. This is
  inherent to static-static Diffie-Hellman.
- **Limited metadata protection** (§8): packet sizes, timing, counters and
  a per-direction routing tag are visible on the wire.
- **No anonymity, deniability guarantees, or group messaging.**
- **Data at rest is the host's job.** The engine stores message plaintext
  (outbox, pending events) through `Storage`. Hosts must encrypt their
  storage (for example the OS keychain plus an encrypted database). The
  identity secret is never written to `Storage`.

## 2. Identities and contacts

An identity is an **Ed25519 keypair** (`Identity`). Its 32-byte public key
(`PublicKey`) is the user's address.

For Diffie-Hellman, the same key is used in its X25519 form. The public key
maps to Montgomery form, and the secret scalar is the standard Ed25519
expanded-seed scalar, as in libsodium's `crypto_sign_ed25519_*_to_curve25519`
and Signal's XEdDSA. We chose Ed25519 rather than a bare X25519 key so that
future signatures (contact cards, multi-device, groups) don't force users to
change identities they have already shared as QR codes. Using one key for
both signing and DH is a known, accepted construction. v1 performs no
signatures.

Contacts are added by public key, obtained out of band or from a contact
request (§2.1). There is no handshake. `add_contact` rejects keys that don't
decode to a valid point, small-order ("weak") keys, and our own key.

**Fingerprints.** `PublicKey::fingerprint()` is
`SHA-256("avianlink-fingerprint-v1" ‖ PK)[..10]` (80 bits).
`format_fingerprint` renders it as five dash-separated groups of four
lowercase hex characters (`a1b2-c3d4-e5f6-7890-abcd`). Users compare it
out of band. Every client must show the same string. This definition is
shared with the desktop app (desktop DA-009, request AR-004).

The identity secret belongs to the host. `Identity::secret_bytes()` exports
it for keychain storage, and `Identity::from_secret_bytes` reloads it. The
engine stores only the public key, to check on restore that storage belongs
to this identity.

### 2.1 Contact requests (Hello)

Only one side needs the other's key in advance. If Alice knows Bob's key
but Bob doesn't know hers, Bob drops all her packets: he has no routing tag
for her. A Hello (`wire-format.md` §2.5) carries Alice's public key in the
clear with a MAC that proves she holds its secret. Bob's engine reports it
as `Event::ContactRequest`. **The engine never adds a contact by itself;**
the host decides:
- an app asks the user, who should compare fingerprints out of band
  first;
- a relay or gateway accepts automatically, or only keys on an allowlist.

The use that motivates this: relays and gateways coming online must
register clients and each other without every pair having swapped keys
beforehand.

**What a verified Hello proves.** It proves that the sender holds `sk_S`
(or `sk_R`; see key-compromise impersonation, §1) for the `PK_S` it
carries, and that it was made for `PK_R`. It proves nothing about *who*
that key belongs to. Anyone can generate a key and send a Hello, so a
contact request is an unverified identity until fingerprints are compared.

**Why a MAC and not a signature.** The static Diffie-Hellman both sides
already use gives a shared key with no extra bytes on the wire. An Ed25519
signature would add 64 bytes, and the Hello would no longer fit a 48-byte
MTU. The cost is the same deniability property as data packets: Bob can't
prove to a third party that Alice sent it.

**Why HMAC-SHA256 truncated to 96 bits.** Truncated HMAC is a standard
construction (RFC 2104 §5; IPsec's `HMAC-SHA-256-128` and the
96-bit-truncated HMACs before it). A forger needs about 2⁹⁶ tries per
recipient, and each try is rate-limited by the recipient (§9). Even a
successful forgery yields only a contact request for a key whose secret
the forger doesn't have: they can't read or send anything as that key.
`hmac::Mac::verify_truncated_left` compares in constant time.

**Why not encrypted.** Hiding `PK_S` would need an ephemeral key on the
wire (Noise `X`: +32 bytes plus a second tag, about 97 bytes), which doesn't
fit small links. avianlink's goal is getting through bad links, and the
exposure is stated in §8. Hosts that don't want it set `HelloMode::Off`
and add contacts out of band only.

## 3. Key schedule

For contacts A and B:

```
s       = X25519(sk_A, PK_B)   (equal to X25519(sk_B, PK_A))
          reject if s is all zeros (low-order input)
prk     = HKDF-SHA256-Extract(salt = "avianlink/v1/pair", ikm = s)
key A→B = HKDF-Expand(prk, "key" ‖ PK_A ‖ PK_B, 32)
tag A→B = HKDF-Expand(prk, "tag" ‖ PK_A ‖ PK_B, 3)
hello A→B = HKDF-Expand(prk, "hello" ‖ PK_A ‖ PK_B, 32)   (Hello MAC key, §2.1)
```

The Hello hint, `SHA-256("avianlink-hello-hint-v1" ‖ PK_R)[..2]`, depends on
the recipient's public key only. It is a filter, not a secret.

Each direction has its own key and routing tag. Keys live in memory and are
zeroized on drop. Nothing derived from `s` is persisted.

## 4. Packet protection

```
packet = header ‖ ChaCha20-Poly1305(key = key S→R, nonce, ad = header, frames) ‖ tag[16]
header = kind:u8  routing_tag:[3]  counter:varint
nonce  = counter as 8 bytes little-endian ‖ 0x00000000
```

- **AEAD:** ChaCha20-Poly1305 (RFC 8439) from RustCrypto
  `chacha20poly1305`. Every packet decrypts on its own, with no session
  state.
- **Nonces come from the packet counter,** which is strictly increasing
  per direction and never sent in full beyond its varint. Because each
  direction has its own key, a (key, nonce) pair repeats only if a counter
  repeats. The engine reserves counters in blocks in `Storage` before using
  them, and a restored engine resumes past the reservation
  (`reliability.md` §4). Restoring an *older* copy of storage (a backup)
  breaks this and can reuse nonces. Hosts must not roll storage back. §7
  lists a mitigation.
- **The header is associated data:** authenticated but not encrypted.
  Tampering with kind, tag or counter fails authentication.
- **No pre-decryption check.** The 3-byte routing tag already discards
  almost all foreign or garbage packets with a map lookup (§5). Whatever
  survives that is cheapest to settle by running the AEAD: Poly1305
  verifies before any decryption. An extra checksum would add bytes to every
  packet to save work on the rare packet that passes the tag lookup.
- **The full 16-byte tag.** A truncated Poly1305 tag (8 bytes) would save 8
  bytes per packet, which matters at a 48-byte MTU. But the audited AEAD
  crate only verifies full tags, and a truncated-tag construction would mean
  composing ChaCha20 and Poly1305 ourselves. We decline that for v1. A
  future kind byte could carry an audited truncated-tag mode.

## 5. Routing tags and trial decryption

The receiver precomputes `tag C→self` for every contact C. An incoming
packet's tag selects candidate contacts, usually exactly one. Each candidate
gets a trial decryption, and the first success identifies the sender. A
3-byte tag collides with probability about n²/2²⁵ among n contacts (about
3% at 1000). A collision costs one extra AEAD attempt. Packets matching no
tag are dropped after the lookup, and packets that no candidate can decrypt
are dropped after at most `candidates` attempts.

Because the tag depends on the shared secret, an observer who knows both
public keys still can't compute it. It is **static** per direction, though,
so all packets from A to B carry the same tag and are linkable to each
other (§8).

## 6. Replay protection

Per contact, the receiver keeps the highest counter accepted and a
512-packet sliding bitmap below it. A packet is dropped
(`packets_dropped_replay`) if its counter was already accepted, or falls
below the window. The window check runs before decryption, but the window
is updated only after successful decryption, so forged packets can't move
it.

Network duplicates, common on these links, are rejected the same way.
Reordering by more than 512 packets drops the late packets, and the sender
retransmits their content.

**Across restarts.** The highest accepted counter is persisted with each
newly received message (in the receive-window record). After a crash,
packets with counters up to that value are rejected. Packets received after
the last persisted message, which carry only ACKs or duplicates, can be
replayed once after a restart. Their effects are bounded and idempotent:
- old ACKs acknowledge only what is already acknowledged;
- old FRAG_ACKs can delay one retransmission by up to `max_rto_ms`;
- the extra RTT samples skew the RTT estimate.

Messages are additionally deduplicated by sequence number and content
address, so a replay never delivers a message twice.

**Hellos are replayable by design.** They carry no counter: a Hello for a
pair is the same 47 bytes every time, so a replay is indistinguishable from
the sender repeating itself. The effects are bounded:
- a replayed Hello from an unknown key raises a contact request again,
  unless one is already outstanding. Hosts should remember keys the user
  dismissed;
- a replayed Hello from a known contact triggers at most one SYNC per RTO
  to that contact;
- **a Hello never moves a contact's address.** `handle_packet` reports a
  contact as authenticated only for data packets with a counter accepted by
  the replay window. A Hello is reported separately, and hosts treat its
  source address as a candidate only (`hosting.md`). Otherwise anyone who
  had recorded Alice's Hello could redirect Bob's traffic for Alice to
  themselves.

## 7. No forward secrecy, and the ratchet extension point

v1 trades forward secrecy for the postal model. Any single packet can be
decrypted with nothing but the two static keys and its own header, in any
order, after any delay. A Signal-style double ratchet assumes a mostly live
conversation and keeps state that heavy loss and reordering make expensive.

The extension point:
- **Selector.** A future wire version (or a frame type that is safe to
  ignore) carries an *epoch* and a sender's ephemeral X25519 public key in
  an `EPOCH` frame. It is sent repeatedly until acknowledged, like a
  message.
- **Epoch keys.** Once both sides have each other's epoch keys, the
  direction key becomes `HKDF(s ‖ X25519(eph_A, eph_B), epoch)`, and the
  ephemeral secrets of superseded epochs are deleted. Forward secrecy then
  covers each epoch.
- **Reordering tolerance.** The counter-derived nonce stays. Within an
  epoch any packet still decrypts on its own. Receivers keep a bounded
  number of recent epochs (say 3), so reordering and skipped messages work
  across epoch changes.
- **Where it plugs in.** The engine's key schedule is confined to
  `crypto::PairKeys`. An epoch-aware version swaps that type per contact.
  Nothing else in the engine touches key material.
- **Mitigation for §4's backup problem.** Mixing a per-boot random value
  into an epoch key also removes the nonce-reuse risk from storage
  rollback.

## 8. Metadata exposure

An on-path observer sees:
- packet sizes and timing;
- the kind byte;
- the counter, which gives packet counts per direction;
- the static per-direction routing tag, which links all of A's packets to
  B together without revealing who A and B are;
- link-layer identifiers (IP addresses, radio IDs), which are outside
  avianlink.

Message lengths leak through fragment counts. Timestamps, sequence numbers,
Lamport values and ACK contents are encrypted. PADDING frames exist in the
format, but v1 doesn't pad.

**Hellos expose more.** When a host sends Hellos (the default), an observer
also sees:
- the sender's public key, i.e. its long-term identity;
- 16 bits of a hash of the recipient's key. Against a known set of keys,
  such as a relay's users, that narrows the recipient to roughly
  1 in 65,536 of them;
- *when* a pair is being introduced or one side has gone silent, because
  Hellos are sent only then (`reliability.md` §3);
- that repeated Hellos are the same pair, since they are byte-identical.

Data packets that follow stay as opaque as before. `HelloMode::Off`
removes all of this, at the cost of both sides needing each other's keys
out of band.

## 9. Denial of service

**Per packet:**
- a tag lookup, with no cryptography;
- at most one AEAD attempt per candidate, where candidates are contacts
  whose tag matches, usually 0 or 1;
- for authenticated packets, frame processing bounded by packet size.

**Memory** is bounded throughout by `Config` (reassembly, receive window,
event queue, outbox, replay window).

**Replay-driven traffic.** A replay of a genuine packet whose original was
lost authenticates (its counter is fresh) and is accepted. That is
harmless for content, but it could falsely signal that an unreachable peer
is back, which would make the engine resend its whole outbox. So only a
packet carrying a *new highest* counter takes a contact out of backoff.
Each lost packet can be replayed into acceptance at most once. The
simulator's `disaster_hostile` scenario measures the residual cost (Phase 3
report).

**Hellos.** Packets of kind `0x02` cost:
- a 2-byte hint comparison, for Hellos meant for someone else;
- one HMAC, for Hellos from known contacts;
- a set lookup, for keys with a request already outstanding;
- for everything else, one X25519 operation plus an HKDF and an HMAC.
  That is the only per-packet public-key work an unauthenticated sender
  can cause. It is capped by a token bucket (`hello_verify_per_minute`,
  `hello_verify_burst`). Excess Hellos are dropped before any
  Diffie-Hellman, and the rate of 0 turns verification off entirely.

Memory stays bounded: the recent-requests set has `hello_dedupe_entries`
slots, and contact requests share the bounded event queue.

**Request spam.** An attacker can mint keys freely and send a valid Hello
from each, up to the verification rate. That can't reach the user's
contacts or messages, but it can bury a genuine request among fakes or use
up the bucket so a genuine Hello waits. The sender repeats its Hello, so it
gets through once the flood stops. Hosts should show requests unobtrusively
and offer a way to clear them all. An allowlist removes the problem for
infrastructure.

A peer that sends authenticated packets is a *contact*. It can still waste
the receiver's resources within those bounds, for example by claiming huge
fragment counts or acknowledging nothing, but it can't exceed them. Fuzzing
covers this path through the harness's "sealed packet from a known contact"
mode, which found and fixed a FRAG_ACK livelock in Phase 2.

## 10. Dependencies

All are RustCrypto or dalek crates, `no_std`, with no custom primitives:
`ed25519-dalek` 3, `curve25519-dalek` 5, `chacha20poly1305` 0.11,
`hkdf` 0.13, `hmac` 0.13 (Hello MAC; already a dependency of `hkdf`),
`sha2` 0.11, `zeroize` 1. See `decisions.md` D-029, D-035 and D-044.
