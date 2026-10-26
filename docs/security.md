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

Contacts are added by public key, obtained out of band. There is no
handshake. `add_contact` rejects keys that don't decode to a valid point,
small-order ("weak") keys, and our own key.

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

## 3. Key schedule

For contacts A and B:

```
s       = X25519(sk_A, PK_B)   (equal to X25519(sk_B, PK_A))
          reject if s is all zeros (low-order input)
prk     = HKDF-SHA256-Extract(salt = "avianlink/v1/pair", ikm = s)
key A→B = HKDF-Expand(prk, "key" ‖ PK_A ‖ PK_B, 32)
tag A→B = HKDF-Expand(prk, "tag" ‖ PK_A ‖ PK_B, 3)
```

Each direction has its own key and routing tag. Keys live in memory and are
zeroized on drop. Nothing derived from `s` is persisted.

## 4. Packet protection

```
packet = header ‖ ChaCha20-Poly1305(key = key S→R, nonce, ad = header, frames) ‖ tag[16]
header = version:u8  routing_tag:[3]  counter:varint
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
  Tampering with version, tag or counter fails authentication.
- **No pre-decryption check.** The 3-byte routing tag already discards
  almost all foreign or garbage packets with a map lookup (§5). Whatever
  survives that is cheapest to settle by running the AEAD: Poly1305
  verifies before any decryption. An extra checksum would add bytes to every
  packet to save work on the rare packet that passes the tag lookup.
- **The full 16-byte tag.** A truncated Poly1305 tag (8 bytes) would save 8
  bytes per packet, which matters at a 48-byte MTU. But the audited AEAD
  crate only verifies full tags, and a truncated-tag construction would mean
  composing ChaCha20 and Poly1305 ourselves. We decline that for v1. A
  future version byte could carry an audited truncated-tag mode.

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
- the version byte;
- the counter, which gives packet counts per direction;
- the static per-direction routing tag, which links all of A's packets to
  B together without revealing who A and B are;
- link-layer identifiers (IP addresses, radio IDs), which are outside
  avianlink.

Message lengths leak through fragment counts. Timestamps, sequence numbers,
Lamport values and ACK contents are encrypted. PADDING frames exist in the
format, but v1 doesn't pad.

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

A peer that sends authenticated packets is a *contact*. It can still waste
the receiver's resources within those bounds, for example by claiming huge
fragment counts or acknowledging nothing, but it can't exceed them. Fuzzing
covers this path through the harness's "sealed packet from a known contact"
mode, which found and fixed a FRAG_ACK livelock in Phase 2.

## 10. Dependencies

All are RustCrypto or dalek crates, `no_std`, with no custom primitives:
`ed25519-dalek` 2, `curve25519-dalek` 4, `chacha20poly1305` 0.10,
`hkdf` 0.12, `sha2` 0.10, `zeroize` 1. See `decisions.md` D-029.
