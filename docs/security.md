# avianlink security model

> **Status: outline (Phase 0).** Phase 3 fills this in, before the crypto
> code is written. Until then avianlink provides **no confidentiality or
> authenticity**. Phase 1–2 builds send plaintext.

## Planned sections

1. Goals and non-goals.
2. Identities: X25519 / Ed25519 keypairs, and contacts added out-of-band
   (e.g. QR code). There is no handshake.
3. Pairwise key derivation: X25519 static-static, then HKDF, with domain
   separation per direction and purpose.
4. Per-packet AEAD (ChaCha20-Poly1305 / XChaCha20-Poly1305) with
   counter-derived nonces. Nonce uniqueness across restarts (persisted
   counters via `Storage`).
5. Replay protection under heavy reordering (sliding window), and its
   interaction with dedupe.
6. Routing tags: what they leak, and collision handling by trial decryption.
7. **No forward secrecy in v1.** What a compromise of a static key exposes,
   and the extension point for a reorder-tolerant ratchet.
8. Metadata exposure: sizes, timing, routing tags, link-layer identifiers.
9. Denial-of-service considerations: trial decryption cost, and memory
   bounds on reassembly and replay state.
