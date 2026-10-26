# avianlink wire format

> **Status: outline (Phase 0).** Phase 1 fills this in, before any encoder or
> decoder code is written. Nothing here is normative yet.

## Design constraints

- Must work at any link MTU from **48 bytes** upward.
- Every byte is untrusted. Decoders must reject malformed input without
  panicking. Every length is checked against the remaining buffer.
- Peers will run mismatched versions for years:
  - The first byte of every packet carries the version.
  - Unknown versions are dropped and counted, never treated as fatal.
  - Unknown fields/record types must be skippable (length-prefixed TLV for
    extension records).
- Overhead is spent sparingly: varints, short routing tags, nonces derived
  from counters rather than sent in full.

## Planned sections

1. Conventions: byte order, varint encoding (LEB128, canonical/minimal form
   required), notation.
2. Packet header: version byte, packet type, routing tag, counter.
3. Packet types: data fragment, ack (selective bitmap), FEC repair, sync
   summary.
4. Message encoding: conversation, Lamport clock / parents, timestamp
   (and a wall-clock-validity flag, see decisions D-007), UTF-8 text.
5. Message IDs: content-addressed truncated hash; truncation length and
   collision analysis.
6. Fragmentation and reassembly: fragment header, limits, timeouts,
   behaviour when the reassembly table is full.
7. Extension mechanism and version negotiation (implicit; there is no
   handshake).
8. Header-overhead budget table per MTU (48, 64, 128, 222, 255, 512, 1200).
