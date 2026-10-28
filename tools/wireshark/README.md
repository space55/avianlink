# Wireshark dissector

`avianlink.lua` decodes avianlink traffic in Wireshark and `tshark`
(Wireshark 4.x, Lua 5.4).

| Packet | What you see |
|---|---|
| Data (kind `0x01`) | Routing tag, counter, size of the encrypted frames, AEAD tag. The frames are end-to-end encrypted and stay opaque. |
| Hello (kind `0x02`) | Recipient hint, sender key, the sender's **fingerprint** (computed), MAC. |
| Relay messages (`0x10`–`0x13`, `0x18`, `0x19`) | Every field: tags, anchors, proofs, `since`/`release`/`max`, reply codes, retention, cursors, page and receipt hashes, and whether the **checksum** is valid. |

For data packets and Hellos it also computes the **receipt hash** a relay
names them by. Filter `avianlink.receipt_hash == 09:81:74:e0 ||
avianlink.relay.hash == 09:81:74:e0` to follow one packet:
- its upload;
- the relay's RECEIPT for it;
- its delivery to the recipient;
- the REPLY page that listed it.

## Install

Copy `avianlink.lua` into Wireshark's personal Lua plugins folder (shown
under *Help → About Wireshark → Folders*), then restart Wireshark. Or
load it for one run:

```sh
tshark -n -X lua_script:tools/wireshark/avianlink.lua -r capture.pcap
```

## Which UDP traffic is decoded

avianlink has no fixed port, so the dissector recognises packets by
content:
- **Hellos and relay messages anywhere.** A Hello is exactly 47 bytes, and
  relay messages carry a checksum, which is verified.
- **Data packets in a UDP conversation where one of those was seen.** A
  data packet only starts with byte `0x01`, too weak to claim arbitrary
  UDP.
- **Everything on chosen ports:** *Preferences → Protocols → avianlink →
  UDP ports* (for example `7000,7400`), or *Decode As… → avianlink*.

A capture that starts mid-conversation between two direct peers, with no
Hello in it, needs the port preference or *Decode As*.

## Sample capture

```sh
cargo run -p avianlink-relay --example sample_pcap -- avianlink-sample.pcap
```

writes 74 packets covering:
- a direct exchange that starts with a Hello;
- three turns through a relay: registration, sessions, uploads with
  receipts, paged fetches, and Hello fetches.

`scripts/wireshark-check.sh` regenerates it and checks the dissector
against it. `scripts/ci.sh` runs that check when `tshark` is installed.
