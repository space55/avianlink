-- Wireshark dissector for avianlink (docs/wire-format.md, docs/relay.md).
--
-- Install: copy to your Wireshark personal plugins folder (Help → About
-- Wireshark → Folders → Personal Lua Plugins), or run
--   tshark -X lua_script:avianlink.lua -r capture.pcap
--
-- avianlink has no fixed port, so traffic is recognised by content:
--   * Hellos (kind 0x02, exactly 47 bytes) and relay messages (kinds
--     0x10–0x13, 0x18, 0x19, whose checksum is verified) are recognised
--     anywhere;
--   * data packets (kind 0x01) are encrypted and only start with 0x01,
--     which is too weak alone: they are decoded on the UDP ports set in
--     the preferences, with "Decode As…", or in a UDP conversation where a
--     Hello or relay message was already seen.
--
-- Data packets are end-to-end encrypted: the header is shown, the frames
-- are not. The dissector computes each packet's relay receipt hash, so a
-- RECEIPT can be matched to the upload it acknowledges (filter on
-- avianlink.receipt_hash), and a Hello sender's fingerprint.

local avl = Proto("avianlink", "avianlink")

-- SHA-256 in pure Lua (Wireshark's Lua API has no hashing). Lua 5.4
-- integers are 64-bit, so every 32-bit result is masked.
local K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}
local M32 = 0xffffffff

local function rrot(x, n)
  return ((x >> n) | (x << (32 - n))) & M32
end

local function sha256(msg)
  local h = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
  local len = #msg
  msg = msg .. "\128" .. string.rep("\0", (55 - len) % 64) .. string.pack(">I8", len * 8)
  local w = {}
  for chunk = 1, #msg, 64 do
    for j = 0, 15 do
      w[j] = string.unpack(">I4", msg, chunk + j * 4)
    end
    for j = 16, 63 do
      local a, b = w[j - 15], w[j - 2]
      local s0 = rrot(a, 7) ~ rrot(a, 18) ~ (a >> 3)
      local s1 = rrot(b, 17) ~ rrot(b, 19) ~ (b >> 10)
      w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & M32
    end
    local a, b, c, d, e, f, g, hh = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]
    for j = 0, 63 do
      local S1 = rrot(e, 6) ~ rrot(e, 11) ~ rrot(e, 25)
      local ch = (e & f) ~ ((~e) & g)
      local t1 = (hh + S1 + ch + K[j + 1] + w[j]) & M32
      local S0 = rrot(a, 2) ~ rrot(a, 13) ~ rrot(a, 22)
      local maj = (a & b) ~ (a & c) ~ (b & c)
      local t2 = (S0 + maj) & M32
      hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & M32, c, b, a, (t1 + t2) & M32
    end
    h[1] = (h[1] + a) & M32; h[2] = (h[2] + b) & M32
    h[3] = (h[3] + c) & M32; h[4] = (h[4] + d) & M32
    h[5] = (h[5] + e) & M32; h[6] = (h[6] + f) & M32
    h[7] = (h[7] + g) & M32; h[8] = (h[8] + hh) & M32
  end
  return string.pack(">I4I4I4I4I4I4I4I4", table.unpack(h))
end

local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

-- Labels, as in the library (hash.rs, wire/relay.rs, crypto.rs).
local function receipt_hash(raw)
  return sha256("avianlink-receipt-v1" .. raw):sub(1, 4)
end

local function relay_check(body)
  return sha256("avianlink-relay-v1" .. body):sub(1, 4)
end

local function fingerprint(key)
  local fp = hex(sha256("avianlink-fingerprint-v1" .. key):sub(1, 10))
  return fp:sub(1, 4) .. "-" .. fp:sub(5, 8) .. "-" .. fp:sub(9, 12) .. "-" .. fp:sub(13, 16) .. "-" .. fp:sub(17, 20)
end

-- Unsigned LEB128 varint at `offset`: value, length (nil if malformed).
local function varint(tvb, offset)
  local value, shift = 0, 0
  for i = 0, 9 do
    if offset + i >= tvb:len() then return nil end
    local b = tvb(offset + i, 1):uint()
    value = value | ((b & 0x7f) << shift)
    if b < 0x80 then return value, i + 1 end
    shift = shift + 7
  end
  return nil
end

local KINDS = {
  [0x01] = "Data", [0x02] = "Hello",
  [0x10] = "REGISTER", [0x11] = "OPEN", [0x12] = "FETCH", [0x13] = "FETCH_HELLO",
  [0x18] = "REPLY", [0x19] = "RECEIPT",
}
local CODES = {
  [0] = "OK", [1] = "BAD_PROOF", [2] = "UNKNOWN_MAILBOX", [3] = "FULL",
  [4] = "NO_SESSION", [5] = "RATE_LIMITED", [6] = "MORE",
}

local F = {
  kind = ProtoField.uint8("avianlink.kind", "Kind", base.HEX, KINDS),
  receipt_hash = ProtoField.bytes("avianlink.receipt_hash", "Receipt hash (computed)"),
  -- Data
  tag = ProtoField.bytes("avianlink.tag", "Routing tag"),
  counter = ProtoField.uint64("avianlink.counter", "Counter"),
  ciphertext = ProtoField.bytes("avianlink.ciphertext", "Encrypted frames"),
  aead_tag = ProtoField.bytes("avianlink.aead_tag", "AEAD tag"),
  -- Hello
  hint = ProtoField.bytes("avianlink.hint", "Recipient hint"),
  sender = ProtoField.bytes("avianlink.sender", "Sender key"),
  fingerprint = ProtoField.string("avianlink.fingerprint", "Sender fingerprint (computed)"),
  mac = ProtoField.bytes("avianlink.mac", "MAC"),
  -- Relay
  up_anchor = ProtoField.bytes("avianlink.relay.up_anchor", "Upload anchor"),
  down_anchor = ProtoField.bytes("avianlink.relay.down_anchor", "Fetch anchor"),
  proof = ProtoField.bytes("avianlink.relay.proof", "Chain proof"),
  since = ProtoField.uint64("avianlink.relay.since", "Since"),
  release = ProtoField.uint64("avianlink.relay.release", "Release below"),
  max = ProtoField.uint8("avianlink.relay.max", "Max packets"),
  request = ProtoField.uint8("avianlink.relay.request", "Request", base.HEX, KINDS),
  code = ProtoField.uint8("avianlink.relay.code", "Code", base.DEC, CODES),
  key = ProtoField.bytes("avianlink.relay.key", "Key (tag or hint)"),
  retention = ProtoField.uint64("avianlink.relay.retention_s", "Retention (s)"),
  cursor = ProtoField.uint64("avianlink.relay.cursor", "Cursor"),
  count = ProtoField.uint8("avianlink.relay.count", "Count"),
  hash = ProtoField.bytes("avianlink.relay.hash", "Packet hash"),
  check = ProtoField.bytes("avianlink.relay.check", "Checksum"),
  check_ok = ProtoField.bool("avianlink.relay.check_ok", "Checksum valid"),
}
local field_list = {}
for _, f in pairs(F) do table.insert(field_list, f) end
avl.fields = field_list

local E = {
  bad_check = ProtoExpert.new("avianlink.relay.bad_check", "Relay checksum mismatch (corrupted)",
    expert.group.CHECKSUM, expert.severity.ERROR),
  malformed = ProtoExpert.new("avianlink.malformed", "Malformed avianlink packet",
    expert.group.MALFORMED, expert.severity.ERROR),
}
avl.experts = { E.bad_check, E.malformed }

avl.prefs.ports = Pref.range("UDP ports", "", "UDP ports always decoded as avianlink (e.g. 7000,7400)", 65535)

local function is_relay_kind(k)
  return (k >= 0x10 and k <= 0x13) or k == 0x18 or k == 0x19
end

local function relay_check_ok(tvb)
  local n = tvb:len()
  if n < 5 then return false end
  local raw = tvb:raw()
  return relay_check(raw:sub(1, n - 4)) == raw:sub(n - 3)
end

local function dissect_data(tvb, tree)
  local n = tvb:len()
  tree:add(F.tag, tvb(1, 3))
  local counter, clen = varint(tvb, 4)
  if not counter or n < 4 + clen + 16 then
    tree:add_proto_expert_info(E.malformed)
    return "Data (malformed)"
  end
  tree:add(F.counter, tvb(4, clen), UInt64(counter))
  local body = n - 4 - clen - 16
  if body > 0 then
    tree:add(F.ciphertext, tvb(4 + clen, body)):append_text(string.format(" (%d bytes)", body))
  end
  tree:add(F.aead_tag, tvb(n - 16, 16))
  return string.format("Data tag=%s ctr=%d frames=%dB", hex(tvb(1, 3):raw()), counter, body)
end

local function dissect_hello(tvb, tree)
  tree:add(F.hint, tvb(1, 2))
  tree:add(F.sender, tvb(3, 32))
  local fp = fingerprint(tvb(3, 32):raw())
  tree:add(F.fingerprint, tvb(3, 32), fp)
  tree:add(F.mac, tvb(35, 12))
  return string.format("Hello from %s to hint %s", fp, hex(tvb(1, 2):raw()))
end

local function dissect_relay(tvb, tree, kind)
  local n = tvb:len()
  local body = n - 4
  local ok = relay_check_ok(tvb)
  local o = 1
  local info = KINDS[kind]
  local function need(k)
    return o + k <= body
  end
  local function v(field)
    local val, len = varint(tvb, o)
    if not val or o + len > body then return nil end
    tree:add(field, tvb(o, len), UInt64(val))
    o = o + len
    return val
  end
  if kind == 0x10 and need(35) then
    tree:add(F.tag, tvb(1, 3)); tree:add(F.up_anchor, tvb(4, 16)); tree:add(F.down_anchor, tvb(20, 16))
    info = info .. " tag=" .. hex(tvb(1, 3):raw())
  elseif kind == 0x11 and need(19) then
    tree:add(F.tag, tvb(1, 3)); tree:add(F.proof, tvb(4, 16))
    info = info .. " tag=" .. hex(tvb(1, 3):raw())
  elseif kind == 0x12 and need(19) then
    tree:add(F.tag, tvb(1, 3)); tree:add(F.proof, tvb(4, 16)); o = 20
    local since, release = v(F.since), v(F.release)
    if o < body then tree:add(F.max, tvb(o, 1)); o = o + 1 end
    info = string.format("%s tag=%s since=%s release=%s", info, hex(tvb(1, 3):raw()),
      tostring(since), tostring(release))
  elseif kind == 0x13 and need(2) then
    tree:add(F.hint, tvb(1, 2)); o = 3
    info = string.format("%s hint=%s since=%s", info, hex(tvb(1, 2):raw()), tostring(v(F.since)))
  elseif kind == 0x18 and need(5) then
    local req, code = tvb(1, 1):uint(), tvb(2, 1):uint()
    tree:add(F.request, tvb(1, 1)); tree:add(F.code, tvb(2, 1)); tree:add(F.key, tvb(3, 3)); o = 6
    v(F.retention)
    local cursor = v(F.cursor)
    local pages = 0
    if o < body then
      pages = tvb(o, 1):uint()
      local pt = tree:add(F.count, tvb(o, 1)); o = o + 1
      for _ = 1, pages do
        if o + 4 > body then break end
        tree:add(F.hash, tvb(o, 4)); o = o + 4
      end
    end
    info = string.format("REPLY to %s: %s", KINDS[req] or string.format("0x%02x", req),
      CODES[code] or tostring(code))
    if req == 0x12 or req == 0x13 then
      info = info .. string.format(" cursor=%s page=%d", tostring(cursor), pages)
    end
  elseif kind == 0x19 and need(2) then
    local code, count = tvb(1, 1):uint(), tvb(2, 1):uint()
    tree:add(F.code, tvb(1, 1)); tree:add(F.count, tvb(2, 1)); o = 3
    local hs = {}
    for _ = 1, count do
      if o + 4 > body then break end
      tree:add(F.hash, tvb(o, 4)); table.insert(hs, hex(tvb(o, 4):raw())); o = o + 4
    end
    info = string.format("RECEIPT %s %s", CODES[code] or tostring(code), table.concat(hs, ","))
  else
    tree:add_proto_expert_info(E.malformed)
  end
  local ck = tree:add(F.check, tvb(n - 4, 4))
  tree:add(F.check_ok, tvb(n - 4, 4), ok):set_generated()
  if not ok then
    ck:add_proto_expert_info(E.bad_check)
    info = info .. " [BAD CHECKSUM]"
  end
  return info
end

function avl.dissector(tvb, pinfo, root)
  local n = tvb:len()
  if n < 1 then return 0 end
  pinfo.cols.protocol = "avianlink"
  local kind = tvb(0, 1):uint()
  local tree = root:add(avl, tvb(), "avianlink")
  tree:add(F.kind, tvb(0, 1))
  local info
  if kind == 0x01 and n >= 21 then
    info = dissect_data(tvb, tree)
  elseif kind == 0x02 and n == 47 then
    info = dissect_hello(tvb, tree)
  elseif is_relay_kind(kind) then
    info = dissect_relay(tvb, tree, kind)
  else
    tree:add_proto_expert_info(E.malformed)
    info = string.format("Unknown kind 0x%02x", kind)
  end
  pinfo.cols.info = info
  -- Packets a relay stores (data and Hellos) are named by this in RECEIPTs
  -- and REPLY pages.
  if kind == 0x01 or kind == 0x02 then
    -- Its own 4-byte data source, so the field is exactly the hash and
    -- filters compare like avianlink.relay.hash.
    local h = ByteArray.new(hex(receipt_hash(tvb:raw()))):tvb("Receipt hash")
    tree:add(F.receipt_hash, h()):set_generated()
  end
  return n
end

-- Recognise by content: Hellos and checksummed relay messages are
-- distinctive; data packets only in a conversation already identified.
local function heuristic(tvb, pinfo, root)
  local n = tvb:len()
  if n < 1 then return false end
  local kind = tvb(0, 1):uint()
  local strong = (kind == 0x02 and n == 47) or (is_relay_kind(kind) and relay_check_ok(tvb))
  if not strong then return false end
  pinfo.conversation = avl
  avl.dissector(tvb, pinfo, root)
  return true
end
avl:register_heuristic("udp", heuristic)

local udp_port = DissectorTable.get("udp.port")
udp_port:add_for_decode_as(avl)
local registered = nil
function avl.prefs_changed()
  if registered then udp_port:remove(registered, avl) end
  registered = avl.prefs.ports
  if registered and tostring(registered) ~= "" then udp_port:add(registered, avl) end
end
