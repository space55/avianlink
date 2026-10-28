# avianlink C ABI

> **Status: Phase 7.** The C interface in `crates/avianlink-ffi`, the
> generated header `crates/avianlink-ffi/include/avianlink.h`, and the
> Apple XCFramework built from them.

## 1. What is exposed

The **sans-IO engine**, not the UDP host. Mobile apps move packets over
their own transports (Network.framework, BLE, a satellite modem) and keep
the clock. The C API therefore mirrors `avianlink_core::Engine`:
- **inputs:** `handle_packet`, `send_text`, `handle_timeout`, `nudge`;
- **outputs:** `poll_transmit`, `poll_event`, `next_timeout`;
- **management:** links, contacts, and status queries.

Storage comes in three kinds:

| Kind | Function | Use |
|---|---|---|
| File | `avl_storage_file_open(dir)` | The durable write-ahead log of `hosting.md` §2. |
| Memory | `avl_storage_memory_new()` | Tests. Not durable. |
| Callbacks | `avl_storage_callbacks(&callbacks)` | The app's own database, e.g. SQLite encrypted with a keychain key. It must give `Storage`'s guarantees: atomic `begin`/`commit` batches, durable after `commit`. |

The RNG is ChaCha20 seeded from the OS. Time is passed in on every call as
Unix milliseconds (`uint64_t now_ms`).

## 2. Conventions

- **Handles** (`AvlEngine *`, `AvlStorage *`) are opaque. `avl_engine_open`
  takes ownership of the storage handle. `avl_engine_free` releases the
  engine, and with it the storage.
- **Return values.** Every fallible call returns `AvlStatus`:
  - `AVL_STATUS_OK`;
  - `AVL_STATUS_NONE`: nothing to return, such as an empty event queue;
  - `AVL_STATUS_HELLO`: only from `avl_engine_handle_packet`. A verified
    Hello from an unknown key; the key is written to `public_key_out` and
    an `AVL_EVENT_KIND_CONTACT_REQUEST` is queued. Treat the packet's source
    address as a candidate only (D-044);
  - `AVL_STATUS_ERR_*`: failure. `AVL_STATUS_ERR_ENGINE` comes with an
    `AvlEngineError` detail (`AVL_ENGINE_ERROR_*`) available from
    `avl_last_engine_error()`. That value is thread-local and holds for the
    most recent failing call on the thread.
- **Fixed-size values** are passed as fixed-size byte arrays: keys (32),
  conversation and message IDs (16), identity secrets (32).
- **Buffers.** `poll_transmit` writes into a caller buffer. If the buffer is
  too small it returns `AVL_STATUS_ERR_BUFFER_TOO_SMALL`, sets the needed length,
  and keeps the packet for the next call. A buffer of the link's MTU is
  always enough.
- **Borrowed text.** An event's `text` points into memory owned by the
  engine. It is valid until the next `avl_engine_poll_event` or
  `avl_engine_free` on that engine. Copy it.
- **Threading.** An engine is not thread-safe. Call it from one thread at a
  time (a serial queue in Swift). Different engines are independent.
- **No unwinding across the boundary.** Every entry point catches panics and
  returns `AVL_STATUS_ERR_PANIC`. The engine is never expected to panic. Its
  input paths are fuzzed.
- **Null pointers** for required arguments return
  `AVL_STATUS_ERR_INVALID_ARGUMENT`; they are never dereferenced. Invalid
  UTF-8 text is rejected the same way.
- **Enumerations read from C** (`AvlConfig.fec`, `AvlConfig.hello`,
  `AvlLinkConfig.budget`) are `uint8_t` fields taking `AVL_FEC_MODE_*`,
  `AVL_HELLO_MODE_*` and `AVL_BUDGET_KIND_*` values, not C enums: an out-of-range enum would be undefined behaviour on the Rust
  side, an out-of-range integer is just `AVL_ENGINE_ERROR_INVALID_CONFIG` /
  `_INVALID_LINK_CONFIG`. Enumerations Rust *returns* (`AvlStatus`,
  `AvlEngineError`, `AvlEventKind`) are C enums.
- **Sizes** are `size_t` (Swift: `Int`).
- **Opening.** `avl_engine_open(..., create, ...)` is explicit. With
  `create`, it starts fresh state for a *new* identity, failing with
  `AVL_ENGINE_ERROR_STORAGE_NOT_EMPTY` if the storage already holds an
  engine. Without it, it restores, failing with
  `AVL_ENGINE_ERROR_STATE_MISSING` if the storage is empty. An app that
  finds its identity in the keychain but its database gone (iOS keeps
  keychain items across reinstalls) must generate a **new** identity: reusing
  the old one would reuse nonces (`security.md` §4). The storage handle is
  consumed even on failure. Opening with a different identity than the one stored fails
  with `AVL_ENGINE_ERROR_IDENTITY_MISMATCH`. `avl_engine_add_contact`
  returns the existing conversation for a known key, so an app can re-add
  its contacts on every launch.

## 3. Callback storage

```c
typedef struct AvlStorageCallbacks {
    void *ctx;
    /* 0: found, value copied (or *value_len set larger than cap: the engine
       retries with a bigger buffer); 1: not found; <0: error. */
    int (*load)(void *ctx, const uint8_t *key, size_t key_len,
                uint8_t *value, size_t value_cap, size_t *value_len);
    /* Calls visit(visit_ctx, ...) for every key with the prefix, in
       ascending key order. 0 ok, <0 error. */
    int (*scan_prefix)(void *ctx, const uint8_t *prefix, size_t prefix_len,
                       void (*visit)(void *visit_ctx, const uint8_t *key, size_t key_len,
                                     const uint8_t *value, size_t value_len),
                       void *visit_ctx);
    int (*begin)(void *ctx);
    int (*store)(void *ctx, const uint8_t *key, size_t key_len,
                 const uint8_t *value, size_t value_len);
    int (*remove)(void *ctx, const uint8_t *key, size_t key_len);
    int (*commit)(void *ctx);
    void (*rollback)(void *ctx);
    /* Called once when the engine is freed. May be NULL. */
    void (*release)(void *ctx);
} AvlStorageCallbacks;
```

## 4. Apple packaging

`scripts/build-xcframework.sh` builds `Avianlink.xcframework` with these
slices:
- iOS device (`aarch64-apple-ios`);
- iOS simulator (`aarch64-apple-ios-sim` and `x86_64-apple-ios`, combined
  with `lipo`);
- macOS (`aarch64-apple-darwin` and `x86_64-apple-darwin`).

Each slice carries the static library, `avianlink.h` and a `module.modulemap`
(`module Avianlink`), so Swift can `import Avianlink`. No extra frameworks
are needed: the OS RNG is `CCRandomGenerateBytes` / `getentropy`, both in
libSystem.

The script uses `xcodebuild -create-xcframework` when it works. Otherwise
(Command Line Tools only, or a damaged Xcode) it writes the bundle's
`Info.plist` and slice directories itself; the format is a plain directory.

`scripts/swift-smoke-test.sh` builds the XCFramework, consumes it through a
SwiftPM `binaryTarget` (which validates the bundle), and runs
`examples/swift/main.swift` on macOS: two engines exchange a message in
memory. `scripts/c-example.sh` does the same from C
(`examples/c/loopback.c`) and is part of `scripts/ci.sh`, as is a check that
the checked-in header matches `cbindgen`'s output.

The static libraries are large (17 MB per architecture) because they carry
all of Rust's `std`; the app's linker keeps only what is used.

## 5. Not in v1

- Swift-friendly wrappers (classes, `Data`, `async`), which belong in a
  Swift package on top of this.
- Kotlin/JNI.
- Exposing the UDP host. Mobile hosts own their transports.
- Relays (D-045): `add_relay_link`, `handle_receipt`, the mailbox calls,
  `relay_settled`, and `RelayClient` itself are Rust-only for now.
