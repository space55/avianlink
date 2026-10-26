# Desktop app decision log

Decisions specific to `apps/desktop`. The library keeps its own log in
`/docs/decisions.md`; entries there are numbered `D-nnn`, entries here
`DA-nnn` ("desktop app"), so the two can be cited without ambiguity.

Entries are append-only. A reversed decision gets a new entry referencing the
old one. Every new dependency gets an entry.

---

## DA-001: Stack taken as given (Phase 0)

Tauri 2, Svelte 5 + TypeScript + Vite, plain CSS with custom-property design
tokens, Rust backend with `tokio` + `rusqlite` + `serde`, and Rust/Vitest/
Playwright tests. Prescribed by the app brief; not re-litigated. Everything
below records only where reality forced a choice the brief left open.

## DA-002: The app crate does not inherit the workspace MSRV (Phase 0)

**Decision.** `avianlink-desktop` sets `rust-version = "1.85"` instead of
inheriting `rust-version.workspace = true` (1.82).

**Why.** The workspace MSRV exists to keep `avianlink-core` buildable on old
embedded and vendor toolchains (library D-004). The app has the opposite
constraint: it is only ever built on a developer or CI machine, and its
dependency tree (`tauri` 2.12, `ts-rs` 12) requires a newer compiler than
1.82. Inheriting would make `cargo build --locked` fail resolution. The app's
MSRV is a separate, much weaker promise, so it gets its own number.

## DA-003: Adding the app to the root Cargo workspace has a cost (Phase 0)

**Decision.** `apps/desktop/src-tauri` is a member of the root workspace, as
the brief requires.

**Consequence, flagged not worked around.** The root `scripts/ci.sh` runs
`cargo clippy --workspace --all-targets` and `cargo test --workspace`, so the
library's CI gate now compiles Tauri and its system-webview bindings. On
Linux that needs `libwebkit2gtk-4.1-dev` and friends installed, which the
library's gate previously did not. The library agent owns `scripts/ci.sh`, so
this app does not edit it. `scripts/desktop-ci.sh` is the app's own gate and
is self-contained.

**Rejected.** A separate workspace under `apps/desktop`. It would isolate the
build graphs and keep the library's CI light, but it also means a second
`Cargo.lock` and a path dependency on `avianlink-core` that resolves outside
the workspace — more friction than the shared lockfile costs, and the brief
asked for a single workspace.

## DA-004: `EngineHandle` mirrors the sans-IO engine, not the UI (Phase 0)

**Decision.** The `EngineHandle` trait in `src-tauri/src/engine.rs` has the
shape of `avianlink_core::Engine`: `handle_packet`, `handle_timeout`,
`send_text`, `poll_transmit`, `poll_event`, `next_timeout`, link and contact
registration. It is _not_ a UI-level interface (no "list messages", no
"conversation summaries").

**Why.** The driver task's job is to pump a sans-IO state machine, and that
pumping loop is the part that must be identical for the fake and the real
engine. UI-level reads (message history, pagination, conversation lists) come
from the app's own SQLite store, which is populated from engine events — so
they belong to `storage.rs`, not to the engine abstraction. Keeping the
boundary here makes the real adapter in Phase 3 close to a no-op and keeps
`FakeEngine` honest: it has to produce the same event stream over the same
pump protocol, not a convenient summary.

**Consequence.** `FakeEngine` has to encode and decode its own packets to
look like a link (it does, with a trivial JSON-ish framing, since the fake's
packets never meet a real peer).

## DA-005: `EngineHandle` reuses `avianlink-core`'s domain types (Phase 0)

**Decision.** The trait signature uses `avianlink_core`'s `PublicKey`,
`ConversationId`, `MessageId`, `LinkId`, `LinkConfig`, `Timestamp`,
`Transmit` and `Event` directly, rather than app-local copies. IPC types
(`src-tauri/src/ipc.rs`) are separate and app-owned.

**Why.** Copying the domain types would mean a conversion layer that exists
only to be maintained, and the real adapter would be the place where a drift
bug hides. Reusing them couples the app to a Phase 1 library API that will
still move, which is the real cost — accepted, because the IPC layer is the
boundary that matters: the frontend sees only app-owned DTOs with hex-string
keys, so a library type change cannot reach the UI.

## DA-006: Dependency: `ts-rs` 12, not `specta`/`tauri-specta` (Phase 0)

**Decision.** TypeScript types are generated from the Rust IPC types with
`ts-rs = "12"`. The typed command and event wrappers on the TypeScript side
are hand-written (`src/lib/ipc/client.ts`), consuming the generated types.

**Why.** The brief named either. `ts-rs` 12.0.1 is a stable release;
`specta` and `tauri-specta` are at `2.0.0-rc.26`/`rc.27` and have been in
release-candidate state for a long time. `tauri-specta` would additionally
generate the command wrappers, which is real value — but it buys that by
putting a pre-1.0 crate on the critical path of every IPC call, in a
repository whose library half deliberately avoids pre-release dependencies
(library D-002). The hand-written wrapper layer is ~1 line per command and is
checked by `tsc`, so the generated-types-only approach loses little.

**Revisit** when `tauri-specta` 2.0 ships stable.

## DA-007: Generated bindings are committed, and CI checks they are current (Phase 0)

**Decision.** `src/lib/ipc/bindings.ts` is generated by
`cargo test -p avianlink-desktop` (ts-rs exports during tests) and committed
to git. `scripts/desktop-ci.sh` regenerates it and fails if the working tree
changed.

**Why.** The frontend must typecheck and the Vitest/Playwright suites must
run without a Rust toolchain present (CI splits those jobs, and frontend
contributors should not need `cargo`). Committing the artefact buys that; the
diff check removes the usual cost of a committed artefact, which is drift.

## DA-008: Dependency: `hex` 0.4 (Phase 0)

Public keys, conversation IDs and message IDs cross the IPC boundary as
lowercase hex strings (see `ipc.md`). `hex = "0.4.3"` has no dependencies,
is `no_std`-capable, and is already ubiquitous. Hand-rolling encode is
trivial, but hand-rolling _decode_ of attacker-pasted text is exactly the
kind of small parser that acquires an off-by-one, so it is worth a dependency
with a decade of use behind it.

## DA-009: Fingerprints are computed by the app, with a request to move them (Phase 0)

**Decision.** The human-checkable fingerprint is
`hex(SHA-256("avianlink-fingerprint-v1" || public_key)[..10])`, rendered as
five groups of four lowercase hex characters (`a1b2-c3d4-e5f6-7890-abcd`,
80 bits).

**Why that shape.** 80 bits is far beyond what a human will compare but keeps
the string short enough to read aloud in five chunks. Grouping is what makes
character-by-character comparison actually happen. Lowercase hex avoids the
`0`/`O` and `1`/`l` confusions of base32 without needing a custom alphabet.

**Why in the app, and why that is wrong long-term.** The library does not
expose a fingerprint function. Two avianlink clients that show _different_
fingerprints for the same key would be an authentication footgun, so this
belongs in `avianlink-core` where every client shares it. Filed in
`api-requests.md` (AR-004); the app's implementation is the stand-in and uses
a domain-separated label so it can be adopted as-is.

## DA-010: Dependencies: `rand_core`/`rand_chacha` reused from the workspace (Phase 0)

The engine takes an injected `CryptoRngCore`. The app uses `rand_core`'s
`OsRng` for the real engine and `rand_chacha::ChaCha20Rng` seeded from a
fixed value inside `FakeEngine`, so a fake-engine session replays identically
and a UI bug found in a demo can be reproduced. Both are already workspace
dependencies (library D-002, D-003), so this adds nothing to the tree.

## DA-011: Frontend test stack: Vitest 5 (Phase 0)

**Decision.** `vitest = "^5"` with `jsdom`, `@testing-library/svelte` and
`@testing-library/jest-dom`.

**Why 5 and not 3.** Vitest ≤ 4.1.10 pulls `@vitest/mocker` and `tinypool`
versions with published advisories (GHSA-5gmw-xhrv-c9v3 and
GHSA-85c8-ppgw-ccpr, prototype pollution to RCE in `tinypool`). `npm audit`
is clean on 5. A dev-only dependency still runs with repository write access
on every contributor's machine, so "dev-only" is not a reason to carry a
known RCE.
