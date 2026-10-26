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

## DA-012: `FakeEngine` runs two real engines, not an imitation (Phase 1)

**Decision.** `FakeEngine` owns a real `avianlink_core::Engine` for this
machine and one more per simulated contact, connected by an impaired channel.
It does not imitate the protocol; it runs it. Fragmentation at the real MTU,
real acknowledgements, real adaptive retransmission, real duplicate
suppression and real causal ordering all happen, over a link that really does
lose, delay, corrupt, duplicate and reorder packets.

**Why.** The brief asks the fake to "behave like a bad link, not a perfect
one, so the UI is designed against reality from day one". A hand-written fake
that emits plausible events would let the interface be built against behaviour
the real engine never produces, and every difference would surface in the
app's Phase 3 as a UI bug found late. Running the real engine makes the Phase 3
adapter a change of _where packets go_ and nothing else.

It also turned out to be less code, not more: the peer's acknowledgements,
retransmission timers and reassembly are the library's problem, not the app's.

**Cost.** The app's test suite now depends on the library's behaviour, so a
library regression fails the app's tests. That is arguably a feature. It also
means the app cannot be built while the library is mid-refactor, which
happened twice during Phase 1.

## DA-013: Dependency: `avianlink-sim`, for impairment parameters only (Phase 1)

**Decision.** `avianlink-sim` is a normal dependency of the app, used for
`Profile::link() -> LinkProfile`: the tuned delay, bursty-loss, corruption,
duplication, reordering, MTU, airtime and outage parameters of the five named
profiles. The code that _applies_ them is reimplemented in
`src-tauri/src/engine/channel.rs`.

**Why not reuse the simulator's channel.** It is `pub(crate)`, and the only
public entry point, `Scenario::run()`, executes a whole batch over virtual
time — the wrong shape for a GUI advancing in real time. Filed as AR-009.

**Why reuse the parameters.** They are the half that was tuned against real
links and that `scripts/netem/` mirrors. A second set of invented numbers
would make the app's "disaster cellular" mean something different from the
library's, which would make every comparison between them meaningless.

**Flagged.** Shipping a simulator inside the release binary is wrong
long-term. Phase 3 should put `FakeEngine` and this dependency behind a
feature that is off by default.

## DA-014: Dependency: `@paulmillr/qr` 0.3 for the QR code (Phase 1)

The brief requires showing your own public key as a QR code. `@paulmillr/qr`
has no dependencies, is maintained by the author of the `noble` cryptography
libraries, and its `encodeQR(value, 'raw')` returns a boolean matrix — which
is what the app wants, because it renders the code as inline SVG rather than
to a canvas. SVG is crisp at any size, prints, and needs no `<canvas>`
permission or pixel-ratio handling.

**Rejected:** `qrcode` (pulls a CLI and several dependencies) and hand-rolling
one (Reed–Solomon over GF(256), mask selection and version tables, to draw a
square — not a good use of a budget that should go to the interface).

## DA-015: A single `Simulation` escape hatch, not scattered `is_fake()` checks (Phase 1)

**Decision.** `EngineHandle::simulation() -> Option<&mut dyn Simulation>`
returns `Some` only for `FakeEngine`. Everything that exists only in the
simulation — impairment settings, inventing a contact, seeding history,
forcing a message into `failed` — is behind it.

**Why.** The alternative is a scattering of capability questions through the
command layer, each of which quietly becomes a place where a dev-only path can
leak into a release build. One named hatch makes the set of such things
explicit and finite, and makes `add_simulated_contact` fail honestly on the
real engine rather than creating a contact nothing will ever answer.

## DA-016: The app is English-only, and relative times are hand-written (Phase 1)

`Intl.RelativeTimeFormat` produces "2 hours ago", which is the wrong register
and too wide for the sidebar; the app wants "2h". There is no localisation
layer, so the terse English in `lib/format.ts` is written directly. Absolute
times and dates _do_ go through `Intl`, because those are the parts where the
user's locale and timezone genuinely matter.

**Revisit** if the app is ever localised, at which point the terse forms need
a proper message catalogue rather than string concatenation.

## DA-017: Contrast is enforced by a test, not by eye (Phase 1)

**Decision.** `tests/tokens.test.ts` parses `src/app.css`, computes WCAG
contrast ratios for every text token against every surface token in both
themes, and fails below 4.5:1.

**Why.** It found a real defect immediately: `--text-faint` was at 3.01:1 in
light and 3.97:1 in dark. That token carries timestamps, link health and the
queued state — all real information at small sizes, all of which WCAG holds to
the full 4.5:1. It is also exactly the token a designer keeps nudging quieter,
so it is the one most likely to drift back.

Both themes' faint tones were darkened/lightened to clear the threshold.

## DA-018: The bindings check asks whether regeneration changed the file (Phase 1)

**Decision.** `scripts/desktop-ci.sh` snapshots `bindings.ts`, runs
`cargo test` (which regenerates it), and compares against the snapshot.

**Reversed from DA-007**, which compared against git `HEAD`. That version
failed on _any_ uncommitted work, including the commit that was introducing
the change — it was testing "is the working tree clean" rather than "is the
generated file current", which made the gate unrunnable mid-change.

## DA-019: Brand assets are used as supplied, and the tier is chosen by rendered size (Phase 1)

**Decision.** The `avianlink-logo` package (v1.0) is vendored into
`src/assets/brand/` and `src-tauri/icons/`, and the app follows its sizing
rules rather than scaling one file everywhere:

| Where                           | File                      | Rule                            |
| ------------------------------- | ------------------------- | ------------------------------- |
| Sidebar header, sidebar ≥ 248px | compact lockup, 24px tall | lockup 24–47px → compact        |
| Sidebar header, narrower        | wordmark alone, 16px tall | below 24px → wordmark alone     |
| Empty-state placeholder         | full mark, 112px wide     | mark ≥ 96px → full              |
| App icon                        | full icon, 1024px         | icon ≥ 128px → full             |
| `index.html`                    | `favicon.svg`             | micro mark, adapts to dark mode |

**Why the `-currentcolor` variants.** They inherit the surrounding text
colour, so one file is correct in both themes. The alternative — a `-dark`
and a `-light` file swapped by a media query — is two files that can drift and
a second place for the theme to be wrong.

**Why inline SVG rather than `<img>`.** `currentColor` does not resolve inside
an `<img>`; the image is an isolated document. The files are imported with
Vite's `?raw` and inserted with `{@html}`, which keeps them byte-identical to
the package. The guidelines say to use the supplied files as they are and not
to rebuild the lockup from its parts, and a component that reconstructed the
mark from its rectangles would be doing exactly that.

**Clear space** — half the mark's height on every side, with nothing entering
it — is implemented as padding on the wrapper with a compensating negative
margin, so the reserved space is real but the element still aligns to its
container's edge.

**The accessible name comes from the file.** Every supplied SVG already
carries `role="img"` and `aria-label="avianlink"`; the wrapper adds neither,
because nesting two identical image roles is worse than nesting none.

## DA-020: The app icon is rendered by Chromium, not reimplemented (Phase 1)

**Decision.** `src-tauri/icons/render-source.mjs` loads the supplied
1024×1024 icon SVG in headless Chromium (via the Playwright the test suite
already depends on) and screenshots it to `source.png`, which `tauri icon`
expands into the platform set.

**Rejected:** the previous placeholder generator, which drew rounded
rectangles from scratch in pure Python. Reimplementing the mark's 14 lines and
their per-line opacity would produce an approximation of the brand asset
rather than the asset itself — and the icon is the one place where being
approximately on-brand is indistinguishable from being off-brand.

**Rejected:** adding `resvg`/`librsvg`/ImageMagick. A build-time dependency on
a native image toolchain, for one file that changes about once a year, when a
real browser engine is already installed.
