# avianlink desktop

A one-to-one text messenger for links that lose most of what they carry:
latency of seconds to hours, bursty loss, corruption, tiny MTUs, and peers
that are unreachable for days. It is a host for the sans-IO engine in
`crates/avianlink-core` — it supplies the clock, the randomness, the storage
and the packets, and drives the engine's pump loop.

```sh
make setup      # install the Node dependencies
make dev        # run it, with hot reload
make dist       # the final application bundle, gate first
make            # everything else
```

## Prerequisites

- **Rust** 1.85 or newer (`rustup`). The app's MSRV is separate from the
  library's, which targets embedded toolchains.
- **Node** 20 or newer, with npm.

**macOS** — Xcode Command Line Tools (`xcode-select --install`). WebKit comes
with the OS.

**Linux** — the WebKitGTK development packages. On Debian or Ubuntu:

```sh
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
  libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
```

Building an AppImage additionally needs `libfuse2`.

## Running it

`make dev` starts the Vite dev server and the Tauri shell together, with hot
reload for the frontend and a rebuild on Rust changes.

`make web` runs only the frontend in an ordinary browser. The IPC is absent
there, so every command fails — useful for working on layout, useless for
anything else.

**What you will see on first run.** The app currently runs on `FakeEngine`,
which is not a mock: it holds a real `avianlink-core` engine for you and one
for each simulated contact, joined by a link that genuinely loses, delays,
corrupts, duplicates and reorders packets, using the impairment profiles from
`avianlink-sim`. Messages really are fragmented, retransmitted and
acknowledged. It starts with no contacts; **Settings → Links** chooses the
profile, and the add-contact dialog can conjure a simulated peer that answers.

The identity is regenerated on every launch until the keychain work lands, so
restarting changes who you are and existing contacts stop matching.

## Checking

`make check` runs the whole gate — the same script CI runs:

```
cargo fmt --check · clippy -D warnings · cargo test · bindings freshness
prettier · eslint · svelte-check · tsc · vitest · vite build · playwright
```

`make test` and `make e2e` are the faster subsets. `make fmt` rewrites
everything to the canonical formatting.

The Rust lints run with `--no-deps`, so a warning in the library crates
cannot fail this app's gate, or the reverse.

## Packaging

`make dist` is the one to use. It runs the full gate and only then packages,
because an installer is the worst place to find out the tests were red.
`make bundle` skips the gate when you are iterating on packaging itself.

| Target          | Host  | Produces                              |
| --------------- | ----- | ------------------------------------- |
| `make dmg`      | macOS | `avianlink_<version>_<arch>.dmg`      |
| `make app`      | macOS | `avianlink.app`                       |
| `make deb`      | Linux | `avianlink_<version>_<arch>.deb`      |
| `make appimage` | Linux | `avianlink_<version>_<arch>.AppImage` |

Artefacts land in `../../target/release/bundle/` — the Rust workspace is
shared with the library crates, so the target directory is the workspace's
rather than this app's. `make artefacts` lists what is there.

**Cross-compiling is not set up.** Each bundle is built on its own platform.
Tauri can cross-compile in principle, but the webview is a system library on
both targets, so in practice it means a CI matrix with a runner per platform.

## Signing

Signing is configured **entirely by environment**, never by editing the
committed config, so a developer build and a release build are the same
build. `make bundle` prints whether the build will be signed before it starts,
and `make verify` reports the result — an unsigned artefact should never be
mistaken for a signed one.

### macOS

```sh
export APPLE_SIGNING_IDENTITY="Developer ID Application: Example Ltd (TEAMID)"

# To notarize as well, which is what stops Gatekeeper warning:
export APPLE_ID="you@example.com"
export APPLE_PASSWORD="app-specific-password"   # not your Apple ID password
export APPLE_TEAM_ID="TEAMID"

make dist && make verify
```

In CI, where there is no keychain, supply the certificate itself instead of
an identity name:

```sh
export APPLE_CERTIFICATE="$(base64 < certificate.p12)"
export APPLE_CERTIFICATE_PASSWORD="..."
```

Without these the build still succeeds and produces an ad-hoc signed bundle.
It runs on the machine that built it and is refused everywhere else, which is
what `make verify` will tell you.

### Linux

`.deb` and AppImage packages are not signed by Tauri. Distribute them through
a repository that signs its index (`dpkg-sig`, `reprepro`, or the hosting
platform's own signing), rather than signing the file.

If the updater is enabled later, its signing key is separate from any of the
above and goes in `TAURI_SIGNING_PRIVATE_KEY`.

## Layout

```
src/              Svelte 5 frontend
  lib/ipc/        the only module that talks to the backend
  lib/components/ the interface
src-tauri/        Rust backend
  src/engine/     the EngineHandle boundary, FakeEngine, the impaired channel
  src/driver.rs   the one task that owns the engine and pumps it
  src/storage.rs  history, contacts, read marks, settings
  src/commands.rs the IPC surface
docs/             design.md, ipc.md, decisions.md, api-requests.md
```

`src/lib/ipc/bindings.ts` is **generated** from `src-tauri/src/ipc.rs` by
`ts-rs`; run `make bindings` after changing an IPC type. It is committed so
the frontend typechecks without a Rust toolchain, and the gate fails if it is
stale.

## Where to read next

- `docs/design.md` — what the interface does and why, which is where the
  unusual decisions are argued.
- `docs/ipc.md` — the contract between the halves.
- `docs/decisions.md` — choices and rejected alternatives.
- `docs/api-requests.md` — what this app needs from the library.
