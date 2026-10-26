# netem profiles

`tc netem` scripts for the simulator's named profiles. They are
**generated** by `cargo run -p avianlink-sim --bin netem-gen` from
`crates/avianlink-sim/src/profiles.rs`. Don't edit them: a test fails if
they drift from the profiles. `docs/hosting.md` §5 says how each simulator
impairment maps to netem, and how faithfully.

| Script | Use |
|---|---|
| `<profile>.sh DEV [DEV...]` | Apply a profile on each device's egress, as root on Linux. Profiles with outages keep running and toggle the link; Ctrl-C clears it. |
| `clear.sh DEV [DEV...]` | Remove the qdiscs. |
| `docker-test.sh [PROFILE] [N] [INTERVAL_S] [TIMEOUT_S]` | The Phase 6 acceptance test in Docker: alice ↔ router (netem) ↔ bob, with two `avianlink chat` peers. Exits non-zero unless every message arrives and is acknowledged. |
