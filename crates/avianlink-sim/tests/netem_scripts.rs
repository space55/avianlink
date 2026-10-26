//! The checked-in netem scripts must match the simulator profiles.

use avianlink_sim::{netem, Profile};

#[test]
fn scripts_match_profiles() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/netem");
    for p in Profile::ALL {
        let path = format!("{dir}/{}.sh", p.name());
        let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(
            on_disk,
            netem::script(p),
            "{path} is stale: run `cargo run -p avianlink-sim --bin netem-gen`"
        );
    }
    let clear = std::fs::read_to_string(format!("{dir}/clear.sh")).unwrap_or_default();
    assert_eq!(clear, netem::clear_script());
}
