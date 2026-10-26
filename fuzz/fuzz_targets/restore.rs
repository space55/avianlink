#![no_main]
//! `Engine::restore` on arbitrary storage contents.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| avianlink_sim::fuzz_harness::restore(data));
