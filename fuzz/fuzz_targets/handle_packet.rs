#![no_main]
//! Engine driven by a fuzzer-chosen script of raw packets, sealed frames,
//! sends and time steps. See `avianlink_sim::fuzz_harness::handle_packet`.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| avianlink_sim::fuzz_harness::handle_packet(data));
