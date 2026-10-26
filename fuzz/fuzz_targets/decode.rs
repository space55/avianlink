#![no_main]
//! Every standalone wire parser on arbitrary bytes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| avianlink_sim::fuzz_harness::decode(data));
