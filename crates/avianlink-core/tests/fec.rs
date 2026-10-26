//! Property tests for the cross-packet erasure code.

use avianlink_core::fec::{decode, encode, MAX_SOURCES};
use proptest::prelude::*;

proptest! {
    /// Any `e ≤ m` erasures are recovered from any `e` of the `m` repairs.
    #[test]
    fn recovers_any_erasures_from_any_repairs(
        sources in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..40), 1..=MAX_SOURCES),
        m in 1usize..=6,
        erase_seed in any::<u64>(),
        pick_seed in any::<u64>(),
    ) {
        let k = sources.len();
        let refs: Vec<&[u8]> = sources.iter().map(|s| &s[..]).collect();
        let repairs = encode(&refs, m);
        prop_assert_eq!(repairs.len(), m);
        let max_len = sources.iter().map(Vec::len).max().unwrap_or(0);
        prop_assume!(max_len > 0);
        // Choose e = 1..=min(m, k) erased positions and e repairs.
        let e = 1 + (erase_seed as usize) % m.min(k);
        let mut positions: Vec<usize> = (0..k).collect();
        let mut x = erase_seed;
        for i in (1..k).rev() {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            positions.swap(i, (x >> 33) as usize % (i + 1));
        }
        let mut missing: Vec<usize> = positions[..e].to_vec();
        missing.sort_unstable();
        let mut js: Vec<usize> = (0..m).collect();
        let mut y = pick_seed;
        for i in (1..m).rev() {
            y = y.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            js.swap(i, (y >> 33) as usize % (i + 1));
        }
        let chosen: Vec<(usize, &[u8])> = js[..e].iter().map(|&j| (j, &repairs[j][..])).collect();
        let known: Vec<(usize, &[u8])> =
            (0..k).filter(|i| !missing.contains(i)).map(|i| (i, refs[i])).collect();
        let got = decode(m, &known, &chosen, &missing).unwrap();
        for (t, &i) in missing.iter().enumerate() {
            prop_assert_eq!(&got[t][..sources[i].len()], &sources[i][..]);
            prop_assert!(got[t][sources[i].len()..].iter().all(|&b| b == 0));
        }
    }

    /// Decoding never panics on arbitrary (inconsistent) inputs.
    #[test]
    fn decode_never_panics(
        m in 0usize..20,
        known in prop::collection::vec((0usize..40, prop::collection::vec(any::<u8>(), 0..20)), 0..20),
        repairs in prop::collection::vec((0usize..20, prop::collection::vec(any::<u8>(), 0..20)), 0..20),
        missing in prop::collection::vec(0usize..40, 0..20),
    ) {
        let known: Vec<(usize, &[u8])> = known.iter().map(|(i, s)| (*i, &s[..])).collect();
        let repairs: Vec<(usize, &[u8])> = repairs.iter().map(|(j, s)| (*j, &s[..])).collect();
        let _ = decode(m, &known, &repairs, &missing);
    }
}
