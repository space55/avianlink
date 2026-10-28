//! Hash chains for relay mailboxes (`docs/relay.md` §2.1).

use sha2::{Digest, Sha256};

use crate::wire::{Proof, PROOF_LEN};

/// Proofs per chain (one chain per role, direction and epoch).
pub const CHAIN_LEN: u32 = 16_384;
/// How far ahead of the relay's last accepted value a proof may be.
pub const PROOF_WINDOW: u32 = 256;
/// Length of a mailbox epoch: chains are renewed every epoch
/// (`relay.md` §2.1).
pub const EPOCH_MS: u64 = 30 * 24 * 3_600_000;

/// The mailbox epoch that Unix time `now_ms` falls in.
pub fn epoch(now_ms: u64) -> u64 {
    now_ms / EPOCH_MS
}

const CHAIN_LABEL: &[u8] = b"avianlink-chain-v1";

/// One chain step: `SHA-256(label ‖ v)[..16]`.
pub fn step(v: &Proof) -> Proof {
    let d: [u8; 32] = Sha256::new()
        .chain_update(CHAIN_LABEL)
        .chain_update(v)
        .finalize()
        .into();
    let mut out = [0u8; PROOF_LEN];
    out.iter_mut().zip(d).for_each(|(o, b)| *o = b);
    out
}

/// `v_i` of the chain starting at `seed` (`v_0`).
pub fn value(seed: &Proof, i: u32) -> Proof {
    (0..i).fold(*seed, |v, _| step(&v))
}

/// The chain's public end, `v_N`.
pub fn anchor(seed: &Proof) -> Proof {
    value(seed, CHAIN_LEN)
}

/// The `k`-th proof (`k` = 1 for the first), `v_{N-k}`; `None` once the
/// chain is used up.
pub fn proof(seed: &Proof, k: u32) -> Option<Proof> {
    let i = CHAIN_LEN.checked_sub(k)?;
    (k > 0).then(|| value(seed, i))
}

/// Relay side: whether `p` is a fresh proof for a chain whose last
/// accepted value is `last`, i.e. `step^j(p) == last` for some
/// 1 ≤ j ≤ [`PROOF_WINDOW`].
pub fn verify(last: &Proof, p: &Proof) -> bool {
    let mut v = *p;
    for _ in 0..PROOF_WINDOW {
        v = step(&v);
        if v == *last {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs_verify_once_in_order_within_the_window() {
        let seed = [7u8; PROOF_LEN];
        let mut last = anchor(&seed);
        let p1 = proof(&seed, 1).unwrap();
        assert!(verify(&last, &p1));
        last = p1;
        assert!(!verify(&last, &p1), "one-time");
        // Proofs 2..10 lost on the way: proof 11 still verifies.
        let p11 = proof(&seed, 11).unwrap();
        assert!(verify(&last, &p11));
        last = p11;
        let far = proof(&seed, 11 + PROOF_WINDOW + 1).unwrap();
        assert!(!verify(&last, &far), "beyond the window");
        assert!(!verify(&last, &proof(&seed, 5).unwrap()), "an old proof");
        assert!(!verify(&last, &[0u8; PROOF_LEN]));
        assert_eq!(proof(&seed, CHAIN_LEN), Some(seed));
        assert_eq!(proof(&seed, CHAIN_LEN + 1), None);
        assert_eq!(proof(&seed, 0), None);
    }
}
