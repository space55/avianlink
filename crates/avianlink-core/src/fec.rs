//! Erasure coding across packets (`docs/reliability.md` §6, wire §3.4).
//!
//! GF(2⁸) with polynomial 0x11d. One repair is XOR; `m > 1` repairs use the
//! Cauchy coefficients `c(j, i) = (j ⊕ (16 + i))⁻¹`, any square submatrix
//! of which is invertible, so any `e` repairs recover any `e` erasures.
//! Public for property tests; not a stable API.

use alloc::vec;
use alloc::vec::Vec;

/// Most sources in one window (and most repairs per window).
pub const MAX_SOURCES: usize = 16;

const POLY: u16 = 0x11d;

/// `EXP[i] = α^i` for `i < 510` (doubled so products need no reduction);
/// `LOG[x] = log_α x` for `x ≠ 0`.
// Index arithmetic is bounded by the loop limits (i < 255, x < 256).
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
const fn tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        exp[i + 255] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= POLY;
        }
        i += 1;
    }
    (exp, log)
}

const TABLES: ([u8; 512], [u8; 256]) = tables();
static EXP: [u8; 512] = TABLES.0;
static LOG: [u8; 256] = TABLES.1;

fn log(x: u8) -> usize {
    LOG.get(usize::from(x)).map_or(0, |&l| usize::from(l))
}

/// Product in GF(2⁸).
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    EXP.get(log(a).saturating_add(log(b))).copied().unwrap_or(0)
}

/// Multiplicative inverse; `inv(0) = 0`.
pub fn inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    EXP.get(255usize.saturating_sub(log(a)))
        .copied()
        .unwrap_or(0)
}

/// Coefficient of source `i` in repair `j` of a window with `m` repairs.
pub fn coeff(m: usize, j: usize, i: usize) -> u8 {
    if m <= 1 {
        return 1;
    }
    // j < 16 and 16 + i in 16..32, so the XOR is never zero.
    let j = u8::try_from(j).unwrap_or(0);
    let y = u8::try_from(i.saturating_add(16)).unwrap_or(16);
    inv(j ^ y)
}

/// `dst ^= c · src`, treating `src` as zero-padded to `dst`'s length.
fn mul_add(dst: &mut [u8], src: &[u8], c: u8) {
    if c == 1 {
        dst.iter_mut().zip(src).for_each(|(d, s)| *d ^= s);
    } else if c != 0 {
        dst.iter_mut().zip(src).for_each(|(d, s)| *d ^= mul(c, *s));
    }
}

/// Computes `m` repair symbols over `sources`, each as long as the longest
/// source. Returns nothing for an empty window or `m == 0`.
pub fn encode(sources: &[&[u8]], m: usize) -> Vec<Vec<u8>> {
    let len = sources.iter().map(|s| s.len()).max().unwrap_or(0);
    if sources.is_empty() || sources.len() > MAX_SOURCES || m > MAX_SOURCES {
        return Vec::new();
    }
    (0..m)
        .map(|j| {
            let mut out = vec![0u8; len];
            for (i, s) in sources.iter().enumerate() {
                mul_add(&mut out, s, coeff(m, j, i));
            }
            out
        })
        .collect()
}

/// Recovers the sources at positions `missing` of a window of `m`
/// repairs, from the `known` (position, symbol) sources and at least
/// `missing.len()` repairs `(j, symbol)` of equal length. Returns the
/// recovered symbols in `missing` order, or `None` if the inputs are
/// inconsistent.
pub fn decode(
    m: usize,
    known: &[(usize, &[u8])],
    repairs: &[(usize, &[u8])],
    missing: &[usize],
) -> Option<Vec<Vec<u8>>> {
    let e = missing.len();
    if e == 0 || repairs.len() < e || e > MAX_SOURCES {
        return None;
    }
    let repairs = repairs.get(..e)?;
    let len = repairs.first()?.1.len();
    if repairs
        .iter()
        .any(|(j, r)| r.len() != len || *j >= m.max(1))
        || known.iter().any(|(_, s)| s.len() > len)
    {
        return None;
    }
    // rhs_r = repair_r − Σ known contributions; a_rt = c(m, j_r, missing_t).
    let mut rhs: Vec<Vec<u8>> = repairs
        .iter()
        .map(|&(j, data)| {
            let mut v = data.to_vec();
            for &(i, s) in known {
                mul_add(&mut v, s, coeff(m, j, i));
            }
            v
        })
        .collect();
    let mut a: Vec<Vec<u8>> = repairs
        .iter()
        .map(|&(j, _)| missing.iter().map(|&i| coeff(m, j, i)).collect())
        .collect();

    // Gauss-Jordan elimination.
    for t in 0..e {
        let pivot =
            (t..e).find(|&r| a.get(r).and_then(|row| row.get(t)).is_some_and(|&x| x != 0))?;
        a.swap(t, pivot);
        rhs.swap(t, pivot);
        let scale = inv(*a.get(t)?.get(t)?);
        a.get_mut(t)?.iter_mut().for_each(|x| *x = mul(*x, scale));
        rhs.get_mut(t)?.iter_mut().for_each(|x| *x = mul(*x, scale));
        let (pivot_row, pivot_rhs) = (a.get(t)?.clone(), rhs.get(t)?.clone());
        for r in (0..e).filter(|&r| r != t) {
            let f = *a.get(r)?.get(t)?;
            if f != 0 {
                mul_add(a.get_mut(r)?, &pivot_row, f);
                mul_add(rhs.get_mut(r)?, &pivot_rhs, f);
            }
        }
    }
    Some(rhs)
}

/// Repair need of a window of `k` sources at `loss_permille`, in
/// thousandths of a repair: `k · 1.5 · p/(1−p)`, at most `k`.
pub fn repair_credit(k: usize, loss_permille: u64) -> u64 {
    let p = loss_permille.min(999);
    let k64 = u64::try_from(k).unwrap_or(0);
    let need = k64
        .saturating_mul(1500)
        .saturating_mul(p)
        .checked_div(1000u64.saturating_sub(p))
        .unwrap_or(0);
    need.min(k64.saturating_mul(1000))
}

/// Repairs to send for a window of `k` sources at `loss_permille`
/// (`reliability.md` §6): `⌈k · 1.5 · p/(1−p)⌉`, between 1 and `k`.
pub fn reed_solomon_repairs(k: usize, loss_permille: u64) -> usize {
    let p = loss_permille.min(999);
    let k64 = u64::try_from(k).unwrap_or(0);
    // k · 1.5 · p / (1000 − p), rounded up, in integers.
    let num = k64.saturating_mul(3).saturating_mul(p);
    let den = 2u64.saturating_mul(1000u64.saturating_sub(p)).max(1);
    let m = usize::try_from(num.div_ceil(den)).unwrap_or(k);
    m.clamp(1, k.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_axioms_spot_checks() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)), 1, "{a}");
            assert_eq!(mul(a, 1), a);
            assert_eq!(mul(a, 0), 0);
        }
        // Known value for 0x11d: α^8 = 0x1d.
        assert_eq!(mul(0x80, 2), 0x1d);
        assert_eq!(mul(3, 7), mul(7, 3));
    }

    #[test]
    fn xor_window_recovers_one_loss() {
        let srcs: [&[u8]; 3] = [b"alpha", b"be", b"gamma!"];
        let rep = encode(&srcs, 1);
        assert_eq!(rep.len(), 1);
        assert_eq!(rep[0].len(), 6);
        let got = decode(1, &[(0, srcs[0]), (2, srcs[2])], &[(0, &rep[0])], &[1]).unwrap();
        assert_eq!(&got[0][..2], b"be");
        assert!(got[0][2..].iter().all(|&b| b == 0), "zero padded");
    }

    #[test]
    fn cauchy_recovers_any_erasure_pattern() {
        let srcs: Vec<Vec<u8>> = (0..6u8)
            .map(|i| vec![i.wrapping_mul(37); 3 + usize::from(i)])
            .collect();
        let refs: Vec<&[u8]> = srcs.iter().map(|s| &s[..]).collect();
        let m = 3;
        let reps = encode(&refs, m);
        // Every subset of up to 3 missing sources, from every choice of
        // repairs of that size.
        for mask in 1u32..(1 << 6) {
            let missing: Vec<usize> = (0..6).filter(|i| mask & (1 << i) != 0).collect();
            if missing.len() > m {
                continue;
            }
            let known: Vec<(usize, &[u8])> = (0..6)
                .filter(|i| mask & (1 << i) == 0)
                .map(|i| (i, refs[i]))
                .collect();
            for start in 0..m {
                let chosen: Vec<(usize, &[u8])> = (0..missing.len())
                    .map(|n| {
                        let j = (start + n) % m;
                        (j, &reps[j][..])
                    })
                    .collect();
                let got = decode(m, &known, &chosen, &missing).unwrap();
                for (t, &i) in missing.iter().enumerate() {
                    assert_eq!(&got[t][..srcs[i].len()], &srcs[i][..], "mask {mask:b}");
                }
            }
        }
    }

    #[test]
    fn decode_rejects_inconsistent_inputs() {
        let srcs: [&[u8]; 2] = [b"aa", b"bb"];
        let rep = encode(&srcs, 1);
        assert!(
            decode(1, &[], &[(0, &rep[0])], &[0, 1]).is_none(),
            "too few repairs"
        );
        assert!(decode(1, &[(0, b"toolong")], &[(0, &rep[0])], &[1]).is_none());
        assert!(
            decode(1, &[(0, srcs[0])], &[(5, &rep[0])], &[1]).is_none(),
            "j ≥ m"
        );
        assert!(decode(1, &[], &[], &[]).is_none());
    }

    #[test]
    fn repair_counts() {
        assert_eq!(reed_solomon_repairs(8, 20), 1);
        assert_eq!(reed_solomon_repairs(8, 100), 2); // 8·1.5·0.111 = 1.33
        assert_eq!(reed_solomon_repairs(8, 350), 7); // 8·1.5·0.538 = 6.46
        assert_eq!(reed_solomon_repairs(8, 900), 8);
        assert_eq!(reed_solomon_repairs(1, 30), 1);
        assert_eq!(reed_solomon_repairs(0, 500), 1);
    }
}
