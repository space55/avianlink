use super::{msg_frame_len, varint_len, CHECK_LEN, MAX_HEADER_LEN};

/// Bytes available for frames in a packet on a link with this MTU, assuming
/// the worst-case header used for sizing.
pub fn frame_space(mtu: usize) -> usize {
    mtu.saturating_sub(MAX_HEADER_LEN.saturating_add(CHECK_LEN))
}

/// How a record is split into MSG fragments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragmentPlan {
    /// Number of fragments (1 = unfragmented).
    pub count: u64,
    /// Data bytes per fragment; the last may be shorter.
    pub frag_size: usize,
}

impl FragmentPlan {
    /// Byte range of fragment `index` within a record of `record_len`.
    pub fn range(&self, index: u64, record_len: usize) -> core::ops::Range<usize> {
        let i = usize::try_from(index).unwrap_or(usize::MAX);
        let start = i.saturating_mul(self.frag_size).min(record_len);
        let end = start.saturating_add(self.frag_size).min(record_len);
        start..end
    }
}

/// Plans the fragmentation of a record so every MSG frame fits in `space`
/// bytes on its own. Returns `None` if `space` is too small for any data.
pub fn plan_fragments(space: usize, seq: u64, record_len: usize) -> Option<FragmentPlan> {
    if msg_frame_len(seq, 1, 0, record_len) <= space {
        return Some(FragmentPlan {
            count: 1,
            frag_size: record_len,
        });
    }
    // `width` is the worst-case varint length of count and index.
    for width in 1..=3usize {
        let max_count: u64 = match width {
            1 => 0x7f,
            2 => 0x3fff,
            _ => 0x1f_ffff,
        };
        let frag_size = max_data(space, seq, max_count)?;
        let count = u64::try_from(record_len.div_ceil(frag_size)).ok()?;
        if count <= max_count {
            debug_assert!(varint_len(count) <= width);
            return Some(FragmentPlan { count, frag_size });
        }
    }
    None
}

/// Largest `d` such that a MSG frame with worst-case `count`/`index` up to
/// `max_count` and `d` data bytes fits in `space`.
fn max_data(space: usize, seq: u64, max_count: u64) -> Option<usize> {
    let mut d = space;
    // The frame length is monotonic in `d`; overhead is at most ~25 bytes,
    // so a short downward search from the upper bound converges quickly.
    while d > 0 {
        if msg_frame_len(seq, max_count, max_count, d) <= space {
            return Some(d);
        }
        let over = msg_frame_len(seq, max_count, max_count, d).saturating_sub(space);
        d = d.saturating_sub(over.max(1));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_fit_space() {
        for mtu in [48usize, 51, 64, 128, 256, 1200] {
            let space = frame_space(mtu);
            for seq in [0u64, 200, u64::MAX] {
                for len in [1usize, 10, 40, 100, 4200] {
                    let plan = plan_fragments(space, seq, len).unwrap();
                    assert!(plan.frag_size > 0);
                    let mut total = 0;
                    for i in 0..plan.count {
                        let r = plan.range(i, len);
                        assert!(!r.is_empty(), "mtu {mtu} len {len} frag {i}");
                        total += r.len();
                        assert!(msg_frame_len(seq, plan.count, i, r.len()) <= space);
                    }
                    assert_eq!(total, len);
                }
            }
        }
    }

    #[test]
    fn no_space_no_plan() {
        assert_eq!(plan_fragments(3, 0, 10), None);
    }
}
