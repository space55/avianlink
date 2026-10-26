use super::{msg_frame_len, Part, AEAD_TAG_LEN, MAX_HEADER_LEN};

/// Bytes available for frames in a packet on a link with this MTU, assuming
/// the worst-case header used for sizing.
pub fn frame_space(mtu: usize) -> usize {
    mtu.saturating_sub(MAX_HEADER_LEN.saturating_add(AEAD_TAG_LEN))
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
    if msg_frame_len(seq, None, record_len) <= space {
        return Some(FragmentPlan {
            count: 1,
            frag_size: record_len,
        });
    }
    // Worst case for the offset varint: the record length.
    let worst = Some(Part {
        offset: u64::try_from(record_len).ok()?,
        last: true,
    });
    let mut d = space;
    while d > 0 {
        let len = msg_frame_len(seq, worst, d);
        if len <= space {
            let count = u64::try_from(record_len.div_ceil(d)).ok()?;
            return Some(FragmentPlan {
                count,
                frag_size: d,
            });
        }
        d = d.saturating_sub(len.saturating_sub(space).max(1));
    }
    None
}

impl FragmentPlan {
    /// The MSG part descriptor of fragment `index` (`None` when
    /// unfragmented).
    pub fn part(&self, index: u64, record_len: usize) -> Option<Part> {
        if self.count <= 1 {
            return None;
        }
        Some(Part {
            offset: u64::try_from(self.range(index, record_len).start).unwrap_or(u64::MAX),
            last: index.saturating_add(1) >= self.count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_fit_space() {
        for mtu in [48usize, 51, 64, 128, 256, 1200] {
            let space = frame_space(mtu);
            for seq in [0u64, 200, (1 << 35) - 1] {
                for len in [1usize, 10, 40, 100, 4200] {
                    let plan = plan_fragments(space, seq, len).unwrap();
                    assert!(plan.frag_size > 0);
                    let mut total = 0;
                    for i in 0..plan.count {
                        let r = plan.range(i, len);
                        assert!(!r.is_empty(), "mtu {mtu} len {len} frag {i}");
                        total += r.len();
                        assert!(msg_frame_len(seq, plan.part(i, len), r.len()) <= space);
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
