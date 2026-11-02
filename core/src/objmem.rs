//! Where kernel objects may lie: the physical memory behind every slot
//! address and every range `core/` zeroes (`docs/design.md`, "How `core/`
//! reaches kernel memory").
//!
//! Slots live in CNodes and TCBs, and `Kernel::zero` clears untyped memory.
//! Before M7, which adds the IRQ node in kernel static memory, all of these
//! are RAM the kernel hands out after step 5: a `USABLE`, `LOADER` or
//! `ACPI_RECLAIMABLE` region, at or above 1 MiB (no untyped and no boot
//! region lies lower), below the direct map's end, and outside the holes the
//! kernel names: its own image, and a hypercall page the firmware locked.
//! [`ObjectMemory`] holds that set as sorted, disjoint ranges, computed once
//! at boot, so the kernel's debug assertion on each slot access is one binary
//! search.

use core::ops::Range;

use crate::handoff::{MemoryRegion, RegionKind};

/// The most memory-map entries [`ObjectMemory::new`] takes, as many as the
/// kernel copies from the handoff.
pub const MAX_REGIONS: usize = 256;
/// The most holes [`ObjectMemory::new`] takes. Each splits at most one range
/// in two.
pub const MAX_HOLES: usize = 4;
/// No kernel object lies below this address (`docs/design.md`, "What each
/// physical page becomes").
pub const LOW_MEMORY_END: u64 = 1 << 20;

const CAPACITY: usize = MAX_REGIONS + MAX_HOLES;

/// Whether memory of `kind` becomes RAM untyped once boot step 5 is over.
pub const fn holds_objects(kind: RegionKind) -> bool {
    matches!(
        kind,
        RegionKind::USABLE | RegionKind::LOADER | RegionKind::ACPI_RECLAIMABLE
    )
}

/// The physical memory kernel objects may occupy, as sorted, disjoint,
/// non-adjacent `[start, end)` ranges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectMemory {
    ranges: [(u64, u64); CAPACITY],
    len: usize,
}

impl ObjectMemory {
    /// The `USABLE`, `LOADER` and `ACPI_RECLAIMABLE` memory of `regions`,
    /// merged where regions touch or overlap, clipped to
    /// `[LOW_MEMORY_END, direct_map_end)`, without `holes`. `regions` need
    /// not be sorted. Panics with more than [`MAX_REGIONS`] regions or
    /// [`MAX_HOLES`] holes.
    pub fn new(regions: &[MemoryRegion], direct_map_end: u64, holes: &[Range<u64>]) -> Self {
        assert!(regions.len() <= MAX_REGIONS, "too many memory regions");
        assert!(holes.len() <= MAX_HOLES, "too many holes");
        let mut m = ObjectMemory {
            ranges: [(0, 0); CAPACITY],
            len: 0,
        };
        for r in regions.iter().filter(|r| holds_objects(r.kind)) {
            let start = r.base.max(LOW_MEMORY_END);
            let end = r.base.saturating_add(r.len).min(direct_map_end);
            if start < end {
                m.ranges[m.len] = (start, end);
                m.len += 1;
            }
        }
        m.ranges[..m.len].sort_unstable();
        m.merge();
        for h in holes {
            m.subtract(h.start, h.end);
        }
        m
    }

    /// The ranges, sorted by address.
    pub fn ranges(&self) -> &[(u64, u64)] {
        &self.ranges[..self.len]
    }

    /// Whether all of `[base, base + len)` lies inside one range; for
    /// `len` 0, whether `base` does.
    pub fn contains(&self, base: u64, len: u64) -> bool {
        let Some(end) = base.checked_add(len) else {
            return false;
        };
        let ranges = self.ranges();
        let i = ranges.partition_point(|&(_, e)| e <= base);
        ranges.get(i).is_some_and(|&(s, e)| s <= base && end <= e)
    }

    /// Joins sorted ranges that overlap or touch.
    fn merge(&mut self) {
        let mut out = 0;
        for i in 0..self.len {
            let (s, e) = self.ranges[i];
            if out > 0 && s <= self.ranges[out - 1].1 {
                let last = &mut self.ranges[out - 1].1;
                *last = (*last).max(e);
            } else {
                self.ranges[out] = (s, e);
                out += 1;
            }
        }
        self.len = out;
    }

    /// Removes `[start, end)` from every range.
    fn subtract(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let mut i = 0;
        while i < self.len {
            let (s, e) = self.ranges[i];
            if e <= start || end <= s {
                i += 1;
                continue;
            }
            match (s < start, end < e) {
                (true, true) => {
                    // Split: room for one more, since each hole adds one.
                    self.ranges.copy_within(i + 1..self.len, i + 2);
                    self.ranges[i] = (s, start);
                    self.ranges[i + 1] = (end, e);
                    self.len += 1;
                    i += 2;
                }
                (true, false) => {
                    self.ranges[i].1 = start;
                    i += 1;
                }
                (false, true) => {
                    self.ranges[i].0 = end;
                    i += 1;
                }
                (false, false) => {
                    self.ranges.copy_within(i + 1..self.len, i);
                    self.len -= 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::vec::Vec;

    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;

    fn region(base: u64, end: u64, kind: RegionKind) -> MemoryRegion {
        MemoryRegion::new(base, end - base, kind)
    }

    /// The memory map of the QEMU boot recorded for M4 (`test=hello`).
    fn qemu_map() -> Vec<MemoryRegion> {
        use RegionKind as K;
        [
            (0x0, 0xa0000, K::USABLE),
            (0x100000, 0x800000, K::USABLE),
            (0x800000, 0x808000, K::ACPI_NVS),
            (0x808000, 0x80b000, K::USABLE),
            (0x80b000, 0x80c000, K::ACPI_NVS),
            (0x80c000, 0x810000, K::USABLE),
            (0x810000, 0x900000, K::ACPI_NVS),
            (0x900000, 0xde9d000, K::USABLE),
            (0xde9d000, 0xe12b000, K::LOADER),
            (0xe12b000, 0xe133000, K::USABLE),
            (0xe133000, 0xe137000, K::LOADER),
            (0xe137000, 0xe3d1000, K::USABLE),
            (0xe3d1000, 0xe3d2000, K::LOADER),
            (0xe3d2000, 0xf010000, K::USABLE),
            (0xf010000, 0xf0d1000, K::FIRMWARE),
            (0xf0d1000, 0xf8ed000, K::USABLE),
            (0xf8ed000, 0xfaed000, K::FIRMWARE),
            (0xfaed000, 0xfb6d000, K::RESERVED),
            (0xfb6d000, 0xfb7f000, K::ACPI_RECLAIMABLE),
            (0xfb7f000, 0xfbff000, K::ACPI_NVS),
            (0xfbff000, 0xfef4000, K::USABLE),
            (0xfef4000, 0xff78000, K::FIRMWARE),
            (0xff78000, 0x10000000, K::ACPI_NVS),
            (0xe0000000, 0xf0000000, K::RESERVED),
            (0xfd00000000, 0x10000000000, K::RESERVED),
        ]
        .iter()
        .map(|&(b, e, k)| region(b, e, k))
        .collect()
    }

    /// The QEMU kernel image: 600 KiB at `0xdead000`.
    const QEMU_KERNEL: Range<u64> = 0xdead000..0xdead000 + 600 * 1024;

    #[test]
    fn qemu_map_ranges() {
        let m = ObjectMemory::new(&qemu_map(), 4 * GIB, &[QEMU_KERNEL]);
        assert_eq!(
            m.ranges(),
            &[
                (0x100000, 0x800000),
                (0x808000, 0x80b000),
                (0x80c000, 0x810000),
                // USABLE, then the LOADER and USABLE runs around the image.
                (0x900000, 0xdead000),
                (0xdf43000, 0xf010000),
                (0xf0d1000, 0xf8ed000),
                (0xfb6d000, 0xfb7f000),
                (0xfbff000, 0xfef4000),
            ]
        );
    }

    #[test]
    fn qemu_map_checks() {
        let m = ObjectMemory::new(&qemu_map(), 4 * GIB, &[QEMU_KERNEL]);
        // A slot, a page and a range across USABLE into LOADER.
        assert!(m.contains(0x200000, 32));
        assert!(m.contains(0x900000, 4096));
        assert!(m.contains(0xde9c000, 0x2000));
        // The kernel image, and ranges that reach into it.
        assert!(!m.contains(0xdead000, 32));
        assert!(!m.contains(0xdf42fe0, 32));
        assert!(!m.contains(0xdeac000, 0x2000));
        assert!(m.contains(0xdeacfe0, 32));
        assert!(m.contains(0xdf43000, 32));
        // Below 1 MiB, though USABLE.
        assert!(!m.contains(0x1000, 32));
        assert!(!m.contains(0xff000, 0x2000));
        // ACPI_NVS, FIRMWARE, RESERVED, a hole in the map, past RAM.
        assert!(!m.contains(0x800000, 32));
        assert!(!m.contains(0xf010000, 32));
        assert!(!m.contains(0xfaed000, 32));
        assert!(!m.contains(0xa0000, 32));
        assert!(!m.contains(0x10000000, 32));
        assert!(!m.contains(0xe0000000, 32));
        // ACPI_RECLAIMABLE is RAM after step 5.
        assert!(m.contains(0xfb6d000, 0x12000));
        // The last byte of a range, and one past it.
        assert!(m.contains(0xfef3fff, 1));
        assert!(!m.contains(0xfef3fff, 2));
        assert!(!m.contains(u64::MAX - 8, 32));
        // Zero length: the address alone.
        assert!(m.contains(0x200000, 0));
        assert!(!m.contains(0xdead000, 0));
    }

    #[test]
    fn the_direct_map_end_clips() {
        let map = [region(0, 6 * GIB, RegionKind::USABLE)];
        let m = ObjectMemory::new(&map, 4 * GIB, &[]);
        assert_eq!(m.ranges(), &[(MIB, 4 * GIB)]);
        assert!(m.contains(4 * GIB - 32, 32));
        assert!(!m.contains(4 * GIB - 32, 64));
        assert!(!m.contains(4 * GIB, 32));
        let m = ObjectMemory::new(&map, MIB, &[]);
        assert_eq!(m.ranges(), &[]);
        assert!(!m.contains(0, 0));
    }

    #[test]
    fn holes_split_trim_and_remove() {
        let map = [
            region(MIB, 2 * MIB, RegionKind::USABLE),
            region(4 * MIB, 5 * MIB, RegionKind::LOADER),
            region(6 * MIB, 7 * MIB, RegionKind::ACPI_RECLAIMABLE),
        ];
        let holes = [
            // A locked hypercall page inside the first range.
            0x10_0000 + 0x8000..0x10_0000 + 0x9000,
            // The whole second range and more.
            3 * MIB..5 * MIB + 0x1000,
            // The start of the third, and an empty hole.
            6 * MIB..6 * MIB + 0x1000,
            9 * MIB..9 * MIB,
        ];
        let m = ObjectMemory::new(&map, GIB, &holes);
        assert_eq!(
            m.ranges(),
            &[
                (MIB, MIB + 0x8000),
                (MIB + 0x9000, 2 * MIB),
                (6 * MIB + 0x1000, 7 * MIB),
            ]
        );
        assert!(!m.contains(MIB + 0x8fe0, 32));
        assert!(!m.contains(MIB + 0x7000, 0x2000));
    }

    #[test]
    fn unsorted_and_overlapping_regions_merge() {
        let map = [
            region(8 * MIB, 9 * MIB, RegionKind::USABLE),
            region(2 * MIB, 4 * MIB, RegionKind::LOADER),
            region(3 * MIB, 5 * MIB, RegionKind::USABLE),
            region(5 * MIB, 6 * MIB, RegionKind::ACPI_RECLAIMABLE),
            region(6 * MIB, 8 * MIB, RegionKind::ACPI_NVS),
            region(10 * MIB, 10 * MIB, RegionKind::USABLE),
        ];
        let m = ObjectMemory::new(&map, GIB, &[]);
        assert_eq!(m.ranges(), &[(2 * MIB, 6 * MIB), (8 * MIB, 9 * MIB)]);
        assert!(m.contains(2 * MIB, 4 * MIB));
    }

    #[test]
    fn full_capacity() {
        // 256 separate regions and four holes, each splitting one.
        let map: Vec<MemoryRegion> = (0..MAX_REGIONS as u64)
            .map(|i| region((2 + 2 * i) * MIB, (3 + 2 * i) * MIB, RegionKind::USABLE))
            .collect();
        let holes: Vec<Range<u64>> = (0..MAX_HOLES as u64)
            .map(|i| (2 + 2 * i) * MIB + 0x1000..(2 + 2 * i) * MIB + 0x2000)
            .collect();
        let m = ObjectMemory::new(&map, 64 * GIB, &holes);
        assert_eq!(m.ranges().len(), CAPACITY);
        assert!(m.ranges().windows(2).all(|w| w[0].1 < w[1].0));
        assert!(!m.contains(2 * MIB + 0x1000, 32));
        assert!(m.contains(513 * MIB - 32, 32));
    }

    /// The oracle: page by page, in pages of `PAGE` bytes.
    const PAGE: u64 = 0x1000;

    fn page_ok(map: &[MemoryRegion], end: u64, holes: &[Range<u64>], page: u64) -> bool {
        page >= LOW_MEMORY_END
            && page + PAGE <= end
            && map
                .iter()
                .any(|r| holds_objects(r.kind) && r.base <= page && page + PAGE <= r.end())
            && !holes.iter().any(|h| h.start < page + PAGE && page < h.end)
    }

    fn kind() -> impl Strategy<Value = RegionKind> {
        prop_oneof![
            Just(RegionKind::USABLE),
            Just(RegionKind::LOADER),
            Just(RegionKind::ACPI_RECLAIMABLE),
            Just(RegionKind::ACPI_NVS),
            Just(RegionKind::RESERVED),
        ]
    }

    fn config() -> ProptestConfig {
        ProptestConfig {
            cases: if cfg!(miri) { 4 } else { 256 },
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    proptest! {
        #![proptest_config(config())]

        /// Page-granular maps, holes and queries in the first 4 MiB:
        /// `contains` agrees with checking every page, and the ranges stay
        /// sorted, disjoint and non-adjacent. The map is laid out as
        /// firmware does, region after region with the odd gap, plus a few
        /// overlapping strays, in random order.
        #[test]
        fn agrees_with_page_by_page(
            first in 0u64..320,
            tiles in prop::collection::vec((1u64..64, prop_oneof![3 => Just(0u64), 1 => 1u64..4], kind()), 0..14),
            strays in prop::collection::vec((0u64..1024, 1u64..96, kind()), 0..3),
            order in any::<proptest::sample::Index>(),
            raw_holes in prop::collection::vec((0u64..1024, 0u64..16), 0..=MAX_HOLES),
            end_pages in 0u64..1100,
            queries in prop::collection::vec((0u64..1040, 0u64..40), 24),
        ) {
            let mut map = Vec::new();
            let mut page = first;
            for &(n, gap, k) in &tiles {
                map.push(MemoryRegion::new(page * PAGE, n * PAGE, k));
                page += n + gap;
            }
            for &(p, n, k) in &strays {
                map.push(MemoryRegion::new(p * PAGE, n * PAGE, k));
            }
            if !map.is_empty() {
                let at = order.index(map.len());
                map.rotate_left(at);
                map.swap(0, at);
            }
            let holes: Vec<Range<u64>> = raw_holes
                .iter()
                .map(|&(p, n)| p * PAGE..(p + n) * PAGE)
                .collect();
            let end = end_pages * PAGE;
            let m = ObjectMemory::new(&map, end, &holes);
            prop_assert!(m.ranges().iter().all(|&(s, e)| s < e));
            prop_assert!(m.ranges().windows(2).all(|w| w[0].1 < w[1].0));
            for &(p, n) in &queries {
                let expect = (p..p + n.max(1)).all(|q| page_ok(&map, end, &holes, q * PAGE));
                prop_assert_eq!(m.contains(p * PAGE, n * PAGE), expect, "pages {}+{}", p, n);
            }
        }
    }
}
