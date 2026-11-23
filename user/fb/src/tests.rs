//! `fb`'s rules (`docs/design.md`, "`fb`" and "Code and tests"): each row
//! of the checks, in order; QEMU's and Hyper-V's recorded framebuffers
//! (Hyper-V's with GOP sizes of 3, 4 and 8 MiB) and their plans; a base
//! not aligned to 2 MiB; untyped that do not tile; both pixel formats; the
//! surface's bounds; and random tilings against the plan's invariants.

use std::format;
use std::string::ToString;
use std::vec;
use std::vec::Vec;

use super::*;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

/// The power-of-two chunks the kernel cuts a span into (`l4core::boot`'s
/// `chunks`): at each address the largest aligned size that fits.
fn chunks(start: u64, end: u64) -> Vec<Untyped> {
    let mut at = start;
    let mut out = Vec::new();
    while at < end {
        let bits = (end - at).ilog2().min(at.trailing_zeros()).min(47);
        out.push(Untyped::new(at, bits as u8, true));
        at += 1 << bits;
    }
    out
}

/// A framebuffer whose GOP size is its visible bytes, with the kernel's
/// untyped for it.
fn gop(base: u64, size: u64, width: u32, height: u32, stride: u32) -> (Fields, Vec<Untyped>) {
    let f = Fields {
        base,
        size,
        width,
        height,
        stride,
        format: 2,
    };
    let untyped = chunks(round_down(base, PAGE), round_up(base + size, PAGE).unwrap());
    (f, untyped)
}

/// QEMU's OVMF: 1280x800, stride 1280, BGR at 0x80000000
/// (`core/tests/boot/q35.memmap`, and the harness builder's 1280x800 from
/// the std VGA's EDID).
fn qemu() -> (Fields, Vec<Untyped>) {
    gop(0x8000_0000, 4 * 1280 * 800, 1280, 800, 1280)
}

/// Hyper-V: 1024x768, stride 1024, BGR at 0xF8000000 (the M0 Hyper-V
/// check), with a GOP size of `size`.
fn hyperv(size: u64) -> (Fields, Vec<Untyped>) {
    gop(0xF800_0000, size, 1024, 768, 1024)
}

fn plan_of((f, u): &(Fields, Vec<Untyped>)) -> Plan<'_> {
    Plan::new(f, u).unwrap()
}

// The checks, row by row.

#[test]
fn no_format_or_no_base_is_no_framebuffer() {
    let (f, u) = qemu();
    for bad in [
        Fields { format: 0, ..f },
        Fields { base: 0, ..f },
        Fields::default(),
    ] {
        assert_eq!(Geometry::check(&bad, &u), Err(Unusable::None));
        // First in the order: whatever else is wrong.
        let worse = Fields {
            width: 1,
            stride: 0,
            ..bad
        };
        assert_eq!(Geometry::check(&worse, &[]), Err(Unusable::None));
    }
    assert_eq!(
        Unusable::None.to_string(),
        "the loader found no GOP framebuffer"
    );
}

#[test]
fn no_untyped_is_a_framebuffer_the_kernel_kept() {
    let (f, _) = qemu();
    assert_eq!(Geometry::check(&f, &[]), Err(Unusable::NotHandedOut));
    let small = Fields { format: 7, ..f };
    assert_eq!(Geometry::check(&small, &[]), Err(Unusable::NotHandedOut));
    assert_eq!(
        Unusable::NotHandedOut.to_string(),
        "the kernel kept it (see its boot summary)"
    );
}

#[test]
fn only_rgb_and_bgr_are_formats() {
    let (f, u) = qemu();
    for n in [3, 4, 0xFFFF_FFFF] {
        let bad = Fields {
            format: n,
            width: 1,
            ..f
        };
        assert_eq!(Geometry::check(&bad, &u), Err(Unusable::Format(n)));
    }
    assert_eq!(
        Unusable::Format(3).to_string(),
        "pixel format 3, neither RGB (1) nor BGR (2)"
    );
    let rgb = Fields { format: 1, ..f };
    assert_eq!(Geometry::check(&rgb, &u).unwrap().format(), Format::Rgb);
    assert_eq!(Geometry::check(&f, &u).unwrap().format(), Format::Bgr);
}

#[test]
fn below_640_by_384_is_too_small() {
    let (f, u) = qemu();
    for (w, h) in [(639, 800), (1280, 383), (0, 0), (639, 383)] {
        let bad = Fields {
            width: w,
            height: h,
            stride: 0,
            ..f
        };
        assert_eq!(
            Geometry::check(&bad, &u),
            Err(Unusable::TooSmall {
                width: w,
                height: h
            })
        );
    }
    // 640 x 384 exactly is 80 x 24 cells.
    let (f, u) = gop(0x8000_0000, 4 * 640 * 384, 640, 384, 640);
    let g = Geometry::check(&f, &u).unwrap();
    assert_eq!(g.cells(), (80, 24));
    assert_eq!(
        Unusable::TooSmall {
            width: 639,
            height: 400
        }
        .to_string(),
        "639x400, below 640x384"
    );
}

#[test]
fn a_stride_alignment_or_size_that_does_not_hold_the_pixels_is_bad_geometry() {
    let (f, u) = qemu();
    let bad = [
        Fields { stride: 1279, ..f },
        Fields {
            base: f.base + 2,
            ..f
        },
        Fields {
            size: f.size - 1,
            ..f
        },
        Fields { stride: 1281, ..f },
        Fields {
            base: u64::MAX - 3,
            ..f
        },
    ];
    for b in bad {
        assert_eq!(Geometry::check(&b, &u), Err(Unusable::Geometry(b)), "{b:?}");
    }
    // Before the untyped are looked at.
    assert_eq!(
        Geometry::check(&bad[0], &[Untyped::default()]),
        Err(Unusable::Geometry(bad[0]))
    );
    let s = Unusable::Geometry(bad[0]).to_string();
    assert!(
        s.starts_with("1280x800, stride 1279, 0x3e8000 bytes at 0x80000000: "),
        "{s}"
    );
    // A stride wider than the width, with the size for it, is fine.
    let (f, u) = gop(0x8000_0000, 4 * 1344 * 800, 1280, 800, 1344);
    assert_eq!(Geometry::check(&f, &u).unwrap().stride(), 1344);
}

#[test]
fn untyped_must_be_device_memory_tiling_the_framebuffer_in_order() {
    let (f, u) = qemu();
    let n = u.len();
    assert_eq!(n, 6);
    let err = |index, expected| {
        Err(Unusable::Untyped {
            index,
            count: n,
            expected,
        })
    };
    // Not device memory.
    let mut v = u.clone();
    v[2].device = false;
    assert_eq!(Geometry::check(&f, &v), err(2, v[2].paddr));
    // Out of order.
    let mut v = u.clone();
    v.swap(1, 2);
    assert_eq!(Geometry::check(&f, &v), err(1, u[1].paddr));
    // A gap: one missing in the middle.
    let mut v = u.clone();
    v.remove(3);
    assert_eq!(
        Geometry::check(&f, &v),
        Err(Unusable::Untyped {
            index: 3,
            count: n - 1,
            expected: u[3].paddr
        })
    );
    // Short: the last missing.
    let v = &u[..n - 1];
    assert_eq!(
        Geometry::check(&f, v),
        Err(Unusable::Untyped {
            index: n - 1,
            count: n - 1,
            expected: u[n - 1].paddr
        })
    );
    // Past the end: one more, or the last too large.
    let mut v = u.clone();
    v.push(Untyped::new(u[n - 1].paddr + u[n - 1].size(), 12, true));
    assert_eq!(
        Geometry::check(&f, &v),
        Err(Unusable::Untyped {
            index: n,
            count: n + 1,
            expected: v[n].paddr
        })
    );
    let mut v = u.clone();
    v[n - 1].size_bits += 1;
    assert_eq!(Geometry::check(&f, &v), err(n - 1, u[n - 1].paddr));
    // Starting late, or early.
    let mut v = u.clone();
    v[0] = Untyped::new(0x8000_1000, 12, true);
    assert_eq!(Geometry::check(&f, &v), err(0, 0x8000_0000));
    // Not aligned to its size, though it would tile.
    let (f2, _) = gop(0x8000_1000, 4 * 640 * 384, 640, 384, 640);
    let mut misaligned = vec![Untyped::new(0x8000_1000, 13, true)];
    misaligned.extend(chunks(
        0x8000_3000,
        round_up(f2.base + f2.size, PAGE).unwrap(),
    ));
    assert_eq!(
        Geometry::check(&f2, &misaligned),
        Err(Unusable::Untyped {
            index: 0,
            count: misaligned.len(),
            expected: 0x8000_1000
        })
    );
    // Sizes no untyped has.
    for bits in [0, 11, 64, 255] {
        let mut v = u.clone();
        v[0].size_bits = bits;
        assert_eq!(Geometry::check(&f, &v), err(0, u[0].paddr), "{bits}");
    }
    assert_eq!(
        Unusable::Untyped {
            index: 2,
            count: 6,
            expected: 0x8030_0000
        }
        .to_string(),
        "framebuffer untyped 2 of 6 is not the device untyped at 0x80300000 that the tiling needs"
    );
    assert_eq!(
        Unusable::Untyped {
            index: 5,
            count: 5,
            expected: 0x803e_0000
        }
        .to_string(),
        "the 5 framebuffer untyped end at 0x803e0000, before its last page"
    );
}

#[test]
fn a_window_past_one_gib_is_too_large() {
    // 0x3000_0000 bytes of window: 768 MiB. 12288 x 16384 x 4 = 768 MiB.
    let (f, u) = gop(0x1_0000_0000, 768 * MIB, 12288, 16384, 12288);
    let p = Plan::new(&f, &u).unwrap();
    assert_eq!(p.geometry().window_bytes(), Some(768 * MIB));
    assert_eq!(p.window_end(), WINDOW_END);
    // One more scan line passes it.
    let (f, u) = gop(0x1_0000_0000, 4 * 12288 * 16385, 12288, 16385, 12288);
    assert_eq!(
        Geometry::check(&f, &u),
        Err(Unusable::TooLarge {
            bytes: 768 * MIB + 2 * MIB
        })
    );
    // So does the same size, offset in its 2 MiB page.
    let (f, u) = gop(0x1_0000_1000, 768 * MIB, 12288, 16384, 12288);
    assert_eq!(
        Geometry::check(&f, &u),
        Err(Unusable::TooLarge {
            bytes: 768 * MIB + 2 * MIB
        })
    );
    assert_eq!(
        Unusable::TooLarge { bytes: 770 * MIB }.to_string(),
        "a 788480 KiB window from 0x10000000 would pass 0x40000000"
    );
}

// The recorded framebuffers.

#[test]
fn qemu_s_framebuffer_is_one_2mib_and_488_4kib_frames_under_one_page_table() {
    let q = qemu();
    let p = plan_of(&q);
    let g = p.geometry();
    assert_eq!((g.width(), g.height(), g.stride()), (1280, 800, 1280));
    assert_eq!(
        (g.format(), g.offset(), g.cells()),
        (Format::Bgr, 0, (160, 50))
    );
    assert_eq!(g.visible_bytes(), 4000 * KIB);
    assert_eq!(g.pixels(), 1280 * 800);
    assert_eq!(
        q.1.iter().map(|u| u.size_bits).collect::<Vec<_>>(),
        [21, 20, 19, 18, 17, 15]
    );
    assert_eq!((p.huge_frames(), p.small_frames()), (1, 488));
    assert_eq!(p.frames().count(), 489);
    assert_eq!(p.page_tables().collect::<Vec<_>>(), [WINDOW + 2 * MIB]);
    let r: Vec<Retype> = p.retypes().collect();
    let shape: Vec<(usize, u32, usize)> = r
        .iter()
        .map(|r| (r.untyped, r.size_bits, r.count))
        .collect();
    assert_eq!(
        shape,
        [
            (0, 21, 1),
            (1, 12, 256),
            (2, 12, 128),
            (3, 12, 64),
            (4, 12, 32),
            (5, 12, 8)
        ]
    );
    assert_eq!((r[0].paddr, r[0].vaddr), (0x8000_0000, WINDOW));
    assert_eq!((r[1].paddr, r[1].vaddr), (0x8020_0000, WINDOW + 2 * MIB));
    assert_eq!(r[5].frame(7).vaddr, WINDOW + 4000 * KIB - PAGE);
    assert_eq!(p.window_end(), WINDOW + 4000 * KIB);
    assert_eq!(g.window_bytes(), Some(4 * MIB));
    assert_eq!(
        format!("fb: {p}; {}x{} cells", g.cells().0, g.cells().1),
        "fb: 1280x800 BGR, stride 1280, 4000 KiB at 0x80000000: 6 untyped, 1 2 MiB and 488 4 KiB frames; 160x50 cells"
    );
}

#[test]
fn hyper_v_s_framebuffer_at_each_gop_size() {
    // 3 MiB, the visible bytes: two untyped, so one 2 MiB frame and 256
    // 4 KiB frames under one page table.
    let h = hyperv(3 * MIB);
    let p = plan_of(&h);
    assert_eq!(h.1.len(), 2);
    assert_eq!((p.huge_frames(), p.small_frames()), (1, 256));
    assert_eq!(p.page_tables().collect::<Vec<_>>(), [WINDOW + 2 * MIB]);
    assert_eq!(p.geometry().cells(), (128, 48));
    assert_eq!(
        p.to_string(),
        "1024x768 BGR, stride 1024, 3072 KiB at 0xf8000000: 2 untyped, 1 2 MiB and 256 4 KiB frames"
    );
    // 4 and 8 MiB: one untyped, as the M5 Hyper-V check's log shows; two
    // 2 MiB frames and no page table.
    for (size, kib) in [(4 * MIB, 4096), (8 * MIB, 8192)] {
        let h = hyperv(size);
        let p = plan_of(&h);
        assert_eq!(h.1.len(), 1);
        assert_eq!((p.huge_frames(), p.small_frames()), (2, 0));
        assert_eq!(p.page_tables().count(), 0);
        let r: Vec<Retype> = p.retypes().collect();
        assert_eq!(
            r,
            [Retype {
                untyped: 0,
                size_bits: 21,
                count: 2,
                paddr: 0xF800_0000,
                vaddr: WINDOW
            }]
        );
        assert_eq!(p.window_end(), WINDOW + 4 * MIB);
        assert_eq!(
            p.to_string(),
            format!(
                "1024x768 BGR, stride 1024, {kib} KiB at 0xf8000000: 1 untyped, 2 2 MiB and 0 4 KiB frames"
            )
        );
    }
}

#[test]
fn a_base_not_aligned_to_2mib_keeps_addresses_equal_modulo_2mib() {
    let q = gop(0x8010_0000, 4000 * KIB, 1280, 800, 1280);
    let p = plan_of(&q);
    let g = p.geometry();
    assert_eq!(g.offset(), MIB);
    assert_eq!(g.window_bytes(), Some(6 * MIB));
    let r: Vec<(u32, usize, u64)> = p
        .retypes()
        .map(|r| (r.size_bits, r.count, r.vaddr))
        .collect();
    assert_eq!(
        r,
        [
            (12, 256, WINDOW + MIB),
            (21, 1, WINDOW + 2 * MIB),
            (12, 128, WINDOW + 4 * MIB),
            (12, 64, WINDOW + 4 * MIB + 512 * KIB),
            (12, 32, WINDOW + 4 * MIB + 768 * KIB),
            (12, 8, WINDOW + 4 * MIB + 896 * KIB),
        ]
    );
    assert_eq!(
        p.page_tables().collect::<Vec<_>>(),
        [WINDOW, WINDOW + 4 * MIB]
    );
    for f in p.frames() {
        assert_eq!(f.vaddr % HUGE, f.paddr % HUGE);
    }
    // The first pixel at WINDOW + base mod 2 MiB, on a frame's first byte.
    assert_eq!(p.frames().next().unwrap().vaddr, WINDOW + g.offset());
    // A base inside a page: the frames start at its page.
    let q = gop(0x8000_0040, 4000 * KIB, 1280, 800, 1280);
    let p = plan_of(&q);
    assert_eq!(p.geometry().offset(), 0x40);
    let first = p.frames().next().unwrap();
    assert_eq!((first.paddr, first.vaddr), (0x8000_0000, WINDOW));
    let last = p.frames().last().unwrap();
    assert!(last.paddr + PAGE >= 0x8000_0040 + 4000 * KIB);
    assert_eq!((p.huge_frames(), p.small_frames()), (1, 489));
}

#[test]
fn frames_stop_once_the_visible_bytes_are_covered() {
    // A GOP size well past the visible bytes, as on Hyper-V: the untyped
    // past them give nothing, and the plan lists every untyped.
    let (mut f, _) = qemu();
    f.size = 16 * MIB;
    let u = chunks(f.base, f.base + f.size);
    assert_eq!(u.len(), 1);
    let p = Plan::new(&f, &u).unwrap();
    assert_eq!((p.huge_frames(), p.small_frames()), (2, 0));
    // A 4 MiB untyped, then twelve of 1 MiB past the end.
    let mut u = chunks(f.base, f.base + 4 * MIB);
    u.extend((4..16).map(|i| Untyped::new(f.base + i * MIB, 20, true)));
    let p = Plan::new(&f, &u).unwrap();
    assert_eq!((p.huge_frames(), p.small_frames()), (2, 0));
    assert!(p.retypes().all(|r| r.untyped == 0));
    assert_eq!(p.page_tables().count(), 0);
    assert_eq!(
        p.to_string().split(": ").nth(1),
        Some("13 untyped, 2 2 MiB and 0 4 KiB frames")
    );
}

#[test]
fn retypes_stay_within_the_fan_out_limit() {
    // 640 x 384 in 4 KiB untyped: 240 small untyped, one retype each.
    let (f, _) = gop(0x8000_0000, 4 * 640 * 384, 640, 384, 640);
    let u: Vec<Untyped> = (0..240)
        .map(|i| Untyped::new(0x8000_0000 + i * PAGE, 12, true))
        .collect();
    let p = Plan::new(&f, &u).unwrap();
    assert_eq!(p.retypes().count(), 240);
    assert_eq!(p.page_tables().count(), 1);
    // 600 MiB in one untyped: 300 2 MiB frames in two retypes.
    let (mut f, _) = gop(0x1_0000_0000, 600 * MIB, 10240, 15360, 10240);
    f.size = 1024 * MIB;
    let u = [Untyped::new(0x1_0000_0000, 30, true)];
    let p = Plan::new(&f, &u).unwrap();
    let r: Vec<Retype> = p.retypes().collect();
    assert_eq!(r.iter().map(|r| r.count).collect::<Vec<_>>(), [256, 44]);
    assert_eq!(r[1].paddr, 0x1_0000_0000 + 256 * HUGE);
    assert_eq!(r[1].vaddr, WINDOW + 256 * HUGE);
    assert_eq!(p.huge_frames(), 300);
}

/// A small generator: xorshift, seeded.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A random tiling of `[start, end)` by power-of-two untyped, each aligned
/// to its size, some split smaller than the kernel would.
fn random_tiling(rng: &mut Rng, start: u64, end: u64) -> Vec<Untyped> {
    let mut out = Vec::new();
    for c in chunks(start, end) {
        let mut stack = vec![c];
        while let Some(u) = stack.pop() {
            if u.size_bits > 12 && rng.below(4) == 0 {
                let half = u.size_bits - 1;
                stack.push(Untyped::new(u.paddr + (1 << half), half, true));
                stack.push(Untyped::new(u.paddr, half, true));
            } else {
                out.push(u);
            }
        }
    }
    out
}

/// The plan's invariants for random modes, bases and tilings: its frames
/// cover the visible bytes from the first page on, in order, without
/// overlap; each lies inside its untyped, aligned to its size; virtual and
/// physical addresses agree modulo 2 MiB; the page tables are exactly the
/// 2 MiB stretches holding 4 KiB frames; and everything lies in the window.
#[test]
fn random_tilings_keep_the_plan_s_invariants() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let cases = if cfg!(miri) { 8 } else { 600 };
    for case in 0..cases {
        let width = 640 + rng.below(1400) as u32;
        let stride = width + rng.below(3) as u32 * rng.below(64) as u32;
        let height = 384 + rng.below(1000) as u32;
        let base = 0x8000_0000 + 4 * rng.below(1 << 20);
        let visible = 4 * u64::from(stride) * u64::from(height);
        let size = visible + 4 * rng.below(3) * rng.below(1 << 20);
        let f = Fields {
            base,
            size,
            width,
            height,
            stride,
            format: 1 + rng.below(2) as u32,
        };
        let start = round_down(base, PAGE);
        let end = round_up(base + size, PAGE).unwrap();
        let u = random_tiling(&mut rng, start, end);
        let p = Plan::new(&f, &u).unwrap_or_else(|e| panic!("case {case}: {e}"));
        let window_base = round_down(base, HUGE);
        let mut at = start;
        let mut tables = Vec::new();
        let mut frames = 0;
        for r in p.retypes() {
            assert!((1..=RETYPE_FAN_OUT_LIMIT).contains(&r.count), "case {case}");
            let ut = u[r.untyped];
            for i in 0..r.count {
                let fr = r.frame(i);
                frames += 1;
                let size = 1u64 << fr.size_bits;
                assert_eq!(fr.paddr, at, "case {case}: in order, no gap");
                assert!(fr.paddr >= ut.paddr && fr.paddr + size <= ut.paddr + ut.size());
                assert_eq!(fr.paddr % size, 0);
                assert_eq!(fr.vaddr % size, 0);
                assert_eq!(fr.vaddr % HUGE, fr.paddr % HUGE);
                assert_eq!(fr.vaddr, WINDOW + fr.paddr - window_base);
                assert!(fr.vaddr + size <= WINDOW_END);
                if fr.size_bits == PAGE_BITS {
                    let t = round_down(fr.vaddr, HUGE);
                    if tables.last() != Some(&t) {
                        tables.push(t);
                    }
                } else {
                    assert_eq!(fr.size_bits, HUGE_BITS);
                }
                at += size;
            }
        }
        assert!(at >= base + visible, "case {case}: covered");
        assert!(at - (base + visible) < HUGE, "case {case}: and no further");
        assert_eq!(p.page_tables().collect::<Vec<_>>(), tables, "case {case}");
        assert_eq!(p.huge_frames() + p.small_frames(), frames);
        assert_eq!(p.window_end(), WINDOW + at - window_base);
        assert!(p.window_end() <= WINDOW + p.geometry().window_bytes().unwrap());
        // The words term gets give the same geometry.
        assert_eq!(
            Geometry::from_words(p.geometry().to_words()),
            Some(p.geometry())
        );
    }
}

// The words.

#[test]
fn the_words_round_trip_and_are_checked_again() {
    let q = qemu();
    let g = plan_of(&q).geometry();
    let w = g.to_words();
    assert_eq!(w, [1280 | 800 << 32, 1280 | 2 << 32, 0]);
    assert_eq!(Geometry::from_words(w), Some(g));
    let off = gop(0x8010_0010, 4000 * KIB, 1280, 800, 1280);
    let g2 = plan_of(&off).geometry();
    assert_eq!(g2.to_words()[2], MIB + 0x10);
    assert_eq!(Geometry::from_words(g2.to_words()), Some(g2));
    for bad in [
        [w[0], 1280 | 3 << 32, 0],
        [w[0], 1280, 0],
        [639 | 800 << 32, w[1], 0],
        [1280 | 383 << 32, w[1], 0],
        [w[0], 1279 | 2 << 32, 0],
        [w[0], w[1], 2],
        [w[0], w[1], HUGE],
        [12288 | 16385 << 32, 12288 | 2 << 32, 0],
        [u64::MAX, u64::MAX, u64::MAX],
    ] {
        assert_eq!(Geometry::from_words(bad), None, "{bad:x?}");
    }
}

// Pixel formats.

#[test]
fn both_pixel_formats() {
    let c = Rgb::new(0x12, 0x34, 0x56);
    assert_eq!(c, Rgb(0x123456));
    assert_eq!((c.r(), c.g(), c.b()), (0x12, 0x34, 0x56));
    // RGB: byte 0 red; BGR: byte 0 blue; byte 3 zero.
    assert_eq!(Format::Rgb.pixel(c).to_le_bytes(), [0x12, 0x34, 0x56, 0]);
    assert_eq!(Format::Bgr.pixel(c).to_le_bytes(), [0x56, 0x34, 0x12, 0]);
    for fmt in [Format::Rgb, Format::Bgr] {
        assert_eq!(fmt.colour(fmt.pixel(c)), c);
        assert_eq!(fmt.colour(fmt.pixel(c) | 0xFF00_0000), c);
        assert_eq!(Format::from_number(fmt.number()), Some(fmt));
    }
    assert_eq!(Format::from_number(0), None);
    assert_eq!(Format::from_number(3), None);
    assert_eq!(
        (Format::Rgb.to_string(), Format::Bgr.to_string()),
        ("RGB".into(), "BGR".into())
    );
}

// The surface.

const PAD: u32 = 0xDEAD_BEEF;

/// A surface of `w x h` in a `stride`-wide buffer, with one scan line of
/// sentinels past it, and the buffer.
fn buffer(w: u32, h: u32, stride: u32) -> (Geometry, Vec<u32>) {
    let g = Geometry::new(w, h, stride, Format::Bgr).unwrap();
    (g, vec![PAD; (stride * (h + 1)) as usize])
}

/// Every pixel outside the visible `w x h` is still a sentinel.
fn padding_untouched(px: &[u32], w: u32, h: u32, stride: u32) {
    for (i, &p) in px.iter().enumerate() {
        let (x, y) = (i as u32 % stride, i as u32 / stride);
        if x >= w || y >= h {
            assert_eq!(p, PAD, "pixel ({x}, {y}) is padding");
        }
    }
}

#[test]
fn fill_writes_every_visible_pixel_and_no_padding() {
    let (g, mut px) = buffer(21, 5, 24);
    let mut s = Surface::new(g, &mut px).unwrap();
    s.fill(Rgb(0xAAAAAA));
    assert_eq!(s.geometry(), g);
    padding_untouched(&px, 21, 5, 24);
    for y in 0..5 {
        for x in 0..21 {
            assert_eq!(px[(y * 24 + x) as usize], 0x00AAAAAA);
        }
    }
}

#[test]
fn a_cell_is_its_glyph_in_two_colours() {
    let (g, mut px) = buffer(16, 32, 16);
    let mut s = Surface::new(g, &mut px).unwrap();
    let mut glyph = [0u8; 16];
    glyph[0] = 0x80;
    glyph[1] = 0x01;
    glyph[15] = 0xFF;
    let (fg, bg) = (Rgb(0xFF0000), Rgb(0x0000FF));
    s.cell(1, 1, &glyph, fg, bg);
    let at = |x: u32, y: u32| Format::Bgr.colour(px[(y * 16 + x) as usize]);
    assert_eq!(at(8, 16), fg, "bit 7 is the leftmost pixel");
    assert_eq!(at(9, 16), bg);
    assert_eq!(at(15, 17), fg, "bit 0 the rightmost");
    assert_eq!(at(14, 17), bg);
    assert!((8..16).all(|x| at(x, 31) == fg), "row 15 the bottom");
    // Nothing outside the cell.
    for y in 0..33 {
        for x in 0..16 {
            if !(8..16).contains(&x) || !(16..32).contains(&y) {
                assert_eq!(px[(y * 16 + x) as usize], PAD, "({x}, {y})");
            }
        }
    }
}

#[test]
fn cells_are_cut_at_the_right_and_bottom_edges() {
    // 21 x 21 pixels in a 24-wide buffer: column 2 has 5 visible pixels
    // and row 1 five visible lines.
    let (g, mut px) = buffer(21, 21, 24);
    let mut s = Surface::new(g, &mut px).unwrap();
    let full = [0xFF; 16];
    for row in 0..4 {
        for col in 0..5 {
            s.cell(col, row, &full, Rgb(0x010203), Rgb(0));
        }
    }
    s.cell(u32::MAX, u32::MAX, &full, Rgb(0x010203), Rgb(0));
    padding_untouched(&px, 21, 21, 24);
    assert!(
        px.iter()
            .enumerate()
            .filter(|&(i, _)| (i % 24) < 21 && i / 24 < 21)
            .all(|(_, &p)| p == 0x010203)
    );
}

#[test]
fn a_surface_needs_its_pixels() {
    let (g, mut px) = buffer(10, 10, 12);
    assert!(Surface::new(g, &mut px[..119]).is_none());
    assert!(Surface::new(g, &mut px[..120]).is_some());
    // A host geometry needs a stride of at least its width and a window
    // that fits.
    assert!(Geometry::new(10, 10, 9, Format::Rgb).is_none());
    assert!(Geometry::new(0, 10, 9, Format::Rgb).is_none());
    assert!(Geometry::new(1, 1, 1, Format::Rgb).is_some());
    assert!(Geometry::new(16384, 16384, 16384, Format::Rgb).is_none());
}

/// The recorded QEMU surface, full size: the last cell ends at the last
/// pixel.
#[test]
#[cfg_attr(miri, ignore = "a million pixels")]
fn qemu_s_surface_full_size() {
    let q = qemu();
    let g = plan_of(&q).geometry();
    let mut px = vec![PAD; g.pixels()];
    let mut s = Surface::new(g, &mut px).unwrap();
    s.fill(Rgb(0));
    s.cell(159, 49, &[0xFF; 16], Rgb(0xFFFFFF), Rgb(0));
    s.cell(160, 49, &[0xFF; 16], Rgb(0xFFFFFF), Rgb(0));
    assert_eq!(px[1280 * 800 - 1], 0xFFFFFF);
    assert_eq!(px[1280 * 784 + 1272], 0xFFFFFF);
    assert_eq!(px[1280 * 784 + 1271], 0);
}
