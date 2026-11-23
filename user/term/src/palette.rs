//! The 256 colours (`docs/design.md`, "The screen model"): 0 to 15 the VGA
//! text palette, 16 to 231 xterm's 6 × 6 × 6 cube, 232 to 255 its grey
//! ramp; the two defaults, kept apart from 7 and 0; and the mapping of a
//! true colour to the nearest entry from 16 up.
//!
//! A colour here is `0xRRGGBB`; the renderer converts it to the
//! framebuffer's pixel format.

/// The default foreground, the same as colour 7 but kept apart.
pub const DEFAULT_FG: u32 = 0xAA_AAAA;
/// The default background, the same as colour 0 but kept apart.
pub const DEFAULT_BG: u32 = 0x00_0000;

/// Colours 0 to 15.
pub const VGA: [u32; 16] = [
    0x00_0000, 0xAA_0000, 0x00_AA00, 0xAA_5500, 0x00_00AA, 0xAA_00AA, 0x00_AAAA, 0xAA_AAAA,
    0x55_5555, 0xFF_5555, 0x55_FF55, 0xFF_FF55, 0x55_55FF, 0xFF_55FF, 0x55_FFFF, 0xFF_FFFF,
];

/// The cube's six levels per channel.
pub const LEVELS: [u8; 6] = [0x00, 0x5F, 0x87, 0xAF, 0xD7, 0xFF];

/// Colour `index`'s red, green and blue as `0xRRGGBB`.
pub const fn rgb(index: u8) -> u32 {
    let i = index as usize;
    if i < 16 {
        VGA[i]
    } else if i < 232 {
        let c = i - 16;
        let r = LEVELS[c / 36] as u32;
        let g = LEVELS[c / 6 % 6] as u32;
        let b = LEVELS[c % 6] as u32;
        r << 16 | g << 8 | b
    } else {
        let v = grey(i - 232);
        v << 16 | v << 8 | v
    }
}

/// The grey ramp's level `i`, 0 to 23.
const fn grey(i: usize) -> u32 {
    8 + 10 * i as u32
}

/// The cube level nearest `v`, ties to the lower.
const fn nearest_level(v: u8) -> usize {
    let mut best = 0;
    let mut i = 1;
    while i < LEVELS.len() {
        if LEVELS[i].abs_diff(v) < LEVELS[best].abs_diff(v) {
            best = i;
        }
        i += 1;
    }
    best
}

const fn distance(a: [u32; 3], b: [u32; 3]) -> u32 {
    let mut d = 0;
    let mut i = 0;
    while i < 3 {
        let x = a[i].abs_diff(b[i]);
        d += x * x;
        i += 1;
    }
    d
}

/// The palette entry from 16 up nearest the true colour `(r, g, b)`: the
/// cube's (per channel the nearest level, ties to the lower) or the grey
/// ramp's (the level nearest the channels' mean, ties to the lower),
/// whichever is nearer by squared distance, the cube on a tie.
pub const fn nearest(r: u8, g: u8, b: u8) -> u8 {
    let (ri, gi, bi) = (nearest_level(r), nearest_level(g), nearest_level(b));
    let cube = [LEVELS[ri] as u32, LEVELS[gi] as u32, LEVELS[bi] as u32];
    // The mean is (r + g + b) / 3; compare 3 × level with the sum so that
    // a tie is exact.
    let sum = r as u32 + g as u32 + b as u32;
    let mut gi_best = 0;
    let mut i = 1;
    while i < 24 {
        if (3 * grey(i)).abs_diff(sum) < (3 * grey(gi_best)).abs_diff(sum) {
            gi_best = i;
        }
        i += 1;
    }
    let v = grey(gi_best);
    let me = [r as u32, g as u32, b as u32];
    if distance(me, cube) <= distance(me, [v, v, v]) {
        (16 + 36 * ri + 6 * gi + bi) as u8
    } else {
        (232 + gi_best) as u8
    }
}
