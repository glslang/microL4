//! The font's tests (`docs/design.md`, "Code and tests"): every code point
//! of its table, and every other one drawing the replacement glyph; the
//! arms of every box glyph at the edge columns and rows, against arms
//! parsed from its Unicode name rather than the font's own table; the
//! double corners and junctions, a heavy corner, the joins of single and
//! double lines, the diagonals, the diamond and the replacement glyph
//! against hand-drawn cells; the dashes, block elements and scan lines by
//! their rules; and a checksum of the Spleen table against its header.

use std::string::String;
use std::vec;
use std::vec::Vec;

use crate::font::spleen;
use crate::font::{
    BOX_SHAPES, COUNT, D, DOWN, GLYPHS, Glyph, H, L, LEFT, N, REPLACEMENT, RIGHT, SPACE, Shape, UP,
    bitmap, code_point, glyph,
};

/// `g` as 16 rows of `#` and `.`.
fn picture(g: &Glyph) -> Vec<String> {
    g.iter()
        .map(|r| {
            (0..8)
                .map(|x| if r & (0x80 >> x) != 0 { '#' } else { '.' })
                .collect()
        })
        .collect()
}

/// Checks each glyph of `chars` against its column of `rows`, a picture of
/// the glyphs side by side, one space apart.
fn check_pictures(chars: &str, rows: [&str; 16]) {
    for (i, c) in chars.chars().enumerate() {
        let want: Vec<String> = rows
            .iter()
            .map(|r| r.split(' ').nth(i).unwrap().into())
            .collect();
        let got = picture(bitmap(glyph(c)));
        assert_eq!(got, want, "U+{:04X} {c}", c as u32);
    }
}

/// The rows lit in column `x`.
fn column(g: &Glyph, x: usize) -> Vec<usize> {
    (0..16).filter(|&y| g[y] & (0x80 >> x) != 0).collect()
}

/// The shape a box-drawing name describes: each part between `AND`s gives
/// its directions its weight, or, if it names none, the other part's.
fn shape_from_name(name: &str) -> Shape {
    let mut arms = [N; 4];
    if name.contains("DIAGONAL") {
        let diagonals = if name.contains("CROSS") {
            3
        } else if name.contains("UPPER RIGHT TO LOWER LEFT") {
            1
        } else {
            2
        };
        return Shape {
            arms,
            dashes: 0,
            diagonals,
        };
    }
    // The arcs are drawn as the light corners.
    let mut name: String = name.replace("ARC ", "");
    let mut dashes = 0;
    for (words, n) in [
        ("DOUBLE DASH ", 2),
        ("TRIPLE DASH ", 3),
        ("QUADRUPLE DASH ", 4),
    ] {
        if name.contains(words) {
            dashes = n;
            name = name.replace(words, "");
        }
    }
    let weight = |w: &str| match w {
        "LIGHT" | "SINGLE" => Some(L),
        "HEAVY" => Some(H),
        "DOUBLE" => Some(D),
        _ => None,
    };
    let directions = |w: &str| match w {
        "UP" => vec![UP],
        "DOWN" => vec![DOWN],
        "LEFT" => vec![LEFT],
        "RIGHT" => vec![RIGHT],
        "VERTICAL" => vec![UP, DOWN],
        "HORIZONTAL" => vec![LEFT, RIGHT],
        _ => vec![],
    };
    let parts: Vec<(Option<u8>, Vec<usize>)> = name
        .split(" AND ")
        .map(|p| {
            (
                p.split(' ').find_map(weight),
                p.split(' ').flat_map(directions).collect(),
            )
        })
        .collect();
    let default = parts.iter().find_map(|p| p.0).expect(&name);
    for (w, dirs) in parts {
        for d in dirs {
            arms[d] = w.unwrap_or(default);
        }
    }
    Shape {
        arms,
        dashes,
        diagonals: 0,
    }
}

#[test]
fn the_table_holds_the_notes_code_points_in_order() {
    let mut want: Vec<u32> = (0x20..=0x7E).collect();
    want.extend([0xA0, 0xA3, 0xB0, 0xB1, 0xB7]);
    want.extend(0x2500..=0x257F);
    want.extend(0x2580..=0x259F);
    want.extend(0x23BA..=0x23BD);
    want.push(0x25C6);
    assert_eq!(want.len(), COUNT - 1);
    let got: Vec<u32> = (0..REPLACEMENT)
        .map(|i| code_point(i).unwrap() as u32)
        .collect();
    assert_eq!(got, want);
    for i in 0..REPLACEMENT {
        assert_eq!(glyph(code_point(i).unwrap()), i, "index {i}");
    }
    assert_eq!(code_point(REPLACEMENT), None);
    assert_eq!(code_point(COUNT as u16), None);
    assert_eq!(glyph(' '), SPACE);
    assert_eq!(size_of_val(&GLYPHS), 4256);
}

#[test]
fn every_other_code_point_draws_the_replacement_glyph() {
    let listed = |u: u32| {
        (0x20..=0x7E).contains(&u)
            || [0xA0, 0xA3, 0xB0, 0xB1, 0xB7, 0x25C6].contains(&u)
            || (0x2500..=0x259F).contains(&u)
            || (0x23BA..=0x23BD).contains(&u)
    };
    // Every code point natively; under Miri a sample. Then those DEC
    // Special Graphics maps to and the font lacks, and their neighbours.
    let step = if cfg!(miri) { 4093 } else { 1 };
    for u in (0..=0x10_FFFFu32).step_by(step).chain([
        0x7F, 0x9F, 0xA1, 0xE9, 0x3C0, 0x2260, 0x2264, 0x2265, 0x2409, 0x240A, 0x240B, 0x240C,
        0x240D, 0x2424, 0x23B9, 0x23BE, 0x24FF, 0x25A0, 0x25C5, 0x25C7, 0xFFFD,
    ]) {
        let Some(c) = char::from_u32(u) else {
            continue;
        };
        assert_eq!(glyph(c) == REPLACEMENT, !listed(u), "U+{u:04X}");
    }
    assert_eq!(bitmap(COUNT as u16), bitmap(REPLACEMENT));
    assert_eq!(bitmap(u16::MAX), bitmap(REPLACEMENT));
    check_pictures(
        "\u{FFFD}\u{2409}\u{3C0}",
        [
            "........ ........ ........",
            "........ ........ ........",
            ".######. .######. .######.",
            ".#....#. .#....#. .#....#.",
            ".#....#. .#....#. .#....#.",
            ".#....#. .#....#. .#....#.",
            ".#....#. .#....#. .#....#.",
            ".#....#. .#....#. .#....#.",
            ".#....#. .#....#. .#....#.",
            ".#....#. .#....#. .#....#.",
            ".#....#. .#....#. .#....#.",
            ".#....#. .#....#. .#....#.",
            ".#....#. .#....#. .#....#.",
            ".######. .######. .######.",
            "........ ........ ........",
            "........ ........ ........",
        ],
    );
}

#[test]
fn the_spleen_table_matches_its_header() {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for (_, rows) in &spleen::GLYPHS {
        for &b in rows {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x100_0000_01B3);
        }
    }
    assert_eq!(
        h,
        spleen::FNV1A_64,
        "the Spleen table differs from the BDF it came from"
    );
    for (i, (c, rows)) in spleen::GLYPHS.iter().enumerate() {
        assert_eq!(&GLYPHS[i], rows, "U+{:04X}", *c as u32);
        // Every glyph but the two spaces draws something.
        assert_eq!(
            rows.iter().all(|&r| r == 0),
            *c == ' ' || *c == '\u{A0}',
            "U+{:04X}",
            *c as u32
        );
    }
    // From the BDF: `A` is 00 00 7C C6 C6 C6 FE C6 C6 C6 C6 C6 00 00 00 00,
    // `°` 00 38 6C 6C 38 00 ... 00.
    check_pictures(
        "A\u{B0}",
        [
            "........ ........",
            "........ ..###...",
            ".#####.. .##.##..",
            "##...##. .##.##..",
            "##...##. ..###...",
            "##...##. ........",
            "#######. ........",
            "##...##. ........",
            "##...##. ........",
            "##...##. ........",
            "##...##. ........",
            "##...##. ........",
            "........ ........",
            "........ ........",
            "........ ........",
            "........ ........",
        ],
    );
}

#[test]
fn every_box_glyph_has_the_arms_its_unicode_name_gives() {
    for (i, name) in BOX_NAMES.iter().enumerate() {
        let u = 0x2500 + i as u32;
        let shape = shape_from_name(name);
        assert_eq!(BOX_SHAPES[i], shape, "U+{u:04X} {name}");
        if shape.diagonals != 0 {
            continue;
        }
        let g = bitmap(glyph(char::from_u32(u).unwrap()));
        // An arm's lines at the edge it starts from: columns across row 0
        // or 15, rows down column 0 or 7.
        let across = |w: u8| match w {
            L => 0b0001_0000,
            H => 0b0001_1000,
            D => 0b0010_0100,
            _ => 0,
        };
        let down = |w: u8| match w {
            L => vec![7],
            H => vec![7, 8],
            D => vec![6, 9],
            _ => vec![],
        };
        let a = shape.arms;
        assert_eq!(g[0], across(a[UP]), "U+{u:04X} {name}: up");
        assert_eq!(column(g, 0), down(a[LEFT]), "U+{u:04X} {name}: left");
        // A dashed line ends in a gap.
        if shape.dashes == 0 {
            assert_eq!(g[15], across(a[DOWN]), "U+{u:04X} {name}: down");
            assert_eq!(column(g, 7), down(a[RIGHT]), "U+{u:04X} {name}: right");
        }
    }
}

#[test]
fn dashed_lines_have_evenly_spaced_gaps() {
    // Light and heavy, across then down: 2, 3 and 4 dashes per cell, each
    // gap an eighth of the cell.
    let row = |c: char, y: usize| picture(bitmap(glyph(c)))[y].clone();
    let col = |c: char, x: usize| {
        let g = bitmap(glyph(c));
        (0..16)
            .map(|y| if g[y] & (0x80 >> x) != 0 { '#' } else { '.' })
            .collect::<String>()
    };
    for (light, heavy, want) in [
        ('╌', '╍', "###.###."),
        ('┄', '┅', "##.##.#."),
        ('┈', '┉', "#.#.#.#."),
    ] {
        assert_eq!(row(light, 7), want, "{light}");
        assert_eq!(row(heavy, 7), want, "{heavy}");
        assert_eq!(row(heavy, 8), want, "{heavy}");
    }
    for (light, heavy, want) in [
        ('╎', '╏', "######..######.."),
        ('┆', '┇', "####..###..###.."),
        ('┊', '┋', "##..##..##..##.."),
    ] {
        assert_eq!(col(light, 3), want, "{light}");
        assert_eq!(col(heavy, 3), want, "{heavy}");
        assert_eq!(col(heavy, 4), want, "{heavy}");
    }
}

#[test]
fn double_corners_and_junctions_and_a_heavy_corner_are_as_drawn() {
    // ╔ has its outer corner at column 2, row 6 and its inner one at
    // column 5, row 9; ╬ four inner corners; ┛ no notch.
    check_pictures(
        "╔╗╚╝═║",
        [
            "........ ........ ..#..#.. ..#..#.. ........ ..#..#..",
            "........ ........ ..#..#.. ..#..#.. ........ ..#..#..",
            "........ ........ ..#..#.. ..#..#.. ........ ..#..#..",
            "........ ........ ..#..#.. ..#..#.. ........ ..#..#..",
            "........ ........ ..#..#.. ..#..#.. ........ ..#..#..",
            "........ ........ ..#..#.. ..#..#.. ........ ..#..#..",
            "..###### ######.. ..#..### ###..#.. ######## ..#..#..",
            "..#..... .....#.. ..#..... .....#.. ........ ..#..#..",
            "..#..... .....#.. ..#..... .....#.. ........ ..#..#..",
            "..#..### ###..#.. ..###### ######.. ######## ..#..#..",
            "..#..#.. ..#..#.. ........ ........ ........ ..#..#..",
            "..#..#.. ..#..#.. ........ ........ ........ ..#..#..",
            "..#..#.. ..#..#.. ........ ........ ........ ..#..#..",
            "..#..#.. ..#..#.. ........ ........ ........ ..#..#..",
            "..#..#.. ..#..#.. ........ ........ ........ ..#..#..",
            "..#..#.. ..#..#.. ........ ........ ........ ..#..#..",
        ],
    );
    check_pictures(
        "╠╣╦╩╬┛",
        [
            "..#..#.. ..#..#.. ........ ..#..#.. ..#..#.. ...##...",
            "..#..#.. ..#..#.. ........ ..#..#.. ..#..#.. ...##...",
            "..#..#.. ..#..#.. ........ ..#..#.. ..#..#.. ...##...",
            "..#..#.. ..#..#.. ........ ..#..#.. ..#..#.. ...##...",
            "..#..#.. ..#..#.. ........ ..#..#.. ..#..#.. ...##...",
            "..#..#.. ..#..#.. ........ ..#..#.. ..#..#.. ...##...",
            "..#..### ###..#.. ######## ###..### ###..### ...##...",
            "..#..... .....#.. ........ ........ ........ #####...",
            "..#..... .....#.. ........ ........ ........ #####...",
            "..#..### ###..#.. ###..### ######## ###..### ........",
            "..#..#.. ..#..#.. ..#..#.. ........ ..#..#.. ........",
            "..#..#.. ..#..#.. ..#..#.. ........ ..#..#.. ........",
            "..#..#.. ..#..#.. ..#..#.. ........ ..#..#.. ........",
            "..#..#.. ..#..#.. ..#..#.. ........ ..#..#.. ........",
            "..#..#.. ..#..#.. ..#..#.. ........ ..#..#.. ........",
            "..#..#.. ..#..#.. ..#..#.. ........ ..#..#.. ........",
        ],
    );
}

#[test]
fn single_lines_meet_double_ones_without_gaps_or_stubs() {
    // A light arm runs to a double corner's farther line (╒ ╖ ╘), stops at
    // the nearer line of a straight double line it ends at (╟ ╤), and
    // crosses one it continues past (╪ ╫).
    check_pictures(
        "╒╖╘╟╤╪╫",
        [
            "........ ........ ...#.... ..#..#.. ........ ...#.... ..#..#..",
            "........ ........ ...#.... ..#..#.. ........ ...#.... ..#..#..",
            "........ ........ ...#.... ..#..#.. ........ ...#.... ..#..#..",
            "........ ........ ...#.... ..#..#.. ........ ...#.... ..#..#..",
            "........ ........ ...#.... ..#..#.. ........ ...#.... ..#..#..",
            "........ ........ ...#.... ..#..#.. ........ ...#.... ..#..#..",
            "...##### ........ ...##### ..#..#.. ######## ######## ..#..#..",
            "...#.... ######.. ...#.... ..#..### ........ ...#.... ########",
            "...#.... ..#..#.. ...#.... ..#..#.. ........ ...#.... ..#..#..",
            "...##### ..#..#.. ...##### ..#..#.. ######## ######## ..#..#..",
            "...#.... ..#..#.. ........ ..#..#.. ...#.... ...#.... ..#..#..",
            "...#.... ..#..#.. ........ ..#..#.. ...#.... ...#.... ..#..#..",
            "...#.... ..#..#.. ........ ..#..#.. ...#.... ...#.... ..#..#..",
            "...#.... ..#..#.. ........ ..#..#.. ...#.... ...#.... ..#..#..",
            "...#.... ..#..#.. ........ ..#..#.. ...#.... ...#.... ..#..#..",
            "...#.... ..#..#.. ........ ..#..#.. ...#.... ...#.... ..#..#..",
        ],
    );
}

#[test]
fn diagonals_and_the_diamond_are_as_drawn() {
    check_pictures(
        "╱╲╳◆",
        [
            ".......# #....... #......# ........",
            ".......# #....... #......# ........",
            "......#. .#...... .#....#. ........",
            "......#. .#...... .#....#. ........",
            ".....#.. ..#..... ..#..#.. ........",
            ".....#.. ..#..... ..#..#.. ...##...",
            "....#... ...#.... ...##... ..####..",
            "....#... ...#.... ...##... .######.",
            "...#.... ....#... ...##... .######.",
            "...#.... ....#... ...##... ..####..",
            "..#..... .....#.. ..#..#.. ...##...",
            "..#..... .....#.. ..#..#.. ........",
            ".#...... ......#. .#....#. ........",
            ".#...... ......#. .#....#. ........",
            "#....... .......# #......# ........",
            "#....... .......# #......# ........",
        ],
    );
}

#[test]
fn block_elements_follow_their_rules() {
    let rows = |c: char| bitmap(glyph(c)).to_vec();
    // Lower eighths: the bottom 2, 4, ... 16 rows.
    for (k, c) in "▁▂▃▄▅▆▇█".chars().enumerate() {
        let lit = 2 * (k + 1);
        assert_eq!(
            rows(c),
            [vec![0; 16 - lit], vec![0xFF; lit]].concat(),
            "{c}"
        );
    }
    // Left eighths: 7 down to 1 columns.
    for (k, c) in "▉▊▋▌▍▎▏".chars().enumerate() {
        let mask = (0xFF00u16 >> (7 - k)) as u8;
        assert_eq!(rows(c), vec![mask; 16], "{c}");
    }
    assert_eq!(rows('▀'), [vec![0xFF; 8], vec![0; 8]].concat());
    assert_eq!(rows('▐'), vec![0x0F; 16]);
    assert_eq!(rows('▔'), [vec![0xFF; 2], vec![0; 14]].concat());
    assert_eq!(rows('▕'), vec![0x01; 16]);
    // Quadrants of 4 × 8 pixels, by name.
    for (i, name) in BLOCK_NAMES.iter().enumerate() {
        let Some(quadrants) = name.strip_prefix("QUADRANT ") else {
            continue;
        };
        let c = char::from_u32(0x2580 + i as u32).unwrap();
        let mut want = [0u8; 16];
        for q in quadrants.split(" AND ") {
            let (x, y) = match q {
                "UPPER LEFT" => (0xF0, 0..8),
                "UPPER RIGHT" => (0x0F, 0..8),
                "LOWER LEFT" => (0xF0, 8..16),
                "LOWER RIGHT" => (0x0F, 8..16),
                _ => panic!("{name}"),
            };
            for r in y {
                want[r] |= x;
            }
        }
        assert_eq!(*bitmap(glyph(c)), want, "{name}");
    }
    // Shades: a quarter, a half and three quarters of the pixels.
    let count = |c: char| bitmap(glyph(c)).iter().map(|r| r.count_ones()).sum::<u32>();
    assert_eq!((count('░'), count('▒'), count('▓')), (32, 64, 96));
    let mut shades = Vec::new();
    for _ in 0..8 {
        shades.push("#...#... #.#.#.#. .###.###");
        shades.push("..#...#. .#.#.#.# ##.###.#");
    }
    check_pictures("░▒▓", shades.try_into().unwrap());
}

#[test]
fn the_five_scan_lines_are_evenly_spaced() {
    let lines: Vec<Vec<usize>> = "⎺⎻─⎼⎽"
        .chars()
        .map(|c| {
            let g = bitmap(glyph(c));
            assert!(g.iter().all(|&r| r == 0 || r == 0xFF), "{c}");
            (0..16).filter(|&y| g[y] == 0xFF).collect()
        })
        .collect();
    assert_eq!(lines, [[1], [4], [7], [10], [13]].map(|r| r.to_vec()));
}

/// The box-drawing block's Unicode names (Unicode 15.1, without the `BOX
/// DRAWINGS` prefix): the oracle for the arms.
const BOX_NAMES: [&str; 128] = [
    "LIGHT HORIZONTAL",
    "HEAVY HORIZONTAL",
    "LIGHT VERTICAL",
    "HEAVY VERTICAL",
    "LIGHT TRIPLE DASH HORIZONTAL",
    "HEAVY TRIPLE DASH HORIZONTAL",
    "LIGHT TRIPLE DASH VERTICAL",
    "HEAVY TRIPLE DASH VERTICAL",
    "LIGHT QUADRUPLE DASH HORIZONTAL",
    "HEAVY QUADRUPLE DASH HORIZONTAL",
    "LIGHT QUADRUPLE DASH VERTICAL",
    "HEAVY QUADRUPLE DASH VERTICAL",
    "LIGHT DOWN AND RIGHT",
    "DOWN LIGHT AND RIGHT HEAVY",
    "DOWN HEAVY AND RIGHT LIGHT",
    "HEAVY DOWN AND RIGHT",
    "LIGHT DOWN AND LEFT",
    "DOWN LIGHT AND LEFT HEAVY",
    "DOWN HEAVY AND LEFT LIGHT",
    "HEAVY DOWN AND LEFT",
    "LIGHT UP AND RIGHT",
    "UP LIGHT AND RIGHT HEAVY",
    "UP HEAVY AND RIGHT LIGHT",
    "HEAVY UP AND RIGHT",
    "LIGHT UP AND LEFT",
    "UP LIGHT AND LEFT HEAVY",
    "UP HEAVY AND LEFT LIGHT",
    "HEAVY UP AND LEFT",
    "LIGHT VERTICAL AND RIGHT",
    "VERTICAL LIGHT AND RIGHT HEAVY",
    "UP HEAVY AND RIGHT DOWN LIGHT",
    "DOWN HEAVY AND RIGHT UP LIGHT",
    "VERTICAL HEAVY AND RIGHT LIGHT",
    "DOWN LIGHT AND RIGHT UP HEAVY",
    "UP LIGHT AND RIGHT DOWN HEAVY",
    "HEAVY VERTICAL AND RIGHT",
    "LIGHT VERTICAL AND LEFT",
    "VERTICAL LIGHT AND LEFT HEAVY",
    "UP HEAVY AND LEFT DOWN LIGHT",
    "DOWN HEAVY AND LEFT UP LIGHT",
    "VERTICAL HEAVY AND LEFT LIGHT",
    "DOWN LIGHT AND LEFT UP HEAVY",
    "UP LIGHT AND LEFT DOWN HEAVY",
    "HEAVY VERTICAL AND LEFT",
    "LIGHT DOWN AND HORIZONTAL",
    "LEFT HEAVY AND RIGHT DOWN LIGHT",
    "RIGHT HEAVY AND LEFT DOWN LIGHT",
    "DOWN LIGHT AND HORIZONTAL HEAVY",
    "DOWN HEAVY AND HORIZONTAL LIGHT",
    "RIGHT LIGHT AND LEFT DOWN HEAVY",
    "LEFT LIGHT AND RIGHT DOWN HEAVY",
    "HEAVY DOWN AND HORIZONTAL",
    "LIGHT UP AND HORIZONTAL",
    "LEFT HEAVY AND RIGHT UP LIGHT",
    "RIGHT HEAVY AND LEFT UP LIGHT",
    "UP LIGHT AND HORIZONTAL HEAVY",
    "UP HEAVY AND HORIZONTAL LIGHT",
    "RIGHT LIGHT AND LEFT UP HEAVY",
    "LEFT LIGHT AND RIGHT UP HEAVY",
    "HEAVY UP AND HORIZONTAL",
    "LIGHT VERTICAL AND HORIZONTAL",
    "LEFT HEAVY AND RIGHT VERTICAL LIGHT",
    "RIGHT HEAVY AND LEFT VERTICAL LIGHT",
    "VERTICAL LIGHT AND HORIZONTAL HEAVY",
    "UP HEAVY AND DOWN HORIZONTAL LIGHT",
    "DOWN HEAVY AND UP HORIZONTAL LIGHT",
    "VERTICAL HEAVY AND HORIZONTAL LIGHT",
    "LEFT UP HEAVY AND RIGHT DOWN LIGHT",
    "RIGHT UP HEAVY AND LEFT DOWN LIGHT",
    "LEFT DOWN HEAVY AND RIGHT UP LIGHT",
    "RIGHT DOWN HEAVY AND LEFT UP LIGHT",
    "DOWN LIGHT AND UP HORIZONTAL HEAVY",
    "UP LIGHT AND DOWN HORIZONTAL HEAVY",
    "RIGHT LIGHT AND LEFT VERTICAL HEAVY",
    "LEFT LIGHT AND RIGHT VERTICAL HEAVY",
    "HEAVY VERTICAL AND HORIZONTAL",
    "LIGHT DOUBLE DASH HORIZONTAL",
    "HEAVY DOUBLE DASH HORIZONTAL",
    "LIGHT DOUBLE DASH VERTICAL",
    "HEAVY DOUBLE DASH VERTICAL",
    "DOUBLE HORIZONTAL",
    "DOUBLE VERTICAL",
    "DOWN SINGLE AND RIGHT DOUBLE",
    "DOWN DOUBLE AND RIGHT SINGLE",
    "DOUBLE DOWN AND RIGHT",
    "DOWN SINGLE AND LEFT DOUBLE",
    "DOWN DOUBLE AND LEFT SINGLE",
    "DOUBLE DOWN AND LEFT",
    "UP SINGLE AND RIGHT DOUBLE",
    "UP DOUBLE AND RIGHT SINGLE",
    "DOUBLE UP AND RIGHT",
    "UP SINGLE AND LEFT DOUBLE",
    "UP DOUBLE AND LEFT SINGLE",
    "DOUBLE UP AND LEFT",
    "VERTICAL SINGLE AND RIGHT DOUBLE",
    "VERTICAL DOUBLE AND RIGHT SINGLE",
    "DOUBLE VERTICAL AND RIGHT",
    "VERTICAL SINGLE AND LEFT DOUBLE",
    "VERTICAL DOUBLE AND LEFT SINGLE",
    "DOUBLE VERTICAL AND LEFT",
    "DOWN SINGLE AND HORIZONTAL DOUBLE",
    "DOWN DOUBLE AND HORIZONTAL SINGLE",
    "DOUBLE DOWN AND HORIZONTAL",
    "UP SINGLE AND HORIZONTAL DOUBLE",
    "UP DOUBLE AND HORIZONTAL SINGLE",
    "DOUBLE UP AND HORIZONTAL",
    "VERTICAL SINGLE AND HORIZONTAL DOUBLE",
    "VERTICAL DOUBLE AND HORIZONTAL SINGLE",
    "DOUBLE VERTICAL AND HORIZONTAL",
    "LIGHT ARC DOWN AND RIGHT",
    "LIGHT ARC DOWN AND LEFT",
    "LIGHT ARC UP AND LEFT",
    "LIGHT ARC UP AND RIGHT",
    "LIGHT DIAGONAL UPPER RIGHT TO LOWER LEFT",
    "LIGHT DIAGONAL UPPER LEFT TO LOWER RIGHT",
    "LIGHT DIAGONAL CROSS",
    "LIGHT LEFT",
    "LIGHT UP",
    "LIGHT RIGHT",
    "LIGHT DOWN",
    "HEAVY LEFT",
    "HEAVY UP",
    "HEAVY RIGHT",
    "HEAVY DOWN",
    "LIGHT LEFT AND HEAVY RIGHT",
    "LIGHT UP AND HEAVY DOWN",
    "HEAVY LEFT AND LIGHT RIGHT",
    "HEAVY UP AND LIGHT DOWN",
];

/// The block elements' Unicode names, for the quadrants.
const BLOCK_NAMES: [&str; 32] = [
    "UPPER HALF BLOCK",
    "LOWER ONE EIGHTH BLOCK",
    "LOWER ONE QUARTER BLOCK",
    "LOWER THREE EIGHTHS BLOCK",
    "LOWER HALF BLOCK",
    "LOWER FIVE EIGHTHS BLOCK",
    "LOWER THREE QUARTERS BLOCK",
    "LOWER SEVEN EIGHTHS BLOCK",
    "FULL BLOCK",
    "LEFT SEVEN EIGHTHS BLOCK",
    "LEFT THREE QUARTERS BLOCK",
    "LEFT FIVE EIGHTHS BLOCK",
    "LEFT HALF BLOCK",
    "LEFT THREE EIGHTHS BLOCK",
    "LEFT ONE QUARTER BLOCK",
    "LEFT ONE EIGHTH BLOCK",
    "RIGHT HALF BLOCK",
    "LIGHT SHADE",
    "MEDIUM SHADE",
    "DARK SHADE",
    "UPPER ONE EIGHTH BLOCK",
    "RIGHT ONE EIGHTH BLOCK",
    "QUADRANT LOWER LEFT",
    "QUADRANT LOWER RIGHT",
    "QUADRANT UPPER LEFT",
    "QUADRANT UPPER LEFT AND LOWER LEFT AND LOWER RIGHT",
    "QUADRANT UPPER LEFT AND LOWER RIGHT",
    "QUADRANT UPPER LEFT AND UPPER RIGHT AND LOWER LEFT",
    "QUADRANT UPPER LEFT AND UPPER RIGHT AND LOWER RIGHT",
    "QUADRANT UPPER RIGHT",
    "QUADRANT UPPER RIGHT AND LOWER LEFT",
    "QUADRANT UPPER RIGHT AND LOWER LEFT AND LOWER RIGHT",
];
