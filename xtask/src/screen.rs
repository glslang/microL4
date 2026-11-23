//! Screen images for the scenario harness's `screendump:`: QEMU's PPM in,
//! PNG goldens, exact comparison and a difference image.
//!
//! QEMU's `screendump` writes a binary PPM (P6): 8-bit RGB, 3 bytes a pixel,
//! about 3 MiB for OVMF's 1280x800. Goldens are PNG, which GitHub shows in
//! a pull request's diff: palette-indexed when the image has at most 256
//! colours, as a text screen does, else 8-bit RGB, compressed with
//! `miniz_oxide`. The PNG chunks, filters and CRC are done here. The decoder
//! reads what the encoder writes and what other encoders commonly make of
//! it (palettes of 1, 2, 4 or 8 bits a pixel, 8-bit RGB or grey, any
//! filter, not interlaced), so a golden another tool has recompressed still
//! reads.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;

/// An RGB image, 3 bytes a pixel, rows top to bottom.
#[derive(Clone, PartialEq, Eq)]
pub struct Image {
    pub width: usize,
    pub height: usize,
    pub rgb: Vec<u8>,
}

impl fmt::Debug for Image {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Image({}x{})", self.width, self.height)
    }
}

/// The largest width or height read from a file, which bounds the memory a
/// bad header can ask for: 64 Mi pixels.
const MAX_SIDE: usize = 8192;

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

type Result<T> = std::result::Result<T, String>;

impl Image {
    pub fn new(width: usize, height: usize, rgb: Vec<u8>) -> Result<Image> {
        if width == 0 || height == 0 || width > MAX_SIDE || height > MAX_SIDE {
            return Err(format!(
                "{width}x{height}: each side must be 1 to {MAX_SIDE}"
            ));
        }
        if rgb.len() != width * height * 3 {
            return Err(format!(
                "{width}x{height} needs {} bytes of RGB, not {}",
                width * height * 3,
                rgb.len()
            ));
        }
        Ok(Image { width, height, rgb })
    }

    /// Its pixels, rows top to bottom.
    fn pixels(&self) -> &[[u8; 3]] {
        self.rgb.as_chunks().0
    }

    fn pixel(&self, x: usize, y: usize) -> [u8; 3] {
        self.pixels()[y * self.width + x]
    }
}

/// Reads a binary PPM (P6) with a maximum value of 255, as QEMU writes.
pub fn read_ppm(bytes: &[u8]) -> Result<Image> {
    let mut at = 0;
    // A header field: skips whitespace and `#` comments, then reads up to
    // the next whitespace.
    let mut field = || -> Result<&[u8]> {
        loop {
            match bytes.get(at) {
                Some(b) if b.is_ascii_whitespace() => at += 1,
                Some(b'#') => {
                    while bytes.get(at).is_some_and(|&b| b != b'\n') {
                        at += 1;
                    }
                }
                _ => break,
            }
        }
        let start = at;
        while bytes.get(at).is_some_and(|b| !b.is_ascii_whitespace()) {
            at += 1;
        }
        if start == at {
            return Err("PPM: the header ends early".into());
        }
        Ok(&bytes[start..at])
    };
    if field()? != b"P6" {
        return Err("PPM: not a binary PPM (P6)".into());
    }
    let mut number = |what: &str| -> Result<usize> {
        std::str::from_utf8(field()?)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("PPM: bad {what}"))
    };
    let (width, height, max) = (number("width")?, number("height")?, number("maximum")?);
    if max != 255 {
        return Err(format!("PPM: maximum value {max}, not 255"));
    }
    // Exactly one whitespace byte comes between the header and the pixels.
    let pixels = bytes.get(at + 1..).unwrap_or_default();
    if width.checked_mul(height).and_then(|n| n.checked_mul(3)) != Some(pixels.len()) {
        return Err(format!(
            "PPM: {width}x{height} with {} bytes of pixels",
            pixels.len()
        ));
    }
    Image::new(width, height, pixels.to_vec()).map_err(|e| format!("PPM: {e}"))
}

/// Encodes `image` as a PNG with `text` as `tEXt` chunks (Latin-1 keyword
/// and text; xtask writes only ASCII). Palette-indexed, 8 bits a pixel, if
/// it has at most 256 colours, numbered in the order they first appear, so
/// the same pixels always give the same file.
pub fn encode_png(image: &Image, text: &[(&str, &str)]) -> Vec<u8> {
    let mut palette: Vec<[u8; 3]> = Vec::new();
    let mut index: HashMap<[u8; 3], u8> = HashMap::new();
    for &p in image.pixels() {
        if let Entry::Vacant(e) = index.entry(p) {
            if palette.len() == 256 {
                palette.clear();
                break;
            }
            e.insert(palette.len() as u8);
            palette.push(p);
        }
    }
    let indexed = !palette.is_empty();
    let (colour_type, bpp) = if indexed { (3, 1) } else { (2, 3) };
    let row_bytes = image.width * bpp;

    // Each row gets a filter byte. A palette image is left unfiltered, as
    // the PNG specification advises; an RGB row takes the filter whose
    // output has the smallest sum of absolute values, the usual heuristic.
    let mut raw = Vec::with_capacity(image.height * (row_bytes + 1));
    let mut previous = vec![0; row_bytes];
    for row in image.pixels().chunks(image.width) {
        let row: Vec<u8> = if indexed {
            row.iter().map(|p| index[p]).collect()
        } else {
            row.as_flattened().to_vec()
        };
        if indexed {
            raw.push(0);
            raw.extend_from_slice(&row);
        } else {
            let (filter, out) = (0..5u8)
                .map(|f| (f, filter_row(f, &row, &previous, bpp)))
                .min_by_key(|(_, out)| {
                    out.iter()
                        .map(|&b| u32::from((b as i8).unsigned_abs()))
                        .sum::<u32>()
                })
                .unwrap();
            raw.push(filter);
            raw.extend_from_slice(&out);
        }
        previous = row;
    }

    let mut png = PNG_SIGNATURE.to_vec();
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&(image.width as u32).to_be_bytes());
    ihdr.extend_from_slice(&(image.height as u32).to_be_bytes());
    // Depth 8; compression, filter method and interlace all 0.
    ihdr.extend_from_slice(&[8, colour_type, 0, 0, 0]);
    chunk(&mut png, b"IHDR", &ihdr);
    if indexed {
        chunk(&mut png, b"PLTE", palette.as_flattened());
    }
    for (keyword, value) in text {
        chunk(&mut png, b"tEXt", format!("{keyword}\0{value}").as_bytes());
    }
    chunk(
        &mut png,
        b"IDAT",
        &miniz_oxide::deflate::compress_to_vec_zlib(&raw, 9),
    );
    chunk(&mut png, b"IEND", &[]);
    png
}

/// A decoded PNG and its `tEXt` chunks.
pub struct Png {
    pub image: Image,
    pub text: Vec<(String, String)>,
}

/// Decodes a PNG that is not interlaced: palette-indexed at 1, 2, 4 or 8
/// bits a pixel, or 8-bit RGB or grey.
pub fn decode_png(bytes: &[u8]) -> Result<Png> {
    let mut rest = bytes
        .strip_prefix(PNG_SIGNATURE)
        .ok_or("PNG: no PNG signature")?;
    let mut header = None;
    let mut palette: Option<&[u8]> = None;
    let mut idat = Vec::new();
    let mut text = Vec::new();
    loop {
        if rest.len() < 12 {
            return Err("PNG: ends without IEND".into());
        }
        let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        let kind: [u8; 4] = rest[4..8].try_into().unwrap();
        if rest.len() - 12 < len {
            return Err(format!(
                "PNG: chunk {} runs past the end",
                kind.escape_ascii()
            ));
        }
        let data = &rest[8..8 + len];
        let crc = u32::from_be_bytes(rest[8 + len..12 + len].try_into().unwrap());
        if crc32(&[&kind, data]) != crc {
            return Err(format!("PNG: chunk {} has a bad CRC", kind.escape_ascii()));
        }
        rest = &rest[12 + len..];
        if header.is_none() && &kind != b"IHDR" {
            return Err("PNG: the first chunk is not IHDR".into());
        }
        match &kind {
            b"IHDR" if header.is_some() => return Err("PNG: two IHDR chunks".into()),
            b"IHDR" => {
                let ihdr: [u8; 13] = data.try_into().map_err(|_| "PNG: bad IHDR")?;
                let width = u32::from_be_bytes(ihdr[..4].try_into().unwrap()) as usize;
                let height = u32::from_be_bytes(ihdr[4..8].try_into().unwrap()) as usize;
                let [depth, colour, compression, filter, interlace] = ihdr[8..].try_into().unwrap();
                // Palette images may pack 2, 4 or 8 pixels a byte, as
                // other encoders write few colours.
                let known = match colour {
                    0 | 2 => depth == 8,
                    3 => matches!(depth, 1 | 2 | 4 | 8),
                    _ => false,
                };
                if !known || compression != 0 || filter != 0 || interlace != 0 {
                    return Err(format!(
                        "PNG: depth {depth}, colour type {colour}, methods {compression} \
                         {filter}, interlace {interlace}: only palette, 8-bit RGB or 8-bit \
                         grey, methods 0, not interlaced"
                    ));
                }
                if width == 0 || height == 0 || width > MAX_SIDE || height > MAX_SIDE {
                    return Err(format!(
                        "PNG: {width}x{height}: each side must be 1 to {MAX_SIDE}"
                    ));
                }
                header = Some((width, height, colour, usize::from(depth)));
            }
            b"PLTE" => {
                if data.is_empty() || data.len() % 3 != 0 || data.len() > 256 * 3 {
                    return Err("PNG: bad PLTE".into());
                }
                palette = Some(data);
            }
            b"IDAT" => idat.extend_from_slice(data),
            b"tEXt" => {
                let latin1 = |b: &[u8]| b.iter().map(|&c| char::from(c)).collect::<String>();
                let (k, v) = data
                    .iter()
                    .position(|&b| b == 0)
                    .map(|nul| (&data[..nul], &data[nul + 1..]))
                    .ok_or("PNG: tEXt without a keyword")?;
                text.push((latin1(k), latin1(v)));
            }
            b"IEND" => break,
            // Bit 5 of the first byte clear: a critical chunk, which a
            // decoder must understand.
            k if k[0] & 0x20 == 0 => {
                return Err(format!("PNG: unknown critical chunk {}", k.escape_ascii()));
            }
            _ => {}
        }
    }
    let (width, height, colour, depth) = header.unwrap();
    // Filters work on whole bytes: a pixel's, or 1 below 8 bits a pixel.
    let bpp = if colour == 2 { 3 } else { 1 };
    let row_bytes = (width * depth).div_ceil(8) * bpp;
    let size = height * (row_bytes + 1);
    let raw = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&idat, size)
        .map_err(|e| format!("PNG: bad image data: {:?}", e.status))?;
    if raw.len() != size {
        return Err(format!(
            "PNG: {} bytes of image data for {width}x{height}, not {size}",
            raw.len()
        ));
    }
    let palette = match (colour, palette) {
        (3, None) => return Err("PNG: a palette image without PLTE".into()),
        (_, p) => p.unwrap_or_default(),
    };

    let mut rgb = Vec::with_capacity(width * height * 3);
    let mut previous = vec![0; row_bytes];
    for line in raw.chunks_exact(row_bytes + 1) {
        let row = unfilter_row(line[0], &line[1..], &previous, bpp)?;
        match colour {
            2 => rgb.extend_from_slice(&row),
            0 => rgb.extend(row.iter().flat_map(|&g| [g, g, g])),
            _ => {
                // Packed indices, the leftmost pixel in the high bits.
                let mask = (1u16 << depth) - 1;
                for x in 0..width {
                    let bit = x * depth;
                    let i = (u16::from(row[bit / 8]) >> (8 - depth - bit % 8)) & mask;
                    let p = palette
                        .get(usize::from(i) * 3..usize::from(i) * 3 + 3)
                        .ok_or_else(|| format!("PNG: palette index {i} past the palette"))?;
                    rgb.extend_from_slice(p);
                }
            }
        }
        previous = row;
    }
    Ok(Png {
        image: Image::new(width, height, rgb)?,
        text,
    })
}

/// The Paeth predictor of the PNG specification.
fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = i16::from(a) + i16::from(b) - i16::from(c);
    let (pa, pb, pc) = (
        (p - i16::from(a)).abs(),
        (p - i16::from(b)).abs(),
        (p - i16::from(c)).abs(),
    );
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

/// The predictor filter type `filter` uses for a byte, from the byte `bpp`
/// to its left (`a`), the one above (`b`) and the one above that (`c`).
fn predict(filter: u8, a: u8, b: u8, c: u8) -> u8 {
    match filter {
        1 => a,
        2 => b,
        3 => ((u16::from(a) + u16::from(b)) / 2) as u8,
        4 => paeth(a, b, c),
        _ => 0,
    }
}

fn filter_row(filter: u8, row: &[u8], previous: &[u8], bpp: usize) -> Vec<u8> {
    (0..row.len())
        .map(|i| {
            let (a, c) = match i.checked_sub(bpp) {
                Some(j) => (row[j], previous[j]),
                None => (0, 0),
            };
            row[i].wrapping_sub(predict(filter, a, previous[i], c))
        })
        .collect()
}

fn unfilter_row(filter: u8, line: &[u8], previous: &[u8], bpp: usize) -> Result<Vec<u8>> {
    if filter > 4 {
        return Err(format!("PNG: unknown filter type {filter}"));
    }
    let mut row = line.to_vec();
    for i in 0..row.len() {
        let (a, c) = match i.checked_sub(bpp) {
            Some(j) => (row[j], previous[j]),
            None => (0, 0),
        };
        row[i] = row[i].wrapping_add(predict(filter, a, previous[i], c));
    }
    Ok(row)
}

fn chunk(png: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    png.extend_from_slice(&(data.len() as u32).to_be_bytes());
    png.extend_from_slice(kind);
    png.extend_from_slice(data);
    png.extend_from_slice(&crc32(&[kind, data]).to_be_bytes());
}

/// CRC-32 (ISO 3309, as PNG and zlib's `crc32` use) of the parts in order.
fn crc32(parts: &[&[u8]]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0; 256];
        let mut n = 0;
        while n < 256 {
            let mut c = n as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            table[n] = c;
            n += 1;
        }
        table
    };
    let mut c = !0u32;
    for &b in parts.iter().flat_map(|p| p.iter()) {
        c = TABLE[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

/// How a captured screen differs from its golden.
#[derive(Debug, PartialEq, Eq)]
pub enum Difference {
    /// The two sizes, captured then golden.
    Size((usize, usize), (usize, usize)),
    /// How many pixels differ, and the smallest box holding them all: the
    /// first and last column, then the first and last row.
    Pixels {
        count: usize,
        x: (usize, usize),
        y: (usize, usize),
    },
}

impl fmt::Display for Difference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Difference::Size((cw, ch), (gw, gh)) => {
                write!(f, "the screen is {cw}x{ch}, the golden {gw}x{gh}")
            }
            Difference::Pixels { count, x, y } => write!(
                f,
                "{count} pixel{} differ{}, in x {}-{}, y {}-{}",
                if *count == 1 { "" } else { "s" },
                if *count == 1 { "s" } else { "" },
                x.0,
                x.1,
                y.0,
                y.1
            ),
        }
    }
}

/// Compares two images pixel for pixel: `None` if they are the same.
pub fn compare(captured: &Image, golden: &Image) -> Option<Difference> {
    if (captured.width, captured.height) != (golden.width, golden.height) {
        return Some(Difference::Size(
            (captured.width, captured.height),
            (golden.width, golden.height),
        ));
    }
    let mut count = 0;
    let (mut x, mut y) = ((usize::MAX, 0), (usize::MAX, 0));
    for py in 0..captured.height {
        for px in 0..captured.width {
            if captured.pixel(px, py) != golden.pixel(px, py) {
                count += 1;
                x = (x.0.min(px), x.1.max(px));
                y = (y.0.min(py), y.1.max(py));
            }
        }
    }
    (count > 0).then_some(Difference::Pixels { count, x, y })
}

/// The colour of a differing pixel in [`difference_image`].
pub const DIFFERENT: [u8; 3] = [255, 0, 255];

/// An image of where two images of one size differ: each differing pixel is
/// [`DIFFERENT`] (magenta), every other the golden's at a quarter of its
/// brightness, for context.
pub fn difference_image(captured: &Image, golden: &Image) -> Image {
    assert_eq!(
        (captured.width, captured.height),
        (golden.width, golden.height)
    );
    let rgb = captured
        .pixels()
        .iter()
        .zip(golden.pixels())
        .flat_map(|(c, g)| {
            if c == g {
                [g[0] / 4, g[1] / 4, g[2] / 4]
            } else {
                DIFFERENT
            }
        })
        .collect();
    Image {
        width: golden.width,
        height: golden.height,
        rgb,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `w`x`h` image whose pixel colours come from `f(x, y)`.
    fn image(w: usize, h: usize, f: impl Fn(usize, usize) -> [u8; 3]) -> Image {
        let rgb = (0..h)
            .flat_map(|y| (0..w).map(move |x| (x, y)))
            .flat_map(|(x, y)| f(x, y))
            .collect();
        Image::new(w, h, rgb).unwrap()
    }

    /// Text-like: a few colours on black.
    fn screen(w: usize, h: usize) -> Image {
        image(w, h, |x, y| match (x / 8 + y / 16) % 5 {
            0 if (x + y) % 3 == 0 => [0xAA, 0xAA, 0xAA],
            1 if x % 2 == 0 => [0xFF, 0x55, 0x55],
            2 => [0, 0, 0xAA],
            _ => [0, 0, 0],
        })
    }

    /// Every pixel different, so RGB.
    fn photo(w: usize, h: usize) -> Image {
        image(w, h, |x, y| {
            [
                (x * 7 + y) as u8,
                ((y * 13) ^ (x * 3)) as u8,
                (x * y + 11) as u8,
            ]
        })
    }

    fn ppm(w: usize, h: usize, header: &str, rgb: &[u8]) -> Vec<u8> {
        let mut v = header
            .replace("W", &w.to_string())
            .replace("H", &h.to_string())
            .into_bytes();
        v.extend_from_slice(rgb);
        v
    }

    #[test]
    fn reads_qemus_ppm() {
        let img = screen(5, 3);
        // As QEMU's ppm_save writes it.
        let file = ppm(5, 3, "P6\nW H\n255\n", &img.rgb);
        assert_eq!(read_ppm(&file).unwrap(), img);
        // Comments and other whitespace in the header.
        let file = ppm(5, 3, "P6 # QEMU\n W\tH\n# max\n255 ", &img.rgb);
        assert_eq!(read_ppm(&file).unwrap(), img);
    }

    #[test]
    fn rejects_bad_ppm() {
        let rgb = [7; 3 * 6];
        for (file, why) in [
            (ppm(3, 2, "P3\nW H\n255\n", &rgb), "not a binary PPM"),
            (ppm(3, 2, "P6\nW H\n65535\n", &rgb), "maximum value 65535"),
            (ppm(3, 2, "P6\nW H\n255\n", &rgb[1..]), "3x2 with 17 bytes"),
            (
                ppm(3, 2, "P6\nW H\n255\n", &[rgb, rgb].concat()),
                "with 36 bytes",
            ),
            (ppm(3, 2, "P6\nW\n", &[]), "header ends early"),
            (ppm(3, 2, "P6\nW x\n255\n", &rgb), "bad height"),
            (ppm(0, 2, "P6\nW H\n255\n", &[]), "must be 1 to 8192"),
            (
                b"P6\n99999999999 99999999999\n255\n".to_vec(),
                "with 0 bytes",
            ),
        ] {
            let e = read_ppm(&file).unwrap_err();
            assert!(e.contains(why), "{e:?}, wanted {why:?}");
        }
    }

    #[test]
    fn png_round_trips_palette_and_rgb_images() {
        for (img, colour) in [
            (screen(64, 48), 3),
            (photo(33, 17), 2),
            (image(1, 1, |_, _| [1, 2, 3]), 3),
            // 256 colours still fit a palette; 257 do not.
            (image(16, 16, |x, y| [x as u8, y as u8, 0]), 3),
            (image(257, 1, |x, _| [x as u8, (x >> 8) as u8, 9]), 2),
        ] {
            let png = encode_png(&img, &[("Software", "xtask test")]);
            // Byte 25 is IHDR's colour type.
            assert_eq!(png[25], colour, "{img:?}");
            let back = decode_png(&png).unwrap();
            assert_eq!(back.image, img);
            assert_eq!(back.text, [("Software".into(), "xtask test".into())]);
            assert_eq!(encode_png(&img, &[("Software", "xtask test")]), png);
        }
    }

    #[test]
    fn rgb_rows_use_every_filter() {
        // A row's best filter depends on its content: black rows suit None
        // (which wins ties), ramps Sub, a row like the one above Up, and
        // rows built from their left, upper and upper-left neighbours as
        // Average and Paeth predict them, each above a row of products.
        const W: usize = 100;
        let mut rgb: Vec<u8> = Vec::new();
        for y in 0..42 {
            let above = rgb.len().checked_sub(W * 3).map(|i| rgb[i..].to_vec());
            for i in 0..W * 3 {
                let x = i / 3;
                let left = if i >= 3 { rgb[rgb.len() - 3] } else { 0 };
                rgb.push(match (y % 7, &above) {
                    (1, _) => (x * (5 + i % 3)) as u8,
                    (2, Some(a)) => a[i],
                    (3 | 5, _) => (x * y * (1 + i % 3)) as u8,
                    (4, Some(a)) => predict(3, left, a[i], 0),
                    (6, Some(a)) => predict(4, left, a[i], if i >= 3 { a[i - 3] } else { 0 }),
                    _ => 0,
                });
            }
        }
        let img = Image::new(W, 42, rgb).unwrap();
        let pixels: std::collections::HashSet<_> = img.pixels().iter().collect();
        assert!(pixels.len() > 256);
        let png = encode_png(&img, &[]);
        assert_eq!(decode_png(&png).unwrap().image, img);
        // The IDAT chunk follows IHDR (33 bytes with the signature).
        let len = u32::from_be_bytes(png[33..37].try_into().unwrap()) as usize;
        assert_eq!(&png[37..41], b"IDAT");
        let raw = miniz_oxide::inflate::decompress_to_vec_zlib(&png[41..41 + len]).unwrap();
        // Each row's first byte is its filter type.
        assert_eq!(raw.len(), 42 * (W * 3 + 1));
        let mut used: Vec<u8> = raw.iter().step_by(W * 3 + 1).copied().collect();
        used.sort();
        used.dedup();
        assert_eq!(used, [0, 1, 2, 3, 4]);
        // Each filter decodes on its own, against the same rows.
        for f in 0..5 {
            let row = &img.rgb[W * 3..2 * W * 3];
            let above = &img.rgb[..W * 3];
            let out = filter_row(f, row, above, 3);
            assert_eq!(unfilter_row(f, &out, above, 3).unwrap(), row, "filter {f}");
        }
        assert!(unfilter_row(5, &[0], &[0], 3).is_err());
    }

    #[test]
    fn decodes_another_encoders_pngs() {
        // A 3x2 image saved by Python's PIL 12.3, as RGB (its own filters
        // and zlib stream) and as a 6-colour palette, which PIL packs 4 bits
        // a pixel and orders its own way.
        let want = Image::new(
            3,
            2,
            vec![
                255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255, 10, 20, 30, 10, 20, 31,
            ],
        )
        .unwrap();
        let rgb = [
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x08, 0x02, 0x00, 0x00,
            0x00, 0x12, 0x16, 0xf1, 0x4d, 0x00, 0x00, 0x00, 0x1c, 0x49, 0x44, 0x41, 0x54, 0x78,
            0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0xc0, 0xf0, 0x9f, 0x81, 0x81, 0xe1, 0x3f, 0xe3, 0xff,
            0xff, 0xff, 0xb9, 0x45, 0xe5, 0x19, 0x18, 0x18, 0x01, 0x46, 0x01, 0x06, 0x3c, 0x79,
            0x07, 0x58, 0xe6, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60,
            0x82,
        ];
        let palette = [
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x04, 0x03, 0x00, 0x00,
            0x00, 0x6f, 0x5a, 0x7b, 0x29, 0x00, 0x00, 0x00, 0x12, 0x50, 0x4c, 0x54, 0x45, 0xff,
            0xff, 0xff, 0x00, 0xff, 0x00, 0x0a, 0x14, 0x1f, 0x0a, 0x14, 0x1e, 0xff, 0x00, 0x00,
            0x00, 0x00, 0xff, 0xea, 0x51, 0xbb, 0x1b, 0x00, 0x00, 0x00, 0x0e, 0x49, 0x44, 0x41,
            0x54, 0x78, 0x9c, 0x63, 0x74, 0xe4, 0x67, 0x64, 0x96, 0x05, 0x00, 0x01, 0xb3, 0x00,
            0x73, 0xf1, 0x29, 0x31, 0x35, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
            0x42, 0x60, 0x82,
        ];
        assert_eq!(decode_png(&rgb).unwrap().image, want);
        assert_eq!(decode_png(&palette).unwrap().image, want);
    }

    #[test]
    fn unpacks_palette_depths_below_8() {
        // 5 pixels a row, indices 0 1 2 3 0 at depth 2 (01 10 11 00 | 00),
        // and 1 0 1 1 0 at depth 1.
        let plte = [0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3];
        for (depth, packed, want) in [
            (2, vec![0b0001_1011, 0b0000_0000], [0, 1, 2, 3, 0]),
            (1, vec![0b1011_0000], [1, 0, 1, 1, 0]),
            (4, vec![0x01, 0x23, 0x00], [0, 1, 2, 3, 0]),
        ] {
            let mut png = PNG_SIGNATURE.to_vec();
            chunk(
                &mut png,
                b"IHDR",
                &[0, 0, 0, 5, 0, 0, 0, 1, depth, 3, 0, 0, 0],
            );
            chunk(&mut png, b"PLTE", &plte);
            let raw = [&[0][..], &packed].concat();
            chunk(
                &mut png,
                b"IDAT",
                &miniz_oxide::deflate::compress_to_vec_zlib(&raw, 6),
            );
            chunk(&mut png, b"IEND", &[]);
            let rgb: Vec<u8> = want.iter().flat_map(|&i| [i, i, i]).collect();
            assert_eq!(decode_png(&png).unwrap().image.rgb, rgb, "depth {depth}");
        }
    }

    #[test]
    fn rejects_bad_png() {
        let good = encode_png(&screen(8, 4), &[]);
        // Patches `good` at `at` and fixes the CRC of the chunk holding it.
        let patch = |at: usize, bytes: &[u8]| {
            let mut png = good.clone();
            png[at..at + bytes.len()].copy_from_slice(bytes);
            let len_at = |i: usize| u32::from_be_bytes(png[i..i + 4].try_into().unwrap()) as usize;
            let (mut start, mut len) = (8, len_at(8));
            while start + 12 + len <= at {
                start += 12 + len;
                len = len_at(start);
            }
            let crc = crc32(&[&png[start + 4..start + 8], &png[start + 8..start + 8 + len]]);
            png[start + 8 + len..start + 12 + len].copy_from_slice(&crc.to_be_bytes());
            png
        };
        let mut bad_crc = good.clone();
        bad_crc[30] ^= 1;
        for (png, why) in [
            (good[1..].to_vec(), "no PNG signature"),
            (good[..good.len() - 12].to_vec(), "ends without IEND"),
            (good[..50].to_vec(), "runs past the end"),
            (bad_crc, "bad CRC"),
            (patch(24, &[16]), "depth 16"),
            (patch(25, &[6]), "colour type 6"),
            (patch(28, &[1]), "interlace 1"),
            (patch(26, &[1]), "methods 1 0"),
            (patch(27, &[1]), "methods 0 1"),
            (patch(24, &[4, 2]), "depth 4, colour type 2"),
            // Rows of 4 bits a pixel are half as long as the data.
            (patch(24, &[4]), "bad image data"),
            (patch(16, &[0, 0, 0, 0]), "0x4: each side"),
            (patch(16, &[0, 0, 0x20, 1]), "8193x4"),
            (patch(20, &[0, 0, 0, 5]), "data for 8x5"),
            (patch(12, b"IHDX"), "first chunk is not IHDR"),
            (patch(37, b"PLTX"), "unknown critical chunk PLTX"),
        ] {
            let e = decode_png(&png).err().unwrap();
            assert!(e.contains(why), "{e:?}, wanted {why:?}");
        }
        // An ancillary chunk it does not know is skipped.
        assert!(decode_png(&patch(37, b"pLTX")).is_err(), "no palette then");
        let mut extra = good[..33].to_vec();
        chunk(&mut extra, b"zzZz", b"ignored");
        extra.extend_from_slice(&good[33..]);
        assert_eq!(decode_png(&extra).unwrap().image, screen(8, 4));
    }

    #[test]
    fn crc32_matches_zlib() {
        // zlib.crc32(b"123456789") and zlib.crc32(b"IEND").
        assert_eq!(crc32(&[b"123456789"]), 0xCBF4_3926);
        assert_eq!(crc32(&[b"1234", b"56789"]), 0xCBF4_3926);
        assert_eq!(crc32(&[b"IEND"]), 0xAE42_6082);
    }

    #[test]
    fn compares_pixel_for_pixel() {
        let golden = screen(32, 20);
        assert_eq!(compare(&golden, &golden.clone()), None);
        let mut captured = golden.clone();
        // Pixels (3, 2) and (30, 17) change.
        for (x, y) in [(3, 2), (30, 17)] {
            captured.rgb[(y * 32 + x) * 3 + 1] ^= 0x40;
        }
        let d = compare(&captured, &golden).unwrap();
        assert_eq!(
            d,
            Difference::Pixels {
                count: 2,
                x: (3, 30),
                y: (2, 17)
            }
        );
        assert_eq!(d.to_string(), "2 pixels differ, in x 3-30, y 2-17");
        let diff = difference_image(&captured, &golden);
        assert_eq!(diff.pixel(3, 2), DIFFERENT);
        assert_eq!(diff.pixel(30, 17), DIFFERENT);
        for (x, y) in [(0, 0), (4, 2), (31, 19)] {
            let g = golden.pixel(x, y);
            assert_eq!(diff.pixel(x, y), [g[0] / 4, g[1] / 4, g[2] / 4]);
        }
        assert_eq!(diff.pixels().iter().filter(|&&p| p == DIFFERENT).count(), 2);

        let mut one = golden.clone();
        one.rgb[0] ^= 1;
        assert_eq!(
            compare(&one, &golden).unwrap().to_string(),
            "1 pixel differs, in x 0-0, y 0-0"
        );
        let d = compare(&screen(32, 21), &golden).unwrap();
        assert_eq!(d, Difference::Size((32, 21), (32, 20)));
        assert_eq!(d.to_string(), "the screen is 32x21, the golden 32x20");
    }
}
