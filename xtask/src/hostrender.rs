//! The screendump goldens of the `tui` scenario, drawn on the host
//! (`docs/design.md`, "Golden tests", "The screendump goldens").
//!
//! For each of the scenario's three moments, `tui_screendumps_are_the_host_render`
//! starts term as the guest's term starts (`term::Session::start`, on an
//! `fb::Surface` over a BGR host buffer), writes it `tui::App`'s output up
//! to that moment in the `Write`s tui's `run` makes, converts the pixels
//! to RGB and compares them, exactly, with the golden: at 1280x800 with
//! `tests/qemu/golden/<name>.png`, which the `tui` scenario's
//! `screendump:` compares the guest's screen with, and at 1024x768 with
//! `tools/hyperv/golden/<name>.png`, which the owner compares Hyper-V's
//! thumbnails with by eye. A golden must also carry the `Source` text
//! [`screen::HOST_RENDER`], which `cargo xtask test --bless` never
//! replaces, so the guest's screen is compared with an image only the host
//! drew. `MICROL4_BLESS=1` writes each golden that differs, through
//! xtask's encoder; otherwise a failure keeps the host render and a
//! difference image under `target/xtask/host-render/`.

use std::fs;
use std::path::{Path, PathBuf};

use crate::scenario;
use crate::screen::{self, Image};

/// The `tui` scenario's moments: each screendump's name and the bytes
/// typed for console's client 4 by then, the focus keys excluded, one
/// `send:` a `Read`.
pub const MOMENTS: [(&str, &[&[u8]]); 3] = [
    // The banner and the first frame.
    ("tui-main", &[]),
    // Down, Down and Enter: the Colours panel.
    ("tui-colours", &[b"\x1b[B\x1b[B\r"]),
    // Then q: the goodbye on the main screen.
    ("tui-quit", &[b"\x1b[B\x1b[B\r", b"q"]),
];

/// The framebuffers the goldens are drawn for: QEMU's, pinned by the
/// scenario's `qemu_args:`, and Hyper-V's GOP default.
pub const SIZES: [(u32, u32, &str); 2] = [
    (1280, 800, "tests/qemu/golden"),
    (1024, 768, "tools/hyperv/golden"),
];

/// The most bytes one term `Write` carries (`libsys::proto::MAX_BYTES`):
/// tui's `run` gathers a frame's bytes into `Write`s of this size.
const WRITE: usize = 952;

/// tui's `Out` as its `run` makes it, writing to the host's term.
struct ToTerm<'s, 'a> {
    session: &'s mut term::Session<'a>,
    buf: Vec<u8>,
    replies: Vec<u8>,
}

impl ToTerm<'_, '_> {
    /// Sends what is gathered, as one `Write`.
    fn flush(&mut self) {
        if !self.buf.is_empty() {
            let replies = &mut self.replies;
            self.session
                .write(&self.buf, |r| replies.extend_from_slice(r));
            self.buf.clear();
        }
    }
}

impl tui::Out for ToTerm<'_, '_> {
    fn put(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let n = (WRITE - self.buf.len()).min(bytes.len());
            self.buf.extend_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            if self.buf.len() == WRITE {
                self.flush();
            }
        }
    }
}

/// The screen of a `width` x `height` BGR framebuffer once term has drawn
/// tui's start and then a frame for each key in `reads`, as RGB. Panics
/// if term ignored a sequence or owed tui a reply, or if the frames term
/// drew by damage differ from a full render of its final screen.
pub fn render(width: u32, height: u32, reads: &[&[u8]]) -> Image {
    let geometry = fb::Geometry::new(width, height, width, fb::Format::Bgr).unwrap();
    let mut pixels = vec![0u32; geometry.pixels()];
    let mut full = vec![0u32; geometry.pixels()];
    let mut state = vec![0u64; term::STATE_WORDS];
    {
        let surface = fb::Surface::new(geometry, &mut pixels).unwrap();
        let mut session = term::Session::start(surface, &mut state);
        let (cols, rows) = session.size();
        let mut app = tui::App::new(cols as u64, rows as u64).unwrap();
        let mut out = ToTerm {
            session: &mut session,
            buf: Vec::new(),
            replies: Vec::new(),
        };
        app.start(&mut out);
        out.flush();
        for read in reads {
            app.received(read);
            for &b in *read {
                if let Some(key) = app.decode(b) {
                    app.key(key, &mut out);
                    out.flush();
                }
            }
        }
        let replies = std::mem::take(&mut out.replies);
        assert!(replies.is_empty(), "term owed tui {replies:?}");
        assert_eq!(session.ignored(), 0, "term ignored a sequence of tui's");
        let mut whole = term::Pixels(fb::Surface::new(geometry, &mut full).unwrap());
        term::render::full(session.screen(), &mut whole);
    }
    assert!(
        pixels == full,
        "{width}x{height}, {reads:?}: the frames drawn by damage differ from a full render"
    );
    let mut rgb = Vec::with_capacity(pixels.len() * 3);
    for &p in &pixels {
        let c = fb::Format::Bgr.colour(p);
        rgb.extend_from_slice(&[c.r(), c.g(), c.b()]);
    }
    Image::new(width as usize, height as usize, rgb).unwrap()
}

/// Why the golden at `path` is not the host render `image`, if it is not.
fn check(path: &Path, image: &Image) -> Option<String> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => return Some(format!("{e}")),
    };
    let golden = match screen::decode_png(&bytes) {
        Ok(g) => g,
        Err(e) => return Some(e),
    };
    if let Some(d) = screen::compare(image, &golden.image) {
        return Some(format!("{d}"));
    }
    let source: Vec<&str> = golden
        .text
        .iter()
        .filter(|(k, _)| k == "Source")
        .map(|(_, v)| v.as_str())
        .collect();
    if source != [screen::HOST_RENDER] {
        return Some(format!(
            "the pixels match, but its Source text is {source:?}, not [{:?}]",
            screen::HOST_RENDER
        ));
    }
    None
}

fn golden(dir: &str, name: &str) -> PathBuf {
    crate::root().join(dir).join(format!("{name}.png"))
}

#[test]
fn tui_screendumps_are_the_host_render() {
    let bless = std::env::var_os("MICROL4_BLESS").is_some_and(|v| v == "1");
    let mut failures = Vec::new();
    for (width, height, dir) in SIZES {
        for (name, reads) in MOMENTS {
            let image = render(width, height, reads);
            let path = golden(dir, name);
            let Some(why) = check(&path, &image) else {
                continue;
            };
            let png = screen::encode_png(&image, &[("Source", screen::HOST_RENDER)]);
            if bless {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, &png).unwrap();
                println!("blessed {} ({why}), {} bytes", crate::rel(&path), png.len());
                continue;
            }
            // Keep the host render, and where they differ, for a look.
            let out = crate::xtask_dir().join("host-render").join(dir);
            fs::create_dir_all(&out).unwrap();
            let kept = out.join(format!("{name}.png"));
            fs::write(&kept, &png).unwrap();
            let mut shown = String::new();
            if let Some(g) = fs::read(&path)
                .ok()
                .and_then(|b| screen::decode_png(&b).ok())
                .filter(|g| (g.image.width, g.image.height) == (image.width, image.height))
            {
                let diff = out.join(format!("{name}.diff.png"));
                let d = screen::difference_image(&image, &g.image);
                fs::write(&diff, screen::encode_png(&d, &[])).unwrap();
                shown = format!(", where they differ in magenta in {}", crate::rel(&diff));
            }
            failures.push(format!(
                "{}: {why}; the host render is in {}{shown}; if it is right, \
                 MICROL4_BLESS=1 cargo test -p xtask tui_screendumps makes it the golden",
                crate::rel(&path),
                crate::rel(&kept)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The moments are the `tui` scenario's screendumps, and the Hyper-V
/// check's: each golden here belongs to a step that takes the screen. The
/// Hyper-V check's scenarios are in the harness's format, which
/// `Test-L4Vhdx.ps1 -Scenario` follows; the M9 COM1 runs' are checked
/// against `m8-release`'s in `scenario.rs`.
#[test]
fn the_moments_are_the_scenarios_screendumps() {
    let names: Vec<&str> = MOMENTS.iter().map(|(n, _)| *n).collect();
    let hyperv = |name: &str| {
        let path = crate::root().join(format!("tools/hyperv/{name}.scenario"));
        scenario::parse(name, &fs::read_to_string(&path).unwrap()).unwrap()
    };
    let tui = hyperv("m8-tui");
    assert_eq!(tui.screendumps().collect::<Vec<_>>(), names, "m8-tui");
    assert_eq!(tui.cmdline, "test=tui");
    let release = hyperv("m8-release");
    assert_eq!(release.screendumps().count(), 0);
    assert_eq!(
        (release.cmdline.as_str(), release.kernel),
        ("test=release", crate::compile::Kernel::Release)
    );
    // The QEMU scenario takes these screendumps, at the 1280x800 the
    // goldens are drawn at.
    let text = fs::read_to_string(crate::root().join("tests/qemu/tui.scenario")).unwrap();
    let sc = scenario::parse("tui", &text).unwrap();
    assert_eq!(sc.screendumps().collect::<Vec<_>>(), names, "tui.scenario");
    assert!(
        sc.qemu_args
            .join(" ")
            .contains("-global VGA.xres=1280 -global VGA.yres=800"),
        "tui.scenario pins the 1280x800 the goldens are drawn at"
    );
    // Nothing else lives in tools/hyperv/golden/.
    let dir = crate::root().join(SIZES[1].2);
    let mut files: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    let mut want: Vec<String> = names.iter().map(|n| format!("{n}.png")).collect();
    want.sort();
    assert_eq!(files, want, "{}", crate::rel(&dir));
}

/// The host render's sizes and what it draws, without the goldens: the
/// grid is the framebuffer's whole cells, the title bar names it, and a
/// margin past the grid stays the default background.
#[test]
fn the_host_render_fills_the_framebuffer_and_its_margins() {
    for (width, height, cols, rows) in [(1280, 800, 160, 50), (1024, 768, 128, 48)] {
        let image = render(width, height, &[]);
        assert_eq!(
            (image.width, image.height),
            (width as usize, height as usize)
        );
        // The title bar's blue: the first cell's background, and the
        // last column's, a blank on blue.
        let px = |x: usize, y: usize| {
            let i = 3 * (y * image.width + x);
            [image.rgb[i], image.rgb[i + 1], image.rgb[i + 2]]
        };
        assert_eq!(px(0, 0), [0x00, 0x00, 0xAA]);
        assert_eq!(px(8 * cols - 1, 15), [0x00, 0x00, 0xAA]);
        // Row 2 is blank: the default background.
        assert_eq!(px(4, 16 + 8), [0, 0, 0]);
        assert_eq!(rows * 16, height as usize);
    }
    // A framebuffer that is not whole cells: the margin is the default
    // background, though the title bar's blue reaches the last column.
    let image = render(1284, 805, &[]);
    let px = |x: usize, y: usize| {
        let i = 3 * (y * image.width + x);
        [image.rgb[i], image.rgb[i + 1], image.rgb[i + 2]]
    };
    assert_eq!(px(1279, 0), [0x00, 0x00, 0xAA]);
    for (x, y) in [(1280, 0), (1283, 0), (0, 800), (1283, 804)] {
        assert_eq!(px(x, y), [0, 0, 0], "{x},{y}");
    }
}
