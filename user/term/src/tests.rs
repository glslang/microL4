//! term's host tests (`docs/design.md`, "Golden tests" and "Code and
//! tests"): the golden screens, the parser's table test, the proptest of
//! random byte streams, unit tests of the palette, the cell and look words
//! and the renderer's look steps, the font's glyphs, the renderer's
//! pixels, and the session and the term protocol; and the M8 red team's
//! attacks (`redteam`, `docs/redteam/m8-*.md`).

mod font;
mod golden;
mod props;
mod redteam;
mod render;
mod server;
mod table;
mod unit;
