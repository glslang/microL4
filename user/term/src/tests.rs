//! term's host tests (`docs/design.md`, "Golden tests" and "Code and
//! tests"): the golden screens, the parser's table test, the proptest of
//! random byte streams, unit tests of the palette, the cell and look words
//! and the renderer's look steps, the font's glyphs, and the renderer's
//! pixels.

mod font;
mod golden;
mod props;
mod render;
mod table;
mod unit;
