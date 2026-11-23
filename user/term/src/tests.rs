//! term's host tests (`docs/design.md`, "Golden tests" and "Code and
//! tests"): the golden screens, the parser's table test, the proptest of
//! random byte streams, and unit tests of the palette, the cell and look
//! words and the renderer's look steps.

mod golden;
mod props;
mod table;
mod unit;
