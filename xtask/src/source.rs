//! Checks on the kernel's source that no test can make at run time.

use std::fs;
use std::path::Path;

use crate::{Result, rel};

/// The kernel never executes `stac`, so SMAP is never lifted
/// (`docs/design.md`, "Privilege levels"). Fails if the instruction appears
/// anywhere in `kernel/` outside a `//` comment.
pub fn check_kernel(kernel: &Path) -> Result<()> {
    let mut hits = Vec::new();
    scan(kernel, &mut hits)?;
    if hits.is_empty() {
        Ok(())
    } else {
        Err(format!("`stac` in the kernel:\n  {}", hits.join("\n  ")).into())
    }
}

fn scan(dir: &Path, hits: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            scan(&path, hits)?;
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if names_stac(code) {
                hits.push(format!("{}:{}: {}", rel(&path), n + 1, line.trim()));
            }
        }
    }
    Ok(())
}

/// Whether `code` contains `stac` as a whole word, in any case.
fn names_stac(code: &str) -> bool {
    code.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|word| word.eq_ignore_ascii_case("stac"))
}

#[cfg(test)]
mod tests {
    use super::names_stac;

    #[test]
    fn finds_the_instruction_but_not_its_cousins() {
        assert!(names_stac(r#"asm!("stac")"#));
        assert!(names_stac("    STAC"));
        assert!(names_stac(r#""clac; stac""#));
        assert!(!names_stac(r#"asm!("clac")"#));
        assert!(!names_stac("let stack = 1;"));
        assert!(!names_stac("stac_count"));
    }
}
