//! The kernel command line: space-separated `key=value` words.
//!
//! The loader copies it from `cmdline.txt` on the EFI system partition. QEMU
//! scenarios use it to pick a test, as in `test=hello`.

/// Returns the value of the first `key=value` word whose key is `key`.
///
/// A bare word `key` with no `=` yields `Some("")`.
pub fn value<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    cmdline.split_ascii_whitespace().find_map(|word| {
        let (k, v) = word.split_once('=').unwrap_or((word, ""));
        (k == key).then_some(v)
    })
}

#[cfg(test)]
mod tests {
    use super::value;

    #[test]
    fn finds_a_key() {
        assert_eq!(value("test=hello", "test"), Some("hello"));
        assert_eq!(value("  a=1   test=panic b=2 ", "test"), Some("panic"));
    }

    #[test]
    fn first_occurrence_wins() {
        assert_eq!(value("test=a test=b", "test"), Some("a"));
    }

    #[test]
    fn bare_word_has_an_empty_value() {
        assert_eq!(value("quiet test=hello", "quiet"), Some(""));
    }

    #[test]
    fn missing_key() {
        assert_eq!(value("", "test"), None);
        assert_eq!(value("testing=1 tes=2", "test"), None);
    }

    #[test]
    fn value_may_contain_equals() {
        assert_eq!(value("k=a=b", "k"), Some("a=b"));
    }

    #[test]
    fn tabs_and_newlines_separate_words() {
        assert_eq!(value("a=1\ttest=hello\n", "test"), Some("hello"));
    }
}
