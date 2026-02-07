//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: sanitize.rs                                                                                                    |
//|======================================================================================================================|

//! M-16: Log sanitization utilities
//!
//! Provides functions to sanitize user input before logging to prevent:
//! - Log injection attacks (newline injection to forge log entries)
//! - Control character injection
//! - Excessively long strings causing log overflow

/// Maximum length for sanitized log strings
const MAX_LOG_STRING_LEN: usize = 256;

/// M-16: Sanitize a string for safe logging
///
/// This function:
/// - Removes control characters (except space)
/// - Replaces newlines and carriage returns with visible markers
/// - Truncates to a maximum length with ellipsis
///
/// # Example
/// ```
/// use ghost_common::sanitize_for_log;
///
/// let malicious = "user123\nFake log entry: INFO password=secret";
/// let safe = sanitize_for_log(&malicious);
/// assert!(!safe.contains('\n'));
/// assert!(safe.contains("\\n")); // Visible marker
/// ```
pub fn sanitize_for_log(input: &str) -> String {
    let mut result = String::with_capacity(input.len().min(MAX_LOG_STRING_LEN + 3));

    for c in input.chars().take(MAX_LOG_STRING_LEN) {
        match c {
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            // Keep printable ASCII and valid Unicode
            c if c.is_control() => result.push_str("\\x"),
            c => result.push(c),
        }
    }

    // Add ellipsis if truncated
    if input.chars().count() > MAX_LOG_STRING_LEN {
        result.push_str("...");
    }

    result
}

/// M-16: Sanitize a string for logging with custom max length
pub fn sanitize_for_log_with_len(input: &str, max_len: usize) -> String {
    let mut result = String::with_capacity(input.len().min(max_len + 3));

    for c in input.chars().take(max_len) {
        match c {
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => result.push_str("\\x"),
            c => result.push(c),
        }
    }

    if input.chars().count() > max_len {
        result.push_str("...");
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_normal_string() {
        assert_eq!(sanitize_for_log("hello world"), "hello world");
    }

    #[test]
    fn test_sanitize_newlines() {
        assert_eq!(sanitize_for_log("line1\nline2"), "line1\\nline2");
        assert_eq!(sanitize_for_log("line1\r\nline2"), "line1\\r\\nline2");
    }

    #[test]
    fn test_sanitize_tabs() {
        assert_eq!(sanitize_for_log("col1\tcol2"), "col1\\tcol2");
    }

    #[test]
    fn test_sanitize_control_chars() {
        // Null byte and other control characters
        assert_eq!(sanitize_for_log("hello\x00world"), "hello\\xworld");
        assert_eq!(sanitize_for_log("hello\x07world"), "hello\\xworld");
    }

    #[test]
    fn test_sanitize_truncation() {
        let long_string = "a".repeat(300);
        let sanitized = sanitize_for_log(&long_string);
        assert_eq!(sanitized.len(), MAX_LOG_STRING_LEN + 3); // + "..."
        assert!(sanitized.ends_with("..."));
    }

    #[test]
    fn test_sanitize_custom_length() {
        let input = "hello world";
        assert_eq!(sanitize_for_log_with_len(input, 5), "hello...");
    }

    #[test]
    fn test_log_injection_attack() {
        // Attempt to forge a log entry
        let malicious = "user\nERROR: Critical security breach! Password: hunter2";
        let sanitized = sanitize_for_log(malicious);
        assert!(!sanitized.contains('\n'));
        assert!(sanitized.contains("\\n"));
    }

    #[test]
    fn test_unicode_preserved() {
        // Unicode should be preserved
        assert_eq!(sanitize_for_log("日本語"), "日本語");
        assert_eq!(sanitize_for_log("émojis 🎉"), "émojis 🎉");
    }
}
