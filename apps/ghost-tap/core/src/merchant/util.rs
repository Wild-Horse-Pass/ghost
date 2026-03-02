//! Shared utility functions for the merchant module.

/// Convert days since Unix epoch to (year, month, day).
///
/// Algorithm adapted from Howard Hinnant's chrono-compatible date library.
pub fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    days += 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Minimal HTML escaping for untrusted text.
pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Format a satoshi amount as a human-readable GHOST string (8 decimal places).
pub fn format_ghost_amount(sats: u64) -> String {
    let whole = sats / 100_000_000;
    let frac = sats % 100_000_000;
    format!("{}.{:08}", whole, frac)
}

/// Escape a value for safe embedding in CSV.
///
/// Wraps in double quotes and doubles any existing quotes if the value
/// contains special characters. Also handles formula-triggering characters
/// (`=`, `+`, `-`, `@`, `\t`) to prevent CSV injection attacks.
pub fn csv_escape(value: &str) -> String {
    let needs_quoting = value.contains(',')
        || value.contains('"')
        || value.contains('\n')
        || value.contains('\r')
        || value.starts_with('=')
        || value.starts_with('+')
        || value.starts_with('-')
        || value.starts_with('@')
        || value.starts_with('\t');
    if needs_quoting {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_days_to_ymd_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_known_date() {
        // 2024-02-29 (leap day) = day 19_782
        assert_eq!(days_to_ymd(19_782), (2024, 2, 29));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("hello"), "hello");
        assert_eq!(
            html_escape("Bob's <Shop> & \"Grill\""),
            "Bob&#39;s &lt;Shop&gt; &amp; &quot;Grill&quot;"
        );
    }

    #[test]
    fn test_format_ghost_amount() {
        assert_eq!(format_ghost_amount(100_000_000), "1.00000000");
        assert_eq!(format_ghost_amount(50_000), "0.00050000");
        assert_eq!(format_ghost_amount(0), "0.00000000");
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(csv_escape("simple"), "simple");
        assert_eq!(csv_escape("has, comma"), "\"has, comma\"");
        assert_eq!(csv_escape("has \"quote\""), "\"has \"\"quote\"\"\"");
    }
}
