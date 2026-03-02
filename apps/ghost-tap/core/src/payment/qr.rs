//! QR code payment URI handling for Ghost.
//!
//! Implements the ghost: URI scheme for encoding and decoding payment requests
//! into QR-scannable strings.
//!
//! Format: `ghost:<address>?amount=<sats>&memo=<text>&label=<text>`

use std::fmt;

/// A Ghost payment request that can be serialized to/from a `ghost:` URI.
#[derive(Debug, Clone, PartialEq)]
pub struct PaymentRequest {
    /// The recipient Ghost address.
    pub address: String,
    /// Amount in satoshis. `None` means the sender chooses.
    pub amount: Option<u64>,
    /// Free-text memo attached to the payment.
    pub memo: Option<String>,
    /// Human-readable label for the recipient (e.g. merchant name).
    pub label: Option<String>,
    /// Unix timestamp after which this payment request expires.
    pub exp: Option<u64>,
    /// Network identifier (e.g. "ghost", "bitcoin", "lightning").
    pub net: Option<String>,
}

/// Errors that can occur when parsing a Ghost payment URI.
#[derive(Debug, Clone, PartialEq)]
pub enum PaymentUriError {
    /// The URI does not start with `ghost:`.
    InvalidScheme,
    /// The address portion of the URI is empty.
    MissingAddress,
    /// The amount parameter is present but not a valid u64.
    InvalidAmount(String),
    /// A query parameter could not be percent-decoded.
    DecodingError(String),
    /// The payment request has expired.
    Expired { exp: u64 },
}

impl fmt::Display for PaymentUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaymentUriError::InvalidScheme => {
                write!(f, "URI does not start with 'ghost:'")
            }
            PaymentUriError::MissingAddress => {
                write!(f, "address is missing from URI")
            }
            PaymentUriError::InvalidAmount(v) => {
                write!(f, "invalid amount value: {v}")
            }
            PaymentUriError::DecodingError(v) => {
                write!(f, "percent-decoding failed: {v}")
            }
            PaymentUriError::Expired { exp } => {
                write!(f, "payment request expired at timestamp {exp}")
            }
        }
    }
}

impl std::error::Error for PaymentUriError {}

impl PaymentRequest {
    /// Create a new payment request with only an address.
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            amount: None,
            memo: None,
            label: None,
            exp: None,
            net: None,
        }
    }

    /// Builder-style setter for amount.
    pub fn with_amount(mut self, amount: u64) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Builder-style setter for memo.
    pub fn with_memo(mut self, memo: impl Into<String>) -> Self {
        self.memo = Some(memo.into());
        self
    }

    /// Builder-style setter for label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Builder-style setter for expiry (Unix timestamp).
    pub fn with_expiry(mut self, exp: u64) -> Self {
        self.exp = Some(exp);
        self
    }

    /// Builder-style setter for network identifier.
    pub fn with_network(mut self, net: impl Into<String>) -> Self {
        self.net = Some(net.into());
        self
    }

    /// Serialize to a `ghost:` URI string.
    ///
    /// The address is placed directly after the `ghost:` scheme. Optional
    /// parameters are appended as query string key-value pairs. Values are
    /// percent-encoded to be URI-safe.
    pub fn to_uri(&self) -> String {
        let mut uri = format!("ghost:{}", self.address);

        let mut params: Vec<String> = Vec::new();

        if let Some(amount) = self.amount {
            params.push(format!("amount={amount}"));
        }
        if let Some(ref memo) = self.memo {
            params.push(format!("memo={}", percent_encode(memo)));
        }
        if let Some(ref label) = self.label {
            params.push(format!("label={}", percent_encode(label)));
        }
        if let Some(exp) = self.exp {
            params.push(format!("exp={exp}"));
        }
        if let Some(ref net) = self.net {
            params.push(format!("net={}", percent_encode(net)));
        }

        if !params.is_empty() {
            uri.push('?');
            uri.push_str(&params.join("&"));
        }

        uri
    }

    /// Parse a `ghost:` URI string into a `PaymentRequest`.
    ///
    /// Accepts URIs with or without query parameters. The amount field is
    /// optional; if present it must be a valid u64 representing satoshis.
    pub fn from_uri(uri: &str) -> Result<Self, PaymentUriError> {
        let stripped = uri
            .strip_prefix("ghost:")
            .ok_or(PaymentUriError::InvalidScheme)?;

        if stripped.is_empty() {
            return Err(PaymentUriError::MissingAddress);
        }

        let (address, query) = match stripped.find('?') {
            Some(idx) => (&stripped[..idx], Some(&stripped[idx + 1..])),
            None => (stripped, None),
        };

        if address.is_empty() {
            return Err(PaymentUriError::MissingAddress);
        }

        // Basic address validation: length and character set
        if address.len() < 25 || address.len() > 90 {
            return Err(PaymentUriError::MissingAddress);
        }
        if !address.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(PaymentUriError::MissingAddress);
        }

        let mut request = PaymentRequest::new(address);

        if let Some(query_str) = query {
            for pair in query_str.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (key, value) = match pair.find('=') {
                    Some(idx) => (&pair[..idx], &pair[idx + 1..]),
                    None => (pair, ""),
                };
                match key {
                    "amount" => {
                        let parsed: u64 = value.parse().map_err(|_| {
                            PaymentUriError::InvalidAmount(value.to_string())
                        })?;
                        request.amount = Some(parsed);
                    }
                    "memo" => {
                        request.memo = Some(
                            percent_decode(value)
                                .map_err(PaymentUriError::DecodingError)?,
                        );
                    }
                    "label" => {
                        request.label = Some(
                            percent_decode(value)
                                .map_err(PaymentUriError::DecodingError)?,
                        );
                    }
                    "exp" => {
                        let parsed: u64 = value.parse().map_err(|_| {
                            PaymentUriError::InvalidAmount(value.to_string())
                        })?;
                        request.exp = Some(parsed);
                    }
                    "net" => {
                        request.net = Some(
                            percent_decode(value)
                                .map_err(PaymentUriError::DecodingError)?,
                        );
                    }
                    _ => {
                        // Unknown parameters are silently ignored for
                        // forward-compatibility.
                    }
                }
            }
        }

        Ok(request)
    }

    /// Parse a `ghost:` URI and validate against the current time and expected
    /// network. Returns the request along with any warnings (e.g. network
    /// mismatch).
    ///
    /// If the URI contains an `exp` parameter in the past (relative to
    /// `now_unix`), an `Expired` error is returned.
    pub fn from_uri_checked(
        uri: &str,
        now_unix: u64,
        expected_net: Option<&str>,
    ) -> Result<ParsedPaymentRequest, PaymentUriError> {
        let request = Self::from_uri(uri)?;

        // Check expiry
        if let Some(exp) = request.exp {
            if now_unix > exp {
                return Err(PaymentUriError::Expired { exp });
            }
        }

        // Check network mismatch
        let mut warnings = Vec::new();
        if let (Some(expected), Some(ref found)) = (expected_net, &request.net) {
            if expected != found.as_str() {
                warnings.push(PaymentUriWarning::NetworkMismatch {
                    expected: expected.to_string(),
                    found: found.clone(),
                });
            }
        }

        Ok(ParsedPaymentRequest { request, warnings })
    }
}

/// Result of parsing a payment URI with validation.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedPaymentRequest {
    /// The parsed payment request.
    pub request: PaymentRequest,
    /// Non-fatal warnings (e.g. network mismatch).
    pub warnings: Vec<PaymentUriWarning>,
}

/// Non-fatal warnings produced when parsing a payment URI.
#[derive(Debug, Clone, PartialEq)]
pub enum PaymentUriWarning {
    /// The URI specifies a different network than expected.
    NetworkMismatch {
        expected: String,
        found: String,
    },
}

impl fmt::Display for PaymentUriWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaymentUriWarning::NetworkMismatch { expected, found } => {
                write!(f, "network mismatch: expected '{expected}', found '{found}'")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal percent-encoding / decoding (no extra dependencies)
// ---------------------------------------------------------------------------

/// Percent-encode a string for use in URI query parameters.
///
/// Encodes all characters except unreserved characters (A-Z, a-z, 0-9, `-`,
/// `.`, `_`, `~`) per RFC 3986.
fn percent_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    encoded
}

/// Percent-decode a URI-encoded string.
fn percent_decode(input: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(format!(
                    "incomplete percent-encoding at position {i}"
                ));
            }
            let hi = hex_digit(bytes[i + 1]).ok_or_else(|| {
                format!("invalid hex digit '{}' at position {}", bytes[i + 1] as char, i + 1)
            })?;
            let lo = hex_digit(bytes[i + 2]).ok_or_else(|| {
                format!("invalid hex digit '{}' at position {}", bytes[i + 2] as char, i + 2)
            })?;
            decoded.push((hi << 4) | lo);
            i += 3;
        } else if bytes[i] == b'+' {
            // Treat `+` as space (common in query strings).
            decoded.push(b' ');
            i += 1;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8(decoded)
        .map_err(|e| format!("invalid UTF-8 after percent-decoding: {e}"))
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_address_only() {
        let req = PaymentRequest::new("GhA1b2c3d4e5f6g7h8i9j0klmnop");
        let uri = req.to_uri();
        assert_eq!(uri, "ghost:GhA1b2c3d4e5f6g7h8i9j0klmnop");

        let parsed = PaymentRequest::from_uri(&uri).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn roundtrip_with_amount() {
        let req = PaymentRequest::new("GhA1b2c3d4e5f6g7h8i9j0klmnop")
            .with_amount(100_000_000);
        let uri = req.to_uri();
        assert!(uri.contains("amount=100000000"));

        let parsed = PaymentRequest::from_uri(&uri).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn roundtrip_full() {
        let req = PaymentRequest::new("GhA1b2c3d4e5f6g7h8i9j0klmnop")
            .with_amount(50_000)
            .with_memo("Coffee order #42")
            .with_label("Ghost Cafe");
        let uri = req.to_uri();

        let parsed = PaymentRequest::from_uri(&uri).unwrap();
        assert_eq!(parsed.address, req.address);
        assert_eq!(parsed.amount, req.amount);
        assert_eq!(parsed.memo, req.memo);
        assert_eq!(parsed.label, req.label);
    }

    #[test]
    fn roundtrip_special_characters() {
        let req = PaymentRequest::new("GhAddr1234567890abcdefghij")
            .with_memo("Payment for item #1 & item #2 (50% off)")
            .with_label("Bob's Store / Main St.");
        let uri = req.to_uri();

        let parsed = PaymentRequest::from_uri(&uri).unwrap();
        assert_eq!(parsed.memo, req.memo);
        assert_eq!(parsed.label, req.label);
    }

    #[test]
    fn roundtrip_unicode_memo() {
        let req = PaymentRequest::new("GhAddr4567890abcdefghijklm")
            .with_memo("Thanks! \u{2615}\u{1F600}");
        let uri = req.to_uri();

        let parsed = PaymentRequest::from_uri(&uri).unwrap();
        assert_eq!(parsed.memo, req.memo);
    }

    #[test]
    fn parse_no_scheme() {
        let result = PaymentRequest::from_uri("bitcoin:addr");
        assert_eq!(result, Err(PaymentUriError::InvalidScheme));
    }

    #[test]
    fn parse_empty_address() {
        let result = PaymentRequest::from_uri("ghost:");
        assert_eq!(result, Err(PaymentUriError::MissingAddress));
    }

    #[test]
    fn parse_empty_address_with_query() {
        let result = PaymentRequest::from_uri("ghost:?amount=100");
        assert_eq!(result, Err(PaymentUriError::MissingAddress));
    }

    #[test]
    fn parse_invalid_amount() {
        let result = PaymentRequest::from_uri("ghost:GhAddrABCDEFGHIJKLMNOPQRS?amount=notanumber");
        assert!(matches!(result, Err(PaymentUriError::InvalidAmount(_))));
    }

    #[test]
    fn parse_unknown_params_ignored() {
        let parsed = PaymentRequest::from_uri(
            "ghost:GhAddrABCDEFGHIJKLMNOPQRS?amount=1000&future_param=value",
        )
        .unwrap();
        assert_eq!(parsed.amount, Some(1000));
        assert_eq!(parsed.address, "GhAddrABCDEFGHIJKLMNOPQRS");
    }

    #[test]
    fn parse_no_amount() {
        let parsed = PaymentRequest::from_uri(
            "ghost:GhAddrABCDEFGHIJKLMNOPQRS?memo=test&label=shop",
        )
        .unwrap();
        assert_eq!(parsed.amount, None);
        assert_eq!(parsed.memo.as_deref(), Some("test"));
        assert_eq!(parsed.label.as_deref(), Some("shop"));
    }

    #[test]
    fn amount_zero() {
        let req = PaymentRequest::new("GhAddrABCDEFGHIJKLMNOPQRS").with_amount(0);
        let uri = req.to_uri();
        let parsed = PaymentRequest::from_uri(&uri).unwrap();
        assert_eq!(parsed.amount, Some(0));
    }

    #[test]
    fn amount_max() {
        let req = PaymentRequest::new("GhAddrABCDEFGHIJKLMNOPQRS").with_amount(u64::MAX);
        let uri = req.to_uri();
        let parsed = PaymentRequest::from_uri(&uri).unwrap();
        assert_eq!(parsed.amount, Some(u64::MAX));
    }

    #[test]
    fn roundtrip_with_expiry() {
        let req = PaymentRequest::new("GhAddr1234567890abcdefghij")
            .with_amount(50_000)
            .with_expiry(1710374400);
        let uri = req.to_uri();
        assert!(uri.contains("exp=1710374400"));

        let parsed = PaymentRequest::from_uri(&uri).unwrap();
        assert_eq!(parsed.exp, Some(1710374400));
        assert_eq!(parsed.amount, Some(50_000));
    }

    #[test]
    fn expired_uri_rejected() {
        let req = PaymentRequest::new("GhAddrABCDEFGHIJKLMNOPQRS")
            .with_expiry(1000);
        let uri = req.to_uri();

        // now_unix=2000 > exp=1000 → expired
        let result = PaymentRequest::from_uri_checked(&uri, 2000, None);
        assert!(matches!(result, Err(PaymentUriError::Expired { exp: 1000 })));
    }

    #[test]
    fn valid_expiry_accepted() {
        let req = PaymentRequest::new("GhAddrABCDEFGHIJKLMNOPQRS")
            .with_expiry(5000);
        let uri = req.to_uri();

        // now_unix=2000 < exp=5000 → valid
        let parsed = PaymentRequest::from_uri_checked(&uri, 2000, None).unwrap();
        assert_eq!(parsed.request.exp, Some(5000));
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn old_uri_still_parses() {
        // URI without exp/net fields should still parse (backward compat)
        let uri = "ghost:GhAddrABCDEFGHIJKLMNOPQRS?amount=1000&memo=hello";
        let parsed = PaymentRequest::from_uri(uri).unwrap();
        assert_eq!(parsed.exp, None);
        assert_eq!(parsed.net, None);
        assert_eq!(parsed.amount, Some(1000));
    }

    #[test]
    fn network_mismatch_warning() {
        let req = PaymentRequest::new("GhAddrABCDEFGHIJKLMNOPQRS")
            .with_network("bitcoin");
        let uri = req.to_uri();

        let parsed = PaymentRequest::from_uri_checked(&uri, 0, Some("ghost")).unwrap();
        assert_eq!(parsed.warnings.len(), 1);
        assert!(matches!(
            &parsed.warnings[0],
            PaymentUriWarning::NetworkMismatch { expected, found }
            if expected == "ghost" && found == "bitcoin"
        ));
    }

    #[test]
    fn roundtrip_with_network() {
        let req = PaymentRequest::new("GhAddrABCDEFGHIJKLMNOPQRS")
            .with_amount(100)
            .with_network("ghost");
        let uri = req.to_uri();
        assert!(uri.contains("net=ghost"));

        let parsed = PaymentRequest::from_uri(&uri).unwrap();
        assert_eq!(parsed.net, Some("ghost".into()));
    }

    #[test]
    fn network_match_no_warning() {
        let req = PaymentRequest::new("GhAddrABCDEFGHIJKLMNOPQRS")
            .with_network("ghost");
        let uri = req.to_uri();

        let parsed = PaymentRequest::from_uri_checked(&uri, 0, Some("ghost")).unwrap();
        assert!(parsed.warnings.is_empty());
    }
}
