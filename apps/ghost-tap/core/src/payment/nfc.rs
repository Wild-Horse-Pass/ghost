//! NFC binary payment protocol for GhostTap APDU exchange.
//!
//! Wire format (request):
//! ```text
//! [version: 1 byte]
//! [msg_type: 1 byte]
//! [amount: 8 bytes, big-endian u64]
//! [addr_len: 2 bytes, big-endian u16]
//! [address: addr_len bytes, UTF-8]
//! [memo_len: 2 bytes, big-endian u16]   // 0 if no memo
//! [memo: memo_len bytes, UTF-8]          // absent if memo_len == 0
//! ```
//!
//! Wire format (response):
//! ```text
//! [status: 1 byte]
//! [txid_len: 2 bytes, big-endian u16]
//! [txid: txid_len bytes, UTF-8]
//! ```

use std::fmt;

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Message type: payment request from merchant to customer device.
pub const MSG_TYPE_PAYMENT_REQUEST: u8 = 0x01;

/// Message type: payment response from customer device to merchant.
pub const MSG_TYPE_PAYMENT_RESPONSE: u8 = 0x02;

/// NFC payment request sent from a merchant terminal to a customer device.
#[derive(Debug, Clone, PartialEq)]
pub struct NfcPaymentRequest {
    /// Protocol version (currently 1).
    pub version: u8,
    /// Message type identifier.
    pub msg_type: u8,
    /// Payment amount in satoshis.
    pub amount: u64,
    /// Recipient Ghost address.
    pub address: String,
    /// Optional memo / description.
    pub memo: Option<String>,
}

/// NFC payment response returned from the customer device to the merchant.
#[derive(Debug, Clone, PartialEq)]
pub struct NfcPaymentResponse {
    /// Transaction ID of the submitted payment.
    pub txid: String,
    /// Status code: 0x00 = success, non-zero = error.
    pub status: u8,
}

/// Errors that can occur during NFC message encoding/decoding.
#[derive(Debug, Clone, PartialEq)]
pub enum NfcProtocolError {
    /// The buffer is shorter than expected.
    BufferTooShort {
        expected: usize,
        actual: usize,
    },
    /// An unsupported protocol version was encountered.
    UnsupportedVersion(u8),
    /// An unknown message type was encountered.
    UnknownMessageType(u8),
    /// A length field points past the end of the buffer.
    LengthOverflow {
        field: &'static str,
        declared: usize,
        remaining: usize,
    },
    /// A UTF-8 string field contains invalid bytes.
    InvalidUtf8(&'static str),
}

impl fmt::Display for NfcProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NfcProtocolError::BufferTooShort { expected, actual } => {
                write!(f, "buffer too short: expected at least {expected} bytes, got {actual}")
            }
            NfcProtocolError::UnsupportedVersion(v) => {
                write!(f, "unsupported protocol version: {v}")
            }
            NfcProtocolError::UnknownMessageType(t) => {
                write!(f, "unknown message type: 0x{t:02X}")
            }
            NfcProtocolError::LengthOverflow { field, declared, remaining } => {
                write!(
                    f,
                    "length overflow in '{field}': declared {declared} bytes, only {remaining} remaining"
                )
            }
            NfcProtocolError::InvalidUtf8(field) => {
                write!(f, "invalid UTF-8 in field '{field}'")
            }
        }
    }
}

impl std::error::Error for NfcProtocolError {}

// ---------------------------------------------------------------------------
// Request encoding / decoding
// ---------------------------------------------------------------------------

/// Encode an `NfcPaymentRequest` into the binary wire format.
pub fn encode_nfc_payment_request(req: &NfcPaymentRequest) -> Result<Vec<u8>, NfcProtocolError> {
    let addr_bytes = req.address.as_bytes();
    let memo_bytes = req.memo.as_deref().unwrap_or("").as_bytes();

    let addr_len = u16::try_from(addr_bytes.len()).map_err(|_| NfcProtocolError::LengthOverflow {
        field: "address",
        declared: addr_bytes.len(),
        remaining: u16::MAX as usize,
    })?;

    let memo_len = u16::try_from(memo_bytes.len()).map_err(|_| NfcProtocolError::LengthOverflow {
        field: "memo",
        declared: memo_bytes.len(),
        remaining: u16::MAX as usize,
    })?;

    // version(1) + msg_type(1) + amount(8) + addr_len(2) + addr(N) + memo_len(2) + memo(N)
    let capacity = 1 + 1 + 8 + 2 + addr_bytes.len() + 2 + memo_bytes.len();
    let mut buf = Vec::with_capacity(capacity);

    buf.push(req.version);
    buf.push(req.msg_type);
    buf.extend_from_slice(&req.amount.to_be_bytes());
    buf.extend_from_slice(&addr_len.to_be_bytes());
    buf.extend_from_slice(addr_bytes);
    buf.extend_from_slice(&memo_len.to_be_bytes());
    if !memo_bytes.is_empty() {
        buf.extend_from_slice(memo_bytes);
    }

    Ok(buf)
}

/// Decode a binary buffer into an `NfcPaymentRequest`.
pub fn decode_nfc_payment_request(buf: &[u8]) -> Result<NfcPaymentRequest, NfcProtocolError> {
    // Minimum size: version(1) + type(1) + amount(8) + addr_len(2) + memo_len(2) = 14
    const MIN_HEADER: usize = 14;
    if buf.len() < MIN_HEADER {
        return Err(NfcProtocolError::BufferTooShort {
            expected: MIN_HEADER,
            actual: buf.len(),
        });
    }

    let version = buf[0];
    if version != PROTOCOL_VERSION {
        return Err(NfcProtocolError::UnsupportedVersion(version));
    }

    let msg_type = buf[1];
    if msg_type != MSG_TYPE_PAYMENT_REQUEST {
        return Err(NfcProtocolError::UnknownMessageType(msg_type));
    }

    let amount = u64::from_be_bytes(buf[2..10].try_into().unwrap());

    let addr_len = u16::from_be_bytes(buf[10..12].try_into().unwrap()) as usize;
    let addr_start = 12;
    let addr_end = addr_start + addr_len;

    if buf.len() < addr_end + 2 {
        return Err(NfcProtocolError::LengthOverflow {
            field: "address",
            declared: addr_len,
            remaining: buf.len().saturating_sub(addr_start),
        });
    }

    let address = std::str::from_utf8(&buf[addr_start..addr_end])
        .map_err(|_| NfcProtocolError::InvalidUtf8("address"))?
        .to_string();

    let memo_len_start = addr_end;
    let memo_len =
        u16::from_be_bytes(buf[memo_len_start..memo_len_start + 2].try_into().unwrap()) as usize;

    let memo_start = memo_len_start + 2;
    let memo_end = memo_start + memo_len;

    if buf.len() < memo_end {
        return Err(NfcProtocolError::LengthOverflow {
            field: "memo",
            declared: memo_len,
            remaining: buf.len().saturating_sub(memo_start),
        });
    }

    let memo = if memo_len == 0 {
        None
    } else {
        Some(
            std::str::from_utf8(&buf[memo_start..memo_end])
                .map_err(|_| NfcProtocolError::InvalidUtf8("memo"))?
                .to_string(),
        )
    };

    Ok(NfcPaymentRequest {
        version,
        msg_type,
        amount,
        address,
        memo,
    })
}

// ---------------------------------------------------------------------------
// Response encoding / decoding
// ---------------------------------------------------------------------------

/// Encode an `NfcPaymentResponse` into the binary wire format.
///
/// Format: `[status(1)][txid_len(2)][txid(N)]`
pub fn encode_nfc_payment_response(resp: &NfcPaymentResponse) -> Result<Vec<u8>, NfcProtocolError> {
    let txid_bytes = resp.txid.as_bytes();

    let txid_len = u16::try_from(txid_bytes.len()).map_err(|_| NfcProtocolError::LengthOverflow {
        field: "txid",
        declared: txid_bytes.len(),
        remaining: u16::MAX as usize,
    })?;

    let mut buf = Vec::with_capacity(1 + 2 + txid_bytes.len());

    buf.push(resp.status);
    buf.extend_from_slice(&txid_len.to_be_bytes());
    buf.extend_from_slice(txid_bytes);

    Ok(buf)
}

/// Decode a binary buffer into an `NfcPaymentResponse`.
pub fn decode_nfc_payment_response(buf: &[u8]) -> Result<NfcPaymentResponse, NfcProtocolError> {
    // Minimum: status(1) + txid_len(2) = 3
    const MIN_HEADER: usize = 3;
    if buf.len() < MIN_HEADER {
        return Err(NfcProtocolError::BufferTooShort {
            expected: MIN_HEADER,
            actual: buf.len(),
        });
    }

    let status = buf[0];

    let txid_len = u16::from_be_bytes(buf[1..3].try_into().unwrap()) as usize;
    let txid_start = 3;
    let txid_end = txid_start + txid_len;

    if buf.len() < txid_end {
        return Err(NfcProtocolError::LengthOverflow {
            field: "txid",
            declared: txid_len,
            remaining: buf.len().saturating_sub(txid_start),
        });
    }

    let txid = std::str::from_utf8(&buf[txid_start..txid_end])
        .map_err(|_| NfcProtocolError::InvalidUtf8("txid"))?
        .to_string();

    Ok(NfcPaymentResponse { txid, status })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> NfcPaymentRequest {
        NfcPaymentRequest {
            version: PROTOCOL_VERSION,
            msg_type: MSG_TYPE_PAYMENT_REQUEST,
            amount: 100_000_000,
            address: "GhA1b2c3d4e5f6g7h8i9j0".to_string(),
            memo: Some("Coffee #42".to_string()),
        }
    }

    fn sample_request_no_memo() -> NfcPaymentRequest {
        NfcPaymentRequest {
            version: PROTOCOL_VERSION,
            msg_type: MSG_TYPE_PAYMENT_REQUEST,
            amount: 50_000,
            address: "GhXyz789".to_string(),
            memo: None,
        }
    }

    fn sample_response() -> NfcPaymentResponse {
        NfcPaymentResponse {
            txid: "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344"
                .to_string(),
            status: 0x00,
        }
    }

    fn sample_response_error() -> NfcPaymentResponse {
        NfcPaymentResponse {
            txid: String::new(),
            status: 0x01,
        }
    }

    // -- Request round-trip tests --

    #[test]
    fn roundtrip_request_with_memo() {
        let req = sample_request();
        let encoded = encode_nfc_payment_request(&req).unwrap();
        let decoded = decode_nfc_payment_request(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn roundtrip_request_no_memo() {
        let req = sample_request_no_memo();
        let encoded = encode_nfc_payment_request(&req).unwrap();
        let decoded = decode_nfc_payment_request(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_wire_layout() {
        let req = NfcPaymentRequest {
            version: 1,
            msg_type: MSG_TYPE_PAYMENT_REQUEST,
            amount: 0x00000000_05F5E100, // 100_000_000
            address: "AB".to_string(),
            memo: None,
        };
        let buf = encode_nfc_payment_request(&req).unwrap();

        // version
        assert_eq!(buf[0], 1);
        // msg_type
        assert_eq!(buf[1], MSG_TYPE_PAYMENT_REQUEST);
        // amount (big-endian)
        assert_eq!(&buf[2..10], &0x05F5E100u64.to_be_bytes());
        // addr_len = 2
        assert_eq!(&buf[10..12], &2u16.to_be_bytes());
        // addr = "AB"
        assert_eq!(&buf[12..14], b"AB");
        // memo_len = 0
        assert_eq!(&buf[14..16], &0u16.to_be_bytes());
        // total length
        assert_eq!(buf.len(), 16);
    }

    #[test]
    fn request_buffer_too_short() {
        let result = decode_nfc_payment_request(&[0x01, 0x01]);
        assert!(matches!(
            result,
            Err(NfcProtocolError::BufferTooShort { .. })
        ));
    }

    #[test]
    fn request_unsupported_version() {
        let mut buf = encode_nfc_payment_request(&sample_request()).unwrap();
        buf[0] = 0xFF;
        let result = decode_nfc_payment_request(&buf);
        assert!(matches!(
            result,
            Err(NfcProtocolError::UnsupportedVersion(0xFF))
        ));
    }

    #[test]
    fn request_unknown_msg_type() {
        let mut buf = encode_nfc_payment_request(&sample_request()).unwrap();
        buf[1] = 0xFE;
        let result = decode_nfc_payment_request(&buf);
        assert!(matches!(
            result,
            Err(NfcProtocolError::UnknownMessageType(0xFE))
        ));
    }

    #[test]
    fn request_addr_length_overflow() {
        let req = sample_request();
        let mut buf = encode_nfc_payment_request(&req).unwrap();
        // Overwrite addr_len to a huge value
        buf[10] = 0xFF;
        buf[11] = 0xFF;
        let result = decode_nfc_payment_request(&buf);
        assert!(matches!(
            result,
            Err(NfcProtocolError::LengthOverflow { field: "address", .. })
        ));
    }

    #[test]
    fn request_memo_length_overflow() {
        let req = sample_request_no_memo();
        let mut buf = encode_nfc_payment_request(&req).unwrap();
        // Overwrite memo_len (last 2 bytes of the encoded no-memo request)
        let memo_pos = buf.len() - 2;
        buf[memo_pos] = 0x00;
        buf[memo_pos + 1] = 0x05; // says 5 bytes but there are 0
        let result = decode_nfc_payment_request(&buf);
        assert!(matches!(
            result,
            Err(NfcProtocolError::LengthOverflow { field: "memo", .. })
        ));
    }

    // -- Response round-trip tests --

    #[test]
    fn roundtrip_response_success() {
        let resp = sample_response();
        let encoded = encode_nfc_payment_response(&resp).unwrap();
        let decoded = decode_nfc_payment_response(&encoded).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn roundtrip_response_error() {
        let resp = sample_response_error();
        let encoded = encode_nfc_payment_response(&resp).unwrap();
        let decoded = decode_nfc_payment_response(&encoded).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn response_wire_layout() {
        let resp = NfcPaymentResponse {
            txid: "DEAD".to_string(),
            status: 0x00,
        };
        let buf = encode_nfc_payment_response(&resp).unwrap();

        assert_eq!(buf[0], 0x00); // status
        assert_eq!(&buf[1..3], &4u16.to_be_bytes()); // txid_len = 4
        assert_eq!(&buf[3..7], b"DEAD"); // txid
        assert_eq!(buf.len(), 7);
    }

    #[test]
    fn response_buffer_too_short() {
        let result = decode_nfc_payment_response(&[0x00, 0x00]);
        assert!(matches!(
            result,
            Err(NfcProtocolError::BufferTooShort { .. })
        ));
    }

    #[test]
    fn response_txid_length_overflow() {
        let buf = vec![0x00, 0x00, 0x10]; // status=0, txid_len=16, but no data
        let result = decode_nfc_payment_response(&buf);
        assert!(matches!(
            result,
            Err(NfcProtocolError::LengthOverflow { field: "txid", .. })
        ));
    }

    #[test]
    fn roundtrip_request_zero_amount() {
        let req = NfcPaymentRequest {
            version: PROTOCOL_VERSION,
            msg_type: MSG_TYPE_PAYMENT_REQUEST,
            amount: 0,
            address: "GhAddr".to_string(),
            memo: None,
        };
        let encoded = encode_nfc_payment_request(&req).unwrap();
        let decoded = decode_nfc_payment_request(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn roundtrip_request_max_amount() {
        let req = NfcPaymentRequest {
            version: PROTOCOL_VERSION,
            msg_type: MSG_TYPE_PAYMENT_REQUEST,
            amount: u64::MAX,
            address: "GhAddr".to_string(),
            memo: Some("max amount".to_string()),
        };
        let encoded = encode_nfc_payment_request(&req).unwrap();
        let decoded = decode_nfc_payment_request(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn roundtrip_response_empty_txid() {
        let resp = NfcPaymentResponse {
            txid: String::new(),
            status: 0x00,
        };
        let encoded = encode_nfc_payment_response(&resp).unwrap();
        let decoded = decode_nfc_payment_response(&encoded).unwrap();
        assert_eq!(decoded, resp);
    }
}
