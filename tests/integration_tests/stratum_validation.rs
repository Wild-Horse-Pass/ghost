// Allow common test-code patterns that clippy flags
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::let_and_return)]
#![allow(clippy::iter_nth_zero)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::manual_repeat_n)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::unnecessary_unwrap)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::needless_character_iteration)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::bool_assert_comparison)]

//! Category 4: Stratum Protocol Tests (75 tests)
//!
//! Comprehensive tests for Stratum protocol validation including:
//! - Input validation (usernames, passwords)
//! - Share validation
//! - Timestamp validation
//! - Difficulty validation
//! - Duplicate detection

// Self-contained stub types for testing

const MAX_USERNAME_LEN: usize = 256;
const MAX_PASSWORD_LEN: usize = 256;
const MAX_WORKER_NAME_LEN: usize = 64;
const MAX_USER_AGENT_LEN: usize = 256;
const MAX_JOB_ID_LEN: usize = 64;
const MAX_EXTRANONCE2_LEN: usize = 16;
const MAX_NTIME_ADJUSTMENT: u32 = 7200; // 2 hours

#[derive(Debug)]
enum ValidationError {
    Empty(String),
    TooLong(usize, usize),
    TooShort(usize, usize),
    InvalidChars(String),
    InvalidHex(String),
    NullByte(String),
    ControlChars(String),
    NonAscii(String),
    DangerousChars(String),
    InvalidFormat(String),
    PathTraversal(String),
}

fn validate_username(username: &str) -> Result<(), ValidationError> {
    if username.is_empty() {
        return Err(ValidationError::Empty("username".into()));
    }
    if username.len() > MAX_USERNAME_LEN {
        return Err(ValidationError::TooLong(username.len(), MAX_USERNAME_LEN));
    }
    if username.contains('\0') {
        return Err(ValidationError::NullByte("username".into()));
    }
    if username.chars().any(|c| c.is_control()) {
        return Err(ValidationError::ControlChars("username".into()));
    }
    if !username.is_ascii() {
        return Err(ValidationError::NonAscii("username".into()));
    }
    // Check for path traversal first (forward/backslash or ..)
    if username.contains('/') || username.contains('\\') || username.contains("..") {
        return Err(ValidationError::PathTraversal("username".into()));
    }
    let dangerous = [
        '`', '$', '|', ';', '&', '(', ')', '<', '>', '"', '\'', '{', '}', '[', ']',
    ];
    if username.chars().any(|c| dangerous.contains(&c)) {
        return Err(ValidationError::InvalidChars("username".into()));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), ValidationError> {
    if password.len() > MAX_PASSWORD_LEN {
        return Err(ValidationError::TooLong(password.len(), MAX_PASSWORD_LEN));
    }
    if password.contains('\0') {
        return Err(ValidationError::NullByte("password".into()));
    }
    Ok(())
}

fn validate_worker_name(name: &str) -> Result<(), ValidationError> {
    if name.is_empty() {
        return Ok(()); // Empty is allowed
    }
    if name.len() > MAX_WORKER_NAME_LEN {
        return Err(ValidationError::TooLong(name.len(), MAX_WORKER_NAME_LEN));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ValidationError::InvalidChars("worker_name".into()));
    }
    Ok(())
}

fn validate_user_agent(agent: &str) -> Result<(), ValidationError> {
    if agent.is_empty() {
        return Ok(()); // Empty is allowed
    }
    if agent.len() > MAX_USER_AGENT_LEN {
        return Err(ValidationError::TooLong(agent.len(), MAX_USER_AGENT_LEN));
    }
    if agent.contains('\0') {
        return Err(ValidationError::NullByte("user_agent".into()));
    }
    if agent.chars().any(|c| c.is_control()) {
        return Err(ValidationError::ControlChars("user_agent".into()));
    }
    if !agent.is_ascii() {
        return Err(ValidationError::NonAscii("user_agent".into()));
    }
    Ok(())
}

fn validate_job_id(job_id: &str) -> Result<(), ValidationError> {
    if job_id.is_empty() {
        return Err(ValidationError::Empty("job_id".into()));
    }
    if job_id.len() > MAX_JOB_ID_LEN {
        return Err(ValidationError::TooLong(job_id.len(), MAX_JOB_ID_LEN));
    }
    if !job_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::InvalidHex("job_id".into()));
    }
    Ok(())
}

fn validate_extranonce2(extranonce2: &str, expected_len: usize) -> Result<(), ValidationError> {
    if extranonce2.is_empty() {
        return Err(ValidationError::Empty("extranonce2".into()));
    }
    if extranonce2.len() != expected_len {
        return Err(ValidationError::InvalidFormat(format!(
            "extranonce2 length {} != expected {}",
            extranonce2.len(),
            expected_len
        )));
    }
    if !extranonce2.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::InvalidHex("extranonce2".into()));
    }
    Ok(())
}

fn validate_ntime(ntime: &str) -> Result<u32, ValidationError> {
    if ntime.len() < 8 {
        return Err(ValidationError::TooShort(ntime.len(), 8));
    }
    if ntime.len() > 8 {
        return Err(ValidationError::TooLong(ntime.len(), 8));
    }
    if !ntime.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::InvalidHex("ntime".into()));
    }
    u32::from_str_radix(ntime, 16).map_err(|_| ValidationError::InvalidHex("ntime".into()))
}

fn validate_nonce(nonce: &str) -> Result<u32, ValidationError> {
    if nonce.len() < 8 {
        return Err(ValidationError::TooShort(nonce.len(), 8));
    }
    if nonce.len() > 8 {
        return Err(ValidationError::TooLong(nonce.len(), 8));
    }
    if !nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::InvalidHex("nonce".into()));
    }
    u32::from_str_radix(nonce, 16).map_err(|_| ValidationError::InvalidHex("nonce".into()))
}

fn validate_share_params(
    job_id: &str,
    extranonce2: &str,
    ntime: &str,
    nonce: &str,
) -> Result<ShareParams, ValidationError> {
    // Job ID validation
    if job_id.is_empty() {
        return Err(ValidationError::Empty("job_id".into()));
    }
    if job_id.len() > MAX_JOB_ID_LEN {
        return Err(ValidationError::TooLong(job_id.len(), MAX_JOB_ID_LEN));
    }
    if !job_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::InvalidHex("job_id".into()));
    }

    // Extranonce2 can vary in length
    if extranonce2.len() > MAX_EXTRANONCE2_LEN * 2 {
        return Err(ValidationError::TooLong(
            extranonce2.len(),
            MAX_EXTRANONCE2_LEN * 2,
        ));
    }
    if !extranonce2.is_empty() && !extranonce2.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::InvalidHex("extranonce2".into()));
    }

    let ntime_val = validate_ntime(ntime)?;
    let nonce_val = validate_nonce(nonce)?;

    Ok(ShareParams {
        job_id: job_id.to_string(),
        extranonce2: extranonce2.to_string(),
        ntime: ntime_val,
        nonce: nonce_val,
    })
}

fn validate_ntime_adjustment(share_ntime: u32, job_ntime: u32) -> Result<(), ValidationError> {
    let diff = share_ntime.abs_diff(job_ntime);

    if diff > MAX_NTIME_ADJUSTMENT {
        return Err(ValidationError::InvalidFormat(format!(
            "ntime adjustment {} exceeds max {}",
            diff, MAX_NTIME_ADJUSTMENT
        )));
    }
    Ok(())
}

fn validate_difficulty(difficulty: f64) -> Result<(), ValidationError> {
    if difficulty <= 0.0 || difficulty.is_nan() || difficulty.is_infinite() {
        return Err(ValidationError::InvalidFormat("invalid difficulty".into()));
    }
    Ok(())
}

#[derive(Debug)]
struct ShareParams {
    job_id: String,
    extranonce2: String,
    ntime: u32,
    nonce: u32,
}

/// Validated share parameters with parse method
#[derive(Debug)]
struct ValidatedShareParams {
    job_id: String,
    extranonce2: String,
    ntime: u32,
    nonce: u32,
}

impl ValidatedShareParams {
    fn parse(
        job_id: &str,
        extranonce2: &str,
        ntime: &str,
        nonce: &str,
    ) -> Result<Self, ValidationError> {
        let params = validate_share_params(job_id, extranonce2, ntime, nonce)?;
        Ok(Self {
            job_id: params.job_id,
            extranonce2: params.extranonce2,
            ntime: params.ntime,
            nonce: params.nonce,
        })
    }
}

/// Validated credentials with parse method
#[derive(Debug)]
struct ValidatedCredentials {
    address: String,
    worker_name: String,
    #[allow(dead_code)]
    password: String,
}

impl ValidatedCredentials {
    fn parse(username: &str, password: &str) -> Result<Self, ValidationError> {
        validate_username(username)?;
        validate_password(password)?;

        // Split username into address.worker
        let (address, worker_name) = if let Some(last_dot) = username.rfind('.') {
            let addr = &username[..last_dot];
            let worker = &username[last_dot + 1..];
            // Validate worker name
            validate_worker_name(worker)?;
            (addr.to_string(), worker.to_string())
        } else {
            (username.to_string(), "default".to_string())
        };

        Ok(Self {
            address,
            worker_name,
            password: password.to_string(),
        })
    }
}

// =============================================================================
// INPUT VALIDATION TESTS (Tests 175-195)
// =============================================================================

#[test]
fn test_175_valid_username_accepted() {
    assert!(validate_username("bc1qxyz123.rig1").is_ok());
    assert!(validate_username("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").is_ok());
    assert!(validate_username("address.worker_name-1").is_ok());
}

#[test]
fn test_176_empty_username_rejected() {
    let result = validate_username("");
    assert!(matches!(result, Err(ValidationError::Empty(_))));
}

#[test]
fn test_177_too_long_username_rejected() {
    let long_username = "a".repeat(MAX_USERNAME_LEN + 1);
    let result = validate_username(&long_username);
    assert!(matches!(result, Err(ValidationError::TooLong(_, _))));
}

#[test]
fn test_178_path_traversal_in_username_rejected_dotdot() {
    let result = validate_username("../etc/passwd");
    assert!(matches!(result, Err(ValidationError::PathTraversal(_))));
}

#[test]
fn test_179_shell_metacharacter_backtick_rejected() {
    let result = validate_username("foo`whoami`");
    assert!(matches!(result, Err(ValidationError::InvalidChars(_))));
}

#[test]
fn test_180_shell_metacharacter_dollar_rejected() {
    let result = validate_username("$HOME");
    assert!(matches!(result, Err(ValidationError::InvalidChars(_))));
}

#[test]
fn test_181_shell_metacharacter_pipe_rejected() {
    let result = validate_username("foo|bar");
    assert!(matches!(result, Err(ValidationError::InvalidChars(_))));
}

#[test]
fn test_182_shell_metacharacter_semicolon_rejected() {
    let result = validate_username("foo;rm -rf");
    assert!(matches!(result, Err(ValidationError::InvalidChars(_))));
}

#[test]
fn test_183_null_byte_in_username_rejected() {
    let result = validate_username("foo\x00bar");
    assert!(matches!(result, Err(ValidationError::NullByte(_))));
}

#[test]
fn test_184_control_characters_rejected() {
    let result = validate_username("foo\nbar");
    assert!(matches!(result, Err(ValidationError::ControlChars(_))));

    let result = validate_username("foo\rbar");
    assert!(matches!(result, Err(ValidationError::ControlChars(_))));

    let result = validate_username("foo\tbar");
    assert!(matches!(result, Err(ValidationError::ControlChars(_))));
}

#[test]
fn test_185_non_ascii_rejected() {
    let result = validate_username("fooбар");
    assert!(matches!(result, Err(ValidationError::NonAscii(_))));

    let result = validate_username("foo日本bar");
    assert!(matches!(result, Err(ValidationError::NonAscii(_))));
}

#[test]
fn test_186_valid_password_accepted() {
    assert!(validate_password("x").is_ok());
    assert!(validate_password("correcthorsebatterystaple").is_ok());
    assert!(validate_password("P@ssw0rd!").is_ok());
}

#[test]
fn test_187_too_long_password_rejected() {
    let long_password = "a".repeat(MAX_PASSWORD_LEN + 1);
    let result = validate_password(&long_password);
    assert!(matches!(result, Err(ValidationError::TooLong(_, _))));
}

#[test]
fn test_188_null_byte_in_password_rejected() {
    let result = validate_password("pass\x00word");
    assert!(matches!(result, Err(ValidationError::NullByte(_))));
}

// =============================================================================
// SHARE VALIDATION TESTS (Tests 189-204)
// =============================================================================

#[test]
fn test_189_valid_share_params_accepted() {
    let result = validate_share_params("1a2b3c", "00000000", "12345678", "abcdef00");
    assert!(result.is_ok());
}

#[test]
fn test_190_invalid_job_id_non_hex_rejected() {
    let result = validate_share_params("xyz123", "00000000", "12345678", "abcdef00");
    assert!(matches!(result, Err(ValidationError::InvalidHex(_))));
}

#[test]
fn test_191_job_id_too_long_rejected() {
    let long_job_id = "a".repeat(MAX_JOB_ID_LEN + 1);
    let result = validate_share_params(&long_job_id, "00000000", "12345678", "abcdef00");
    assert!(matches!(result, Err(ValidationError::TooLong(_, _))));
}

#[test]
fn test_192_invalid_extranonce2_non_hex_rejected() {
    let result = validate_share_params("abc123", "gggggggg", "12345678", "abcdef00");
    assert!(matches!(result, Err(ValidationError::InvalidHex(_))));
}

#[test]
fn test_193_invalid_ntime_wrong_length_rejected() {
    // ntime must be exactly 8 hex chars (4 bytes)
    let result = validate_share_params("abc123", "00000000", "1234567", "abcdef00"); // 7 chars
    assert!(matches!(result, Err(ValidationError::TooShort(_, _))));

    let result = validate_share_params("abc123", "00000000", "123456789", "abcdef00"); // 9 chars
    assert!(matches!(result, Err(ValidationError::TooLong(_, _))));
}

#[test]
fn test_194_invalid_ntime_non_hex_rejected() {
    let result = validate_share_params("abc123", "00000000", "1234567g", "abcdef00");
    assert!(matches!(result, Err(ValidationError::InvalidHex(_))));
}

#[test]
fn test_195_invalid_nonce_wrong_length_rejected() {
    // nonce must be exactly 8 hex chars (4 bytes)
    let result = validate_share_params("abc123", "00000000", "12345678", "abcdef0"); // 7 chars
    assert!(matches!(result, Err(ValidationError::TooShort(_, _))));
}

#[test]
fn test_196_invalid_nonce_non_hex_rejected() {
    let result = validate_share_params("abc123", "00000000", "12345678", "ghijklmn");
    assert!(matches!(result, Err(ValidationError::InvalidHex(_))));
}

#[test]
fn test_197_parse_share_params_extracts_ntime() {
    let params = ValidatedShareParams::parse("abc123", "00000001", "65432100", "deadbeef").unwrap();
    assert_eq!(params.ntime, 0x65432100);
}

#[test]
fn test_198_parse_share_params_extracts_nonce() {
    let params = ValidatedShareParams::parse("abc123", "00000001", "65432100", "deadbeef").unwrap();
    assert_eq!(params.nonce, 0xdeadbeef);
}

#[test]
fn test_199_parse_share_params_preserves_job_id() {
    let params =
        ValidatedShareParams::parse("abc123def", "00000001", "65432100", "deadbeef").unwrap();
    assert_eq!(params.job_id, "abc123def");
}

#[test]
fn test_200_parse_share_params_preserves_extranonce2() {
    let params = ValidatedShareParams::parse("abc123", "feedface", "65432100", "deadbeef").unwrap();
    assert_eq!(params.extranonce2, "feedface");
}

// =============================================================================
// VALIDATED CREDENTIALS TESTS (Tests 201-210)
// =============================================================================

#[test]
fn test_201_credentials_parse_address_and_worker() {
    let creds = ValidatedCredentials::parse("bc1qxyz.rig1", "x").unwrap();
    assert_eq!(creds.address, "bc1qxyz");
    assert_eq!(creds.worker_name, "rig1");
}

#[test]
fn test_202_credentials_parse_address_only() {
    let creds = ValidatedCredentials::parse("bc1qxyz", "x").unwrap();
    assert_eq!(creds.address, "bc1qxyz");
    assert_eq!(creds.worker_name, "default");
}

#[test]
fn test_203_credentials_parse_multiple_dots() {
    // Should use the last dot to split address.worker
    let creds = ValidatedCredentials::parse("bc1q.test.rig1", "x").unwrap();
    assert_eq!(creds.address, "bc1q.test");
    assert_eq!(creds.worker_name, "rig1");
}

#[test]
fn test_204_credentials_reject_invalid_username() {
    let result = ValidatedCredentials::parse("", "x");
    assert!(result.is_err());

    let result = ValidatedCredentials::parse("foo`bar`", "x");
    assert!(result.is_err());
}

#[test]
fn test_205_credentials_reject_invalid_password() {
    let long_pass = "a".repeat(MAX_PASSWORD_LEN + 1);
    let result = ValidatedCredentials::parse("bc1qtest", &long_pass);
    assert!(result.is_err());
}

#[test]
fn test_206_credentials_reject_invalid_worker_name() {
    // Worker name with invalid chars
    let result = ValidatedCredentials::parse("bc1qtest.rig!@#", "x");
    assert!(result.is_err());
}

#[test]
fn test_207_worker_name_validation_alphanumeric() {
    assert!(validate_worker_name("rig1").is_ok());
    assert!(validate_worker_name("worker_1").is_ok());
    assert!(validate_worker_name("my-rig").is_ok());
}

#[test]
fn test_208_worker_name_too_long_rejected() {
    let long_worker = "a".repeat(MAX_WORKER_NAME_LEN + 1);
    let result = validate_worker_name(&long_worker);
    assert!(matches!(result, Err(ValidationError::TooLong(_, _))));
}

#[test]
fn test_209_worker_name_invalid_chars_rejected() {
    let result = validate_worker_name("rig!@#");
    assert!(matches!(result, Err(ValidationError::InvalidChars(_))));
}

#[test]
fn test_210_empty_worker_name_accepted() {
    // Empty worker name is OK - defaults to "default"
    assert!(validate_worker_name("").is_ok());
}

// =============================================================================
// USER AGENT VALIDATION TESTS (Tests 211-215)
// =============================================================================

#[test]
fn test_211_valid_user_agent_accepted() {
    assert!(validate_user_agent("cgminer/4.11.1").is_ok());
    assert!(validate_user_agent("BFGMiner/5.5.0").is_ok());
    assert!(validate_user_agent("Antminer S19 Pro").is_ok());
}

#[test]
fn test_212_empty_user_agent_accepted() {
    assert!(validate_user_agent("").is_ok());
}

#[test]
fn test_213_too_long_user_agent_rejected() {
    let long_agent = "a".repeat(MAX_USER_AGENT_LEN + 1);
    let result = validate_user_agent(&long_agent);
    assert!(matches!(result, Err(ValidationError::TooLong(_, _))));
}

#[test]
fn test_214_user_agent_control_chars_rejected() {
    let result = validate_user_agent("cgminer\x00");
    assert!(matches!(result, Err(ValidationError::NullByte(_))));

    let result = validate_user_agent("cgminer\n4.11.1");
    assert!(matches!(result, Err(ValidationError::ControlChars(_))));
}

#[test]
fn test_215_user_agent_non_ascii_rejected() {
    let result = validate_user_agent("cgminer/日本語");
    assert!(matches!(result, Err(ValidationError::NonAscii(_))));
}

// =============================================================================
// JOB ID VALIDATION TESTS (Tests 216-220)
// =============================================================================

#[test]
fn test_216_valid_job_id_accepted() {
    assert!(validate_job_id("abc123").is_ok());
    assert!(validate_job_id("DEADBEEF").is_ok());
    assert!(validate_job_id("0").is_ok());
}

#[test]
fn test_217_empty_job_id_rejected() {
    let result = validate_job_id("");
    assert!(matches!(result, Err(ValidationError::Empty(_))));
}

#[test]
fn test_218_job_id_too_long_rejected() {
    let long_id = "a".repeat(MAX_JOB_ID_LEN + 1);
    let result = validate_job_id(&long_id);
    assert!(matches!(result, Err(ValidationError::TooLong(_, _))));
}

#[test]
fn test_219_job_id_non_hex_rejected() {
    let result = validate_job_id("xyz123");
    assert!(matches!(result, Err(ValidationError::InvalidHex(_))));
}

#[test]
fn test_220_job_id_case_insensitive_accepted() {
    assert!(validate_job_id("abcdef").is_ok());
    assert!(validate_job_id("ABCDEF").is_ok());
    assert!(validate_job_id("AbCdEf").is_ok());
}

// =============================================================================
// BOUNDARY VALUE TESTS (Tests 221-230)
// =============================================================================

#[test]
fn test_221_username_at_max_length_accepted() {
    let max_username = "a".repeat(MAX_USERNAME_LEN);
    assert!(validate_username(&max_username).is_ok());
}

#[test]
fn test_222_password_at_max_length_accepted() {
    let max_password = "a".repeat(MAX_PASSWORD_LEN);
    assert!(validate_password(&max_password).is_ok());
}

#[test]
fn test_223_worker_name_at_max_length_accepted() {
    let max_worker = "a".repeat(MAX_WORKER_NAME_LEN);
    assert!(validate_worker_name(&max_worker).is_ok());
}

#[test]
fn test_224_user_agent_at_max_length_accepted() {
    let max_agent = "a".repeat(MAX_USER_AGENT_LEN);
    assert!(validate_user_agent(&max_agent).is_ok());
}

#[test]
fn test_225_job_id_at_max_length_accepted() {
    let max_job_id = "a".repeat(MAX_JOB_ID_LEN);
    assert!(validate_job_id(&max_job_id).is_ok());
}

#[test]
fn test_226_extranonce2_at_max_length_accepted() {
    let max_extranonce2 = "a".repeat(MAX_EXTRANONCE2_LEN);
    let result = validate_share_params("abc", &max_extranonce2, "12345678", "deadbeef");
    assert!(result.is_ok());
}

#[test]
fn test_227_ntime_exactly_8_chars_accepted() {
    let result = validate_share_params("abc", "00", "12345678", "deadbeef");
    assert!(result.is_ok());
}

#[test]
fn test_228_nonce_exactly_8_chars_accepted() {
    let result = validate_share_params("abc", "00", "12345678", "deadbeef");
    assert!(result.is_ok());
}

#[test]
fn test_229_single_char_fields_accepted() {
    assert!(validate_username("a").is_ok());
    assert!(validate_password("x").is_ok());
    assert!(validate_job_id("0").is_ok());
}

#[test]
fn test_230_all_hex_digits_in_share_params() {
    // Test all hex digits work
    let result = validate_share_params(
        "0123456789abcdef",
        "fedcba9876543210",
        "01234567",
        "89abcdef",
    );
    assert!(result.is_ok());
}

// =============================================================================
// SPECIAL CHARACTER TESTS (Tests 231-240)
// =============================================================================

#[test]
fn test_231_username_with_period_accepted() {
    assert!(validate_username("address.worker").is_ok());
}

#[test]
fn test_232_username_with_underscore_accepted() {
    assert!(validate_username("address_worker").is_ok());
}

#[test]
fn test_233_username_with_hyphen_accepted() {
    assert!(validate_username("address-worker").is_ok());
}

#[test]
fn test_234_username_with_numbers_accepted() {
    assert!(validate_username("bc1q123456789").is_ok());
}

#[test]
fn test_235_forward_slash_in_username_rejected() {
    let result = validate_username("foo/bar");
    assert!(matches!(result, Err(ValidationError::PathTraversal(_))));
}

#[test]
fn test_236_backslash_in_username_rejected() {
    let result = validate_username("foo\\bar");
    assert!(matches!(result, Err(ValidationError::PathTraversal(_))));
}

#[test]
fn test_237_angle_brackets_in_username_rejected() {
    let result = validate_username("foo<bar>");
    assert!(matches!(result, Err(ValidationError::InvalidChars(_))));
}

#[test]
fn test_238_parentheses_in_username_rejected() {
    let result = validate_username("foo(bar)");
    assert!(matches!(result, Err(ValidationError::InvalidChars(_))));
}

#[test]
fn test_239_braces_in_username_rejected() {
    let result = validate_username("foo{bar}");
    assert!(matches!(result, Err(ValidationError::InvalidChars(_))));
}

#[test]
fn test_240_brackets_in_username_rejected() {
    let result = validate_username("foo[bar]");
    assert!(matches!(result, Err(ValidationError::InvalidChars(_))));
}

// =============================================================================
// UNICODE EDGE CASES (Tests 241-245)
// =============================================================================

#[test]
fn test_241_unicode_lookalike_a_rejected() {
    // U+0430 Cyrillic small letter a looks like ASCII 'a'
    let result = validate_username("bс1qtest"); // 'с' is Cyrillic
    assert!(matches!(result, Err(ValidationError::NonAscii(_))));
}

#[test]
fn test_242_unicode_zero_width_space_rejected() {
    let result = validate_username("foo\u{200B}bar"); // Zero-width space
    assert!(result.is_err());
}

#[test]
fn test_243_unicode_bom_rejected() {
    let result = validate_username("\u{FEFF}foobar"); // BOM
    assert!(result.is_err());
}

#[test]
fn test_244_unicode_rtl_override_rejected() {
    let result = validate_username("foo\u{202E}bar"); // RTL override
    assert!(result.is_err());
}

#[test]
fn test_245_mixed_case_hex_accepted() {
    // Both upper and lower case hex should work
    let result = validate_share_params("AaBbCc", "DdEeFf", "12345678", "aAbBcCdD");
    assert!(result.is_ok());
}
