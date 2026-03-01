//! Merchant profile management
//!
//! Stores business identity information used on receipts, invoices,
//! and other merchant-facing surfaces.

use serde::{Deserialize, Serialize};

/// Merchant business profile.
///
/// Contains all the identifying information for a merchant, including
/// business name, address, optional tax ID, and the Ghost address that
/// receives payments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerchantProfile {
    /// Business name displayed on receipts and invoices.
    pub business_name: String,
    /// Business street / postal address.
    pub business_address: String,
    /// Tax identification number (optional, jurisdiction-dependent).
    pub tax_id: Option<String>,
    /// Local path to a logo image used on receipts.
    pub logo_path: Option<String>,
    /// Ghost address that receives merchant payments.
    pub ghost_address: String,
    /// Whether incoming payments are automatically washed via Wraith.
    pub auto_wash: bool,
    /// Unix timestamp when this profile was created.
    pub created_at: u64,
}

impl MerchantProfile {
    /// Create a new merchant profile.
    ///
    /// `auto_wash` defaults to false; `created_at` should be the current
    /// unix timestamp.
    pub fn new(
        business_name: impl Into<String>,
        business_address: impl Into<String>,
        ghost_address: impl Into<String>,
        created_at: u64,
    ) -> Self {
        Self {
            business_name: business_name.into(),
            business_address: business_address.into(),
            tax_id: None,
            logo_path: None,
            ghost_address: ghost_address.into(),
            auto_wash: false,
            created_at,
        }
    }

    /// Builder-style setter for the tax ID.
    pub fn with_tax_id(mut self, tax_id: impl Into<String>) -> Self {
        self.tax_id = Some(tax_id.into());
        self
    }

    /// Builder-style setter for logo path.
    pub fn with_logo(mut self, path: impl Into<String>) -> Self {
        self.logo_path = Some(path.into());
        self
    }

    /// Builder-style setter for auto-wash.
    pub fn with_auto_wash(mut self, enabled: bool) -> Self {
        self.auto_wash = enabled;
        self
    }

    /// Serialize the profile to a JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize a profile from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_roundtrip() {
        let profile = MerchantProfile::new(
            "Ghost Cafe",
            "123 Main St, Anytown, USA",
            "GhAddr123abc",
            1709164800,
        )
        .with_tax_id("US-12345678")
        .with_auto_wash(true);

        let json = profile.to_json().unwrap();
        let restored = MerchantProfile::from_json(&json).unwrap();

        assert_eq!(restored.business_name, "Ghost Cafe");
        assert_eq!(restored.tax_id.as_deref(), Some("US-12345678"));
        assert!(restored.auto_wash);
        assert_eq!(restored.ghost_address, "GhAddr123abc");
    }

    #[test]
    fn test_profile_defaults() {
        let profile = MerchantProfile::new("Shop", "Addr", "GhAddr", 0);
        assert!(!profile.auto_wash);
        assert!(profile.tax_id.is_none());
        assert!(profile.logo_path.is_none());
    }

    #[test]
    fn test_builder_with_logo() {
        let profile = MerchantProfile::new("Bake Shop", "High St", "GhAddr", 100)
            .with_logo("/images/logo.png");
        assert_eq!(profile.logo_path.as_deref(), Some("/images/logo.png"));
    }

    #[test]
    fn test_builder_chaining_all() {
        let profile = MerchantProfile::new("Full", "123 Elm", "GhFull", 999)
            .with_tax_id("GB-VAT-123")
            .with_logo("/logo.svg")
            .with_auto_wash(true);

        assert_eq!(profile.business_name, "Full");
        assert_eq!(profile.business_address, "123 Elm");
        assert_eq!(profile.ghost_address, "GhFull");
        assert_eq!(profile.created_at, 999);
        assert_eq!(profile.tax_id.as_deref(), Some("GB-VAT-123"));
        assert_eq!(profile.logo_path.as_deref(), Some("/logo.svg"));
        assert!(profile.auto_wash);
    }

    #[test]
    fn test_json_preserves_all_fields() {
        let profile = MerchantProfile::new("Test", "Addr", "Gh1", 42)
            .with_tax_id("TAX")
            .with_logo("/logo")
            .with_auto_wash(true);

        let json = profile.to_json().unwrap();
        let restored = MerchantProfile::from_json(&json).unwrap();

        assert_eq!(restored.business_name, profile.business_name);
        assert_eq!(restored.business_address, profile.business_address);
        assert_eq!(restored.ghost_address, profile.ghost_address);
        assert_eq!(restored.created_at, profile.created_at);
        assert_eq!(restored.tax_id, profile.tax_id);
        assert_eq!(restored.logo_path, profile.logo_path);
        assert_eq!(restored.auto_wash, profile.auto_wash);
    }

    #[test]
    fn test_from_json_invalid() {
        let result = MerchantProfile::from_json("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_json_missing_fields() {
        let result = MerchantProfile::from_json(r#"{"business_name": "X"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_unicode_fields() {
        let profile = MerchantProfile::new("幽霊カフェ", "東京都渋谷区", "GhAddr", 0);
        let json = profile.to_json().unwrap();
        let restored = MerchantProfile::from_json(&json).unwrap();
        assert_eq!(restored.business_name, "幽霊カフェ");
        assert_eq!(restored.business_address, "東京都渋谷区");
    }

    #[test]
    fn test_empty_strings_valid() {
        let profile = MerchantProfile::new("", "", "", 0);
        assert_eq!(profile.business_name, "");
        let json = profile.to_json().unwrap();
        let restored = MerchantProfile::from_json(&json).unwrap();
        assert_eq!(restored.business_name, "");
    }

    #[test]
    fn test_auto_wash_toggle() {
        let profile = MerchantProfile::new("S", "A", "G", 0).with_auto_wash(true);
        assert!(profile.auto_wash);
        let profile = profile.with_auto_wash(false);
        assert!(!profile.auto_wash);
    }
}
