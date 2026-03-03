//! GhostGlyph wallet-side management
//!
//! Provides glyph creation, validation, and rendering for mobile/desktop wallets.
//! Uses the `ghost-glyph` crate for core types and the `GhostPayClient` for API calls.

use crate::network::{GhostPayClient, GlyphClaimResponse, GlyphInfo, NetworkError, PayConfig};

// Re-export core glyph types for convenient access
pub use ghost_glyph::{
    palette_index_to_rgb, render_rgba, rendered_dimensions, GhostGlyph, GlyphError, GLYPH_HEIGHT,
    GLYPH_SIZE, GLYPH_WIDTH, MAX_SCALE, PALETTE, PALETTE_SIZE,
};

/// Validate a Ghost Pay URL to prevent SSRF.
///
/// Rejects non-HTTP(S) schemes and URLs containing embedded credentials (`@`).
pub fn validate_pay_url(url: &str) -> Result<(), NetworkError> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(NetworkError::ConnectionFailed(
            "pay_url scheme must be http:// or https://".to_string(),
        ));
    }
    // Reject embedded credentials (user:pass@host)
    let after_scheme = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else {
        url.strip_prefix("http://").unwrap_or("")
    };
    if after_scheme.contains('@') {
        return Err(NetworkError::ConnectionFailed(
            "pay_url must not contain credentials".to_string(),
        ));
    }
    // Must have a non-empty host portion
    let host_part = after_scheme.split('/').next().unwrap_or("");
    if host_part.is_empty() {
        return Err(NetworkError::ConnectionFailed(
            "pay_url must have a host".to_string(),
        ));
    }
    Ok(())
}

/// Wallet-side glyph manager
///
/// Handles glyph design, claiming via Ghost Pay API, and local rendering.
pub struct GlyphManager {
    client: GhostPayClient,
}

impl GlyphManager {
    /// Create a new glyph manager connected to a Ghost Pay node
    pub fn new(config: PayConfig) -> Result<Self, NetworkError> {
        let client = GhostPayClient::new(config)?;
        Ok(Self { client })
    }

    /// Create a glyph manager using a shared reqwest::Client (avoids per-request pool creation)
    pub fn with_client(config: PayConfig, http_client: reqwest::Client) -> Self {
        Self {
            client: GhostPayClient::with_client(config, http_client),
        }
    }

    /// Validate a pixel array (all values in 0..25, correct size)
    pub fn validate_pixels(pixels: &[u8]) -> Result<(), GlyphError> {
        GhostGlyph::validate_pixel_slice(pixels)
    }

    /// Compute the bitmap hash for a design (to check availability before claiming)
    pub fn compute_bitmap_hash(pixels: &[u8; GLYPH_SIZE]) -> [u8; 32] {
        GhostGlyph::compute_bitmap_hash(pixels)
    }

    /// Check if a glyph design is available for registration
    pub async fn is_available(&self, pixels: &[u8; GLYPH_SIZE]) -> Result<bool, NetworkError> {
        let hash = GhostGlyph::compute_bitmap_hash(pixels);
        let hash_hex = hex::encode(hash);
        self.client.check_glyph_availability(&hash_hex).await
    }

    /// Submit a glyph claim (design chosen, pending lock funding)
    ///
    /// Validates pixels locally before sending to the network.
    pub async fn claim(
        &self,
        ghost_id: &str,
        pixels: &[u8],
    ) -> Result<GlyphClaimResponse, NetworkError> {
        GhostGlyph::validate_pixel_slice(pixels).map_err(|e| {
            NetworkError::RequestFailed(format!("Invalid pixels: {}", e))
        })?;
        self.client.claim_glyph(ghost_id, pixels).await
    }

    /// Get glyph info for a ghost ID
    pub async fn get_glyph(&self, ghost_id: &str) -> Result<Option<GlyphInfo>, NetworkError> {
        self.client.get_glyph(ghost_id).await
    }

    /// Render a glyph as RGBA pixel data at the given scale factor.
    ///
    /// Returns raw RGBA bytes suitable for display in a UI framework.
    /// Width = GLYPH_WIDTH * scale, Height = GLYPH_HEIGHT * scale.
    pub fn render(glyph: &GhostGlyph, scale: u32) -> Result<Vec<u8>, GlyphError> {
        render_rgba(glyph, scale)
    }

    /// Get the rendered dimensions for a given scale factor
    pub fn dimensions(scale: u32) -> Result<(u32, u32), GlyphError> {
        rendered_dimensions(scale)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid_pixels() {
        let pixels = [0u8; GLYPH_SIZE];
        assert!(GlyphManager::validate_pixels(&pixels).is_ok());
    }

    #[test]
    fn test_validate_invalid_pixel() {
        let mut pixels = [0u8; GLYPH_SIZE];
        pixels[0] = 26; // out of range
        assert!(GlyphManager::validate_pixels(&pixels).is_err());
    }

    #[test]
    fn test_compute_bitmap_hash_deterministic() {
        let pixels = [5u8; GLYPH_SIZE];
        let hash1 = GlyphManager::compute_bitmap_hash(&pixels);
        let hash2 = GlyphManager::compute_bitmap_hash(&pixels);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_render_dimensions() {
        let (w, h) = GlyphManager::dimensions(4).unwrap();
        assert_eq!(w, 64); // 16 * 4
        assert_eq!(h, 64); // 16 * 4
    }

    #[test]
    fn test_render_output_size() {
        let glyph = GhostGlyph::new([0u8; GLYPH_SIZE], "ghost1test".to_string()).unwrap();
        let rgba = GlyphManager::render(&glyph, 2).unwrap();
        // 16*2 * 16*2 * 4 bytes per pixel
        assert_eq!(rgba.len(), 32 * 32 * 4);
    }

    #[test]
    fn test_palette_reexport() {
        // Verify palette is accessible via this module
        assert_eq!(PALETTE.len(), PALETTE_SIZE);
        assert!(palette_index_to_rgb(0).is_some());
        assert!(palette_index_to_rgb(25).is_some());
        assert!(palette_index_to_rgb(26).is_none());
    }

    #[test]
    fn test_validate_pay_url_valid() {
        assert!(validate_pay_url("http://127.0.0.1:8800").is_ok());
        assert!(validate_pay_url("https://ghost-pay.example.com").is_ok());
        assert!(validate_pay_url("http://localhost:8800/api").is_ok());
    }

    #[test]
    fn test_validate_pay_url_bad_scheme() {
        assert!(validate_pay_url("ftp://evil.com").is_err());
        assert!(validate_pay_url("file:///etc/passwd").is_err());
        assert!(validate_pay_url("javascript:alert(1)").is_err());
    }

    #[test]
    fn test_validate_pay_url_embedded_credentials() {
        assert!(validate_pay_url("http://user:pass@evil.com").is_err());
        assert!(validate_pay_url("http://admin@evil.com").is_err());
    }

    #[test]
    fn test_validate_pay_url_no_host() {
        assert!(validate_pay_url("http://").is_err());
        assert!(validate_pay_url("https://").is_err());
    }
}
