use crate::error::{AppError, AppResult};
use crate::state::AppState;
use ghost_tap_core::glyph::{validate_pay_url, GhostGlyph, GlyphManager, GLYPH_SIZE, PALETTE};
use ghost_tap_core::network::PayConfig;
use serde::Serialize;
use tauri::State;

#[derive(Serialize)]
pub struct GlyphClaimResult {
    pub commitment: String,
    pub bitmap_hash: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct GlyphInfoResult {
    pub ghost_id: String,
    pub pixels: Vec<u8>,
    pub bitmap_hash: String,
    pub commitment: String,
    pub funding_txid: Option<String>,
    pub registered_at: Option<u64>,
    pub status: String,
}

#[derive(Serialize)]
pub struct PaletteColor {
    pub index: u8,
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

fn make_manager(state: &AppState, pay_url: &str) -> AppResult<GlyphManager> {
    validate_pay_url(pay_url).map_err(|e| AppError::from(e.to_string()))?;
    let config = PayConfig {
        base_url: pay_url.to_string(),
        ..PayConfig::default()
    };
    Ok(GlyphManager::with_client(config, state.http_client.clone()))
}

/// Submit a glyph claim for a ghost ID
#[tauri::command]
pub async fn claim_glyph(
    state: State<'_, AppState>,
    ghost_id: String,
    pixels: Vec<u8>,
    pay_url: String,
) -> AppResult<GlyphClaimResult> {
    // Validate pixels before sending to network
    GlyphManager::validate_pixels(&pixels).map_err(|e| AppError::from(e.to_string()))?;

    let manager = make_manager(&state, &pay_url)?;
    let resp = manager
        .claim(&ghost_id, &pixels)
        .await
        .map_err(|e| AppError::from(e.to_string()))?;

    Ok(GlyphClaimResult {
        commitment: resp.commitment,
        bitmap_hash: resp.bitmap_hash,
        status: resp.status,
    })
}

/// Get glyph info for a ghost ID
#[tauri::command]
pub async fn get_glyph(
    state: State<'_, AppState>,
    ghost_id: String,
    pay_url: String,
) -> AppResult<Option<GlyphInfoResult>> {
    let manager = make_manager(&state, &pay_url)?;
    let info = manager
        .get_glyph(&ghost_id)
        .await
        .map_err(|e| AppError::from(e.to_string()))?;

    Ok(info.map(|g| GlyphInfoResult {
        ghost_id: g.ghost_id,
        pixels: g.pixels,
        bitmap_hash: g.bitmap_hash,
        commitment: g.commitment,
        funding_txid: g.funding_txid,
        registered_at: g.registered_at,
        status: g.status,
    }))
}

/// Check if a glyph design is available
#[tauri::command]
pub async fn check_glyph_availability(
    state: State<'_, AppState>,
    pixels: Vec<u8>,
    pay_url: String,
) -> AppResult<bool> {
    if pixels.len() != GLYPH_SIZE {
        return Err(AppError::from(format!(
            "Expected {} pixels, got {}",
            GLYPH_SIZE,
            pixels.len()
        )));
    }

    let pixel_arr: [u8; GLYPH_SIZE] = pixels
        .as_slice()
        .try_into()
        .map_err(|_| AppError::from("Invalid pixel array"))?;

    let manager = make_manager(&state, &pay_url)?;
    manager
        .is_available(&pixel_arr)
        .await
        .map_err(|e| AppError::from(e.to_string()))
}

/// Render a glyph as RGBA pixel data at a given scale
#[tauri::command]
pub fn render_glyph(pixels: Vec<u8>, ghost_id: String, scale: u32) -> AppResult<Vec<u8>> {
    if pixels.len() != GLYPH_SIZE {
        return Err(AppError::from(format!(
            "Expected {} pixels, got {}",
            GLYPH_SIZE,
            pixels.len()
        )));
    }

    let pixel_arr: [u8; GLYPH_SIZE] = pixels
        .as_slice()
        .try_into()
        .map_err(|_| AppError::from("Invalid pixel array"))?;

    let glyph = GhostGlyph::new(pixel_arr, ghost_id).map_err(|e| AppError::from(e.to_string()))?;

    GlyphManager::render(&glyph, scale).map_err(|e| AppError::from(e.to_string()))
}

/// Get the full 26-color palette
#[tauri::command]
pub fn get_glyph_palette() -> Vec<PaletteColor> {
    PALETTE
        .iter()
        .enumerate()
        .map(|(i, &(r, g, b))| PaletteColor {
            index: i as u8,
            r,
            g,
            b,
        })
        .collect()
}

/// Validate pixel values (all 0..25, correct length)
#[tauri::command]
pub fn validate_glyph_pixels(pixels: Vec<u8>) -> AppResult<bool> {
    GlyphManager::validate_pixels(&pixels).map_err(|e| AppError::from(e.to_string()))?;
    Ok(true)
}
