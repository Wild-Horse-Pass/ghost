//! GhostGlyph error types

use thiserror::Error;

/// Errors for GhostGlyph operations
#[derive(Debug, Error)]
pub enum GlyphError {
    /// A pixel value exceeds the palette range (0..25)
    #[error("Invalid pixel value at index {index}: {value} (max 25)")]
    InvalidPixelValue { index: usize, value: u8 },

    /// The pixel array is not the expected size (256 bytes)
    #[error("Invalid pixel array size: expected {expected}, got {got}")]
    InvalidSize { expected: usize, got: usize },

    /// Another ghost ID already registered this exact bitmap
    #[error("Bitmap already registered by another ghost ID")]
    DuplicateBitmap,

    /// This ghost ID already has a registered glyph
    #[error("Ghost ID already has a registered glyph")]
    AlreadyRegistered,

    /// Scale factor is out of the valid range (1..=256)
    #[error("Invalid scale factor: {0} (must be 1..=256)")]
    InvalidScale(u32),

    /// No glyph found for the given query
    #[error("Glyph not found")]
    NotFound,

    /// Storage layer error
    #[error("Storage error: {0}")]
    StorageError(String),
}
