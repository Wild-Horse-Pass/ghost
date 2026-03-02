//! RGBA rendering for GhostGlyph bitmaps.
//!
//! Produces raw RGBA pixel data from glyph bitmaps. No external image
//! dependencies — output is suitable for direct framebuffer or UI display.

use crate::glyph::{GhostGlyph, GLYPH_HEIGHT, GLYPH_WIDTH};
use crate::palette::PALETTE;

/// Maximum render scale factor (256x produces 4096x4096 = 64MB RGBA).
const MAX_SCALE: u32 = 256;

/// Render a glyph to raw RGBA pixel data at the given scale factor.
///
/// Each glyph pixel becomes a `scale x scale` block of RGBA pixels.
/// Returns a Vec of (width * scale * height * scale * 4) bytes.
///
/// Scale must be 1..=256. Returns an empty Vec if scale is 0 or exceeds MAX_SCALE.
pub fn render_rgba(glyph: &GhostGlyph, scale: u32) -> Vec<u8> {
    if scale == 0 || scale > MAX_SCALE {
        return Vec::new();
    }
    let w = GLYPH_WIDTH as u32 * scale;
    let h = GLYPH_HEIGHT as u32 * scale;
    let mut buf = vec![0u8; (w * h * 4) as usize];

    for gy in 0..GLYPH_HEIGHT as u32 {
        for gx in 0..GLYPH_WIDTH as u32 {
            let idx = glyph.pixels[(gy * GLYPH_WIDTH as u32 + gx) as usize] as usize;
            let (r, g, b) = if idx < PALETTE.len() {
                PALETTE[idx]
            } else {
                (255, 0, 255) // Magenta for invalid
            };

            for sy in 0..scale {
                for sx in 0..scale {
                    let px = (gx * scale + sx) as usize;
                    let py = (gy * scale + sy) as usize;
                    let offset = (py * w as usize + px) * 4;
                    buf[offset] = r;
                    buf[offset + 1] = g;
                    buf[offset + 2] = b;
                    buf[offset + 3] = 255; // Fully opaque
                }
            }
        }
    }

    buf
}

/// Get the rendered dimensions for a given scale factor.
pub fn rendered_dimensions(scale: u32) -> (u32, u32) {
    (GLYPH_WIDTH as u32 * scale, GLYPH_HEIGHT as u32 * scale)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::glyph::GLYPH_SIZE;

    #[test]
    fn test_render_rgba_dimensions() {
        let pixels = [0u8; GLYPH_SIZE];
        let glyph = GhostGlyph::new(pixels, "ghost1test".to_string()).unwrap();

        let scale = 4;
        let buf = render_rgba(&glyph, scale);
        let (w, h) = rendered_dimensions(scale);
        assert_eq!(buf.len(), (w * h * 4) as usize);
    }

    #[test]
    fn test_render_rgba_single_color() {
        let pixels = [1u8; GLYPH_SIZE]; // All Phantom White
        let glyph = GhostGlyph::new(pixels, "ghost1test".to_string()).unwrap();

        let buf = render_rgba(&glyph, 1);
        // Every pixel should be (255, 255, 255, 255)
        for chunk in buf.chunks(4) {
            assert_eq!(chunk, &[255, 255, 255, 255]);
        }
    }
}
