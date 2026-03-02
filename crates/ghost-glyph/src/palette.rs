//! GhostGlyph 26-color palette
//!
//! Ghost-themed palette with spectral, ethereal colors.
//! Each index (0..25) maps to an (R, G, B) tuple.

/// 26-color ghost-themed palette
pub const PALETTE: [(u8, u8, u8); 26] = [
    // Core tones
    (0, 0, 0),         //  0: Void Black
    (255, 255, 255),    //  1: Phantom White
    (28, 28, 36),       //  2: Midnight
    (48, 48, 64),       //  3: Shadow
    (80, 80, 104),      //  4: Dusk
    (128, 128, 160),    //  5: Fog
    (192, 192, 212),    //  6: Mist
    // Spectral blues
    (24, 32, 80),       //  7: Deep Haunt
    (40, 60, 140),      //  8: Specter Blue
    (64, 100, 200),     //  9: Wraith Blue
    (120, 160, 230),    // 10: Ether
    // Ghostly greens
    (16, 48, 32),       // 11: Crypt Green
    (32, 100, 64),      // 12: Ectoplasm
    (80, 200, 120),     // 13: Poltergeist
    (160, 240, 180),    // 14: Spirit Glow
    // Ember / warning
    (80, 16, 16),       // 15: Blood Shadow
    (160, 40, 24),      // 16: Ember
    (220, 80, 40),      // 17: Hellfire
    (255, 160, 80),     // 18: Lantern
    // Purple / arcane
    (48, 16, 80),       // 19: Abyss Purple
    (100, 40, 160),     // 20: Phantom Violet
    (160, 80, 220),     // 21: Arcane
    (200, 160, 255),    // 22: Spectral Lilac
    // Accents
    (255, 220, 60),     // 23: Soul Gold
    (0, 200, 200),      // 24: Ghost Teal
    (255, 100, 160),    // 25: Banshee Pink
];

/// Get the RGB color for a palette index.
///
/// Returns `None` if the index is out of range (>= 26).
pub fn palette_index_to_rgb(index: u8) -> Option<(u8, u8, u8)> {
    PALETTE.get(index as usize).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_palette_coverage() {
        // All 26 indices should map to valid RGB values
        for i in 0u8..26 {
            let rgb = palette_index_to_rgb(i);
            assert!(rgb.is_some(), "Palette index {} should be valid", i);
        }
    }

    #[test]
    fn test_palette_out_of_range() {
        assert!(palette_index_to_rgb(26).is_none());
        assert!(palette_index_to_rgb(255).is_none());
    }

    #[test]
    fn test_palette_known_values() {
        assert_eq!(palette_index_to_rgb(0), Some((0, 0, 0)));       // Void Black
        assert_eq!(palette_index_to_rgb(1), Some((255, 255, 255))); // Phantom White
        assert_eq!(palette_index_to_rgb(25), Some((255, 100, 160))); // Banshee Pink
    }
}
