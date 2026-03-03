```
//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: GHOST_GLYPHS.md                                                                                                |
//|======================================================================================================================|
```

# GhostGlyph

Visual identity system for Ghost IDs -- permanent 16x16 pixel ghost avatars.

## Overview

GhostGlyphs are unique 16x16 pixel bitmaps permanently bound to Ghost IDs. Each glyph serves as a visual identity in wallets, merchant terminals, and the node TUI. Once registered, a glyph cannot be changed or reassigned.

## Registration

1. User designs a 16x16 pixel glyph using the 26-color palette
2. Commitment hash computed: `SHA256("GhostGlyph/v1" || pixels || ghost_id)`
3. Registration funded via Wraith deposit (Ghost Lock)
4. Commitment and bitmap uniqueness hash recorded on-chain
5. Glyph permanently bound to the Ghost ID

Registration records the `registered_at` timestamp and `funding_txid` from the Wraith deposit that triggered it. Before funding, these fields remain unset and the glyph is considered pending.

## Pixel Format

- **Grid**: 16x16 = 256 pixels
- **Storage**: 256 bytes (one byte per pixel, palette index)
- **Palette**: 26 colors (indices 0-25)
- Invalid palette indices (>= 26) are rejected at creation with `GlyphError::InvalidPixelValue`
- Pixel slices that are not exactly 256 bytes are rejected with `GlyphError::InvalidSize`

## Color Palette

26 ghost-themed spectral and ethereal colors:

| Index | Name | RGB | Hex |
|-------|------|-----|-----|
| 0 | Void Black | (0, 0, 0) | `#000000` |
| 1 | Phantom White | (255, 255, 255) | `#FFFFFF` |
| 2 | Midnight | (28, 28, 36) | `#1C1C24` |
| 3 | Shadow | (48, 48, 64) | `#303040` |
| 4 | Dusk | (80, 80, 104) | `#505068` |
| 5 | Fog | (128, 128, 160) | `#8080A0` |
| 6 | Mist | (192, 192, 212) | `#C0C0D4` |
| 7 | Deep Haunt | (24, 32, 80) | `#182050` |
| 8 | Specter Blue | (40, 60, 140) | `#283C8C` |
| 9 | Wraith Blue | (64, 100, 200) | `#4064C8` |
| 10 | Ether | (120, 160, 230) | `#78A0E6` |
| 11 | Crypt Green | (16, 48, 32) | `#103020` |
| 12 | Ectoplasm | (32, 100, 64) | `#206440` |
| 13 | Poltergeist | (80, 200, 120) | `#50C878` |
| 14 | Spirit Glow | (160, 240, 180) | `#A0F0B4` |
| 15 | Blood Shadow | (80, 16, 16) | `#501010` |
| 16 | Ember | (160, 40, 24) | `#A02818` |
| 17 | Hellfire | (220, 80, 40) | `#DC5028` |
| 18 | Lantern | (255, 160, 80) | `#FFA050` |
| 19 | Abyss Purple | (48, 16, 80) | `#301050` |
| 20 | Phantom Violet | (100, 40, 160) | `#6428A0` |
| 21 | Arcane | (160, 80, 220) | `#A050DC` |
| 22 | Spectral Lilac | (200, 160, 255) | `#C8A0FF` |
| 23 | Soul Gold | (255, 220, 60) | `#FFDC3C` |
| 24 | Ghost Teal | (0, 200, 200) | `#00C8C8` |
| 25 | Banshee Pink | (255, 100, 160) | `#FF64A0` |

The palette is organized into five groups:
- **Core tones** (0-6): Grayscale from black to near-white with cool blue undertones
- **Spectral blues** (7-10): Deep ocean to bright sky, the primary ghost identity colors
- **Ghostly greens** (11-14): Dark crypt to luminous spirit, for ectoplasmic effects
- **Ember / warning** (15-18): Blood red to warm lantern, for danger and warmth accents
- **Purple / arcane** (19-22): Deep abyss to soft lilac, for mystical elements
- **Accents** (23-25): Gold, teal, and pink highlights for distinctive features

## Hashing

Both hashes use domain-separated SHA-256 to prevent cross-protocol collisions.

### Commitment Hash

```
commitment = SHA256("GhostGlyph/v1" || pixel_bytes[256] || ghost_id_bytes)
```

Binds the glyph design to a specific Ghost ID. Two different Ghost IDs using the same pixel data will produce different commitment hashes. The `ghost_id_bytes` are the UTF-8 encoding of the bech32m `ghost1...` address.

### Bitmap Uniqueness Hash

```
bitmap_hash = SHA256("GhostGlyphBitmap/v1" || pixel_bytes[256])
```

Identity-independent hash of the raw pixel data. Used to enforce global uniqueness -- each pixel pattern can only be registered once across the entire network. Two glyphs with identical pixels will always produce the same bitmap hash regardless of which Ghost ID they are associated with.

## GhostGlyph Struct

```rust
pub struct GhostGlyph {
    pub pixels: [u8; 256],          // 16x16 palette indices (0-25)
    pub ghost_id: String,           // bech32m ghost1... address
    pub commitment: [u8; 32],       // SHA256 binding commitment
    pub bitmap_hash: [u8; 32],      // SHA256 uniqueness key
    pub registered_at: Option<u64>, // Unix timestamp (None if pending)
    pub funding_txid: Option<String>, // Wraith deposit txid (None if pending)
}
```

Construction via `GhostGlyph::new(pixels, ghost_id)` validates all pixel values and computes both hashes. The `registered_at` and `funding_txid` fields are initially `None` and populated when the Wraith deposit is confirmed.

## Rendering

Glyphs are rendered as raw RGBA pixel data at configurable scale factors. The renderer has no external image library dependencies -- output is suitable for direct framebuffer or UI display.

Each pixel in the source glyph becomes a `scale x scale` block of fully opaque (alpha = 255) RGBA pixels in the output buffer. Invalid palette indices (which should never pass validation) render as magenta `(255, 0, 255)` as a debug safety net.

| Scale | Output Size | Buffer Size | Use Case |
|-------|-------------|-------------|----------|
| 1x | 16x16 | 1,024 bytes | Thumbnails, list views |
| 2x | 32x32 | 4,096 bytes | Standard display |
| 4x | 64x64 | 16,384 bytes | Profile views |
| 8x | 128x128 | 65,536 bytes | Large display |
| 16x | 256x256 | 262,144 bytes | Print / export |
| 32x | 512x512 | 1,048,576 bytes | High-resolution export |
| 256x | 4096x4096 | 67,108,864 bytes | Maximum resolution |

The maximum scale factor is 256 (producing 4096x4096 output). Scale factors of 0 or greater than 256 are rejected with `GlyphError::InvalidScale`.

Output buffer layout: `width * scale * height * scale * 4` bytes, with pixels stored in row-major RGBA order.

## Uniqueness

- `bitmap_hash` (domain-separated SHA-256 of raw pixels) is stored at registration
- No two Ghost IDs can share the same glyph design
- Registration fails with `GlyphError::DuplicateBitmap` if `bitmap_hash` already exists
- A Ghost ID that already has a glyph cannot register another (`GlyphError::AlreadyRegistered`)

## Error Handling

All operations use the `GlyphError` enum:

| Variant | Cause |
|---------|-------|
| `InvalidPixelValue { index, value }` | Pixel at `index` has value >= 26 |
| `InvalidSize { expected, got }` | Pixel slice is not exactly 256 bytes |
| `DuplicateBitmap` | Another Ghost ID already registered this exact bitmap |
| `AlreadyRegistered` | This Ghost ID already has a registered glyph |
| `InvalidScale(scale)` | Render scale is 0 or exceeds 256 |
| `NotFound` | No glyph found for the given query |
| `StorageError(msg)` | Database or storage layer failure |

## Integration

| Context | Display |
|---------|---------|
| GhostTap wallet | Contact list, payment screens |
| Merchant terminal | Customer identity during payment |
| Node TUI | Peer list, elder roster |
| Ghost Pay | Transaction receipts |

## Source Files

| File | Purpose |
|------|---------|
| `crates/ghost-glyph/src/lib.rs` | Crate entry point and re-exports |
| `crates/ghost-glyph/src/glyph.rs` | GhostGlyph struct, validation, commitment and bitmap hashing |
| `crates/ghost-glyph/src/palette.rs` | 26-color ghost-themed palette definition |
| `crates/ghost-glyph/src/render.rs` | Raw RGBA rendering at configurable scale factors |
| `crates/ghost-glyph/src/error.rs` | GlyphError enum (thiserror-based) |

## Related Documentation

- [GhostTap](GHOST_TAP.md) - Mobile wallet displaying glyphs
- [Ghost Keys](GHOST_KEYS.md) - Ghost ID system
- [Ghost Locks](GHOST_LOCKS.md) - Wraith deposit funding mechanism
- [Wraith Protocol](WRAITH_PROTOCOL.md) - CoinJoin mixing used for registration funding
