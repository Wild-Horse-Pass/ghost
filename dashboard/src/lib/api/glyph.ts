// Ghost Glyph API
import { fetchWithTimeout } from './client';

export interface PaletteColor {
  index: number;
  name: string;
  r: number;
  g: number;
  b: number;
}

export interface GlyphInfo {
  ghost_id: string;
  pixels: number[];
  bitmap_hash: string;
  commitment: string;
  status: string;
}

export interface GlyphClaimResult {
  commitment: string;
  bitmap_hash: string;
}

export const GLYPH_PALETTE: PaletteColor[] = [
  { index: 0, name: 'Void Black', r: 0, g: 0, b: 0 },
  { index: 1, name: 'Phantom White', r: 255, g: 255, b: 255 },
  { index: 2, name: 'Midnight', r: 28, g: 28, b: 36 },
  { index: 3, name: 'Shadow', r: 48, g: 48, b: 64 },
  { index: 4, name: 'Dusk', r: 80, g: 80, b: 104 },
  { index: 5, name: 'Fog', r: 128, g: 128, b: 160 },
  { index: 6, name: 'Mist', r: 192, g: 192, b: 212 },
  { index: 7, name: 'Deep Haunt', r: 24, g: 32, b: 80 },
  { index: 8, name: 'Specter Blue', r: 40, g: 60, b: 140 },
  { index: 9, name: 'Wraith Blue', r: 64, g: 100, b: 200 },
  { index: 10, name: 'Ether', r: 120, g: 160, b: 230 },
  { index: 11, name: 'Crypt Green', r: 16, g: 48, b: 32 },
  { index: 12, name: 'Ectoplasm', r: 32, g: 100, b: 64 },
  { index: 13, name: 'Poltergeist', r: 80, g: 200, b: 120 },
  { index: 14, name: 'Spirit Glow', r: 160, g: 240, b: 180 },
  { index: 15, name: 'Blood Shadow', r: 80, g: 16, b: 16 },
  { index: 16, name: 'Ember', r: 160, g: 40, b: 24 },
  { index: 17, name: 'Hellfire', r: 220, g: 80, b: 40 },
  { index: 18, name: 'Lantern', r: 255, g: 160, b: 80 },
  { index: 19, name: 'Abyss Purple', r: 48, g: 16, b: 80 },
  { index: 20, name: 'Phantom Violet', r: 100, g: 40, b: 160 },
  { index: 21, name: 'Arcane', r: 160, g: 80, b: 220 },
  { index: 22, name: 'Spectral Lilac', r: 200, g: 160, b: 255 },
  { index: 23, name: 'Soul Gold', r: 255, g: 220, b: 60 },
  { index: 24, name: 'Ghost Teal', r: 0, g: 200, b: 200 },
  { index: 25, name: 'Banshee Pink', r: 255, g: 100, b: 160 },
];

function getGhostPayProxyBase(): string {
  if (typeof window !== 'undefined') {
    return window.location.origin;
  }
  return 'http://localhost:3000';
}

async function fetchGhostPay<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const proxyUrl = `${getGhostPayProxyBase()}/api/ghostpay-proxy${endpoint}`;

  const response = await fetchWithTimeout(proxyUrl, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || `API error: ${response.status}`);
  }

  return response.json();
}

export async function getGlyph(ghostId: string): Promise<GlyphInfo> {
  return fetchGhostPay<GlyphInfo>(`/api/v1/glyph/${ghostId}`);
}

export async function checkGlyphAvailability(bitmapHashHex: string): Promise<{ available: boolean }> {
  return fetchGhostPay<{ available: boolean }>(`/api/v1/glyph/check/${bitmapHashHex}`);
}

export async function claimGlyph(ghostId: string, pixels: number[]): Promise<GlyphClaimResult> {
  return fetchGhostPay<GlyphClaimResult>('/api/v1/glyph/claim', {
    method: 'POST',
    body: JSON.stringify({ ghost_id: ghostId, pixels }),
  });
}

export async function computeBitmapHash(pixels: number[]): Promise<string> {
  const prefix = new TextEncoder().encode('GhostGlyphBitmap/v1');
  const pixelBytes = new Uint8Array(pixels);
  const combined = new Uint8Array(prefix.length + pixelBytes.length);
  combined.set(prefix);
  combined.set(pixelBytes, prefix.length);
  const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
  const hashArray = new Uint8Array(hashBuffer);
  return Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');
}
