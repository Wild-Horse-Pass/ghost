'use client';

import { useState, useRef, useCallback, useEffect } from 'react';
import { Card } from '@/components/ui/Card';
import { PageHeader } from '@/components/ui/PageHeader';
import { GLYPH_PALETTE, computeBitmapHash, getGlyph, checkGlyphAvailability } from '@/lib/api/glyph';
import { useClaimGlyph } from '@/hooks/queries';

const GRID_SIZE = 16;
const CELL_SIZE = 24;
const PREVIEW_SIZE = 128;
const PREVIEW_CELL = PREVIEW_SIZE / GRID_SIZE; // 8

function paletteToHex(r: number, g: number, b: number): string {
  return `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
}

export default function GlyphsPage() {
  const [pixels, setPixels] = useState<number[]>(() => new Array(256).fill(0));
  const [selectedColor, setSelectedColor] = useState(1);
  const [painting, setPainting] = useState(false);
  const [ghostId, setGhostId] = useState('');
  const [status, setStatus] = useState('');
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const claimMutation = useClaimGlyph();

  // Render preview canvas
  const renderPreview = useCallback((px: number[]) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.clearRect(0, 0, PREVIEW_SIZE, PREVIEW_SIZE);
    for (let i = 0; i < 256; i++) {
      const colorIdx = px[i] ?? 0;
      const color = GLYPH_PALETTE[colorIdx] ?? GLYPH_PALETTE[0];
      ctx.fillStyle = paletteToHex(color.r, color.g, color.b);
      const x = (i % GRID_SIZE) * PREVIEW_CELL;
      const y = Math.floor(i / GRID_SIZE) * PREVIEW_CELL;
      ctx.fillRect(x, y, PREVIEW_CELL, PREVIEW_CELL);
    }
  }, []);

  useEffect(() => {
    renderPreview(pixels);
  }, [pixels, renderPreview]);

  const paintCell = useCallback((index: number) => {
    setPixels(prev => {
      if (prev[index] === selectedColor) return prev;
      const next = [...prev];
      next[index] = selectedColor;
      return next;
    });
  }, [selectedColor]);

  const handleMouseDown = useCallback((index: number) => {
    setPainting(true);
    paintCell(index);
  }, [paintCell]);

  const handleMouseEnter = useCallback((index: number) => {
    if (painting) paintCell(index);
  }, [painting, paintCell]);

  const handleMouseUp = useCallback(() => {
    setPainting(false);
  }, []);

  const handleClear = useCallback(() => {
    setPixels(new Array(256).fill(0));
    setStatus('Grid cleared.');
  }, []);

  const handleCheckAvailability = useCallback(async () => {
    try {
      setStatus('Computing hash...');
      const hash = await computeBitmapHash(pixels);
      setStatus(`Hash: ${hash.slice(0, 16)}... Checking...`);
      const result = await checkGlyphAvailability(hash);
      setStatus(result.available ? 'Design is available!' : 'Design is already claimed.');
    } catch (err) {
      setStatus(`Error: ${err instanceof Error ? err.message : 'Unknown'}`);
    }
  }, [pixels]);

  const handleClaim = useCallback(async () => {
    if (!ghostId.trim()) {
      setStatus('Enter a Ghost ID first.');
      return;
    }
    try {
      setStatus('Claiming glyph...');
      const result = await claimMutation.mutateAsync({ ghostId: ghostId.trim(), pixels });
      setStatus(`Claimed! Commitment: ${result.commitment.slice(0, 16)}...`);
    } catch (err) {
      setStatus(`Claim failed: ${err instanceof Error ? err.message : 'Unknown'}`);
    }
  }, [ghostId, pixels, claimMutation]);

  const handleLoadExisting = useCallback(async () => {
    if (!ghostId.trim()) {
      setStatus('Enter a Ghost ID to load.');
      return;
    }
    try {
      setStatus('Loading glyph...');
      const info = await getGlyph(ghostId.trim());
      setPixels(info.pixels);
      setStatus(`Loaded glyph for ${ghostId.trim()}`);
    } catch (err) {
      setStatus(`Load failed: ${err instanceof Error ? err.message : 'Unknown'}`);
    }
  }, [ghostId]);

  return (
    <div className="space-y-6" onMouseUp={handleMouseUp} onMouseLeave={handleMouseUp}>
      <PageHeader
        title="Ghost Glyphs"
        subtitle="Design and claim a unique 16x16 pixel glyph for your Ghost identity"
      />

      <Card>
        <div className="p-6">
          <div className="flex flex-col lg:flex-row gap-8">
            {/* Left: Grid + Palette */}
            <div className="flex flex-col gap-4">
              <h3 className="text-sm font-medium text-gray-400">Editor</h3>
              {/* Grid */}
              <div
                className="inline-grid border border-gray-700 select-none"
                style={{
                  gridTemplateColumns: `repeat(${GRID_SIZE}, ${CELL_SIZE}px)`,
                  gridTemplateRows: `repeat(${GRID_SIZE}, ${CELL_SIZE}px)`,
                }}
              >
                {pixels.map((colorIdx, i) => {
                  const color = GLYPH_PALETTE[colorIdx] ?? GLYPH_PALETTE[0];
                  return (
                    <div
                      key={i}
                      className="border border-gray-800/50 cursor-crosshair hover:opacity-80"
                      style={{
                        backgroundColor: paletteToHex(color.r, color.g, color.b),
                        width: CELL_SIZE,
                        height: CELL_SIZE,
                      }}
                      onMouseDown={() => handleMouseDown(i)}
                      onMouseEnter={() => handleMouseEnter(i)}
                    />
                  );
                })}
              </div>

              {/* Palette */}
              <div>
                <h3 className="text-sm font-medium text-gray-400 mb-2">Palette</h3>
                <div className="flex flex-wrap gap-1">
                  {GLYPH_PALETTE.map((color) => (
                    <button
                      key={color.index}
                      title={color.name}
                      className={`w-6 h-6 rounded-sm border-2 transition-all ${
                        selectedColor === color.index
                          ? 'border-white scale-110'
                          : 'border-gray-700 hover:border-gray-500'
                      }`}
                      style={{ backgroundColor: paletteToHex(color.r, color.g, color.b) }}
                      onClick={() => setSelectedColor(color.index)}
                    />
                  ))}
                </div>
                <p className="text-xs text-gray-500 mt-1">
                  Selected: {GLYPH_PALETTE[selectedColor]?.name ?? 'Unknown'}
                </p>
              </div>
            </div>

            {/* Right: Preview + Controls */}
            <div className="flex flex-col gap-4 flex-1">
              <h3 className="text-sm font-medium text-gray-400">Preview</h3>
              <canvas
                ref={canvasRef}
                width={PREVIEW_SIZE}
                height={PREVIEW_SIZE}
                className="border border-gray-700 rounded bg-black"
                style={{ imageRendering: 'pixelated' }}
              />

              <div className="space-y-3">
                <div>
                  <label className="text-sm text-gray-400 block mb-1">Ghost ID</label>
                  <input
                    type="text"
                    value={ghostId}
                    onChange={(e) => setGhostId(e.target.value)}
                    placeholder="Enter ghost ID..."
                    className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={handleCheckAvailability}
                    className="px-3 py-1.5 text-sm bg-gray-700 hover:bg-gray-600 text-gray-200 rounded transition-colors"
                  >
                    Check Availability
                  </button>
                  <button
                    onClick={handleClaim}
                    disabled={claimMutation.isPending}
                    className="px-3 py-1.5 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded transition-colors disabled:opacity-50"
                  >
                    {claimMutation.isPending ? 'Claiming...' : 'Claim'}
                  </button>
                  <button
                    onClick={handleLoadExisting}
                    className="px-3 py-1.5 text-sm bg-gray-700 hover:bg-gray-600 text-gray-200 rounded transition-colors"
                  >
                    Load Existing
                  </button>
                  <button
                    onClick={handleClear}
                    className="px-3 py-1.5 text-sm bg-gray-700 hover:bg-gray-600 text-gray-200 rounded transition-colors"
                  >
                    Clear
                  </button>
                </div>

                {status && (
                  <p className="text-sm text-gray-400 bg-gray-800/50 rounded px-3 py-2 border border-gray-700">
                    {status}
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
}
