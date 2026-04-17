import { useEffect, useRef, useState, useCallback } from "react";
import {
  getGlyphPalette,
  renderGlyph,
  checkGlyphAvailability,
  claimGlyph,
  getGlyph,
  validateGlyphPixels,
  type PaletteColor,
} from "../api/commands";
import { useToast } from "../components/ToastProvider";

const GRID_SIZE = 16;
const CELL_SIZE = 24;
const PREVIEW_SCALE = 8;
const PREVIEW_SIZE = GRID_SIZE * PREVIEW_SCALE; // 128

export default function GlyphDesigner() {
  const { toast } = useToast();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [pixels, setPixels] = useState<number[]>(() => new Array(256).fill(0));
  const [selectedColor, setSelectedColor] = useState(0);
  const [palette, setPalette] = useState<PaletteColor[]>([]);
  const [ghostId, setGhostId] = useState("");
  const [payUrl, setPayUrl] = useState("");
  const [status, setStatus] = useState("");
  const [painting, setPainting] = useState(false);

  useEffect(() => {
    getGlyphPalette().then(setPalette).catch((e) => toast(String(e), "error"));
  }, []);

  const updatePreview = useCallback(async (px: number[]) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    try {
      const data = await renderGlyph(px, ghostId || "ghost1preview", PREVIEW_SCALE);
      const imgData = new ImageData(
        new Uint8ClampedArray(data),
        PREVIEW_SIZE,
        PREVIEW_SIZE,
      );
      ctx.putImageData(imgData, 0, 0);
    } catch {
      ctx.clearRect(0, 0, PREVIEW_SIZE, PREVIEW_SIZE);
    }
  }, [ghostId]);

  useEffect(() => {
    updatePreview(pixels);
  }, [pixels, updatePreview]);

  const paintPixel = useCallback((index: number) => {
    setPixels((prev) => {
      if (prev[index] === selectedColor) return prev;
      const next = [...prev];
      next[index] = selectedColor;
      return next;
    });
  }, [selectedColor]);

  const handleMouseDown = (index: number) => {
    setPainting(true);
    paintPixel(index);
  };

  const handleMouseEnter = (index: number) => {
    if (painting) paintPixel(index);
  };

  const handleMouseUp = () => setPainting(false);

  const handleCheckAvailability = async () => {
    setStatus("");
    try {
      const available = await checkGlyphAvailability(pixels, payUrl);
      setStatus(available ? "Glyph design is available" : "Glyph design is already taken");
    } catch (e: unknown) {
      setStatus(`Error: ${e}`);
    }
  };

  const handleClaim = async () => {
    setStatus("");
    if (!ghostId) {
      setStatus("Enter a Ghost ID first");
      return;
    }
    try {
      const valid = await validateGlyphPixels(pixels);
      if (!valid) {
        setStatus("Invalid pixel data");
        return;
      }
      const result = await claimGlyph(ghostId, pixels, payUrl);
      setStatus(`Claimed! commitment=${result.commitment} bitmap_hash=${result.bitmap_hash}`);
      toast("Glyph claimed", "success");
    } catch (e: unknown) {
      setStatus(`Error: ${e}`);
    }
  };

  const handleLoad = async () => {
    setStatus("");
    if (!ghostId) {
      setStatus("Enter a Ghost ID first");
      return;
    }
    try {
      const info = await getGlyph(ghostId, payUrl);
      if (!info) {
        setStatus("No glyph found for this Ghost ID");
        return;
      }
      setPixels(info.pixels);
      setStatus(`Loaded glyph (status: ${info.status})`);
    } catch (e: unknown) {
      setStatus(`Error: ${e}`);
    }
  };

  const handleClear = () => {
    setPixels(new Array(256).fill(0));
    setStatus("");
  };

  const colorForIndex = (idx: number): string => {
    const c = palette.find((p) => p.index === idx);
    return c ? `rgb(${c.r},${c.g},${c.b})` : "#000";
  };

  return (
    <div className="page" onMouseUp={handleMouseUp} onMouseLeave={handleMouseUp}>
      <h1>Glyph Designer</h1>

      <div style={{ display: "flex", gap: 32, flexWrap: "wrap" }}>
        {/* Left: Grid + Palette */}
        <div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: `repeat(${GRID_SIZE}, ${CELL_SIZE}px)`,
              gridTemplateRows: `repeat(${GRID_SIZE}, ${CELL_SIZE}px)`,
              gap: 1,
              background: "var(--border)",
              border: "1px solid var(--border)",
              userSelect: "none",
              cursor: "crosshair",
            }}
          >
            {pixels.map((colorIdx, i) => (
              <div
                key={i}
                onMouseDown={() => handleMouseDown(i)}
                onMouseEnter={() => handleMouseEnter(i)}
                style={{
                  width: CELL_SIZE,
                  height: CELL_SIZE,
                  background: palette.length > 0 ? colorForIndex(colorIdx) : "#000",
                }}
              />
            ))}
          </div>

          {/* Palette */}
          <div style={{ marginTop: 12 }}>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 6 }}>
              Palette ({palette.length} colors)
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {palette.map((c) => (
                <div
                  key={c.index}
                  onClick={() => setSelectedColor(c.index)}
                  title={`Color ${c.index}`}
                  style={{
                    width: 20,
                    height: 20,
                    background: `rgb(${c.r},${c.g},${c.b})`,
                    border: selectedColor === c.index
                      ? "2px solid #fff"
                      : "2px solid transparent",
                    borderRadius: 2,
                    cursor: "pointer",
                    boxSizing: "border-box",
                  }}
                />
              ))}
            </div>
          </div>
        </div>

        {/* Right: Preview + Controls */}
        <div style={{ minWidth: 200 }}>
          <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 6 }}>
            Preview ({PREVIEW_SIZE}x{PREVIEW_SIZE})
          </div>
          <canvas
            ref={canvasRef}
            width={PREVIEW_SIZE}
            height={PREVIEW_SIZE}
            style={{
              border: "1px solid var(--border)",
              background: "#000",
              imageRendering: "pixelated",
            }}
          />

          <div className="form-group" style={{ marginTop: 16 }}>
            <label>Ghost ID</label>
            <input
              value={ghostId}
              onChange={(e) => setGhostId(e.target.value)}
              placeholder="ghost1..."
              style={{ width: "100%", boxSizing: "border-box" }}
            />
          </div>

          <div className="form-group">
            <label>Pay URL</label>
            <input
              value={payUrl}
              onChange={(e) => setPayUrl(e.target.value)}
              style={{ width: "100%", boxSizing: "border-box" }}
            />
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <button className="btn-primary" onClick={handleCheckAvailability}>
              Check Availability
            </button>
            <button className="btn-primary" onClick={handleClaim}>
              Claim Glyph
            </button>
            <button className="btn-secondary" onClick={handleLoad}>
              Load Existing
            </button>
            <button className="btn-secondary" onClick={handleClear}>
              Clear
            </button>
          </div>

          {status && (
            <div
              style={{
                marginTop: 12,
                padding: 10,
                fontSize: 12,
                background: "var(--bg-secondary)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                wordBreak: "break-all",
              }}
            >
              {status}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
