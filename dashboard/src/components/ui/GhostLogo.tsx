'use client';

import { useUIStore, ACCENT_COLORS } from '@/stores';

interface GhostLogoProps {
  size?: number;
  className?: string;
  showBackground?: boolean;
}

export function GhostLogo({ size = 32, className = '', showBackground = true }: GhostLogoProps) {
  const accentColor = useUIStore((s) => s.accentColor);
  const color = ACCENT_COLORS[accentColor];

  return (
    <div
      className={`relative flex items-center justify-center ${className}`}
      style={{ width: size, height: size }}
    >
      {showBackground && (
        <div
          className="absolute inset-0 rounded-lg"
          style={{ backgroundColor: color.hex }}
        />
      )}
      <svg
        viewBox="0 0 100 100"
        width={size * 0.75}
        height={size * 0.75}
        className="relative z-10"
      >
        {/* Ghost body - black silhouette */}
        <path
          d="M50 8
             C25 8 10 28 10 50
             L10 85
             L20 75
             L30 85
             L40 75
             L50 85
             L60 75
             L70 85
             L80 75
             L90 85
             L90 50
             C90 28 75 8 50 8
             Z"
          fill="#000000"
        />
        {/* Left eye */}
        <circle
          cx="35"
          cy="45"
          r="8"
          fill={showBackground ? color.hex : color.hex}
        />
        {/* Right eye */}
        <circle
          cx="65"
          cy="45"
          r="8"
          fill={showBackground ? color.hex : color.hex}
        />
      </svg>
    </div>
  );
}

// Simplified version for favicon/small displays
export function GhostIcon({ size = 24, className = '' }: { size?: number; className?: string }) {
  const accentColor = useUIStore((s) => s.accentColor);
  const color = ACCENT_COLORS[accentColor];

  return (
    <svg
      viewBox="0 0 100 100"
      width={size}
      height={size}
      className={className}
    >
      {/* Ghost body */}
      <path
        d="M50 8
           C25 8 10 28 10 50
           L10 85
           L20 75
           L30 85
           L40 75
           L50 85
           L60 75
           L70 85
           L80 75
           L90 85
           L90 50
           C90 28 75 8 50 8
           Z"
        fill={color.hex}
      />
      {/* Eyes - darker shade */}
      <circle cx="35" cy="45" r="8" fill="#000000" opacity="0.6" />
      <circle cx="65" cy="45" r="8" fill="#000000" opacity="0.6" />
    </svg>
  );
}
