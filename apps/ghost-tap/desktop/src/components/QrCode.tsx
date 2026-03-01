import { QRCodeSVG } from "qrcode.react";

interface Props {
  value: string;
  size?: number;
}

export default function QrCode({ value, size = 200 }: Props) {
  return (
    <div
      style={{
        background: "white",
        padding: 16,
        borderRadius: 10,
        display: "inline-block",
      }}
    >
      <QRCodeSVG value={value} size={size} level="M" />
    </div>
  );
}
