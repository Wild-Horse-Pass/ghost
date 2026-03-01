import SwiftUI
import CoreImage.CIFilterBuiltins

/// A SwiftUI view that generates and displays a QR code from a string.
///
/// Uses Core Image's `CIQRCodeGenerator` filter to create the QR code bitmap,
/// then scales it with nearest-neighbor interpolation for crisp rendering.
///
/// Usage:
/// ```swift
/// QrCodeImageView(content: "ghost:GhAddr123?amount=50000")
///     .frame(width: 256, height: 256)
/// ```
struct QrCodeImageView: View {
    /// The string content to encode into the QR code.
    let content: String

    /// Correction level: L (7%), M (15%), Q (25%), H (30%).
    var correctionLevel: String = "M"

    var body: some View {
        if let image = generateQrCode() {
            Image(uiImage: image)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .accessibilityLabel("QR Code")
        } else {
            Image(systemName: "qrcode")
                .font(.system(size: 64))
                .foregroundColor(.secondary)
                .accessibilityLabel("QR Code generation failed")
        }
    }

    /// Generate a `UIImage` containing the QR code for `content`.
    private func generateQrCode() -> UIImage? {
        let context = CIContext()

        guard let filter = CIFilter(name: "CIQRCodeGenerator") else {
            return nil
        }

        let data = content.data(using: .utf8)
        filter.setValue(data, forKey: "inputMessage")
        filter.setValue(correctionLevel, forKey: "inputCorrectionLevel")

        guard let ciImage = filter.outputImage else {
            return nil
        }

        // Scale up the tiny QR code image to a reasonable size with
        // nearest-neighbor interpolation so pixels stay sharp.
        let scale: CGFloat = 10.0
        let scaledImage = ciImage.transformed(by: CGAffineTransform(scaleX: scale, y: scale))

        guard let cgImage = context.createCGImage(scaledImage, from: scaledImage.extent) else {
            return nil
        }

        return UIImage(cgImage: cgImage)
    }
}

#if DEBUG
struct QrCodeImageView_Previews: PreviewProvider {
    static var previews: some View {
        VStack(spacing: 20) {
            QrCodeImageView(content: "ghost:GhA1b2c3d4e5f6g7h8i9j0?amount=100000000&memo=Coffee")
                .frame(width: 256, height: 256)

            QrCodeImageView(content: "ghost:GhAddr123")
                .frame(width: 200, height: 200)
        }
        .padding()
    }
}
#endif
