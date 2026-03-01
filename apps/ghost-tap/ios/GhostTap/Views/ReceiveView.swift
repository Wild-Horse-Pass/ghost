import SwiftUI
import CoreImage.CIFilterBuiltins

/// Displays a QR code generated from the wallet's receive address,
/// with the address text below and copy/share buttons.
struct ReceiveView: View {
    @EnvironmentObject private var vm: WalletViewModel

    @State private var copied = false

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            // QR code
            if let qrImage = generateQRCode(from: vm.currentAddress) {
                Image(uiImage: qrImage)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 220, height: 220)
                    .padding(16)
                    .background(Color.white)
                    .clipShape(RoundedRectangle(cornerRadius: 16))
                    .shadow(color: .black.opacity(0.1), radius: 8, y: 4)
            } else {
                Image(systemName: "qrcode")
                    .font(.system(size: 100))
                    .foregroundStyle(.tertiary)
            }

            // Address label
            VStack(spacing: 6) {
                Text("Your Receive Address")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                Text(vm.currentAddress)
                    .font(.system(.caption, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .textSelection(.enabled)
                    .padding(.horizontal)
            }

            // Action buttons
            HStack(spacing: 24) {
                Button {
                    UIPasteboard.general.string = vm.currentAddress
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                        copied = false
                    }
                } label: {
                    Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                        .frame(minWidth: 100)
                }
                .buttonStyle(.bordered)

                ShareLink(item: vm.currentAddress) {
                    Label("Share", systemImage: "square.and.arrow.up")
                        .frame(minWidth: 100)
                }
                .buttonStyle(.bordered)
            }

            // New address button
            Button {
                Task { await vm.generateAddress() }
            } label: {
                Label("Generate New Address", systemImage: "arrow.triangle.2.circlepath")
                    .font(.subheadline)
            }
            .foregroundStyle(.secondary)

            Spacer()
        }
        .navigationTitle("Receive")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            if vm.currentAddress.isEmpty {
                await vm.generateAddress()
            }
        }
    }

    /// Generate a QR code UIImage from a string using CIQRCodeGenerator
    private func generateQRCode(from string: String) -> UIImage? {
        guard !string.isEmpty else { return nil }

        let context = CIContext()
        let filter = CIFilter.qrCodeGenerator()

        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"

        guard let outputImage = filter.outputImage else { return nil }

        // Scale up the image for crisp rendering
        let scale = 10.0
        let transformed = outputImage.transformed(by: CGAffineTransform(scaleX: scale, y: scale))

        guard let cgImage = context.createCGImage(transformed, from: transformed.extent) else {
            return nil
        }

        return UIImage(cgImage: cgImage)
    }
}
