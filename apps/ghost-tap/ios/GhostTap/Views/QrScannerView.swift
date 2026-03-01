import SwiftUI
import AVFoundation

/// A SwiftUI view that presents a live camera preview and scans for QR codes.
///
/// Uses `AVCaptureSession` with a `AVCaptureMetadataOutput` to detect QR codes
/// in real-time. When a code is detected, `onCodeScanned` is called with the
/// raw string value.
///
/// Usage:
/// ```swift
/// QrScannerView { code in
///     print("Scanned: \(code)")
/// }
/// ```
struct QrScannerView: View {
    let onCodeScanned: (String) -> Void

    @State private var cameraPermissionGranted = false
    @State private var showPermissionDenied = false

    var body: some View {
        ZStack {
            if cameraPermissionGranted {
                CameraPreviewRepresentable(onCodeScanned: onCodeScanned)
                    .ignoresSafeArea()

                // Crosshair overlay
                VStack {
                    Spacer()
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(Color.white.opacity(0.7), lineWidth: 3)
                        .frame(width: 250, height: 250)
                    Spacer()
                    Text("Point camera at a QR code")
                        .font(.callout)
                        .foregroundColor(.white)
                        .padding(.bottom, 60)
                }
            } else if showPermissionDenied {
                VStack(spacing: 16) {
                    Image(systemName: "camera.fill")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("Camera Access Required")
                        .font(.title3.bold())
                    Text("Go to Settings > GhostTap > Camera to enable access.")
                        .font(.body)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
            } else {
                ProgressView("Requesting camera access...")
            }
        }
        .onAppear {
            checkCameraPermission()
        }
    }

    private func checkCameraPermission() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            cameraPermissionGranted = true
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { granted in
                DispatchQueue.main.async {
                    cameraPermissionGranted = granted
                    showPermissionDenied = !granted
                }
            }
        default:
            showPermissionDenied = true
        }
    }
}

// MARK: - UIViewRepresentable wrapper for AVCaptureSession

/// Wraps an `AVCaptureVideoPreviewLayer` in a `UIViewRepresentable` and
/// configures QR code metadata detection.
private struct CameraPreviewRepresentable: UIViewRepresentable {
    let onCodeScanned: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onCodeScanned: onCodeScanned)
    }

    func makeUIView(context: Context) -> UIView {
        let view = UIView(frame: .zero)
        view.backgroundColor = .black

        let session = AVCaptureSession()
        session.sessionPreset = .high
        context.coordinator.session = session

        guard let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else {
            return view
        }
        session.addInput(input)

        let metadataOutput = AVCaptureMetadataOutput()
        guard session.canAddOutput(metadataOutput) else {
            return view
        }
        session.addOutput(metadataOutput)

        metadataOutput.setMetadataObjectsDelegate(context.coordinator, queue: .main)
        metadataOutput.metadataObjectTypes = [.qr]

        let previewLayer = AVCaptureVideoPreviewLayer(session: session)
        previewLayer.videoGravity = .resizeAspectFill
        previewLayer.frame = view.bounds
        view.layer.addSublayer(previewLayer)
        context.coordinator.previewLayer = previewLayer

        DispatchQueue.global(qos: .userInitiated).async {
            session.startRunning()
        }

        return view
    }

    func updateUIView(_ uiView: UIView, context: Context) {
        context.coordinator.previewLayer?.frame = uiView.bounds
    }

    static func dismantleUIView(_ uiView: UIView, coordinator: Coordinator) {
        coordinator.session?.stopRunning()
    }

    // MARK: - Coordinator

    class Coordinator: NSObject, AVCaptureMetadataOutputObjectsDelegate {
        let onCodeScanned: (String) -> Void
        var session: AVCaptureSession?
        var previewLayer: AVCaptureVideoPreviewLayer?
        private var lastScanned: String?

        init(onCodeScanned: @escaping (String) -> Void) {
            self.onCodeScanned = onCodeScanned
        }

        func metadataOutput(
            _ output: AVCaptureMetadataOutput,
            didOutput metadataObjects: [AVMetadataObject],
            from connection: AVCaptureConnection
        ) {
            guard let readableObject = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
                  let value = readableObject.stringValue,
                  value != lastScanned else {
                return
            }
            lastScanned = value

            // Haptic feedback on successful scan.
            let generator = UIImpactFeedbackGenerator(style: .medium)
            generator.impactOccurred()

            onCodeScanned(value)
        }
    }
}

#if DEBUG
struct QrScannerView_Previews: PreviewProvider {
    static var previews: some View {
        QrScannerView { code in
            print("Scanned: \(code)")
        }
    }
}
#endif
