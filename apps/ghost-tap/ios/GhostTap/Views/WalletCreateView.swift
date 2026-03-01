import SwiftUI

/// Shows a loading spinner while the wallet is being generated,
/// then navigates to the mnemonic backup flow.
/// Prevents screenshots while the mnemonic is on screen.
struct WalletCreateView: View {
    @EnvironmentObject private var vm: WalletViewModel

    @State private var isGenerating = true
    @State private var navigateToBackup = false

    var body: some View {
        VStack(spacing: 32) {
            if isGenerating {
                Spacer()

                ProgressView()
                    .scaleEffect(1.5)
                    .padding(.bottom, 16)

                Text("Generating Wallet...")
                    .font(.title3)
                    .foregroundStyle(.secondary)

                Text("Creating cryptographic keys.\nThis may take a moment.")
                    .font(.subheadline)
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)

                Spacer()
            } else {
                // Generation complete, auto-navigate
                Color.clear
                    .onAppear {
                        navigateToBackup = true
                    }
            }
        }
        .navigationTitle("New Wallet")
        .navigationBarBackButtonHidden(isGenerating)
        .navigationDestination(isPresented: $navigateToBackup) {
            MnemonicBackupView()
                .environmentObject(vm)
        }
        .task {
            await vm.createWallet(wordCount: 12)
            // Small delay so the spinner is visible briefly
            try? await Task.sleep(for: .milliseconds(600))
            isGenerating = false
        }
        .onAppear { disableScreenCapture(true) }
        .onDisappear { disableScreenCapture(false) }
    }

    /// Prevent screenshots by marking the window's layer as secure
    private func disableScreenCapture(_ disable: Bool) {
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let window = windowScene.windows.first else { return }

        if disable {
            let field = UITextField()
            field.isSecureTextEntry = true
            window.addSubview(field)
            field.centerYAnchor.constraint(equalTo: window.centerYAnchor).isActive = true
            field.centerXAnchor.constraint(equalTo: window.centerXAnchor).isActive = true
            window.layer.superlayer?.addSublayer(field.layer)
            field.layer.sublayers?.first?.addSublayer(window.layer)
        }
    }
}
