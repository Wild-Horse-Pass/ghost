import SwiftUI

/// PIN creation screen shown during wallet setup (after mnemonic verification).
struct PinSetupView: View {
    @EnvironmentObject private var vm: WalletViewModel

    @State private var pin = ""
    @State private var confirmPin = ""
    @State private var isConfirming = false
    @State private var error: String?

    let onComplete: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "lock.shield")
                .font(.system(size: 60))
                .foregroundStyle(.tint)

            Text(isConfirming ? "Confirm your PIN" : "Create a 6-digit PIN")
                .font(.title2.bold())

            Text("This PIN is used as a fallback when biometrics are unavailable.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)

            SecureField(
                isConfirming ? "Confirm PIN" : "Enter PIN",
                text: isConfirming ? $confirmPin : $pin
            )
            .keyboardType(.numberPad)
            .textContentType(.oneTimeCode)
            .font(.title3.monospaced())
            .multilineTextAlignment(.center)
            .frame(maxWidth: 200)
            .padding()
            .background(Color(.systemGray6))
            .cornerRadius(12)
            .onChange(of: isConfirming ? confirmPin : pin) { _ in
                error = nil
            }

            if let error = error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            Button {
                handleAction()
            } label: {
                Text(isConfirming ? "Confirm" : "Next")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(.horizontal, 32)
            .disabled((isConfirming ? confirmPin : pin).count != 6)

            Spacer()
        }
        .navigationTitle("Set PIN")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func handleAction() {
        if !isConfirming {
            guard pin.count == 6, pin.allSatisfy(\.isNumber) else {
                error = "PIN must be exactly 6 digits"
                return
            }
            isConfirming = true
        } else {
            guard confirmPin == pin else {
                error = "PINs do not match"
                confirmPin = ""
                return
            }
            do {
                try setPin(pin: pin)
                onComplete()
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}
