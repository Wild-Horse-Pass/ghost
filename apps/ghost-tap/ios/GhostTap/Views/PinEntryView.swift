import SwiftUI

/// Unlock screen shown when the wallet is locked.
struct PinEntryView: View {
    @EnvironmentObject private var vm: WalletViewModel

    @State private var pin = ""
    @State private var error: String?
    @State private var attempts: UInt32 = pinRemainingAttempts()
    @State private var isLockedOut = false

    let onUnlocked: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "lock.fill")
                .font(.system(size: 60))
                .foregroundStyle(.secondary)

            Text("Enter PIN")
                .font(.title.bold())

            if isLockedOut {
                Text("Too many failed attempts. Please re-import your wallet using your mnemonic phrase.")
                    .font(.subheadline)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            } else {
                Text("\(attempts) attempts remaining")
                    .font(.subheadline)
                    .foregroundStyle(attempts <= 2 ? .red : .secondary)
            }

            SecureField("PIN", text: $pin)
                .keyboardType(.numberPad)
                .textContentType(.oneTimeCode)
                .font(.title3.monospaced())
                .multilineTextAlignment(.center)
                .frame(maxWidth: 200)
                .padding()
                .background(Color(.systemGray6))
                .cornerRadius(12)
                .disabled(isLockedOut)
                .onChange(of: pin) { _ in error = nil }

            if let error = error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            Button {
                let result = verifyPinAndUnlock(pin: pin)
                switch result {
                case 0:
                    vm.unlockWallet()
                    onUnlocked()
                case 1:
                    attempts = pinRemainingAttempts()
                    error = "Wrong PIN"
                    pin = ""
                default:
                    isLockedOut = true
                    error = "Account locked"
                }
            } label: {
                Text("Unlock")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(.horizontal, 32)
            .disabled(pin.count != 6 || isLockedOut)

            Button {
                let success = authenticateBiometric()
                if success {
                    vm.unlockWallet()
                    onUnlocked()
                }
            } label: {
                Label("Use Biometrics", systemImage: "faceid")
            }
            .disabled(isLockedOut)

            Spacer()
        }
    }
}
