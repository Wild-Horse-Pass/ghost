import SwiftUI

/// Settings screen with biometric toggle, Wraith mode, merchant mode,
/// network configuration, and version display.
struct SettingsView: View {
    @EnvironmentObject private var vm: WalletViewModel

    @AppStorage("biometricEnabled") private var biometricEnabled = false
    @AppStorage("wraithMode") private var wraithMode = false
    @AppStorage("merchantMode") private var merchantMode = false
    @AppStorage("nodeHost") private var nodeHost = "127.0.0.1"
    @AppStorage("nodePort") private var nodePort = "51725"
    @AppStorage("useSSL") private var useSSL = false

    @State private var showLockConfirmation = false

    var body: some View {
        List {
            // Security
            Section("Security") {
                Toggle(isOn: $biometricEnabled) {
                    Label("Biometric Unlock", systemImage: "faceid")
                }

                Picker(selection: $vm.autoLockMinutes) {
                    Text("1 minute").tag(1)
                    Text("5 minutes").tag(5)
                    Text("15 minutes").tag(15)
                    Text("30 minutes").tag(30)
                    Text("60 minutes").tag(60)
                } label: {
                    Label("Auto-Lock Timeout", systemImage: "timer")
                }

                Button {
                    showLockConfirmation = true
                } label: {
                    Label("Lock Wallet Now", systemImage: "lock.fill")
                        .foregroundStyle(.red)
                }
            }

            // Privacy
            Section {
                Toggle(isOn: $wraithMode) {
                    Label("Wraith Mode", systemImage: "eye.slash")
                }

                if wraithMode {
                    Text("Transactions use the private ledger with stealth addresses. Higher fees apply.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("Privacy")
            } footer: {
                Text("Wraith mode routes transactions through the Ghost private ledger for enhanced privacy.")
            }

            // Merchant
            Section {
                Toggle(isOn: $merchantMode) {
                    Label("Merchant Mode", systemImage: "storefront")
                }

                if merchantMode {
                    Text("Enables payment terminal features: invoices, receipts, and CSV export.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("Merchant")
            }

            // Network
            Section("Network") {
                HStack {
                    Text("Node Host")
                    Spacer()
                    TextField("Host", text: $nodeHost)
                        .multilineTextAlignment(.trailing)
                        .font(.system(.body, design: .monospaced))
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }

                HStack {
                    Text("RPC Port")
                    Spacer()
                    TextField("Port", text: $nodePort)
                        .multilineTextAlignment(.trailing)
                        .font(.system(.body, design: .monospaced))
                        .keyboardType(.numberPad)
                }

                Toggle(isOn: $useSSL) {
                    Label("Use SSL/TLS", systemImage: "lock.shield")
                }
            }

            // About
            Section("About") {
                HStack {
                    Text("App Version")
                    Spacer()
                    Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0")
                        .foregroundStyle(.secondary)
                }

                HStack {
                    Text("Core Version")
                    Spacer()
                    Text(coreVersion)
                        .foregroundStyle(.secondary)
                        .font(.system(.body, design: .monospaced))
                }
            }
        }
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
        .alert("Lock Wallet?", isPresented: $showLockConfirmation) {
            Button("Lock", role: .destructive) {
                vm.lockWallet()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("You will need to unlock the wallet with biometrics or your passcode to continue using it.")
        }
    }

    private var coreVersion: String {
        ghostTapVersion()
    }
}
