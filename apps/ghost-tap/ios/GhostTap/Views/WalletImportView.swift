import SwiftUI

/// Text editor for entering an existing mnemonic to import a wallet.
/// Shows a live word count and validates on submit.
struct WalletImportView: View {
    @EnvironmentObject private var vm: WalletViewModel

    @State private var mnemonicText = ""
    @State private var isImporting = false
    @State private var importError: String?
    @State private var navigateToHome = false

    private var wordCount: Int {
        mnemonicText
            .split(separator: " ")
            .filter { !$0.isEmpty }
            .count
    }

    private var isValidWordCount: Bool {
        wordCount == 12 || wordCount == 24
    }

    private var wordCountColor: Color {
        if mnemonicText.isEmpty { return .secondary }
        if isValidWordCount { return .green }
        if wordCount > 24 { return .red }
        return .orange
    }

    var body: some View {
        VStack(spacing: 20) {
            VStack(spacing: 8) {
                Image(systemName: "arrow.down.doc")
                    .font(.system(size: 48))
                    .foregroundStyle(.blue)

                Text("Import Wallet")
                    .font(.title2)
                    .bold()

                Text("Enter your 12 or 24 word recovery phrase, separated by spaces.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }

            // Mnemonic input
            VStack(alignment: .leading, spacing: 6) {
                TextEditor(text: $mnemonicText)
                    .font(.system(.body, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .frame(minHeight: 120, maxHeight: 180)
                    .padding(8)
                    .background(Color(.secondarySystemBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(Color(.separator), lineWidth: 1)
                    )

                HStack {
                    Text("\(wordCount) / \(wordCount > 12 ? 24 : 12) words")
                        .font(.caption)
                        .foregroundStyle(wordCountColor)

                    Spacer()

                    if isValidWordCount {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                            .font(.caption)
                    }
                }
                .padding(.horizontal, 4)
            }
            .padding(.horizontal)

            if let error = importError {
                HStack(spacing: 6) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.red)
                    Text(error)
                        .font(.subheadline)
                        .foregroundStyle(.red)
                }
                .padding(.horizontal)
            }

            Spacer()

            Button {
                Task { await importWallet() }
            } label: {
                if isImporting {
                    ProgressView()
                        .frame(maxWidth: .infinity)
                } else {
                    Text("Import Wallet")
                        .frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(.horizontal, 32)
            .disabled(!isValidWordCount || isImporting)
            .padding(.bottom, 32)
        }
        .navigationTitle("Import Wallet")
        .navigationBarTitleDisplayMode(.inline)
        .navigationDestination(isPresented: $navigateToHome) {
            HomeView()
                .environmentObject(vm)
                .navigationBarBackButtonHidden(true)
        }
    }

    private func importWallet() async {
        isImporting = true
        importError = nil

        let cleaned = mnemonicText
            .lowercased()
            .split(separator: " ")
            .filter { !$0.isEmpty }
            .joined(separator: " ")

        let success = await vm.importWallet(phrase: cleaned)
        isImporting = false

        if success {
            navigateToHome = true
        } else {
            importError = vm.errorMessage ?? "Invalid mnemonic phrase. Please check your words."
        }
    }
}
