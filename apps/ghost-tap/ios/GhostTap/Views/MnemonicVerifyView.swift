import SwiftUI

/// Picks 3 random word indices from the mnemonic and asks the user
/// to type them to confirm they backed up correctly.
struct MnemonicVerifyView: View {
    @EnvironmentObject private var vm: WalletViewModel

    /// The 3 randomly chosen indices (0-based)
    @State private var challengeIndices: [Int] = []
    @State private var answers: [String] = ["", "", ""]
    @State private var verificationFailed = false
    @State private var navigateToHome = false

    var body: some View {
        VStack(spacing: 24) {
            VStack(spacing: 8) {
                Image(systemName: "checkmark.shield")
                    .font(.system(size: 48))
                    .foregroundStyle(.blue)

                Text("Verify Your Backup")
                    .font(.title2)
                    .bold()

                Text("Enter the requested words from your recovery phrase to confirm your backup.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }
            .padding(.top, 8)

            // Challenge fields
            VStack(spacing: 16) {
                ForEach(0..<3, id: \.self) { i in
                    if i < challengeIndices.count {
                        let wordNumber = challengeIndices[i] + 1
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Word #\(wordNumber)")
                                .font(.caption)
                                .foregroundStyle(.secondary)

                            TextField("Enter word #\(wordNumber)", text: $answers[i])
                                .textFieldStyle(.roundedBorder)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                                .font(.system(.body, design: .monospaced))
                        }
                    }
                }
            }
            .padding(.horizontal, 32)

            if verificationFailed {
                HStack(spacing: 6) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.red)
                    Text("One or more words are incorrect. Please try again.")
                        .font(.subheadline)
                        .foregroundStyle(.red)
                }
                .padding(.horizontal)
            }

            Spacer()

            Button {
                verify()
            } label: {
                Text("Verify")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(.horizontal, 32)
            .disabled(answers.contains(""))

            Button("Skip Verification") {
                navigateToHome = true
            }
            .font(.subheadline)
            .foregroundStyle(.secondary)
            .padding(.bottom, 24)
        }
        .navigationTitle("Verify Phrase")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(true)
        .navigationDestination(isPresented: $navigateToHome) {
            HomeView()
                .environmentObject(vm)
                .navigationBarBackButtonHidden(true)
        }
        .onAppear {
            generateChallenge()
        }
    }

    private func generateChallenge() {
        guard !vm.mnemonic.isEmpty else { return }
        var indices = Set<Int>()
        while indices.count < 3 {
            indices.insert(Int.random(in: 0..<vm.mnemonic.count))
        }
        challengeIndices = indices.sorted()
        answers = ["", "", ""]
        verificationFailed = false
    }

    private func verify() {
        for (i, idx) in challengeIndices.enumerated() {
            let expected = vm.mnemonic[idx].lowercased().trimmingCharacters(in: .whitespaces)
            let given = answers[i].lowercased().trimmingCharacters(in: .whitespaces)
            if expected != given {
                verificationFailed = true
                return
            }
        }
        verificationFailed = false
        navigateToHome = true
    }
}
