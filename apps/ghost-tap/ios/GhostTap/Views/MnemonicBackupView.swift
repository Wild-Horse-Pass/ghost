import SwiftUI

/// Displays the mnemonic words in a numbered 3-column grid.
/// User must confirm they have written the words down before proceeding.
struct MnemonicBackupView: View {
    @EnvironmentObject private var vm: WalletViewModel

    @State private var navigateToVerify = false
    @State private var revealWords = false

    private let columns = Array(repeating: GridItem(.flexible(), spacing: 12), count: 3)

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                // Header
                VStack(spacing: 8) {
                    Image(systemName: "lock.shield")
                        .font(.system(size: 48))
                        .foregroundStyle(.orange)

                    Text("Back Up Your Wallet")
                        .font(.title2)
                        .bold()

                    Text("Write down these \(vm.mnemonic.count) words in order. Store them somewhere safe and offline. Anyone with these words can access your funds.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }
                .padding(.top, 8)

                // Reveal toggle
                if !revealWords {
                    Button {
                        revealWords = true
                    } label: {
                        Label("Tap to Reveal Words", systemImage: "eye")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 40)
                    }
                    .buttonStyle(.bordered)
                    .padding(.horizontal)
                } else {
                    // Word grid
                    LazyVGrid(columns: columns, spacing: 12) {
                        ForEach(Array(vm.mnemonic.enumerated()), id: \.offset) { index, word in
                            HStack(spacing: 4) {
                                Text("\(index + 1).")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .frame(width: 24, alignment: .trailing)

                                Text(word)
                                    .font(.system(.body, design: .monospaced))
                                    .bold()
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.vertical, 10)
                            .padding(.horizontal, 8)
                            .background(Color(.secondarySystemBackground))
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                        }
                    }
                    .padding(.horizontal)
                }

                // Warning
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text("Never share these words. Never store them digitally. GhostTap cannot recover lost mnemonics.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding()
                .background(Color(.secondarySystemBackground))
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .padding(.horizontal)

                // Confirm button
                Button {
                    navigateToVerify = true
                } label: {
                    Text("I've Written It Down")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .padding(.horizontal, 32)
                .disabled(!revealWords)

                Spacer(minLength: 32)
            }
        }
        .navigationTitle("Recovery Phrase")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(true)
        .navigationDestination(isPresented: $navigateToVerify) {
            MnemonicVerifyView()
                .environmentObject(vm)
        }
    }
}
