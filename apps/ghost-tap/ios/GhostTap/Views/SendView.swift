import SwiftUI

/// Send screen: address input, amount, fee picker, review, and confirm.
struct SendView: View {
    @EnvironmentObject private var vm: WalletViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var address = ""
    @State private var amountString = ""
    @State private var feePriority: FeePriority = .medium
    @State private var showReview = false
    @State private var isSending = false
    @State private var sendResult: String?
    @State private var sendError: String?

    private var amountSatoshis: UInt64? {
        guard let decimal = Double(amountString), decimal > 0 else { return nil }
        return UInt64(decimal * 100_000_000)
    }

    private var canProceed: Bool {
        !address.isEmpty && amountSatoshis != nil && (amountSatoshis ?? 0) <= vm.balance
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                // Address field
                VStack(alignment: .leading, spacing: 6) {
                    Text("Recipient Address")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)

                    TextField("Ghost address...", text: $address)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                // Amount field
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text("Amount")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text("Available: \(WalletViewModel.formatBalance(vm.balance))")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }

                    HStack {
                        TextField("0.00000000", text: $amountString)
                            .textFieldStyle(.roundedBorder)
                            .keyboardType(.decimalPad)
                            .font(.system(.body, design: .monospaced))

                        Button("Max") {
                            if vm.balance > 0 {
                                amountString = WalletViewModel.formatBalance(vm.balance)
                            }
                        }
                        .font(.caption)
                        .buttonStyle(.bordered)
                    }

                    if let sats = amountSatoshis, sats > vm.balance {
                        Text("Insufficient balance")
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }

                // Fee picker
                VStack(alignment: .leading, spacing: 6) {
                    Text("Fee Priority")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)

                    Picker("Fee", selection: $feePriority) {
                        ForEach(FeePriority.allCases) { priority in
                            Text("\(priority.label) (\(priority.description))")
                                .tag(priority)
                        }
                    }
                    .pickerStyle(.segmented)
                }

                Divider()

                // Review section
                if showReview, let sats = amountSatoshis {
                    reviewSection(amount: sats)
                }

                // Send error
                if let error = sendError {
                    HStack(spacing: 6) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.red)
                        Text(error)
                            .font(.subheadline)
                            .foregroundStyle(.red)
                    }
                }

                // Send success
                if let txid = sendResult {
                    VStack(spacing: 8) {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 48))
                            .foregroundStyle(.green)
                        Text("Transaction Sent")
                            .font(.headline)
                        Text(txid)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)

                        Button("Done") {
                            dismiss()
                        }
                        .buttonStyle(.borderedProminent)
                        .padding(.top, 8)
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                }

                // Action button
                if sendResult == nil {
                    if showReview {
                        Button {
                            Task { await confirmSend() }
                        } label: {
                            if isSending {
                                ProgressView()
                                    .frame(maxWidth: .infinity)
                            } else {
                                Text("Confirm & Send")
                                    .frame(maxWidth: .infinity)
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(.orange)
                        .controlSize(.large)
                        .disabled(isSending)
                    } else {
                        Button {
                            showReview = true
                        } label: {
                            Text("Review Transaction")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .disabled(!canProceed)
                    }
                }
            }
            .padding()
        }
        .navigationTitle("Send")
        .navigationBarTitleDisplayMode(.inline)
    }

    @ViewBuilder
    private func reviewSection(amount: UInt64) -> some View {
        VStack(spacing: 12) {
            Text("Review")
                .font(.headline)

            VStack(spacing: 8) {
                reviewRow("To", value: address)
                reviewRow("Amount", value: "\(WalletViewModel.formatBalance(amount)) GHOST")
                reviewRow("Fee", value: feePriority.label)
            }
            .padding()
            .background(Color(.secondarySystemBackground))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
    }

    private func reviewRow(_ label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.subheadline)
                .bold()
                .lineLimit(1)
                .truncationMode(.middle)
        }
    }

    private func confirmSend() async {
        guard let sats = amountSatoshis else { return }
        isSending = true
        sendError = nil

        if let txid = await vm.send(to: address, amount: sats, fee: feePriority) {
            sendResult = txid
        } else {
            sendError = vm.errorMessage ?? "Transaction failed"
        }

        isSending = false
    }
}
