import SwiftUI

/// Full-screen payment terminal with numeric keypad for amount entry,
/// a charge button, and post-payment confirmation with QR/NFC receive.
struct PaymentTerminalView: View {
    @EnvironmentObject private var vm: MerchantViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var amountInput: String = "0"
    @State private var terminalState: TerminalState = .enteringAmount
    @State private var lastTxId: String = ""

    private enum TerminalState {
        case enteringAmount
        case waitingForPayment
        case paymentReceived
    }

    var body: some View {
        VStack(spacing: 0) {
            switch terminalState {
            case .enteringAmount:
                amountEntryView
            case .waitingForPayment:
                paymentRequestView
            case .paymentReceived:
                paymentConfirmationView
            }
        }
        .navigationTitle("Payment Terminal")
        .navigationBarBackButtonHidden(terminalState != .enteringAmount)
        .toolbar {
            if terminalState != .enteringAmount {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        terminalState = .enteringAmount
                        amountInput = "0"
                    }
                }
            }
        }
    }

    // MARK: - Amount Entry

    private var amountEntryView: some View {
        VStack(spacing: 24) {
            Spacer()

            // Amount display
            VStack(spacing: 4) {
                Text(amountInput)
                    .font(.system(size: 48, weight: .bold, design: .rounded))
                    .foregroundStyle(Color.accentColor)
                    .lineLimit(1)
                    .minimumScaleFactor(0.5)

                Text("GHOST")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            // Numeric keypad
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 3), spacing: 12) {
                ForEach(["1","2","3","4","5","6","7","8","9",".","0","\u{232B}"], id: \.self) { key in
                    Button(action: { handleKeyPress(key) }) {
                        Text(key)
                            .font(.title2)
                            .fontWeight(.medium)
                            .frame(maxWidth: .infinity)
                            .frame(height: 60)
                            .background(Color(.secondarySystemGroupedBackground))
                            .cornerRadius(12)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal)

            // Charge button
            Button(action: {
                let sats = parseToSatoshis(amountInput)
                if sats > 0 {
                    vm.preparePaymentRequest(amount: sats)
                    terminalState = .waitingForPayment
                }
            }) {
                Text("Charge \(amountInput) GHOST")
                    .font(.headline)
                    .fontWeight(.bold)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 16)
                    .background(parseToSatoshis(amountInput) > 0 ? Color.accentColor : Color.gray)
                    .foregroundStyle(.white)
                    .cornerRadius(16)
            }
            .disabled(parseToSatoshis(amountInput) == 0)
            .padding(.horizontal)
            .padding(.bottom, 16)
        }
    }

    // MARK: - Payment Request (QR + NFC)

    private var paymentRequestView: some View {
        VStack(spacing: 20) {
            Spacer()

            Text("Waiting for Payment")
                .font(.title2)
                .fontWeight(.bold)

            Text(WalletViewModel.formatBalance(parseToSatoshis(amountInput)))
                .font(.system(size: 36, weight: .bold))
                .foregroundStyle(Color.accentColor)

            // QR code placeholder
            RoundedRectangle(cornerRadius: 16)
                .fill(Color.white)
                .frame(width: 250, height: 250)
                .overlay(
                    VStack(spacing: 8) {
                        Image(systemName: "qrcode")
                            .font(.system(size: 60))
                            .foregroundStyle(.gray)
                        Text(String(vm.currentReceiveAddress.prefix(20)) + "...")
                            .font(.caption)
                            .foregroundStyle(.gray)
                    }
                )
                .shadow(radius: 4)

            // NFC indicator
            HStack(spacing: 8) {
                ProgressView()
                Text("NFC ready - tap to pay")
                    .font(.subheadline)
            }
            .padding()
            .frame(maxWidth: .infinity)
            .background(Color(.tertiarySystemGroupedBackground))
            .cornerRadius(12)
            .padding(.horizontal)

            Spacer()

            // Dev: simulate payment
            Button("Simulate Payment Received") {
                lastTxId = "sim_\(Int(Date().timeIntervalSince1970))"
                let sats = parseToSatoshis(amountInput)
                vm.recordPayment(txId: lastTxId, amount: sats)
                terminalState = .paymentReceived
            }
            .buttonStyle(.bordered)
            .padding(.bottom, 16)
        }
    }

    // MARK: - Payment Confirmation

    private var paymentConfirmationView: some View {
        VStack(spacing: 20) {
            Spacer()

            // Success icon
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 72))
                .foregroundStyle(.green)

            Text("Payment Received")
                .font(.title2)
                .fontWeight(.bold)

            Text(WalletViewModel.formatBalance(parseToSatoshis(amountInput)))
                .font(.system(size: 32, weight: .bold))
                .foregroundStyle(Color.accentColor)

            Text("TxID: \(String(lastTxId.prefix(16)))...")
                .font(.caption)
                .foregroundStyle(.secondary)

            Spacer()

            // Wash via Wraith
            Button(action: {
                vm.queueWash(txId: lastTxId, amount: parseToSatoshis(amountInput))
            }) {
                Label("Wash via Wraith", systemImage: "arrow.triangle.2.circlepath")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.bordered)
            .tint(.purple)
            .padding(.horizontal)

            // View receipt
            Button(action: {
                let sats = parseToSatoshis(amountInput)
                vm.generateReceipt(txId: lastTxId, amount: sats)
            }) {
                Label("View Receipt", systemImage: "doc.text")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
            }
            .buttonStyle(.bordered)
            .padding(.horizontal)

            // New charge
            Button(action: {
                amountInput = "0"
                terminalState = .enteringAmount
            }) {
                Text("New Charge")
                    .font(.headline)
                    .fontWeight(.bold)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 16)
                    .background(Color.accentColor)
                    .foregroundStyle(.white)
                    .cornerRadius(16)
            }
            .padding(.horizontal)
            .padding(.bottom, 16)
        }
    }

    // MARK: - Keypad Logic

    private func handleKeyPress(_ key: String) {
        switch key {
        case "\u{232B}":
            if amountInput.count > 1 {
                amountInput.removeLast()
            } else {
                amountInput = "0"
            }
        case ".":
            if !amountInput.contains(".") {
                amountInput += "."
            }
        default:
            if amountInput == "0" {
                amountInput = key
            } else {
                // Limit to 8 decimal places
                if let dotIdx = amountInput.firstIndex(of: ".") {
                    let decimals = amountInput.distance(from: dotIdx, to: amountInput.endIndex) - 1
                    if decimals >= 8 { return }
                }
                amountInput += key
            }
        }
    }

    private func parseToSatoshis(_ input: String) -> UInt64 {
        guard let value = Double(input), value > 0 else { return 0 }
        return UInt64(value * 100_000_000)
    }
}
