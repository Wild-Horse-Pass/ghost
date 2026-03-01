import SwiftUI

/// Full transaction detail view showing txid, amount, fee, confirmations,
/// timestamp, address, and a status badge.
struct TransactionDetailView: View {
    let transaction: Transaction

    @State private var copiedTxid = false

    var body: some View {
        List {
            // Status header
            Section {
                VStack(spacing: 12) {
                    Image(systemName: transaction.isIncoming
                          ? "arrow.down.left.circle.fill"
                          : "arrow.up.right.circle.fill")
                        .font(.system(size: 48))
                        .foregroundStyle(transaction.isIncoming ? .green : .orange)

                    Text("\(transaction.isIncoming ? "+" : "-")\(WalletViewModel.formatBalance(transaction.amount)) GHOST")
                        .font(.system(.title2, design: .monospaced))
                        .bold()

                    statusBadge
                }
                .frame(maxWidth: .infinity)
                .listRowBackground(Color.clear)
            }

            // Details
            Section("Details") {
                detailRow("Direction", value: transaction.isIncoming ? "Received" : "Sent")
                detailRow("Confirmations", value: "\(transaction.confirmations)")
                detailRow("Timestamp", value: formattedDate)

                if let fee = transaction.fee {
                    detailRow("Fee", value: "\(WalletViewModel.formatBalance(fee)) GHOST")
                }

                if let memo = transaction.memo, !memo.isEmpty {
                    detailRow("Memo", value: memo)
                }
            }

            // Address
            Section("Address") {
                VStack(alignment: .leading, spacing: 4) {
                    Text(transaction.address)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }

            // Transaction ID
            Section("Transaction ID") {
                VStack(alignment: .leading, spacing: 8) {
                    Text(transaction.id)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)

                    Button {
                        UIPasteboard.general.string = transaction.id
                        copiedTxid = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                            copiedTxid = false
                        }
                    } label: {
                        Label(copiedTxid ? "Copied" : "Copy TxID", systemImage: copiedTxid ? "checkmark" : "doc.on.doc")
                            .font(.subheadline)
                    }
                }
            }
        }
        .navigationTitle("Transaction")
        .navigationBarTitleDisplayMode(.inline)
    }

    // MARK: - Sub-views

    private var statusBadge: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)
            Text(transaction.status.capitalized)
                .font(.caption)
                .bold()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 4)
        .background(statusColor.opacity(0.15))
        .clipShape(Capsule())
    }

    private var statusColor: Color {
        switch transaction.status {
        case "confirmed": return .green
        case "pending": return .orange
        case "failed": return .red
        default: return .gray
        }
    }

    private var formattedDate: String {
        let date = Date(timeIntervalSince1970: TimeInterval(transaction.timestamp))
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }

    private func detailRow(_ label: String, value: String) -> some View {
        HStack {
            Text(label)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .bold()
        }
    }
}
