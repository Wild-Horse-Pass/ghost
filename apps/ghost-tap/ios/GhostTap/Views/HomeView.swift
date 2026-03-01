import SwiftUI

/// Main wallet home screen: balance card, quick action buttons,
/// and a pull-to-refresh transaction list.
struct HomeView: View {
    @EnvironmentObject private var vm: WalletViewModel

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Balance card
                balanceCard

                // Quick action buttons
                actionButtons

                // Transaction list
                transactionSection
            }
            .padding(.top, 8)
        }
        .refreshable {
            await vm.refreshBalance()
        }
        .navigationTitle("Wallet")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                NavigationLink {
                    SettingsView()
                        .environmentObject(vm)
                } label: {
                    Image(systemName: "gear")
                }
            }
        }
    }

    // MARK: - Balance Card

    private var balanceCard: some View {
        VStack(spacing: 8) {
            Text("Balance")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            Text("\(WalletViewModel.formatBalance(vm.balance)) GHOST")
                .font(.system(.title, design: .monospaced))
                .bold()

            if vm.pendingIncoming > 0 || vm.pendingOutgoing > 0 {
                HStack(spacing: 16) {
                    if vm.pendingIncoming > 0 {
                        Label("+\(WalletViewModel.formatBalance(vm.pendingIncoming))", systemImage: "arrow.down.circle")
                            .font(.caption)
                            .foregroundStyle(.green)
                    }
                    if vm.pendingOutgoing > 0 {
                        Label("-\(WalletViewModel.formatBalance(vm.pendingOutgoing))", systemImage: "arrow.up.circle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
            }

            Text(vm.syncStatus.description)
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 24)
        .background(Color(.secondarySystemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 16))
        .padding(.horizontal)
    }

    // MARK: - Action Buttons

    private var actionButtons: some View {
        HStack(spacing: 0) {
            NavigationLink {
                SendView()
                    .environmentObject(vm)
            } label: {
                actionButton(icon: "arrow.up.circle.fill", label: "Send", color: .orange)
            }

            NavigationLink {
                ReceiveView()
                    .environmentObject(vm)
            } label: {
                actionButton(icon: "arrow.down.circle.fill", label: "Receive", color: .green)
            }

            NavigationLink {
                // QR scanner placeholder -- functionality handled in future iteration
                Text("QR Scanner")
                    .navigationTitle("Scan")
            } label: {
                actionButton(icon: "qrcode.viewfinder", label: "Scan", color: .blue)
            }
        }
        .padding(.horizontal)
    }

    private func actionButton(icon: String, label: String, color: Color) -> some View {
        VStack(spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 28))
                .foregroundStyle(color)
            Text(label)
                .font(.caption)
                .foregroundStyle(.primary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12)
        .background(Color(.secondarySystemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .padding(.horizontal, 4)
    }

    // MARK: - Transaction List

    private var transactionSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Transactions")
                .font(.headline)
                .padding(.horizontal)

            if vm.history.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "tray")
                        .font(.system(size: 32))
                        .foregroundStyle(.tertiary)
                    Text("No transactions yet")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 40)
            } else {
                LazyVStack(spacing: 0) {
                    ForEach(vm.history) { tx in
                        NavigationLink {
                            TransactionDetailView(transaction: tx)
                        } label: {
                            transactionRow(tx)
                        }
                        .buttonStyle(.plain)

                        Divider()
                            .padding(.leading, 56)
                    }
                }
            }
        }
    }

    private func transactionRow(_ tx: Transaction) -> some View {
        HStack(spacing: 12) {
            Image(systemName: tx.isIncoming ? "arrow.down.left.circle.fill" : "arrow.up.right.circle.fill")
                .font(.title2)
                .foregroundStyle(tx.isIncoming ? .green : .orange)
                .frame(width: 36)

            VStack(alignment: .leading, spacing: 2) {
                Text(tx.isIncoming ? "Received" : "Sent")
                    .font(.subheadline)
                    .bold()

                Text(tx.addressSnippet)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 2) {
                Text("\(tx.isIncoming ? "+" : "-")\(WalletViewModel.formatBalance(tx.amount))")
                    .font(.subheadline)
                    .foregroundStyle(tx.isIncoming ? .green : .primary)
                    .bold()

                Text(tx.relativeTime)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        .padding(.horizontal)
        .padding(.vertical, 10)
    }
}
