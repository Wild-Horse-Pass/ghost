import SwiftUI

/// Main merchant dashboard showing sales summaries, wash status,
/// and recent merchant transactions.
struct MerchantDashboardView: View {
    @EnvironmentObject private var vm: MerchantViewModel

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Sales summary cards
                salesOverviewSection

                // Wraith wash status
                if vm.washStats.totalCount > 0 {
                    washStatusSection
                }

                // Quick actions
                quickActionsSection

                // Recent transactions
                recentTransactionsSection
            }
            .padding()
        }
        .navigationTitle("Merchant")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                NavigationLink(destination: MerchantSettingsView().environmentObject(vm)) {
                    Image(systemName: "gearshape")
                }
            }
        }
        .onAppear {
            vm.refreshSalesAggregation()
        }
    }

    // MARK: - Sales Overview

    private var salesOverviewSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Sales Overview")
                .font(.headline)
                .fontWeight(.bold)

            HStack(spacing: 12) {
                SalesSummaryCard(
                    label: "Today",
                    amount: vm.dailyTotal,
                    count: vm.dailyCount
                )
                SalesSummaryCard(
                    label: "This Week",
                    amount: vm.weeklyTotal,
                    count: vm.weeklyCount
                )
                SalesSummaryCard(
                    label: "This Month",
                    amount: vm.monthlyTotal,
                    count: vm.monthlyCount
                )
            }
        }
    }

    // MARK: - Wash Status

    private var washStatusSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Wraith Wash Status")
                .font(.subheadline)
                .fontWeight(.bold)

            HStack(spacing: 16) {
                WashPill(label: "Queued", count: vm.washStats.queued, color: .gray)
                WashPill(label: "Active", count: vm.washStats.inProgress, color: .blue)
                WashPill(label: "Done", count: vm.washStats.completed, color: .green)
                if vm.washStats.failed > 0 {
                    WashPill(label: "Failed", count: vm.washStats.failed, color: .red)
                }
            }
            .frame(maxWidth: .infinity)
        }
        .padding()
        .background(Color(.secondarySystemGroupedBackground))
        .cornerRadius(12)
    }

    // MARK: - Quick Actions

    private var quickActionsSection: some View {
        HStack(spacing: 12) {
            NavigationLink(destination: PaymentTerminalView().environmentObject(vm)) {
                ActionButton(label: "Charge", isPrimary: true)
            }
            NavigationLink(destination: InvoiceCreateView().environmentObject(vm)) {
                ActionButton(label: "Invoice", isPrimary: false)
            }
            NavigationLink(destination: TransactionExportView().environmentObject(vm)) {
                ActionButton(label: "Export", isPrimary: false)
            }
        }
    }

    // MARK: - Recent Transactions

    private var recentTransactionsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Recent Transactions")
                .font(.headline)
                .fontWeight(.bold)

            if vm.recentTransactions.isEmpty() {
                Text("No transactions yet. Use the terminal to start accepting payments.")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .padding()
                    .frame(maxWidth: .infinity)
                    .background(Color(.secondarySystemGroupedBackground))
                    .cornerRadius(8)
            } else {
                ForEach(vm.recentTransactions) { tx in
                    MerchantTransactionRow(transaction: tx)
                }
            }
        }
    }
}

// MARK: - Subviews

private struct SalesSummaryCard: View {
    let label: String
    let amount: UInt64
    let count: Int

    var body: some View {
        VStack(spacing: 4) {
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)

            Text(WalletViewModel.formatBalance(amount))
                .font(.subheadline)
                .fontWeight(.bold)
                .lineLimit(1)
                .minimumScaleFactor(0.7)

            Text("\(count) txns")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(12)
        .background(Color.accentColor.opacity(0.1))
        .cornerRadius(12)
    }
}

private struct WashPill: View {
    let label: String
    let count: Int
    let color: Color

    var body: some View {
        VStack(spacing: 2) {
            Text("\(count)")
                .font(.headline)
                .fontWeight(.bold)
                .foregroundStyle(color)
                .padding(.horizontal, 12)
                .padding(.vertical, 4)
                .background(color.opacity(0.15))
                .cornerRadius(8)

            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }
}

private struct ActionButton: View {
    let label: String
    let isPrimary: Bool

    var body: some View {
        Text(label)
            .font(.subheadline)
            .fontWeight(.semibold)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 12)
            .background(isPrimary ? Color.accentColor : Color(.secondarySystemGroupedBackground))
            .foregroundStyle(isPrimary ? .white : .primary)
            .cornerRadius(12)
    }
}

private struct MerchantTransactionRow: View {
    let transaction: MerchantTransaction

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(String(transaction.txId.prefix(12)) + "...")
                    .font(.subheadline)
                    .fontWeight(.medium)

                Text(transaction.relativeTime)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if let wash = transaction.washStatus {
                    Text("Wash: \(wash.label)")
                        .font(.caption2)
                        .foregroundStyle(wash.color)
                }
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 4) {
                Text("+" + WalletViewModel.formatBalance(transaction.amount))
                    .font(.subheadline)
                    .fontWeight(.bold)
                    .foregroundStyle(.green)

                Text(transaction.status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .background(Color(.secondarySystemGroupedBackground))
        .cornerRadius(8)
    }
}
