import SwiftUI

/// Date range picker with format selection (CSV/PDF) for exporting
/// merchant transaction history.
struct TransactionExportView: View {
    @EnvironmentObject private var vm: MerchantViewModel

    @State private var startDate: Date = Calendar.current.date(
        byAdding: .day, value: -30, to: Date()
    ) ?? Date()
    @State private var endDate: Date = Date()
    @State private var selectedFormat: ExportFormat = .csv
    @State private var isExporting: Bool = false

    private enum ExportFormat: String, CaseIterable, Identifiable {
        case csv = "CSV"
        case pdf = "PDF"

        var id: String { rawValue }

        var description: String {
            switch self {
            case .csv: return "Spreadsheet-compatible"
            case .pdf: return "Printable report"
            }
        }
    }

    var body: some View {
        Form {
            // Date range
            Section("Date Range") {
                DatePicker("Start Date", selection: $startDate, displayedComponents: .date)
                DatePicker("End Date", selection: $endDate, displayedComponents: .date)
            }

            // Format selection
            Section("Format") {
                Picker("Export Format", selection: $selectedFormat) {
                    ForEach(ExportFormat.allCases) { format in
                        VStack(alignment: .leading) {
                            Text(format.rawValue)
                        }
                        .tag(format)
                    }
                }
                .pickerStyle(.segmented)

                Text(selectedFormat.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            // Transaction count
            Section {
                HStack {
                    Text("Transactions in range")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text("\(transactionCount)")
                        .fontWeight(.bold)
                        .foregroundStyle(Color.accentColor)
                }
            }

            // Generate & share
            Section {
                Button(action: generateAndShare) {
                    HStack {
                        if isExporting {
                            ProgressView()
                                .scaleEffect(0.8)
                        }
                        Label(
                            "Generate & Share \(selectedFormat.rawValue)",
                            systemImage: "square.and.arrow.up"
                        )
                        .frame(maxWidth: .infinity)
                        .fontWeight(.bold)
                    }
                }
                .disabled(isExporting || transactionCount == 0)
            }
        }
        .navigationTitle("Export Transactions")
    }

    private var transactionCount: Int {
        let from = UInt64(startDate.timeIntervalSince1970)
        let to = UInt64(endDate.timeIntervalSince1970)
        return vm.getTransactionCountInRange(from: from, to: to)
    }

    private func generateAndShare() {
        isExporting = true

        let from = UInt64(startDate.timeIntervalSince1970)
        let to = UInt64(endDate.timeIntervalSince1970)

        let content: String
        switch selectedFormat {
        case .csv:
            content = vm.exportCsv(from: from, to: to)
        case .pdf:
            content = vm.exportHtmlReport(from: from, to: to)
        }

        isExporting = false

        let activityVC = UIActivityViewController(
            activityItems: [content],
            applicationActivities: nil
        )

        if let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let rootVC = windowScene.windows.first?.rootViewController {
            rootVC.present(activityVC, animated: true)
        }
    }
}
