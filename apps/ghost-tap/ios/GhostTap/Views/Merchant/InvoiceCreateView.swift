import SwiftUI

/// Invoice creation form with line items, due date, and share capability.
struct InvoiceCreateView: View {
    @EnvironmentObject private var vm: MerchantViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var dueDate: Date = Calendar.current.date(byAdding: .day, value: 7, to: Date()) ?? Date()
    @State private var memo: String = ""
    @State private var lineItems: [InvoiceLineItemInput] = [InvoiceLineItemInput()]
    @State private var showingPreview: Bool = false
    @State private var previewInvoiceId: String = ""

    var body: some View {
        List {
            // Due date
            Section("Invoice Details") {
                DatePicker("Due Date", selection: $dueDate, displayedComponents: .date)

                TextField("Notes / Memo (Optional)", text: $memo, axis: .vertical)
                    .lineLimit(2...4)
            }

            // Line items
            Section {
                ForEach(lineItems.indices, id: \.self) { index in
                    HStack(spacing: 8) {
                        TextField("Description", text: $lineItems[index].description)
                            .frame(maxWidth: .infinity)

                        TextField("GHOST", text: $lineItems[index].amount)
                            .frame(width: 100)
                            .keyboardType(.decimalPad)
                            .multilineTextAlignment(.trailing)
                    }
                }
                .onDelete { indices in
                    lineItems.remove(atOffsets: indices)
                    if lineItems.isEmpty {
                        lineItems.append(InvoiceLineItemInput())
                    }
                }

                Button(action: {
                    lineItems.append(InvoiceLineItemInput())
                }) {
                    Label("Add Item", systemImage: "plus")
                }
            } header: {
                Text("Line Items")
            }

            // Total
            Section {
                HStack {
                    Text("Total")
                        .fontWeight(.bold)
                    Spacer()
                    Text("\(WalletViewModel.formatBalance(totalSatoshis)) GHOST")
                        .fontWeight(.bold)
                        .foregroundStyle(Color.accentColor)
                }
            }

            // Actions
            Section {
                Button(action: createAndPreview) {
                    Label("Preview Invoice", systemImage: "eye")
                        .frame(maxWidth: .infinity)
                        .fontWeight(.semibold)
                }
                .disabled(totalSatoshis == 0)

                Button(action: createAndShare) {
                    Label("Create & Share", systemImage: "square.and.arrow.up")
                        .frame(maxWidth: .infinity)
                        .fontWeight(.semibold)
                }
                .disabled(totalSatoshis == 0)
            }
        }
        .navigationTitle("Create Invoice")
        .sheet(isPresented: $showingPreview) {
            NavigationStack {
                InvoicePreviewSheet(invoiceId: previewInvoiceId)
                    .environmentObject(vm)
            }
        }
    }

    private var totalSatoshis: UInt64 {
        lineItems.reduce(0) { total, item in
            total + item.satoshiAmount
        }
    }

    private func createAndPreview() {
        let items = lineItems
            .filter { !$0.description.isEmpty && $0.satoshiAmount > 0 }
            .map { ($0.description, $0.satoshiAmount) }

        let invoiceId = vm.createInvoice(
            totalAmount: totalSatoshis,
            dueDate: UInt64(dueDate.timeIntervalSince1970),
            lineItems: items,
            memo: memo.isEmpty ? nil : memo
        )

        previewInvoiceId = invoiceId
        showingPreview = true
    }

    private func createAndShare() {
        let items = lineItems
            .filter { !$0.description.isEmpty && $0.satoshiAmount > 0 }
            .map { ($0.description, $0.satoshiAmount) }

        let invoiceId = vm.createInvoice(
            totalAmount: totalSatoshis,
            dueDate: UInt64(dueDate.timeIntervalSince1970),
            lineItems: items,
            memo: memo.isEmpty ? nil : memo
        )

        guard let html = vm.getInvoiceHtml(invoiceId: invoiceId) else { return }

        let activityVC = UIActivityViewController(
            activityItems: [html],
            applicationActivities: nil
        )

        if let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let rootVC = windowScene.windows.first?.rootViewController {
            rootVC.present(activityVC, animated: true)
        }
    }
}

// MARK: - Supporting Types

private struct InvoiceLineItemInput {
    var description: String = ""
    var amount: String = ""

    var satoshiAmount: UInt64 {
        guard let value = Double(amount), value > 0 else { return 0 }
        return UInt64(value * 100_000_000)
    }
}

// MARK: - Invoice Preview Sheet

private struct InvoicePreviewSheet: View {
    @EnvironmentObject private var vm: MerchantViewModel
    @Environment(\.dismiss) private var dismiss

    let invoiceId: String

    var body: some View {
        Group {
            if let html = vm.getInvoiceHtml(invoiceId: invoiceId) {
                InvoiceWebView(html: html)
            } else {
                ContentUnavailableView(
                    "Invoice Not Found",
                    systemImage: "doc.questionmark"
                )
            }
        }
        .navigationTitle("Invoice Preview")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("Done") { dismiss() }
            }
        }
    }
}

private struct InvoiceWebView: UIViewRepresentable {
    let html: String

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.defaultWebpagePreferences.allowsContentJavaScript = false

        let wv = WKWebView(frame: .zero, configuration: config)
        wv.loadHTMLString(html, baseURL: nil)
        return wv
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {
        uiView.loadHTMLString(html, baseURL: nil)
    }
}
