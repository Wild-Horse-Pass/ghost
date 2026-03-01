import SwiftUI
import WebKit

/// Renders an HTML receipt in a WebView with share and print capabilities.
struct ReceiptView: View {
    @EnvironmentObject private var vm: MerchantViewModel

    let receiptId: String

    @State private var webView: WKWebView?

    var body: some View {
        VStack(spacing: 0) {
            if let html = vm.getReceiptHtml(receiptId: receiptId), !html.isEmpty {
                ReceiptWebView(html: html, webView: $webView)
                    .edgesIgnoringSafeArea(.bottom)

                // Bottom action bar
                HStack(spacing: 16) {
                    Button(action: shareReceipt) {
                        Label("Share", systemImage: "square.and.arrow.up")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)

                    Button(action: printReceipt) {
                        Label("Print", systemImage: "printer")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding()
            } else {
                ContentUnavailableView(
                    "Receipt Not Found",
                    systemImage: "doc.questionmark",
                    description: Text("The requested receipt could not be loaded.")
                )
            }
        }
        .navigationTitle("Receipt")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func shareReceipt() {
        guard let html = vm.getReceiptHtml(receiptId: receiptId) else { return }

        let activityVC = UIActivityViewController(
            activityItems: [html],
            applicationActivities: nil
        )

        if let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let rootVC = windowScene.windows.first?.rootViewController {
            rootVC.present(activityVC, animated: true)
        }
    }

    private func printReceipt() {
        guard let wv = webView else { return }

        let printController = UIPrintInteractionController.shared
        let printInfo = UIPrintInfo(dictionary: nil)
        printInfo.jobName = "GhostTap Receipt \(receiptId)"
        printInfo.outputType = .general
        printController.printInfo = printInfo
        printController.printFormatter = wv.viewPrintFormatter()
        printController.present(animated: true)
    }
}

/// UIViewRepresentable wrapper for WKWebView that loads HTML content.
private struct ReceiptWebView: UIViewRepresentable {
    let html: String
    @Binding var webView: WKWebView?

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.defaultWebpagePreferences.allowsContentJavaScript = false

        let wv = WKWebView(frame: .zero, configuration: configuration)
        wv.isOpaque = false
        wv.backgroundColor = .systemBackground
        wv.loadHTMLString(html, baseURL: nil)

        DispatchQueue.main.async {
            self.webView = wv
        }

        return wv
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {
        // Reload if the HTML content changes
        uiView.loadHTMLString(html, baseURL: nil)
    }
}
