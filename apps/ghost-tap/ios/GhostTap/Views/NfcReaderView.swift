import SwiftUI
import CoreNFC

/// A SwiftUI view that provides a button to initiate an NFC ISO-DEP session
/// for reading a GhostTap payment from a customer device.
///
/// When the user taps the "Tap to Pay" button, an `NFCTagReaderSession` is
/// started. The session selects the GhostTap AID (F0474854415000), reads the
/// payment request, and optionally sends a payment response back.
///
/// Usage:
/// ```swift
/// NfcReaderView(
///     paymentRequestData: encodedBytes,
///     onPaymentResponse: { responseData in /* handle */ },
///     onError: { error in /* handle */ }
/// )
/// ```
struct NfcReaderView: View {
    /// Binary-encoded payment request to send to the customer device.
    let paymentRequestData: Data

    /// Payment amount in satoshis (for NFC limit checking).
    var paymentAmount: UInt64 = 0

    /// Called with the raw binary payment response when the NFC exchange succeeds.
    let onPaymentResponse: (Data) -> Void

    /// Called when an error occurs during the NFC session.
    let onError: (String) -> Void

    @StateObject private var nfcSession = NfcSessionManager()
    @State private var limitExceeded = false

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "wave.3.right")
                .font(.system(size: 64))
                .foregroundColor(.accentColor)
                .rotationEffect(.degrees(-90))

            Text("Ready to Receive Payment")
                .font(.title2.bold())

            Text("Hold the customer's device near yours to complete the payment.")
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)

            if nfcSession.isScanning {
                ProgressView("Scanning...")
                    .padding()
            }

            Button(action: {
                startNfcSession()
            }) {
                Label("Tap to Pay", systemImage: "contactless.fill")
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.accentColor)
                    .cornerRadius(14)
            }
            .disabled(nfcSession.isScanning || !NFCTagReaderSession.readingAvailable)
            .padding(.horizontal, 32)

            if !NFCTagReaderSession.readingAvailable {
                Text("NFC is not available on this device.")
                    .font(.footnote)
                    .foregroundColor(.red)
            }
        }
        .padding()
    }

    private func startNfcSession() {
        // Check NFC limit before starting the session
        if paymentAmount > 0 && !nfcCheckLimit(amount: paymentAmount) {
            limitExceeded = true
            onError("Amount exceeds NFC limit. Please use QR code.")
            return
        }

        nfcSession.start(
            paymentRequestData: paymentRequestData,
            onPaymentResponse: onPaymentResponse,
            onError: onError
        )
    }
}

// MARK: - NFC Session Manager

/// Manages the `NFCTagReaderSession` lifecycle and APDU communication.
private class NfcSessionManager: NSObject, ObservableObject, NFCTagReaderSessionDelegate {
    @Published var isScanning = false

    private var session: NFCTagReaderSession?
    private var paymentRequestData: Data?
    private var onPaymentResponse: ((Data) -> Void)?
    private var onError: ((String) -> Void)?

    /// GhostTap AID: F0 47 48 54 41 50 00
    private static let ghostTapAID = Data([0xF0, 0x47, 0x48, 0x54, 0x41, 0x50, 0x00])

    /// ISO 7816-4 instruction bytes (must match Android HCE service).
    private static let insGetPaymentRequest: UInt8 = 0xB0
    private static let insSubmitPaymentResponse: UInt8 = 0xD0

    func start(
        paymentRequestData: Data,
        onPaymentResponse: @escaping (Data) -> Void,
        onError: @escaping (String) -> Void
    ) {
        self.paymentRequestData = paymentRequestData
        self.onPaymentResponse = onPaymentResponse
        self.onError = onError

        let session = NFCTagReaderSession(
            pollingOption: [.iso14443],
            delegate: self,
            queue: nil
        )
        session.alertMessage = "Hold your device near the customer's phone."
        self.session = session

        DispatchQueue.main.async {
            self.isScanning = true
        }
        session.begin()
    }

    // MARK: - NFCTagReaderSessionDelegate

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // Session is active, waiting for a tag.
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        DispatchQueue.main.async {
            self.isScanning = false
        }
        // NFCReaderError.readerSessionInvalidationErrorUserCanceled is not a real error.
        let nfcError = error as? NFCReaderError
        if nfcError?.code != .readerSessionInvalidationErrorUserCanceled {
            onError?("NFC session error: \(error.localizedDescription)")
        }
        cleanup()
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let tag = tags.first else {
            session.invalidate(errorMessage: "No tag detected.")
            return
        }

        // We only handle ISO 7816 (ISO-DEP) tags.
        guard case let .iso7816(isoTag) = tag else {
            session.invalidate(errorMessage: "Unsupported tag type.")
            return
        }

        session.connect(to: tag) { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                session.invalidate(errorMessage: "Connection failed: \(error.localizedDescription)")
                return
            }

            self.performApduExchange(tag: isoTag, session: session)
        }
    }

    // MARK: - APDU Exchange

    private func performApduExchange(tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        // Step 1: SELECT the GhostTap application by AID.
        let selectApdu = NFCISO7816APDU(
            instructionClass: 0x00,
            instructionCode: 0xA4,
            p1Parameter: 0x04,
            p2Parameter: 0x00,
            data: Self.ghostTapAID,
            expectedResponseLength: -1
        )

        tag.sendCommand(apdu: selectApdu) { [weak self] selectData, sw1, sw2, error in
            guard let self = self else { return }

            if let error = error {
                session.invalidate(errorMessage: "SELECT failed: \(error.localizedDescription)")
                return
            }

            guard sw1 == 0x90, sw2 == 0x00 else {
                session.invalidate(errorMessage: "SELECT rejected: SW=\(String(format: "%02X%02X", sw1, sw2))")
                return
            }

            if !selectData.isEmpty {
                let version = selectData[0]
                print("GhostTap remote version: \(version)")
            }

            // Step 2: GET_PAYMENT_REQUEST from the customer device.
            let getRequestApdu = NFCISO7816APDU(
                instructionClass: 0x00,
                instructionCode: Self.insGetPaymentRequest,
                p1Parameter: 0x00,
                p2Parameter: 0x00,
                data: Data(),
                expectedResponseLength: -1
            )

            tag.sendCommand(apdu: getRequestApdu) { getData, getSw1, getSw2, getError in
                if getError == nil, getSw1 == 0x90, getSw2 == 0x00 {
                    print("Customer payment request: \(getData.count) bytes")
                }

                // Step 3: SUBMIT_PAYMENT_RESPONSE with our payment request data.
                guard let requestData = self.paymentRequestData else {
                    session.invalidate(errorMessage: "No payment data to send.")
                    return
                }

                let submitApdu = NFCISO7816APDU(
                    instructionClass: 0x00,
                    instructionCode: Self.insSubmitPaymentResponse,
                    p1Parameter: 0x00,
                    p2Parameter: 0x00,
                    data: requestData,
                    expectedResponseLength: -1
                )

                tag.sendCommand(apdu: submitApdu) { submitData, submitSw1, submitSw2, submitError in
                    if let submitError = submitError {
                        session.invalidate(errorMessage: "Submit failed: \(submitError.localizedDescription)")
                        return
                    }

                    guard submitSw1 == 0x90, submitSw2 == 0x00 else {
                        session.invalidate(errorMessage: "Submit rejected: SW=\(String(format: "%02X%02X", submitSw1, submitSw2))")
                        return
                    }

                    session.alertMessage = "Payment received!"
                    session.invalidate()

                    DispatchQueue.main.async {
                        self.isScanning = false
                        self.onPaymentResponse?(submitData)
                    }
                }
            }
        }
    }

    private func cleanup() {
        session = nil
        paymentRequestData = nil
        onPaymentResponse = nil
        onError = nil
    }
}

#if DEBUG
struct NfcReaderView_Previews: PreviewProvider {
    static var previews: some View {
        NfcReaderView(
            paymentRequestData: Data([0x01, 0x01]),
            onPaymentResponse: { _ in },
            onError: { _ in }
        )
    }
}
#endif
