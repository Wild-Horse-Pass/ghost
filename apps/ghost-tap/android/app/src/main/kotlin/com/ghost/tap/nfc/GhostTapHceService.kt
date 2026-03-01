package com.ghost.tap.nfc

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log

/**
 * Host Card Emulation (HCE) service for GhostTap NFC tap-to-pay.
 *
 * This service emulates an NFC smart card so that a merchant terminal can
 * read a payment request from this device and submit a payment response
 * back via ISO 7816-4 APDU commands.
 *
 * Custom AID: F0474854415000  (ASCII "GHTAP\0" with F0 prefix for proprietary)
 *
 * APDU flow:
 * 1. Merchant sends SELECT by AID  -> Service returns success + version info
 * 2. Merchant sends GET_PAYMENT_REQUEST -> Service returns binary payment request
 * 3. Merchant sends SUBMIT_PAYMENT_RESPONSE with txid -> Service returns ACK
 */
class GhostTapHceService : HostApduService() {

    companion object {
        private const val TAG = "GhostTapHCE"

        // GhostTap application identifier: F0 47 48 54 41 50 00
        val AID = byteArrayOf(
            0xF0.toByte(), 0x47, 0x48, 0x54, 0x41, 0x50, 0x00
        )

        // ISO 7816-4 status words
        private val SW_OK = byteArrayOf(0x90.toByte(), 0x00)
        private val SW_FILE_NOT_FOUND = byteArrayOf(0x6A.toByte(), 0x82.toByte())
        private val SW_CONDITIONS_NOT_SATISFIED = byteArrayOf(0x69.toByte(), 0x85.toByte())
        private val SW_WRONG_LENGTH = byteArrayOf(0x67.toByte(), 0x00)
        private val SW_INS_NOT_SUPPORTED = byteArrayOf(0x6D.toByte(), 0x00)

        // Custom instruction bytes
        const val INS_SELECT: Byte = 0xA4.toByte()
        const val INS_GET_PAYMENT_REQUEST: Byte = 0xB0.toByte()
        const val INS_SUBMIT_PAYMENT_RESPONSE: Byte = 0xD0.toByte()

        // Protocol version
        const val PROTOCOL_VERSION: Byte = 0x01

        // Status codes in payment response
        const val STATUS_SUCCESS: Byte = 0x00
        const val STATUS_DEVICE_LOCKED: Byte = 0x01
        const val STATUS_NO_PENDING_REQUEST: Byte = 0x02
        const val STATUS_LIMIT_EXCEEDED: Byte = 0x03

        // Pending payment amount for limit checking (set alongside pendingPaymentRequest)
        @Volatile
        var pendingPaymentAmount: Long = 0

        // Shared state: the pending payment request to be served over NFC.
        // Set by the UI before the NFC tap occurs.
        @Volatile
        var pendingPaymentRequest: ByteArray? = null

        // Callback invoked when a payment response is received from the merchant.
        @Volatile
        var onPaymentResponseReceived: ((ByteArray) -> Unit)? = null
    }

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {
        if (commandApdu.size < 4) {
            Log.w(TAG, "APDU too short: ${commandApdu.size} bytes")
            return SW_WRONG_LENGTH
        }

        val cla = commandApdu[0]
        val ins = commandApdu[1]
        val p1 = commandApdu[2]
        val p2 = commandApdu[3]

        Log.d(TAG, "APDU: CLA=${hex(cla)} INS=${hex(ins)} P1=${hex(p1)} P2=${hex(p2)} len=${commandApdu.size}")

        return when (ins) {
            INS_SELECT -> handleSelect(commandApdu)
            INS_GET_PAYMENT_REQUEST -> handleGetPaymentRequest()
            INS_SUBMIT_PAYMENT_RESPONSE -> handleSubmitPaymentResponse(commandApdu)
            else -> {
                Log.w(TAG, "Unsupported instruction: ${hex(ins)}")
                SW_INS_NOT_SUPPORTED
            }
        }
    }

    override fun onDeactivated(reason: Int) {
        Log.d(TAG, "HCE deactivated, reason=$reason")
    }

    // -----------------------------------------------------------------------
    // APDU handlers
    // -----------------------------------------------------------------------

    /**
     * Handle SELECT command (INS=A4).
     *
     * Verifies the AID matches GhostTap, returns protocol version + SW_OK.
     */
    private fun handleSelect(apdu: ByteArray): ByteArray {
        // SELECT APDU: [CLA(1)] [INS(1)] [P1(1)] [P2(1)] [Lc(1)] [AID(Lc)] [Le(0-1)]
        if (apdu.size < 5) return SW_WRONG_LENGTH

        val lc = apdu[4].toInt() and 0xFF
        if (apdu.size < 5 + lc) return SW_WRONG_LENGTH

        val candidateAid = apdu.copyOfRange(5, 5 + lc)

        if (!candidateAid.contentEquals(AID)) {
            Log.d(TAG, "SELECT: AID mismatch")
            return SW_FILE_NOT_FOUND
        }

        Log.d(TAG, "SELECT: AID matched, returning version")
        // Response: [version(1)] [SW1(1)] [SW2(1)]
        return byteArrayOf(PROTOCOL_VERSION) + SW_OK
    }

    /**
     * Handle GET_PAYMENT_REQUEST (INS=B0).
     *
     * Returns the pending binary payment request set by the wallet UI,
     * or a status error if none is available or the device is locked.
     */
    private fun handleGetPaymentRequest(): ByteArray {
        // Check if wallet is unlocked (simple check -- in production this
        // would query the actual wallet lock state).
        if (isDeviceLocked()) {
            Log.d(TAG, "GET_PAYMENT_REQUEST: device locked")
            return byteArrayOf(STATUS_DEVICE_LOCKED) + SW_CONDITIONS_NOT_SATISFIED
        }

        val request = pendingPaymentRequest
        if (request == null) {
            Log.d(TAG, "GET_PAYMENT_REQUEST: no pending request")
            return byteArrayOf(STATUS_NO_PENDING_REQUEST) + SW_CONDITIONS_NOT_SATISFIED
        }

        // Check NFC amount limit
        val amount = pendingPaymentAmount
        if (amount > 0) {
            try {
                val allowed = com.ghost.tap.RustBridge.nfcCheckLimit(amount)
                if (!allowed) {
                    Log.d(TAG, "GET_PAYMENT_REQUEST: NFC limit exceeded ($amount sats)")
                    return byteArrayOf(STATUS_LIMIT_EXCEEDED) + SW_CONDITIONS_NOT_SATISFIED
                }
            } catch (e: Exception) {
                Log.w(TAG, "NFC limit check failed, proceeding anyway", e)
            }
        }

        Log.d(TAG, "GET_PAYMENT_REQUEST: returning ${request.size} bytes")
        return request + SW_OK
    }

    /**
     * Handle SUBMIT_PAYMENT_RESPONSE (INS=D0).
     *
     * The merchant terminal sends the signed transaction response. The data
     * portion of the APDU contains the binary NfcPaymentResponse.
     */
    private fun handleSubmitPaymentResponse(apdu: ByteArray): ByteArray {
        if (apdu.size < 5) return SW_WRONG_LENGTH

        val lc = apdu[4].toInt() and 0xFF
        if (apdu.size < 5 + lc) return SW_WRONG_LENGTH

        val responseData = apdu.copyOfRange(5, 5 + lc)
        Log.d(TAG, "SUBMIT_PAYMENT_RESPONSE: received ${responseData.size} bytes")

        // Clear the pending request since it has been fulfilled.
        pendingPaymentRequest = null

        // Notify the UI.
        onPaymentResponseReceived?.invoke(responseData)

        return byteArrayOf(STATUS_SUCCESS) + SW_OK
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private fun isDeviceLocked(): Boolean {
        val keyguardManager = getSystemService(android.app.KeyguardManager::class.java)
        return keyguardManager?.isDeviceLocked ?: false
    }

    private fun hex(b: Byte): String = String.format("0x%02X", b)
}
