package com.ghost.tap.nfc

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.util.Log

/**
 * NFC reader (merchant mode) for GhostTap payments.
 *
 * Implements [NfcAdapter.ReaderCallback] to detect NFC tags that support
 * ISO-DEP and communicate with a GhostTap HCE service on the customer device.
 *
 * Usage:
 * ```kotlin
 * val reader = NfcPaymentReader(
 *     paymentRequest = encodedRequestBytes,
 *     onPaymentResponse = { responseBytes -> /* handle */ },
 *     onError = { error -> /* handle */ }
 * )
 * nfcAdapter.enableReaderMode(
 *     activity,
 *     reader,
 *     NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or
 *         NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
 *     null
 * )
 * ```
 */
class NfcPaymentReader(
    private val paymentRequest: ByteArray,
    private val onPaymentResponse: (ByteArray) -> Unit,
    private val onError: (String) -> Unit
) : NfcAdapter.ReaderCallback {

    companion object {
        private const val TAG = "NfcPaymentReader"
        private const val MAX_TRANSCEIVE_LENGTH = 4096

        // Build a SELECT APDU for the GhostTap AID.
        private fun buildSelectApdu(): ByteArray {
            val aid = GhostTapHceService.AID
            // CLA=00, INS=A4, P1=04 (select by name), P2=00, Lc=len, AID, Le=00
            return byteArrayOf(
                0x00,
                0xA4.toByte(),
                0x04,
                0x00,
                aid.size.toByte()
            ) + aid + byteArrayOf(0x00)
        }

        // Build a SUBMIT_PAYMENT_RESPONSE APDU carrying the binary payment
        // request data that the merchant wants the customer to pay.
        private fun buildSubmitPaymentResponseApdu(data: ByteArray): ByteArray {
            // CLA=00, INS=D0, P1=00, P2=00, Lc=len, data
            return byteArrayOf(
                0x00,
                0xD0.toByte(),
                0x00,
                0x00,
                data.size.toByte()
            ) + data
        }

        // Build a GET_PAYMENT_REQUEST APDU.
        private fun buildGetPaymentRequestApdu(): ByteArray {
            // CLA=00, INS=B0, P1=00, P2=00, Le=00 (expect any length)
            return byteArrayOf(0x00, 0xB0.toByte(), 0x00, 0x00, 0x00)
        }

        // Check if the last two bytes of a response are SW 90 00.
        private fun isStatusOk(response: ByteArray): Boolean {
            if (response.size < 2) return false
            return response[response.size - 2] == 0x90.toByte() &&
                response[response.size - 1] == 0x00.toByte()
        }

        // Strip the trailing 2-byte status word from a response.
        private fun stripStatus(response: ByteArray): ByteArray {
            if (response.size < 2) return response
            return response.copyOfRange(0, response.size - 2)
        }
    }

    override fun onTagDiscovered(tag: Tag) {
        val isoDep = IsoDep.get(tag)
        if (isoDep == null) {
            Log.w(TAG, "Tag does not support ISO-DEP")
            onError("Tag does not support ISO-DEP")
            return
        }

        try {
            isoDep.connect()
            isoDep.timeout = 5000 // 5 second timeout
            if (isoDep.maxTransceiveLength < MAX_TRANSCEIVE_LENGTH) {
                Log.d(TAG, "Max transceive length: ${isoDep.maxTransceiveLength}")
            }

            // Step 1: SELECT the GhostTap application by AID.
            val selectResponse = isoDep.transceive(buildSelectApdu())
            if (!isStatusOk(selectResponse)) {
                val msg = "SELECT failed: ${selectResponse.toHex()}"
                Log.w(TAG, msg)
                onError(msg)
                return
            }
            val versionData = stripStatus(selectResponse)
            if (versionData.isNotEmpty()) {
                Log.d(TAG, "Remote protocol version: ${versionData[0]}")
            }

            // Step 2: Send GET_PAYMENT_REQUEST to read the customer's pending
            // payment (if the customer device has one ready). For merchant-
            // initiated flow, this can be skipped. Here we attempt it to see
            // if the customer already has a payment request queued.
            val getResponse = isoDep.transceive(buildGetPaymentRequestApdu())
            if (isStatusOk(getResponse)) {
                val paymentData = stripStatus(getResponse)
                Log.d(TAG, "Got payment request from customer: ${paymentData.size} bytes")
            }

            // Step 3: Submit our payment request to the customer device.
            val submitResponse = isoDep.transceive(
                buildSubmitPaymentResponseApdu(paymentRequest)
            )
            if (!isStatusOk(submitResponse)) {
                val msg = "SUBMIT_PAYMENT_RESPONSE failed: ${submitResponse.toHex()}"
                Log.w(TAG, msg)
                onError(msg)
                return
            }

            val responseData = stripStatus(submitResponse)
            Log.d(TAG, "Payment response received: ${responseData.size} bytes")
            onPaymentResponse(responseData)

        } catch (e: Exception) {
            Log.e(TAG, "NFC communication error", e)
            onError("NFC error: ${e.message}")
        } finally {
            try {
                isoDep.close()
            } catch (_: Exception) {
                // Ignore close errors.
            }
        }
    }
}

private fun ByteArray.toHex(): String =
    joinToString("") { String.format("%02X", it) }
