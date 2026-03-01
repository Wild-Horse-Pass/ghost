package com.ghost.tap

/**
 * Bridge to Rust core library via JNI
 */
object RustBridge {
    init {
        System.loadLibrary("ghost_tap_core")
    }

    /**
     * Initialize the GhostTap core library
     * Must be called before any other functions
     */
    external fun init(): Boolean

    /**
     * Get the library version
     */
    external fun version(): String

    /**
     * Generate a new wallet with 12-word mnemonic
     * Returns the mnemonic phrase or null on error
     */
    external fun generateWallet12(): String?

    /**
     * Generate a new wallet with 24-word mnemonic
     * Returns the mnemonic phrase or null on error
     */
    external fun generateWallet24(): String?

    /**
     * Validate a mnemonic phrase
     */
    external fun validateMnemonic(mnemonic: String): Boolean

    /**
     * Import a wallet from mnemonic
     * Returns wallet handle ID or -1 on error
     */
    external fun importWallet(mnemonic: String, passphrase: String?): Long

    /**
     * Get wallet balance
     */
    external fun getBalance(walletHandle: Long): Long

    /**
     * Generate a new receive address
     */
    external fun newReceiveAddress(walletHandle: Long): String?

    /**
     * Get transaction history
     */
    external fun getTransactionHistory(walletHandle: Long): String // JSON array

    /**
     * Build and sign a transaction
     * Returns raw transaction hex or null on error
     */
    external fun createTransaction(
        walletHandle: Long,
        toAddress: String,
        amount: Long,
        feePriority: Int // 0=low, 1=medium, 2=high
    ): String?

    /**
     * Broadcast a signed transaction
     * Returns txid or null on error
     */
    external fun broadcastTransaction(rawTx: String): String?

    // --- PIN Authentication ---

    /**
     * Set a 6-digit PIN for wallet authentication
     */
    external fun setPin(pin: String)

    /**
     * Verify PIN and unlock wallet.
     * Returns: 0=success, 1=wrong PIN, 2=locked out
     */
    external fun verifyPinAndUnlock(pin: String): Int

    /**
     * Check if a PIN has been configured
     */
    external fun hasPin(): Boolean

    /**
     * Get remaining PIN attempts before lockout
     */
    external fun pinRemainingAttempts(): Int

    /**
     * Authenticate using biometrics. Returns true on success.
     */
    external fun authenticateBiometric(): Boolean

    // --- NFC Limits ---

    /**
     * Check if an NFC payment amount (in satoshis) is within the limit.
     * Returns true if allowed, false if exceeded.
     */
    external fun nfcCheckLimit(amount: Long): Boolean

    /**
     * Set the GHOST/GBP exchange rate and get the recalculated satoshi cap.
     */
    external fun nfcSetRate(rate: Double): Long
}
