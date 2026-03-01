package com.ghost.tap.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.ghost.tap.RustBridge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

data class Transaction(
    val txId: String,
    val amount: Long,
    val fee: Long,
    val address: String,
    val timestamp: Long,
    val confirmations: Int,
    val isSend: Boolean,
    val status: TxStatus
)

enum class TxStatus { Pending, Confirmed, Failed }

enum class SyncStatus { Idle, Syncing, Synced, Error }

data class WalletUiState(
    val hasWallet: Boolean = false,
    val balance: Long = 0L,
    val transactions: List<Transaction> = emptyList(),
    val currentAddress: String = "",
    val syncStatus: SyncStatus = SyncStatus.Idle,
    val walletHandle: Long = -1L,
    val error: String? = null,
    val isGenerating: Boolean = false,
    val isSending: Boolean = false,
    val sendResult: SendResult? = null,
    val isLocked: Boolean = false
)

sealed class SendResult {
    data class Success(val txId: String) : SendResult()
    data class Error(val message: String) : SendResult()
}

class WalletViewModel : ViewModel() {

    private val _uiState = MutableStateFlow(WalletUiState())
    val uiState: StateFlow<WalletUiState> = _uiState.asStateFlow()

    /** Minutes of inactivity before auto-lock (default 5). */
    var autoLockMinutes: Int = 5

    private var lastActivityTimestamp: Long = 0L

    /** Record activity timestamp (call from onPause). */
    fun recordActivity() {
        lastActivityTimestamp = System.currentTimeMillis()
    }

    /** Check if wallet should auto-lock (call from onResume). */
    fun checkAutoLock() {
        if (!_uiState.value.hasWallet || _uiState.value.isLocked) return
        if (lastActivityTimestamp == 0L) return

        val elapsed = System.currentTimeMillis() - lastActivityTimestamp
        if (elapsed >= autoLockMinutes * 60_000L) {
            lockWallet()
        }
    }

    fun createWallet(use24Words: Boolean = false): MutableStateFlow<String?> {
        val mnemonicFlow = MutableStateFlow<String?>(null)
        _uiState.update { it.copy(isGenerating = true, error = null) }

        viewModelScope.launch {
            val mnemonic = withContext(Dispatchers.IO) {
                if (use24Words) RustBridge.generateWallet24() else RustBridge.generateWallet12()
            }
            if (mnemonic != null) {
                mnemonicFlow.value = mnemonic
            } else {
                _uiState.update { it.copy(error = "Failed to generate wallet") }
            }
            _uiState.update { it.copy(isGenerating = false) }
        }
        return mnemonicFlow
    }

    fun finalizeWalletCreation(mnemonic: String) {
        viewModelScope.launch {
            val handle = withContext(Dispatchers.IO) {
                RustBridge.importWallet(mnemonic, null)
            }
            if (handle >= 0) {
                _uiState.update {
                    it.copy(hasWallet = true, walletHandle = handle, error = null)
                }
                generateAddress()
                refreshBalance()
            } else {
                _uiState.update { it.copy(error = "Failed to initialize wallet") }
            }
        }
    }

    fun importWallet(mnemonic: String, passphrase: String? = null) {
        _uiState.update { it.copy(isGenerating = true, error = null) }

        viewModelScope.launch {
            val trimmed = mnemonic.trim().lowercase()
            val valid = withContext(Dispatchers.IO) {
                RustBridge.validateMnemonic(trimmed)
            }
            if (!valid) {
                _uiState.update {
                    it.copy(isGenerating = false, error = "Invalid mnemonic phrase")
                }
                return@launch
            }

            val handle = withContext(Dispatchers.IO) {
                RustBridge.importWallet(trimmed, passphrase)
            }
            if (handle >= 0) {
                _uiState.update {
                    it.copy(
                        hasWallet = true,
                        walletHandle = handle,
                        isGenerating = false,
                        error = null
                    )
                }
                generateAddress()
                refreshBalance()
            } else {
                _uiState.update {
                    it.copy(isGenerating = false, error = "Failed to import wallet")
                }
            }
        }
    }

    fun refreshBalance() {
        val handle = _uiState.value.walletHandle
        if (handle < 0) return

        _uiState.update { it.copy(syncStatus = SyncStatus.Syncing) }

        viewModelScope.launch {
            try {
                val balance = withContext(Dispatchers.IO) {
                    RustBridge.getBalance(handle)
                }
                val historyJson = withContext(Dispatchers.IO) {
                    RustBridge.getTransactionHistory(handle)
                }
                val transactions = parseTransactions(historyJson)

                _uiState.update {
                    it.copy(
                        balance = balance,
                        transactions = transactions,
                        syncStatus = SyncStatus.Synced,
                        error = null
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(syncStatus = SyncStatus.Error, error = e.message)
                }
            }
        }
    }

    fun generateAddress() {
        val handle = _uiState.value.walletHandle
        if (handle < 0) return

        viewModelScope.launch {
            val address = withContext(Dispatchers.IO) {
                RustBridge.newReceiveAddress(handle)
            }
            if (address != null) {
                _uiState.update { it.copy(currentAddress = address) }
            }
        }
    }

    fun sendPayment(toAddress: String, amount: Long, feePriority: Int) {
        val handle = _uiState.value.walletHandle
        if (handle < 0) return

        _uiState.update { it.copy(isSending = true, sendResult = null) }

        viewModelScope.launch {
            try {
                val rawTx = withContext(Dispatchers.IO) {
                    RustBridge.createTransaction(handle, toAddress, amount, feePriority)
                }
                if (rawTx == null) {
                    _uiState.update {
                        it.copy(
                            isSending = false,
                            sendResult = SendResult.Error("Failed to create transaction")
                        )
                    }
                    return@launch
                }

                val txId = withContext(Dispatchers.IO) {
                    RustBridge.broadcastTransaction(rawTx)
                }
                if (txId != null) {
                    _uiState.update {
                        it.copy(isSending = false, sendResult = SendResult.Success(txId))
                    }
                    refreshBalance()
                } else {
                    _uiState.update {
                        it.copy(
                            isSending = false,
                            sendResult = SendResult.Error("Failed to broadcast transaction")
                        )
                    }
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isSending = false,
                        sendResult = SendResult.Error(e.message ?: "Unknown error")
                    )
                }
            }
        }
    }

    fun clearSendResult() {
        _uiState.update { it.copy(sendResult = null) }
    }

    fun lockWallet() {
        _uiState.update { it.copy(isLocked = true) }
    }

    fun unlockWallet() {
        _uiState.update { it.copy(isLocked = false) }
    }

    fun getTransaction(txId: String): Transaction? {
        return _uiState.value.transactions.find { it.txId == txId }
    }

    private fun parseTransactions(json: String): List<Transaction> {
        return try {
            val array = JSONArray(json)
            (0 until array.length()).map { i ->
                val obj = array.getJSONObject(i)
                Transaction(
                    txId = obj.getString("txid"),
                    amount = obj.getLong("amount"),
                    fee = obj.optLong("fee", 0),
                    address = obj.optString("address", ""),
                    timestamp = obj.optLong("timestamp", 0),
                    confirmations = obj.optInt("confirmations", 0),
                    isSend = obj.optBoolean("is_send", false),
                    status = when (obj.optString("status", "pending")) {
                        "confirmed" -> TxStatus.Confirmed
                        "failed" -> TxStatus.Failed
                        else -> TxStatus.Pending
                    }
                )
            }
        } catch (e: Exception) {
            emptyList()
        }
    }
}
