import Foundation
import Combine

/// Sync status for the wallet
enum SyncStatus: Equatable {
    case idle
    case syncing(progress: Double)
    case synced(height: UInt64)
    case error(String)

    var description: String {
        switch self {
        case .idle: return "Idle"
        case .syncing(let p): return "Syncing \(Int(p * 100))%"
        case .synced(let h): return "Synced (block \(h))"
        case .error(let e): return "Error: \(e)"
        }
    }
}

/// Fee priority levels matching Rust FeePriority enum (0=Low, 1=Med, 2=High)
enum FeePriority: UInt8, CaseIterable, Identifiable {
    case low = 0
    case medium = 1
    case high = 2

    var id: UInt8 { rawValue }

    var label: String {
        switch self {
        case .low: return "Low"
        case .medium: return "Medium"
        case .high: return "High"
        }
    }

    var description: String {
        switch self {
        case .low: return "~60 min"
        case .medium: return "~20 min"
        case .high: return "~5 min"
        }
    }
}

/// A simplified transaction model for the UI layer
struct Transaction: Identifiable {
    let id: String          // txid
    let direction: String   // "incoming" or "outgoing"
    let amount: UInt64
    let fee: UInt64?
    let address: String
    let status: String      // "pending", "confirmed", "failed"
    let confirmations: UInt32
    let timestamp: UInt64
    let memo: String?

    var isIncoming: Bool { direction == "incoming" }

    /// Human-readable relative timestamp
    var relativeTime: String {
        let date = Date(timeIntervalSince1970: TimeInterval(timestamp))
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter.localizedString(for: date, relativeTo: Date())
    }

    /// Truncated address for display: first 8 ... last 6
    var addressSnippet: String {
        guard address.count > 16 else { return address }
        let prefix = address.prefix(8)
        let suffix = address.suffix(6)
        return "\(prefix)...\(suffix)"
    }
}

/// Main wallet view model wrapping the Rust WalletHandle via UniFFI
@MainActor
final class WalletViewModel: ObservableObject {

    init() {
        let stored = UserDefaults.standard.integer(forKey: "autoLockMinutes")
        self.autoLockMinutes = stored > 0 ? stored : 5
    }

    // MARK: - Published State

    @Published var balance: UInt64 = 0
    @Published var pendingIncoming: UInt64 = 0
    @Published var pendingOutgoing: UInt64 = 0
    @Published var history: [Transaction] = []
    @Published var addresses: [String] = []
    @Published var currentAddress: String = ""
    @Published var isLocked: Bool = false
    @Published var syncStatus: SyncStatus = .idle
    @Published var hasWallet: Bool = false
    @Published var mnemonic: [String] = []
    @Published var errorMessage: String?

    // MARK: - Auto-Lock

    /// Minutes of inactivity before the wallet locks (user-configurable).
    @Published var autoLockMinutes: Int {
        didSet {
            UserDefaults.standard.set(autoLockMinutes, forKey: "autoLockMinutes")
        }
    }

    /// Timestamp of the last user activity (set when app enters background).
    private var lastActivityTimestamp: Date?

    /// Record that the user is active (call when app enters background).
    func recordActivity() {
        lastActivityTimestamp = Date()
    }

    /// Check if the wallet should be locked based on elapsed time
    /// (call when app enters foreground).
    func checkAutoLock() {
        guard hasWallet, !isLocked, hasPin() else { return }
        guard let last = lastActivityTimestamp else { return }

        let elapsed = Date().timeIntervalSince(last)
        if elapsed >= Double(autoLockMinutes) * 60.0 {
            lockWallet()
        }
    }

    // MARK: - Internal

    private var walletHandle: WalletHandle?

    // MARK: - Wallet Lifecycle

    /// Create a new wallet, storing mnemonic words for backup flow
    func createWallet(wordCount: Int = 12) async {
        do {
            let handle: WalletHandle
            if wordCount == 24 {
                handle = try WalletHandle.generate24()
            } else {
                handle = try WalletHandle.generate12()
            }

            walletHandle = handle
            mnemonic = handle.getMnemonic().split(separator: " ").map(String.init)
            hasWallet = true
            isLocked = false

            await generateAddress()
            await refreshBalance()
        } catch {
            errorMessage = "Failed to create wallet: \(error.localizedDescription)"
        }
    }

    /// Import a wallet from a mnemonic phrase
    func importWallet(phrase: String, passphrase: String? = nil) async -> Bool {
        guard walletValidateMnemonic(mnemonic: phrase) else {
            errorMessage = "Invalid mnemonic phrase"
            return false
        }

        do {
            let handle = try WalletHandle.fromMnemonic(
                mnemonic: phrase,
                passphrase: passphrase
            )
            walletHandle = handle
            mnemonic = phrase.split(separator: " ").map(String.init)
            hasWallet = true
            isLocked = false

            await generateAddress()
            await refreshBalance()
            return true
        } catch {
            errorMessage = "Failed to import wallet: \(error.localizedDescription)"
            return false
        }
    }

    // MARK: - Balance

    func refreshBalance() async {
        guard let handle = walletHandle else { return }

        do {
            let details = try handle.getBalanceDetails()
            balance = details.confirmed
            pendingIncoming = details.pendingIncoming
            pendingOutgoing = details.pendingOutgoing
        } catch {
            balance = handle.getBalance()
        }

        await refreshHistory()
    }

    // MARK: - Addresses

    func generateAddress() async {
        guard let handle = walletHandle else { return }
        do {
            let addr = try handle.newReceiveAddress()
            currentAddress = addr
            if !addresses.contains(addr) {
                addresses.insert(addr, at: 0)
            }
        } catch {
            errorMessage = "Failed to generate address: \(error.localizedDescription)"
        }
    }

    // MARK: - History

    func refreshHistory() async {
        guard let handle = walletHandle else { return }
        do {
            let entries = try handle.getHistory(offset: 0, limit: 100)
            history = entries.map { entry in
                Transaction(
                    id: entry.txid,
                    direction: entry.direction,
                    amount: entry.amount,
                    fee: entry.fee,
                    address: entry.address,
                    status: entry.status,
                    confirmations: entry.confirmations,
                    timestamp: entry.timestamp,
                    memo: entry.memo
                )
            }
        } catch {
            errorMessage = "Failed to load history: \(error.localizedDescription)"
        }
    }

    // MARK: - Send

    /// Build and broadcast a transaction. Returns the txid on success.
    func send(to address: String, amount: UInt64, fee: FeePriority) async -> String? {
        guard let handle = walletHandle else {
            errorMessage = "No wallet loaded"
            return nil
        }

        do {
            let unsigned = try handle.buildTransaction(
                toAddress: address,
                amount: amount,
                feePriority: fee.rawValue
            )
            let txid = try handle.signAndBroadcast(unsignedTxJson: unsigned.txJson)
            await refreshBalance()
            return txid
        } catch {
            errorMessage = "Send failed: \(error.localizedDescription)"
            return nil
        }
    }

    // MARK: - Lock

    func lockWallet() {
        walletHandle?.lock()
        isLocked = true
    }

    func unlockWallet() {
        walletHandle?.unlock()
        isLocked = false
    }

    // MARK: - Formatting Helpers

    static func formatBalance(_ satoshis: UInt64) -> String {
        let whole = satoshis / 100_000_000
        let frac = satoshis % 100_000_000
        return String(format: "%d.%08d", whole, frac)
    }
}
