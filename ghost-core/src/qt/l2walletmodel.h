// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_L2WALLETMODEL_H
#define GHOST_QT_L2WALLETMODEL_H

#include <qt/ghostpaytypes.h>
#include <qt/ghostpayclient.h>

#include <QObject>
#include <QAbstractTableModel>
#include <QList>
#include <QTimer>
#include <memory>

class WalletModel;

/**
 * Table model for Ghost Locks
 * Displays user's L2 locks with denomination, balance, and state
 */
class GhostLocksModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Column {
        LockId = 0,
        Denomination,
        L2Balance,
        State,
        RecoveryHeight,
        ColumnCount
    };

    explicit GhostLocksModel(QObject* parent = nullptr);
    ~GhostLocksModel();

    // QAbstractTableModel interface
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    /** Add a lock to the model */
    void addLock(const GhostPay::GhostLockInfo& lock);

    /** Update a lock in the model */
    void updateLock(const GhostPay::GhostLockInfo& lock);

    /** Remove a lock from the model */
    void removeLock(const QString& lockId);

    /** Clear all locks */
    void clear();

    /** Get lock by row */
    const GhostPay::GhostLockInfo* getLock(int row) const;

    /** Get lock by ID */
    const GhostPay::GhostLockInfo* getLockById(const QString& lockId) const;

    /** Get total L2 balance across all active locks */
    int64_t getTotalL2Balance() const;

    /** Get count of active locks */
    int getActiveLockCount() const;

private:
    QList<GhostPay::GhostLockInfo> m_locks;
};

/**
 * Table model for L2 Payments
 * Displays payment history (sent and received)
 */
class L2PaymentsModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Column {
        PaymentId = 0,
        Direction,  // Sent/Received
        Amount,
        Counterparty,  // Ghost ID or Lock ID
        Timestamp,
        Status,
        ColumnCount
    };

    explicit L2PaymentsModel(QObject* parent = nullptr);
    ~L2PaymentsModel();

    // QAbstractTableModel interface
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    /** Add a payment to the model */
    void addPayment(const GhostPay::PaymentInfo& payment, bool isSent);

    /** Update payment status */
    void updatePayment(const QString& paymentId, bool confirmed, const QString& status);

    /** Clear all payments */
    void clear();

    /** Get payment by row */
    const GhostPay::PaymentInfo* getPayment(int row) const;

private:
    struct PaymentEntry {
        GhostPay::PaymentInfo info;
        bool isSent;
    };
    QList<PaymentEntry> m_payments;
};

/**
 * Main L2 Wallet Model
 * Integrates Ghost Pay client with Qt wallet, manages locks and payments
 */
class L2WalletModel : public QObject
{
    Q_OBJECT

public:
    explicit L2WalletModel(WalletModel* walletModel, QObject* parent = nullptr);
    ~L2WalletModel();

    /** Get the Ghost Pay client */
    GhostPayClient* client() const { return m_client; }

    /** Get locks model */
    GhostLocksModel* locksModel() const { return m_locksModel; }

    /** Get payments model */
    L2PaymentsModel* paymentsModel() const { return m_paymentsModel; }

    /** Configure connection to ghost-pay-node */
    void setNodeEndpoint(const QString& host, int port, bool useTls = false);
    void setNodeAuth(const QString& username, const QString& password);

    /** Check if connected to ghost-pay-node */
    bool isConnected() const { return m_connected; }

    /** Get current node status */
    const GhostPay::NodeStatus& nodeStatus() const { return m_nodeStatus; }

    /** Get total L2 balance */
    GhostPay::L2Balance getTotalBalance() const;

    // ========== Lock Operations ==========

    /** Refresh all locks from node */
    void refreshLocks();

    /** Register a new lock with the node */
    void registerLock(const QString& lockPubkey, const QString& recoveryPubkey,
                      GhostPay::Denomination denomination,
                      GhostPay::TimelockTier timelock,
                      uint32_t creationHeight);

    // ========== Payment Operations ==========

    /** Send an L2 payment */
    void sendPayment(const QString& fromLockId,
                     const QString& toGhostId,
                     int64_t amountSats);

    /** Refresh incoming payments */
    void refreshPayments(const QString& ghostId);

    // ========== Wraith Operations ==========

    /** Join a Wraith session for deposit */
    void joinWraithDeposit(GhostPay::Denomination denomination,
                           const QString& inputTxid, uint32_t inputVout,
                           int64_t inputAmountSats,
                           const QString& outputPubkey);

    // ========== Reconciliation Operations ==========

    /** Request withdrawal/exit via reconciliation */
    void requestWithdrawal(const QString& lockId,
                           const QString& settlementAddress);

Q_SIGNALS:
    // Connection signals
    void connectionStatusChanged(bool connected);
    void nodeStatusUpdated(const GhostPay::NodeStatus& status);

    // Balance signals
    void balanceChanged();
    void lockBalanceChanged(const QString& lockId, int64_t newBalance);

    // Lock signals
    void lockRegistered(const QString& lockId);
    void lockUpdated(const QString& lockId);
    void lockError(const QString& error);

    // Payment signals
    void paymentSent(const QString& paymentId);
    void paymentReceived(const GhostPay::PaymentInfo& payment);
    void paymentError(const QString& error);

    // Wraith signals
    void wraithJoined(const QString& sessionId);
    void wraithPhaseChanged(const QString& sessionId, GhostPay::WraithPhase phase);
    void wraithComplete(const QString& sessionId, const QString& lockId);
    void wraithError(const QString& error);

    // Reconciliation signals
    void withdrawalRequested(const QString& batchId);
    void withdrawalComplete(const QString& lockId, const QString& txid);
    void withdrawalError(const QString& error);

private Q_SLOTS:
    // Client response handlers
    void onNodeInfoReceived(const GhostPay::NodeStatus& status);
    void onHealthReceived(bool healthy, const QString& message);
    void onLockInfoReceived(const GhostPay::GhostLockInfo& lock);
    void onLockRegistered(const QString& lockId);
    void onBalanceReceived(const QString& lockId, const GhostPay::L2Balance& balance);
    void onPaymentSubmitted(const QString& paymentId);
    void onPaymentReceived(const GhostPay::PaymentInfo& payment);
    void onIncomingPaymentsReceived(const QList<GhostPay::PaymentInfo>& payments);
    void onWraithJoined(const QString& sessionId);
    void onReconciliationRequested(const QString& batchId);
    void onClientError(const QString& method, const QString& message);

    // Periodic refresh
    void onRefreshTimer();

private:
    /** Start periodic refresh of node status and balances */
    void startRefreshTimer();

    /** Stop periodic refresh */
    void stopRefreshTimer();

    WalletModel* m_walletModel;
    GhostPayClient* m_client;
    GhostLocksModel* m_locksModel;
    L2PaymentsModel* m_paymentsModel;

    GhostPay::NodeStatus m_nodeStatus;
    bool m_connected;

    QTimer* m_refreshTimer;
    static const int REFRESH_INTERVAL_MS = 10000; // 10 seconds

    // Track pending operations
    QList<QString> m_pendingLockRegistrations;
    QString m_currentGhostId;
};

#endif // GHOST_QT_L2WALLETMODEL_H
