// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/l2walletmodel.h>
#include <qt/walletmodel.h>
#include <qt/bitcoinunits.h>

#include <QDateTime>

// ============================================================================
// GhostLocksModel
// ============================================================================

GhostLocksModel::GhostLocksModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

GhostLocksModel::~GhostLocksModel() = default;

int GhostLocksModel::rowCount(const QModelIndex& parent) const
{
    Q_UNUSED(parent);
    return m_locks.size();
}

int GhostLocksModel::columnCount(const QModelIndex& parent) const
{
    Q_UNUSED(parent);
    return ColumnCount;
}

QVariant GhostLocksModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() >= m_locks.size())
        return QVariant();

    const GhostPay::GhostLockInfo& lock = m_locks.at(index.row());

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case LockId:
            return QString(lock.lockId.left(16) + QStringLiteral("..."));
        case Denomination:
            return GhostPay::denominationName(lock.denomination);
        case L2Balance:
            return BitcoinUnits::formatWithUnit(BitcoinUnits::Unit::SAT, lock.l2Balance, false, BitcoinUnits::SeparatorStyle::ALWAYS);
        case State:
            return GhostPay::lockStateName(lock.state);
        case RecoveryHeight:
            return QString::number(lock.recoveryHeight);
        }
    }
    else if (role == Qt::ToolTipRole) {
        if (index.column() == LockId) {
            return lock.lockId;
        }
    }
    else if (role == Qt::TextAlignmentRole) {
        if (index.column() == L2Balance) {
            return QVariant(Qt::AlignRight | Qt::AlignVCenter);
        }
    }
    else if (role == Qt::UserRole) {
        // Return full lock ID for selection
        return lock.lockId;
    }

    return QVariant();
}

QVariant GhostLocksModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return QVariant();

    switch (section) {
    case LockId:
        return tr("Lock ID");
    case Denomination:
        return tr("Denomination");
    case L2Balance:
        return tr("L2 Balance");
    case State:
        return tr("State");
    case RecoveryHeight:
        return tr("Recovery Height");
    }
    return QVariant();
}

void GhostLocksModel::addLock(const GhostPay::GhostLockInfo& lock)
{
    // Check if already exists
    for (int i = 0; i < m_locks.size(); ++i) {
        if (m_locks[i].lockId == lock.lockId) {
            m_locks[i] = lock;
            Q_EMIT dataChanged(index(i, 0), index(i, ColumnCount - 1));
            return;
        }
    }

    beginInsertRows(QModelIndex(), m_locks.size(), m_locks.size());
    m_locks.append(lock);
    endInsertRows();
}

void GhostLocksModel::updateLock(const GhostPay::GhostLockInfo& lock)
{
    for (int i = 0; i < m_locks.size(); ++i) {
        if (m_locks[i].lockId == lock.lockId) {
            m_locks[i] = lock;
            Q_EMIT dataChanged(index(i, 0), index(i, ColumnCount - 1));
            return;
        }
    }
}

void GhostLocksModel::removeLock(const QString& lockId)
{
    for (int i = 0; i < m_locks.size(); ++i) {
        if (m_locks[i].lockId == lockId) {
            beginRemoveRows(QModelIndex(), i, i);
            m_locks.removeAt(i);
            endRemoveRows();
            return;
        }
    }
}

void GhostLocksModel::clear()
{
    if (m_locks.isEmpty())
        return;

    beginResetModel();
    m_locks.clear();
    endResetModel();
}

const GhostPay::GhostLockInfo* GhostLocksModel::getLock(int row) const
{
    if (row < 0 || row >= m_locks.size())
        return nullptr;
    return &m_locks.at(row);
}

const GhostPay::GhostLockInfo* GhostLocksModel::getLockById(const QString& lockId) const
{
    for (const auto& lock : m_locks) {
        if (lock.lockId == lockId)
            return &lock;
    }
    return nullptr;
}

int64_t GhostLocksModel::getTotalL2Balance() const
{
    int64_t total = 0;
    for (const auto& lock : m_locks) {
        if (GhostPay::stateAllowsL2Activity(lock.state)) {
            total += lock.l2Balance;
        }
    }
    return total;
}

int GhostLocksModel::getActiveLockCount() const
{
    int count = 0;
    for (const auto& lock : m_locks) {
        if (GhostPay::stateAllowsL2Activity(lock.state)) {
            ++count;
        }
    }
    return count;
}

// ============================================================================
// L2PaymentsModel
// ============================================================================

L2PaymentsModel::L2PaymentsModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

L2PaymentsModel::~L2PaymentsModel() = default;

int L2PaymentsModel::rowCount(const QModelIndex& parent) const
{
    Q_UNUSED(parent);
    return m_payments.size();
}

int L2PaymentsModel::columnCount(const QModelIndex& parent) const
{
    Q_UNUSED(parent);
    return ColumnCount;
}

QVariant L2PaymentsModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() >= m_payments.size())
        return QVariant();

    const PaymentEntry& entry = m_payments.at(index.row());
    const GhostPay::PaymentInfo& payment = entry.info;

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case PaymentId:
            return QString(payment.paymentId.left(12) + QStringLiteral("..."));
        case Direction:
            return entry.isSent ? tr("Sent") : tr("Received");
        case Amount:
            return BitcoinUnits::formatWithUnit(BitcoinUnits::Unit::SAT, payment.amount, false, BitcoinUnits::SeparatorStyle::ALWAYS);
        case Counterparty:
            return entry.isSent ? QString(payment.toGhostId.left(20) + QStringLiteral("..."))
                                : QString(payment.fromLockId.left(16) + QStringLiteral("..."));
        case Timestamp:
            return payment.timestamp.toString(QStringLiteral("yyyy-MM-dd hh:mm"));
        case Status:
            return payment.status;
        }
    }
    else if (role == Qt::ToolTipRole) {
        if (index.column() == PaymentId) {
            return payment.paymentId;
        } else if (index.column() == Counterparty) {
            return entry.isSent ? payment.toGhostId : payment.fromLockId;
        }
    }
    else if (role == Qt::TextAlignmentRole) {
        if (index.column() == Amount) {
            return QVariant(Qt::AlignRight | Qt::AlignVCenter);
        }
    }
    else if (role == Qt::ForegroundRole) {
        if (index.column() == Direction) {
            // Could color sent/received differently
        }
    }
    else if (role == Qt::UserRole) {
        return payment.paymentId;
    }

    return QVariant();
}

QVariant L2PaymentsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        return QVariant();

    switch (section) {
    case PaymentId:
        return tr("Payment ID");
    case Direction:
        return tr("Direction");
    case Amount:
        return tr("Amount");
    case Counterparty:
        return tr("Counterparty");
    case Timestamp:
        return tr("Time");
    case Status:
        return tr("Status");
    }
    return QVariant();
}

void L2PaymentsModel::addPayment(const GhostPay::PaymentInfo& payment, bool isSent)
{
    // Insert at beginning (most recent first)
    beginInsertRows(QModelIndex(), 0, 0);
    m_payments.prepend({payment, isSent});
    endInsertRows();
}

void L2PaymentsModel::updatePayment(const QString& paymentId, bool confirmed, const QString& status)
{
    for (int i = 0; i < m_payments.size(); ++i) {
        if (m_payments[i].info.paymentId == paymentId) {
            m_payments[i].info.confirmed = confirmed;
            m_payments[i].info.status = status;
            Q_EMIT dataChanged(index(i, 0), index(i, ColumnCount - 1));
            return;
        }
    }
}

void L2PaymentsModel::clear()
{
    if (m_payments.isEmpty())
        return;

    beginResetModel();
    m_payments.clear();
    endResetModel();
}

const GhostPay::PaymentInfo* L2PaymentsModel::getPayment(int row) const
{
    if (row < 0 || row >= m_payments.size())
        return nullptr;
    return &m_payments.at(row).info;
}

// ============================================================================
// L2WalletModel
// ============================================================================

L2WalletModel::L2WalletModel(WalletModel* walletModel, QObject* parent)
    : QObject(parent)
    , m_walletModel(walletModel)
    , m_client(new GhostPayClient(this))
    , m_locksModel(new GhostLocksModel(this))
    , m_paymentsModel(new L2PaymentsModel(this))
    , m_connected(false)
    , m_refreshTimer(new QTimer(this))
{
    // Connect client signals
    connect(m_client, &GhostPayClient::nodeInfoReceived,
            this, &L2WalletModel::onNodeInfoReceived);
    connect(m_client, &GhostPayClient::healthReceived,
            this, &L2WalletModel::onHealthReceived);
    connect(m_client, &GhostPayClient::lockInfoReceived,
            this, &L2WalletModel::onLockInfoReceived);
    connect(m_client, &GhostPayClient::lockRegistered,
            this, &L2WalletModel::onLockRegistered);
    connect(m_client, &GhostPayClient::balanceReceived,
            this, &L2WalletModel::onBalanceReceived);
    connect(m_client, &GhostPayClient::paymentSubmitted,
            this, &L2WalletModel::onPaymentSubmitted);
    connect(m_client, &GhostPayClient::paymentReceived,
            this, &L2WalletModel::onPaymentReceived);
    connect(m_client, &GhostPayClient::incomingPaymentsReceived,
            this, &L2WalletModel::onIncomingPaymentsReceived);
    connect(m_client, &GhostPayClient::wraithJoined,
            this, &L2WalletModel::onWraithJoined);
    connect(m_client, &GhostPayClient::reconciliationRequested,
            this, &L2WalletModel::onReconciliationRequested);
    connect(m_client, &GhostPayClient::error,
            this, &L2WalletModel::onClientError);

    // Connect refresh timer
    connect(m_refreshTimer, &QTimer::timeout,
            this, &L2WalletModel::onRefreshTimer);
}

L2WalletModel::~L2WalletModel()
{
    stopRefreshTimer();
}

void L2WalletModel::setNodeEndpoint(const QString& host, int port, bool useTls)
{
    m_client->setEndpoint(host, port, useTls);
    if (m_client->isConfigured()) {
        startRefreshTimer();
        m_client->getNodeInfo();
    }
}

void L2WalletModel::setNodeAuth(const QString& username, const QString& password)
{
    m_client->setAuth(username, password);
}

GhostPay::L2Balance L2WalletModel::getTotalBalance() const
{
    GhostPay::L2Balance balance;
    balance.available = m_locksModel->getTotalL2Balance();
    balance.pending = m_pendingPaymentTotal;
    balance.total = balance.available + balance.pending;
    balance.lockCount = m_locksModel->getActiveLockCount();
    return balance;
}

void L2WalletModel::refreshLocks()
{
    // Request balance update for all known locks
    for (int i = 0; i < m_locksModel->rowCount(); ++i) {
        const GhostPay::GhostLockInfo* lock = m_locksModel->getLock(i);
        if (lock) {
            m_client->getLockInfo(lock->lockId);
        }
    }
}

void L2WalletModel::registerLock(const QString& lockPubkey, const QString& recoveryPubkey,
                                  GhostPay::Denomination denomination,
                                  GhostPay::TimelockTier timelock,
                                  uint32_t creationHeight)
{
    m_pendingLockRegistrations.append(lockPubkey);
    m_client->registerLock(lockPubkey, recoveryPubkey, denomination, timelock, creationHeight);
}

void L2WalletModel::sendPayment(const QString& fromLockId,
                                const QString& toGhostId,
                                int64_t amountSats)
{
    // L2 payment signing requires a lock-key mapping infrastructure that maps
    // lockId → wallet key (CTxDestination) for producing real signatures.
    // This code path is blocked until a Send L2 dialog with signing support is built.
    Q_UNUSED(fromLockId);
    Q_UNUSED(toGhostId);
    Q_UNUSED(amountSats);
    Q_EMIT paymentError(tr("L2 payment signing not yet implemented"));
}

void L2WalletModel::refreshPayments(const QString& ghostId)
{
    m_currentGhostId = ghostId;
    m_client->getIncomingPayments(ghostId);
}

void L2WalletModel::joinWraithDeposit(GhostPay::Denomination denomination,
                                       const QString& inputTxid, uint32_t inputVout,
                                       int64_t inputAmountSats,
                                       const QString& outputPubkey)
{
    m_client->joinWraith(denomination, inputTxid, inputVout, inputAmountSats, outputPubkey);
}

void L2WalletModel::requestWithdrawal(const QString& lockId,
                                       const QString& settlementAddress)
{
    m_client->requestReconciliation(lockId, settlementAddress, QStringLiteral("standard"));
}

// ========== Private Slots ==========

void L2WalletModel::onNodeInfoReceived(const GhostPay::NodeStatus& status)
{
    m_nodeStatus = status;
    bool wasConnected = m_connected;
    m_connected = true;

    if (!wasConnected) {
        Q_EMIT connectionStatusChanged(true);
    }
    Q_EMIT nodeStatusUpdated(status);
}

void L2WalletModel::onHealthReceived(bool healthy, const QString& message)
{
    Q_UNUSED(message);
    bool wasConnected = m_connected;
    m_connected = healthy;

    if (wasConnected != m_connected) {
        Q_EMIT connectionStatusChanged(m_connected);
    }
}

void L2WalletModel::onLockInfoReceived(const GhostPay::GhostLockInfo& lock)
{
    const GhostPay::GhostLockInfo* existing = m_locksModel->getLockById(lock.lockId);
    int64_t oldBalance = existing ? existing->l2Balance : 0;

    m_locksModel->addLock(lock);
    Q_EMIT lockUpdated(lock.lockId);

    if (existing && lock.l2Balance != oldBalance) {
        Q_EMIT lockBalanceChanged(lock.lockId, lock.l2Balance);
        Q_EMIT balanceChanged();
    }
}

void L2WalletModel::onLockRegistered(const QString& lockId)
{
    m_pendingLockRegistrations.removeOne(lockId);
    Q_EMIT lockRegistered(lockId);

    // Fetch the full lock info
    m_client->getLockInfo(lockId);
}

void L2WalletModel::onBalanceReceived(const QString& lockId, const GhostPay::L2Balance& balance)
{
    Q_UNUSED(balance);
    // Update lock balance through lock info
    m_client->getLockInfo(lockId);
}

void L2WalletModel::onPaymentSubmitted(const QString& paymentId)
{
    Q_EMIT paymentSent(paymentId);
    Q_EMIT balanceChanged();
}

void L2WalletModel::onPaymentReceived(const GhostPay::PaymentInfo& payment)
{
    // Determine if sent or received based on whether from_lock_id is one of ours
    bool isSent = m_locksModel->getLockById(payment.fromLockId) != nullptr;
    m_paymentsModel->addPayment(payment, isSent);

    if (!isSent) {
        Q_EMIT paymentReceived(payment);
    }
}

void L2WalletModel::onIncomingPaymentsReceived(const QList<GhostPay::PaymentInfo>& payments)
{
    for (const auto& payment : payments) {
        m_paymentsModel->addPayment(payment, false);
    }
}

void L2WalletModel::onWraithJoined(const QString& sessionId)
{
    Q_EMIT wraithJoined(sessionId);
}

void L2WalletModel::onReconciliationRequested(const QString& batchId)
{
    Q_EMIT withdrawalRequested(batchId);
}

void L2WalletModel::onClientError(const QString& method, const QString& message)
{
    if (method.startsWith(QStringLiteral("getLock")) || method == QStringLiteral("registerLock")) {
        Q_EMIT lockError(message);
    } else if (method.startsWith(QStringLiteral("submitPayment")) || method.startsWith(QStringLiteral("getPayment"))) {
        Q_EMIT paymentError(message);
    } else if (method.startsWith(QStringLiteral("joinWraith")) || method.startsWith(QStringLiteral("getWraith"))) {
        Q_EMIT wraithError(message);
    } else if (method.startsWith(QStringLiteral("requestReconciliation"))) {
        Q_EMIT withdrawalError(message);
    }

    // Check if this is a connection error
    if (message.contains(QStringLiteral("Connection refused")) ||
        message.contains(QStringLiteral("Host not found"))) {
        if (m_connected) {
            m_connected = false;
            Q_EMIT connectionStatusChanged(false);
        }
    }
}

void L2WalletModel::onRefreshTimer()
{
    if (m_client->isConfigured()) {
        m_client->getHealth();

        if (m_connected) {
            m_client->getNodeInfo();
            refreshLocks();

            if (!m_currentGhostId.isEmpty()) {
                refreshPayments(m_currentGhostId);
            }
        }
    }
}

void L2WalletModel::startRefreshTimer()
{
    if (!m_refreshTimer->isActive()) {
        m_refreshTimer->start(REFRESH_INTERVAL_MS);
    }
}

void L2WalletModel::stopRefreshTimer()
{
    m_refreshTimer->stop();
}
