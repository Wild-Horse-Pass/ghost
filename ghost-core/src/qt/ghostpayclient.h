// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_GHOSTPAYCLIENT_H
#define GHOST_QT_GHOSTPAYCLIENT_H

#include <qt/ghostpaytypes.h>

#include <QObject>
#include <QString>
#include <QUrl>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonObject>
#include <QJsonArray>
#include <memory>

/**
 * HTTP/JSON client for communicating with ghost-pay-node
 *
 * This follows the same pattern as Bitcoin Core's JSON-RPC:
 * - HTTP POST with JSON body
 * - Basic authentication
 * - Async Qt signals for responses
 */
class GhostPayClient : public QObject
{
    Q_OBJECT

public:
    explicit GhostPayClient(QObject* parent = nullptr);
    ~GhostPayClient();

    /** Configure connection to ghost-pay-node */
    void setEndpoint(const QString& host, int port, bool useTls = false);
    void setAuth(const QString& username, const QString& password);

    /** Check if configured and ready */
    bool isConfigured() const;

    // ========== Info Endpoints ==========

    /** Get node info (GET /info) */
    void getNodeInfo();

    /** Health check (GET /health) */
    void getHealth();

    // ========== Lock Endpoints ==========

    /** Get lock info (GET /lock/:lock_id) */
    void getLockInfo(const QString& lockId);

    /** Register a new lock (POST /lock/register) */
    void registerLock(const QString& lockPubkey, const QString& recoveryPubkey,
                      GhostPay::Denomination denomination,
                      GhostPay::TimelockTier timelock,
                      uint32_t creationHeight);

    // ========== Balance Endpoints ==========

    /** Get balance for a lock (GET /balance/:lock_id) */
    void getBalance(const QString& lockId);

    // ========== Payment Endpoints ==========

    /** Submit an L2 payment (POST /payment) */
    void submitPayment(const QString& fromLockId,
                       const QString& toGhostId,
                       int64_t amountSats,
                       const QString& signature);

    /** Get payment info (GET /payment/:id) */
    void getPayment(const QString& paymentId);

    /** Get incoming payments for a Ghost ID (GET /payments/to/:ghost_id) */
    void getIncomingPayments(const QString& ghostId);

    // ========== Block/State Endpoints ==========

    /** Get latest L2 block (GET /block/latest) */
    void getLatestBlock();

    /** Get specific L2 block (GET /block/:height) */
    void getBlock(uint64_t height);

    /** Get current state root (GET /state/root) */
    void getStateRoot();

    // ========== Wraith Endpoints ==========

    /** List active Wraith sessions (GET /wraith/sessions) */
    void listWraithSessions();

    /** Get Wraith session info (GET /wraith/session/:id) */
    void getWraithSession(const QString& sessionId);

    /** Join a Wraith session (POST /wraith/join) */
    void joinWraith(GhostPay::Denomination denomination,
                    const QString& inputTxid, uint32_t inputVout,
                    int64_t inputAmountSats,
                    const QString& outputPubkey);

    /** Submit signature for Wraith phase (POST /wraith/session/:id/signature) */
    void submitWraithSignature(const QString& sessionId,
                               const QString& signature,
                               int phase);

    /** Get Wraith statistics (GET /wraith/stats) */
    void getWraithStats();

    // ========== Reconciliation Endpoints ==========

    /** Request reconciliation for a lock (POST /reconciliation/request) */
    void requestReconciliation(const QString& lockId,
                               const QString& settlementAddress,
                               const QString& settlementClass);

    /** Get batch info (GET /reconciliation/batch/:id) */
    void getBatch(const QString& batchId);

    /** List batches (GET /reconciliation/batches) */
    void listBatches();

    /** Submit signature for batch (POST /reconciliation/sign) */
    void submitBatchSignature(const QString& batchId,
                              const QString& lockId,
                              const QString& signature);

    // ========== Jump Queue Endpoints ==========

    /** Enqueue lock for jump rotation (POST /jump/enqueue) */
    void jumpEnqueue(const QString& lockId);

    /** Get jump status (GET /jump/status/:lock_id) */
    void getJumpStatus(const QString& lockId);

    /** List jump queue (GET /jump/list) */
    void listJumpQueue();

Q_SIGNALS:
    // Connection signals
    void connected();
    void disconnected();
    void connectionError(const QString& error);

    // Response signals
    void nodeInfoReceived(const GhostPay::NodeStatus& status);
    void healthReceived(bool healthy, const QString& message);

    void lockInfoReceived(const GhostPay::GhostLockInfo& lock);
    void lockRegistered(const QString& lockId);
    void lockError(const QString& lockId, const QString& error);

    void balanceReceived(const QString& lockId, const GhostPay::L2Balance& balance);

    void paymentSubmitted(const QString& paymentId);
    void paymentReceived(const GhostPay::PaymentInfo& payment);
    void incomingPaymentsReceived(const QList<GhostPay::PaymentInfo>& payments);
    void paymentError(const QString& error);

    void latestBlockReceived(uint64_t height, const QString& stateRoot);
    void blockReceived(uint64_t height, const QJsonObject& block);
    void stateRootReceived(const QString& stateRoot);

    void wraithSessionsReceived(const QList<GhostPay::WraithSessionInfo>& sessions);
    void wraithSessionReceived(const GhostPay::WraithSessionInfo& session);
    void wraithJoined(const QString& sessionId);
    void wraithSignatureSubmitted(const QString& sessionId, int phase);
    void wraithError(const QString& error);

    void reconciliationRequested(const QString& batchId);
    void batchReceived(const GhostPay::BatchInfo& batch);
    void batchesReceived(const QList<GhostPay::BatchInfo>& batches);
    void batchSignatureSubmitted(const QString& batchId);
    void reconciliationError(const QString& error);

    void jumpEnqueued(const QString& lockId);
    void jumpStatusReceived(const GhostPay::JumpStatus& status);
    void jumpQueueReceived(const QList<GhostPay::JumpStatus>& queue);
    void jumpError(const QString& error);

    // Generic error signal
    void error(const QString& method, const QString& message);

private Q_SLOTS:
    void handleNetworkReply(QNetworkReply* reply);

private:
    /** Make HTTP GET request */
    void doGet(const QString& path, const QString& tag);

    /** Make HTTP POST request with JSON body */
    void doPost(const QString& path, const QJsonObject& body, const QString& tag);

    /** Parse common response fields */
    bool parseResponse(QNetworkReply* reply, QJsonObject& result, QString& errorMsg);

    /** Parse node status from JSON */
    GhostPay::NodeStatus parseNodeStatus(const QJsonObject& json);

    /** Parse lock info from JSON */
    GhostPay::GhostLockInfo parseLockInfo(const QJsonObject& json);

    /** Parse payment info from JSON */
    GhostPay::PaymentInfo parsePaymentInfo(const QJsonObject& json);

    /** Parse wraith session from JSON */
    GhostPay::WraithSessionInfo parseWraithSession(const QJsonObject& json);

    /** Parse batch info from JSON */
    GhostPay::BatchInfo parseBatchInfo(const QJsonObject& json);

    /** Parse jump status from JSON */
    GhostPay::JumpStatus parseJumpStatus(const QJsonObject& json);

    QNetworkAccessManager* m_networkManager;
    QUrl m_baseUrl;
    QString m_authHeader;
    bool m_configured;
};

#endif // GHOST_QT_GHOSTPAYCLIENT_H
