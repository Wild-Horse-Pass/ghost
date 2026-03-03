// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/ghostpayclient.h>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkRequest>
#include <QAuthenticator>

GhostPayClient::GhostPayClient(QObject* parent)
    : QObject(parent)
    , m_networkManager(new QNetworkAccessManager(this))
    , m_configured(false)
{
    connect(m_networkManager, &QNetworkAccessManager::finished,
            this, &GhostPayClient::handleNetworkReply);
}

GhostPayClient::~GhostPayClient() = default;

void GhostPayClient::setEndpoint(const QString& host, int port, bool useTls)
{
    QString scheme = useTls ? QStringLiteral("https") : QStringLiteral("http");
    m_baseUrl = QUrl(QStringLiteral("%1://%2:%3").arg(scheme).arg(host).arg(port));
    m_configured = !host.isEmpty() && port > 0;
}

void GhostPayClient::setAuth(const QString& username, const QString& password)
{
    if (!username.isEmpty()) {
        QString credentials = QStringLiteral("%1:%2").arg(username, password);
        m_authHeader = QStringLiteral("Basic %1")
            .arg(QString::fromLatin1(credentials.toUtf8().toBase64()));
    } else {
        m_authHeader.clear();
    }
}

bool GhostPayClient::isConfigured() const
{
    return m_configured;
}

// ========== Private Helpers ==========

void GhostPayClient::doGet(const QString& path, const QString& tag)
{
    if (!m_configured) {
        Q_EMIT error(tag, tr("Ghost Pay client not configured"));
        return;
    }

    QUrl url = m_baseUrl;
    url.setPath(path);

    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    if (!m_authHeader.isEmpty()) {
        request.setRawHeader("Authorization", m_authHeader.toUtf8());
    }
    request.setAttribute(QNetworkRequest::User, tag);

    m_networkManager->get(request);
}

void GhostPayClient::doPost(const QString& path, const QJsonObject& body, const QString& tag)
{
    if (!m_configured) {
        Q_EMIT error(tag, tr("Ghost Pay client not configured"));
        return;
    }

    QUrl url = m_baseUrl;
    url.setPath(path);

    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    if (!m_authHeader.isEmpty()) {
        request.setRawHeader("Authorization", m_authHeader.toUtf8());
    }
    request.setAttribute(QNetworkRequest::User, tag);

    QJsonDocument doc(body);
    m_networkManager->post(request, doc.toJson(QJsonDocument::Compact));
}

bool GhostPayClient::parseResponse(QNetworkReply* reply, QJsonObject& result, QString& errorMsg)
{
    if (reply->error() != QNetworkReply::NoError) {
        errorMsg = reply->errorString();
        return false;
    }

    QByteArray data = reply->readAll();
    QJsonDocument doc = QJsonDocument::fromJson(data);

    if (doc.isNull() || !doc.isObject()) {
        errorMsg = tr("Invalid JSON response");
        return false;
    }

    result = doc.object();

    // Check for error field in response
    if (result.contains(QStringLiteral("error")) && !result[QStringLiteral("error")].isNull()) {
        QJsonObject err = result[QStringLiteral("error")].toObject();
        errorMsg = err[QStringLiteral("message")].toString(tr("Unknown error"));
        return false;
    }

    return true;
}

// ========== Info Endpoints ==========

void GhostPayClient::getNodeInfo()
{
    doGet(QStringLiteral("/info"), QStringLiteral("getNodeInfo"));
}

void GhostPayClient::getHealth()
{
    doGet(QStringLiteral("/health"), QStringLiteral("getHealth"));
}

// ========== Lock Endpoints ==========

void GhostPayClient::getLockInfo(const QString& lockId)
{
    doGet(QStringLiteral("/lock/%1").arg(lockId), QStringLiteral("getLockInfo:%1").arg(lockId));
}

void GhostPayClient::registerLock(const QString& lockPubkey, const QString& recoveryPubkey,
                                  GhostPay::Denomination denomination,
                                  GhostPay::TimelockTier timelock,
                                  uint32_t creationHeight)
{
    QJsonObject body;
    body[QStringLiteral("lock_pubkey")] = lockPubkey;
    body[QStringLiteral("recovery_pubkey")] = recoveryPubkey;
    body[QStringLiteral("denomination")] = static_cast<int>(denomination);
    body[QStringLiteral("timelock_tier")] = static_cast<int>(timelock);
    body[QStringLiteral("creation_height")] = static_cast<qint64>(creationHeight);

    doPost(QStringLiteral("/lock/register"), body, QStringLiteral("registerLock"));
}

// ========== Balance Endpoints ==========

void GhostPayClient::getBalance(const QString& lockId)
{
    doGet(QStringLiteral("/balance/%1").arg(lockId), QStringLiteral("getBalance:%1").arg(lockId));
}

// ========== Payment Endpoints ==========

void GhostPayClient::submitPayment(const QString& fromLockId,
                                   const QString& toGhostId,
                                   int64_t amountSats,
                                   const QString& signature)
{
    QJsonObject body;
    body[QStringLiteral("from_lock_id")] = fromLockId;
    body[QStringLiteral("to_ghost_id")] = toGhostId;
    body[QStringLiteral("amount_sats")] = static_cast<qint64>(amountSats);
    body[QStringLiteral("signature")] = signature;

    doPost(QStringLiteral("/payment"), body, QStringLiteral("submitPayment"));
}

void GhostPayClient::getPayment(const QString& paymentId)
{
    doGet(QStringLiteral("/payment/%1").arg(paymentId), QStringLiteral("getPayment:%1").arg(paymentId));
}

void GhostPayClient::getIncomingPayments(const QString& ghostId)
{
    doGet(QStringLiteral("/payments/to/%1").arg(ghostId), QStringLiteral("getIncomingPayments:%1").arg(ghostId));
}

// ========== Block/State Endpoints ==========

void GhostPayClient::getLatestBlock()
{
    doGet(QStringLiteral("/block/latest"), QStringLiteral("getLatestBlock"));
}

void GhostPayClient::getBlock(uint64_t height)
{
    doGet(QStringLiteral("/block/%1").arg(height), QStringLiteral("getBlock:%1").arg(height));
}

void GhostPayClient::getStateRoot()
{
    doGet(QStringLiteral("/state/root"), QStringLiteral("getStateRoot"));
}

// ========== Wraith Endpoints ==========

void GhostPayClient::listWraithSessions()
{
    doGet(QStringLiteral("/wraith/sessions"), QStringLiteral("listWraithSessions"));
}

void GhostPayClient::getWraithSession(const QString& sessionId)
{
    doGet(QStringLiteral("/wraith/session/%1").arg(sessionId),
          QStringLiteral("getWraithSession:%1").arg(sessionId));
}

void GhostPayClient::joinWraith(GhostPay::Denomination denomination,
                                const QString& inputTxid, uint32_t inputVout,
                                int64_t inputAmountSats,
                                const QString& outputPubkey)
{
    QJsonObject body;
    body[QStringLiteral("denomination")] = static_cast<int>(denomination);
    body[QStringLiteral("input_txid")] = inputTxid;
    body[QStringLiteral("input_vout")] = static_cast<int>(inputVout);
    body[QStringLiteral("input_amount_sats")] = static_cast<qint64>(inputAmountSats);
    body[QStringLiteral("output_pubkey")] = outputPubkey;

    doPost(QStringLiteral("/wraith/join"), body, QStringLiteral("joinWraith"));
}

void GhostPayClient::submitWraithSignature(const QString& sessionId,
                                           const QString& signature,
                                           int phase)
{
    QJsonObject body;
    body[QStringLiteral("signature")] = signature;
    body[QStringLiteral("phase")] = phase;

    doPost(QStringLiteral("/wraith/session/%1/signature").arg(sessionId), body,
           QStringLiteral("submitWraithSignature:%1").arg(sessionId));
}

void GhostPayClient::getWraithStats()
{
    doGet(QStringLiteral("/wraith/stats"), QStringLiteral("getWraithStats"));
}

// ========== Reconciliation Endpoints ==========

void GhostPayClient::requestReconciliation(const QString& lockId,
                                           const QString& settlementAddress,
                                           const QString& settlementClass)
{
    QJsonObject body;
    body[QStringLiteral("lock_id")] = lockId;
    body[QStringLiteral("settlement_address")] = settlementAddress;
    body[QStringLiteral("settlement_class")] = settlementClass;

    doPost(QStringLiteral("/reconciliation/request"), body, QStringLiteral("requestReconciliation"));
}

void GhostPayClient::getBatch(const QString& batchId)
{
    doGet(QStringLiteral("/reconciliation/batch/%1").arg(batchId),
          QStringLiteral("getBatch:%1").arg(batchId));
}

void GhostPayClient::listBatches()
{
    doGet(QStringLiteral("/reconciliation/batches"), QStringLiteral("listBatches"));
}

void GhostPayClient::submitBatchSignature(const QString& batchId,
                                          const QString& lockId,
                                          const QString& signature)
{
    QJsonObject body;
    body[QStringLiteral("batch_id")] = batchId;
    body[QStringLiteral("lock_id")] = lockId;
    body[QStringLiteral("signature")] = signature;

    doPost(QStringLiteral("/reconciliation/sign"), body, QStringLiteral("submitBatchSignature"));
}

// ========== Jump Queue Endpoints ==========

void GhostPayClient::jumpEnqueue(const QString& lockId)
{
    QJsonObject body;
    body[QStringLiteral("lock_id")] = lockId;

    doPost(QStringLiteral("/jump/enqueue"), body, QStringLiteral("jumpEnqueue:%1").arg(lockId));
}

void GhostPayClient::getJumpStatus(const QString& lockId)
{
    doGet(QStringLiteral("/jump/status/%1").arg(lockId), QStringLiteral("getJumpStatus:%1").arg(lockId));
}

void GhostPayClient::listJumpQueue()
{
    doGet(QStringLiteral("/jump/list"), QStringLiteral("listJumpQueue"));
}

// ========== Glyph Endpoints ==========

void GhostPayClient::claimGlyph(const QString& ghostId, const QByteArray& pixels)
{
    QJsonArray pixelArray;
    for (int i = 0; i < pixels.size(); ++i) {
        pixelArray.append(static_cast<int>(static_cast<uint8_t>(pixels.at(i))));
    }

    QJsonObject body;
    body[QStringLiteral("ghost_id")] = ghostId;
    body[QStringLiteral("pixels")] = pixelArray;

    doPost(QStringLiteral("/api/v1/glyph/claim"), body, QStringLiteral("glyph_claim"));
}

void GhostPayClient::getGlyph(const QString& ghostId)
{
    doGet(QStringLiteral("/api/v1/glyph/%1").arg(ghostId), QStringLiteral("glyph_get:%1").arg(ghostId));
}

void GhostPayClient::checkGlyphAvailability(const QString& bitmapHashHex)
{
    doGet(QStringLiteral("/api/v1/glyph/check/%1").arg(bitmapHashHex), QStringLiteral("glyph_check"));
}

// ========== Response Parsing ==========

GhostPay::NodeStatus GhostPayClient::parseNodeStatus(const QJsonObject& json)
{
    GhostPay::NodeStatus status;
    status.connected = true;
    status.nodeId = json[QStringLiteral("node_id")].toString();
    status.version = json[QStringLiteral("version")].toString();
    status.l2Height = json[QStringLiteral("l2_height")].toVariant().toULongLong();
    status.currentEpoch = json[QStringLiteral("current_epoch")].toInt();
    status.peerCount = json[QStringLiteral("peer_count")].toInt();
    status.l1Height = json[QStringLiteral("l1_height")].toInt();
    status.stateRoot = json[QStringLiteral("state_root")].toString();
    return status;
}

GhostPay::GhostLockInfo GhostPayClient::parseLockInfo(const QJsonObject& json)
{
    GhostPay::GhostLockInfo lock;
    lock.lockId = json[QStringLiteral("lock_id")].toString();
    lock.lockPubkey = json[QStringLiteral("lock_pubkey")].toString();
    lock.recoveryPubkey = json[QStringLiteral("recovery_pubkey")].toString();
    lock.creationHeight = json[QStringLiteral("creation_height")].toInt();
    lock.denomination = static_cast<GhostPay::Denomination>(json[QStringLiteral("denomination")].toInt());
    lock.timelockTier = static_cast<GhostPay::TimelockTier>(json[QStringLiteral("timelock_tier")].toInt());
    lock.state = static_cast<GhostPay::LockState>(json[QStringLiteral("state")].toInt());
    lock.l2Balance = json[QStringLiteral("l2_balance")].toVariant().toLongLong();
    lock.lastActivityHeight = json[QStringLiteral("last_activity_height")].toVariant().toULongLong();
    lock.recoveryHeight = json[QStringLiteral("recovery_height")].toInt();
    return lock;
}

GhostPay::PaymentInfo GhostPayClient::parsePaymentInfo(const QJsonObject& json)
{
    GhostPay::PaymentInfo payment;
    payment.paymentId = json[QStringLiteral("payment_id")].toString();
    payment.fromLockId = json[QStringLiteral("from_lock_id")].toString();
    payment.toGhostId = json[QStringLiteral("to_ghost_id")].toString();
    payment.amount = json[QStringLiteral("amount")].toVariant().toLongLong();
    payment.virtualBlock = json[QStringLiteral("virtual_block")].toVariant().toULongLong();
    payment.timestamp = QDateTime::fromSecsSinceEpoch(json[QStringLiteral("timestamp")].toVariant().toLongLong());
    payment.confirmed = json[QStringLiteral("confirmed")].toBool();
    payment.status = json[QStringLiteral("status")].toString();
    return payment;
}

GhostPay::WraithSessionInfo GhostPayClient::parseWraithSession(const QJsonObject& json)
{
    GhostPay::WraithSessionInfo session;
    session.sessionId = json[QStringLiteral("session_id")].toString();
    session.denomination = static_cast<GhostPay::Denomination>(json[QStringLiteral("denomination")].toInt());
    session.phase = static_cast<GhostPay::WraithPhase>(json[QStringLiteral("phase")].toInt());
    session.participantCount = json[QStringLiteral("participant_count")].toInt();
    session.minParticipants = json[QStringLiteral("min_participants")].toInt();
    session.maxParticipants = json[QStringLiteral("max_participants")].toInt();
    session.createdAt = QDateTime::fromSecsSinceEpoch(json[QStringLiteral("created_at")].toVariant().toLongLong());
    session.expiresAt = QDateTime::fromSecsSinceEpoch(json[QStringLiteral("expires_at")].toVariant().toLongLong());
    session.coordinatorId = json[QStringLiteral("coordinator_id")].toString();
    session.isCoordinator = json[QStringLiteral("is_coordinator")].toBool();
    return session;
}

GhostPay::BatchInfo GhostPayClient::parseBatchInfo(const QJsonObject& json)
{
    GhostPay::BatchInfo batch;
    batch.batchId = json[QStringLiteral("batch_id")].toString();
    batch.epochId = json[QStringLiteral("epoch_id")].toInt();
    batch.inputCount = json[QStringLiteral("input_count")].toInt();
    batch.outputCount = json[QStringLiteral("output_count")].toInt();
    batch.totalAmount = json[QStringLiteral("total_amount")].toVariant().toLongLong();
    batch.status = json[QStringLiteral("status")].toString();
    batch.createdAt = QDateTime::fromSecsSinceEpoch(json[QStringLiteral("created_at")].toVariant().toLongLong());
    batch.txid = json[QStringLiteral("txid")].toString();
    return batch;
}

GhostPay::JumpStatus GhostPayClient::parseJumpStatus(const QJsonObject& json)
{
    GhostPay::JumpStatus status;
    status.lockId = json[QStringLiteral("lock_id")].toString();
    status.inQueue = json[QStringLiteral("in_queue")].toBool();
    status.queuePosition = json[QStringLiteral("queue_position")].toInt();
    status.deadline = json[QStringLiteral("deadline")].toVariant().toULongLong();
    status.needsRotation = json[QStringLiteral("needs_rotation")].toBool();
    status.riskTier = json[QStringLiteral("risk_tier")].toString();
    return status;
}

// ========== Network Reply Handler ==========

void GhostPayClient::handleNetworkReply(QNetworkReply* reply)
{
    reply->deleteLater();

    QString tag = reply->request().attribute(QNetworkRequest::User).toString();
    QJsonObject result;
    QString errorMsg;

    if (!parseResponse(reply, result, errorMsg)) {
        // Extract method name from tag
        QString method = tag.split(':').first();
        Q_EMIT error(method, errorMsg);

        // Emit specific error signals
        if (tag.startsWith(QStringLiteral("getLockInfo:"))) {
            Q_EMIT lockError(tag.mid(12), errorMsg);
        } else if (tag.startsWith(QStringLiteral("submitPayment"))) {
            Q_EMIT paymentError(errorMsg);
        } else if (tag.startsWith(QStringLiteral("joinWraith")) || tag.startsWith(QStringLiteral("getWraith"))) {
            Q_EMIT wraithError(errorMsg);
        } else if (tag.startsWith(QStringLiteral("requestReconciliation")) || tag.startsWith(QStringLiteral("getBatch"))) {
            Q_EMIT reconciliationError(errorMsg);
        } else if (tag.startsWith(QStringLiteral("jump"))) {
            Q_EMIT jumpError(errorMsg);
        } else if (tag.startsWith(QStringLiteral("glyph_"))) {
            Q_EMIT glyphError(errorMsg);
        }
        return;
    }

    // Route response to appropriate handler
    if (tag == QStringLiteral("getNodeInfo")) {
        Q_EMIT nodeInfoReceived(parseNodeStatus(result));
    }
    else if (tag == QStringLiteral("getHealth")) {
        bool healthy = result[QStringLiteral("healthy")].toBool();
        QString message = result[QStringLiteral("message")].toString();
        Q_EMIT healthReceived(healthy, message);
    }
    else if (tag.startsWith(QStringLiteral("getLockInfo:"))) {
        Q_EMIT lockInfoReceived(parseLockInfo(result));
    }
    else if (tag == QStringLiteral("registerLock")) {
        QString lockId = result[QStringLiteral("lock_id")].toString();
        Q_EMIT lockRegistered(lockId);
    }
    else if (tag.startsWith(QStringLiteral("getBalance:"))) {
        QString lockId = tag.mid(11);
        GhostPay::L2Balance balance;
        balance.available = result[QStringLiteral("available")].toVariant().toLongLong();
        balance.pending = result[QStringLiteral("pending")].toVariant().toLongLong();
        balance.total = result[QStringLiteral("total")].toVariant().toLongLong();
        balance.lockCount = result[QStringLiteral("lock_count")].toInt();
        Q_EMIT balanceReceived(lockId, balance);
    }
    else if (tag == QStringLiteral("submitPayment")) {
        QString paymentId = result[QStringLiteral("payment_id")].toString();
        Q_EMIT paymentSubmitted(paymentId);
    }
    else if (tag.startsWith(QStringLiteral("getPayment:"))) {
        Q_EMIT paymentReceived(parsePaymentInfo(result));
    }
    else if (tag.startsWith(QStringLiteral("getIncomingPayments:"))) {
        QList<GhostPay::PaymentInfo> payments;
        QJsonArray arr = result[QStringLiteral("payments")].toArray();
        for (const QJsonValue& v : arr) {
            payments.append(parsePaymentInfo(v.toObject()));
        }
        Q_EMIT incomingPaymentsReceived(payments);
    }
    else if (tag == QStringLiteral("getLatestBlock")) {
        uint64_t height = result[QStringLiteral("height")].toVariant().toULongLong();
        QString stateRoot = result[QStringLiteral("state_root")].toString();
        Q_EMIT latestBlockReceived(height, stateRoot);
    }
    else if (tag.startsWith(QStringLiteral("getBlock:"))) {
        uint64_t height = result[QStringLiteral("height")].toVariant().toULongLong();
        Q_EMIT blockReceived(height, result);
    }
    else if (tag == QStringLiteral("getStateRoot")) {
        QString stateRoot = result[QStringLiteral("state_root")].toString();
        Q_EMIT stateRootReceived(stateRoot);
    }
    else if (tag == QStringLiteral("listWraithSessions")) {
        QList<GhostPay::WraithSessionInfo> sessions;
        QJsonArray arr = result[QStringLiteral("sessions")].toArray();
        for (const QJsonValue& v : arr) {
            sessions.append(parseWraithSession(v.toObject()));
        }
        Q_EMIT wraithSessionsReceived(sessions);
    }
    else if (tag.startsWith(QStringLiteral("getWraithSession:"))) {
        Q_EMIT wraithSessionReceived(parseWraithSession(result));
    }
    else if (tag == QStringLiteral("joinWraith")) {
        QString sessionId = result[QStringLiteral("session_id")].toString();
        Q_EMIT wraithJoined(sessionId);
    }
    else if (tag.startsWith(QStringLiteral("submitWraithSignature:"))) {
        QString sessionId = tag.mid(22);
        int phase = result[QStringLiteral("phase")].toInt();
        Q_EMIT wraithSignatureSubmitted(sessionId, phase);
    }
    else if (tag == QStringLiteral("requestReconciliation")) {
        QString batchId = result[QStringLiteral("batch_id")].toString();
        Q_EMIT reconciliationRequested(batchId);
    }
    else if (tag.startsWith(QStringLiteral("getBatch:"))) {
        Q_EMIT batchReceived(parseBatchInfo(result));
    }
    else if (tag == QStringLiteral("listBatches")) {
        QList<GhostPay::BatchInfo> batches;
        QJsonArray arr = result[QStringLiteral("batches")].toArray();
        for (const QJsonValue& v : arr) {
            batches.append(parseBatchInfo(v.toObject()));
        }
        Q_EMIT batchesReceived(batches);
    }
    else if (tag == QStringLiteral("submitBatchSignature")) {
        QString batchId = result[QStringLiteral("batch_id")].toString();
        Q_EMIT batchSignatureSubmitted(batchId);
    }
    else if (tag.startsWith(QStringLiteral("jumpEnqueue:"))) {
        QString lockId = tag.mid(12);
        Q_EMIT jumpEnqueued(lockId);
    }
    else if (tag.startsWith(QStringLiteral("getJumpStatus:"))) {
        Q_EMIT jumpStatusReceived(parseJumpStatus(result));
    }
    else if (tag == QStringLiteral("listJumpQueue")) {
        QList<GhostPay::JumpStatus> queue;
        QJsonArray arr = result[QStringLiteral("queue")].toArray();
        for (const QJsonValue& v : arr) {
            queue.append(parseJumpStatus(v.toObject()));
        }
        Q_EMIT jumpQueueReceived(queue);
    }
    else if (tag == QStringLiteral("glyph_claim")) {
        QString commitment = result[QStringLiteral("commitment")].toString();
        QString bitmapHash = result[QStringLiteral("bitmap_hash")].toString();
        Q_EMIT glyphClaimed(commitment, bitmapHash);
    }
    else if (tag.startsWith(QStringLiteral("glyph_get:"))) {
        QString gid = result[QStringLiteral("ghost_id")].toString();
        QJsonArray arr = result[QStringLiteral("pixels")].toArray();
        QByteArray px;
        px.reserve(arr.size());
        for (const QJsonValue& v : arr) {
            px.append(static_cast<char>(v.toInt()));
        }
        QString bitmapHash = result[QStringLiteral("bitmap_hash")].toString();
        QString commitment = result[QStringLiteral("commitment")].toString();
        QString glyphStatus = result[QStringLiteral("status")].toString();
        Q_EMIT glyphReceived(gid, px, bitmapHash, commitment, glyphStatus);
    }
    else if (tag == QStringLiteral("glyph_check")) {
        bool available = result[QStringLiteral("available")].toBool();
        Q_EMIT glyphAvailabilityChecked(available);
    }
}
