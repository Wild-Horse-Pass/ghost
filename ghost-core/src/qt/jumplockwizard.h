// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_JUMPLOCKWIZARD_H
#define GHOST_QT_JUMPLOCKWIZARD_H

#include <qt/ghostpaytypes.h>

#include <QWizard>
#include <QWizardPage>

class L2WalletModel;
class WalletModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QLabel;
class QProgressBar;
class QTableView;
QT_END_NAMESPACE

/**
 * Jump Lock Wizard - Rotate a Ghost Lock's keys via jump
 *
 * Steps:
 * 1. Select Lock (list of active locks fetched from GET /api/v1/locks)
 * 2. Confirm Jump (show fee breakdown)
 * 3. Processing (waiting for jump to complete)
 * 4. Complete (new lock ID + txid)
 *
 * API: GET /api/v1/locks -> POST /api/v1/locks/:id/jump
 */
class JumpLockWizard : public QWizard
{
    Q_OBJECT

public:
    enum Page {
        Page_SelectLock,
        Page_ConfirmJump,
        Page_Processing,
        Page_Complete
    };

    explicit JumpLockWizard(const PlatformStyle *platformStyle,
                            WalletModel *walletModel,
                            L2WalletModel *l2WalletModel,
                            QWidget *parent = nullptr);

    // Pre-select a lock
    void setSelectedLock(const QString& lockId);

    // Result accessors
    QString selectedLockId() const { return m_lockId; }
    QString newLockId() const { return m_newLockId; }
    QString resultTxid() const { return m_resultTxid; }

    // Model access
    L2WalletModel* getL2WalletModel() const { return l2WalletModel; }

public Q_SLOTS:
    void setLockId(const QString& lockId);

    // Jump progress
    void onJumpEnqueued(const QString& lockId);
    void onJumpComplete(const QString& lockId, const QString& newLockId, const QString& txid);
    void onJumpError(const QString& error);

Q_SIGNALS:
    void operationComplete(const QString& newLockId);
    void operationCancelled();

private:
    WalletModel *walletModel;
    L2WalletModel *l2WalletModel;
    const PlatformStyle *platformStyle;

    QString m_lockId;
    QString m_newLockId;
    QString m_resultTxid;
};

// ===== Wizard Pages =====

class JumpSelectLockPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit JumpSelectLockPage(L2WalletModel *l2WalletModel, QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;
    bool isComplete() const override;

    QString selectedLockId() const;

private Q_SLOTS:
    void onLockSelected();

private:
    L2WalletModel *l2WalletModel;
    QTableView *locksTable;
    QLabel *selectedLabel;
    QLabel *balanceLabel;
    QLabel *jumpStatusLabel;
    int m_selectedRow{-1};
};

class ConfirmJumpPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit ConfirmJumpPage(QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;

private:
    QLabel *lockIdLabel;
    QLabel *balanceLabel;
    QLabel *feeLabel;
    QLabel *receiveLabel;
    QLabel *warningLabel;
};

class JumpProcessingPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit JumpProcessingPage(L2WalletModel *l2WalletModel, QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;
    bool isComplete() const override;

public Q_SLOTS:
    void onEnqueued(const QString& lockId);
    void onComplete(const QString& lockId, const QString& newLockId, const QString& txid);
    void onError(const QString& error);

private:
    L2WalletModel *l2WalletModel;
    QLabel *statusLabel;
    QProgressBar *progressBar;
    QLabel *detailLabel;
    bool m_complete{false};
    QString m_error;
};

class JumpCompletePage : public QWizardPage
{
    Q_OBJECT

public:
    explicit JumpCompletePage(QWidget *parent = nullptr);

    void initializePage() override;
    int nextId() const override;

private:
    QLabel *successLabel;
    QLabel *oldLockIdLabel;
    QLabel *newLockIdLabel;
    QLabel *txidLabel;
    QLabel *infoLabel;
};

#endif // GHOST_QT_JUMPLOCKWIZARD_H
