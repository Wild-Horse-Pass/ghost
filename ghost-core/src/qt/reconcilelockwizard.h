// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_RECONCILELOCKWIZARD_H
#define GHOST_QT_RECONCILELOCKWIZARD_H

#include <qt/ghostpaytypes.h>

#include <QWizard>
#include <QWizardPage>

class L2WalletModel;
class WalletModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QLabel;
class QLineEdit;
class QProgressBar;
class QPushButton;
class QRadioButton;
class QButtonGroup;
class QTableView;
QT_END_NAMESPACE

/**
 * Reconcile Lock Wizard - Settle a Ghost Lock to L1
 *
 * Steps:
 * 1. Select Lock (list of active locks)
 * 2. Destination Address (QLineEdit with bech32 validation)
 * 3. Settlement Class (Standard/Batched radio)
 * 4. Confirm summary
 * 5. Processing (waiting for reconciliation)
 * 6. Complete (txid + settlement details)
 *
 * API: GET /api/v1/locks -> POST /api/v1/locks/:id/reconcile
 *      with { destination_address, settlement_class }
 */
class ReconcileLockWizard : public QWizard
{
    Q_OBJECT

public:
    enum Page {
        Page_SelectLock,
        Page_Destination,
        Page_SettlementClass,
        Page_Confirm,
        Page_Processing,
        Page_Complete
    };

    enum SettlementClass {
        Settlement_Standard = 0,
        Settlement_Batched = 1
    };

    explicit ReconcileLockWizard(const PlatformStyle *platformStyle,
                                 WalletModel *walletModel,
                                 L2WalletModel *l2WalletModel,
                                 QWidget *parent = nullptr);

    // Pre-select a lock
    void setSelectedLock(const QString& lockId);

    // Getters
    QString selectedLockId() const { return m_lockId; }
    QString destinationAddress() const { return m_destination; }
    SettlementClass selectedSettlementClass() const { return m_settlementClass; }
    QString batchId() const { return m_batchId; }
    QString resultTxid() const { return m_resultTxid; }

    // Model access
    WalletModel* getWalletModel() const { return walletModel; }
    L2WalletModel* getL2WalletModel() const { return l2WalletModel; }

public Q_SLOTS:
    void setLockId(const QString& lockId);
    void setDestination(const QString& address);
    void setSettlementClass(SettlementClass sc);

    // Reconciliation progress
    void onReconcileRequested(const QString& batchId);
    void onReconcileComplete(const QString& lockId, const QString& txid);
    void onReconcileError(const QString& error);

Q_SIGNALS:
    void operationComplete(const QString& txid);
    void operationCancelled();

private:
    WalletModel *walletModel;
    L2WalletModel *l2WalletModel;
    const PlatformStyle *platformStyle;

    QString m_lockId;
    QString m_destination;
    SettlementClass m_settlementClass{Settlement_Standard};
    QString m_batchId;
    QString m_resultTxid;
};

// ===== Wizard Pages =====

class ReconcileSelectLockPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit ReconcileSelectLockPage(L2WalletModel *l2WalletModel, QWidget *parent = nullptr);

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
    int m_selectedRow{-1};
};

class ReconcileDestinationPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit ReconcileDestinationPage(WalletModel *walletModel, QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;
    bool isComplete() const override;

    QString destinationAddress() const;

private Q_SLOTS:
    void onAddressChanged();
    void onUseNewAddress();

private:
    WalletModel *walletModel;
    QLabel *instructionLabel;
    QLineEdit *addressEdit;
    QPushButton *newAddressButton;
    QLabel *validationLabel;
    bool m_addressValid{false};
};

class SettlementClassPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit SettlementClassPage(QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;

    ReconcileLockWizard::SettlementClass selectedClass() const;

private:
    void updateInfo();

    QButtonGroup *classGroup;
    QRadioButton *standardButton;
    QRadioButton *batchedButton;
    QLabel *infoLabel;
};

class ReconcileConfirmPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit ReconcileConfirmPage(QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;

private:
    QLabel *lockIdLabel;
    QLabel *destinationLabel;
    QLabel *settlementLabel;
    QLabel *balanceLabel;
    QLabel *feeLabel;
    QLabel *receiveLabel;
    QLabel *warningLabel;
};

class ReconcileProcessingPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit ReconcileProcessingPage(L2WalletModel *l2WalletModel, QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;
    bool isComplete() const override;

public Q_SLOTS:
    void onRequested(const QString& batchId);
    void onComplete(const QString& lockId, const QString& txid);
    void onError(const QString& error);

private:
    L2WalletModel *l2WalletModel;
    QLabel *statusLabel;
    QProgressBar *progressBar;
    QLabel *batchIdLabel;
    bool m_complete{false};
    QString m_error;
};

class ReconcileCompletePage : public QWizardPage
{
    Q_OBJECT

public:
    explicit ReconcileCompletePage(QWidget *parent = nullptr);

    void initializePage() override;
    int nextId() const override;

private:
    QLabel *successLabel;
    QLabel *txidLabel;
    QLabel *destinationLabel;
    QLabel *amountLabel;
    QLabel *infoLabel;
};

#endif // GHOST_QT_RECONCILELOCKWIZARD_H
