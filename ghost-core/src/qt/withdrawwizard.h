// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_WITHDRAWWIZARD_H
#define GHOST_QT_WITHDRAWWIZARD_H

#include <qt/ghostpaytypes.h>

#include <QWizard>
#include <QWizardPage>

class L2WalletModel;
class WalletModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QComboBox;
class QLabel;
class QLineEdit;
class QProgressBar;
class QRadioButton;
class QButtonGroup;
class QTableView;
QT_END_NAMESPACE

/**
 * Withdraw Wizard - L2 to L1 via Reconciliation
 *
 * Modes:
 * - Exit: Withdraw to L1 address
 * - Rotate: Create new lock with fresh keys
 * - Jump: Emergency key rotation
 *
 * Steps:
 * 1. Select Ghost Lock
 * 2. Choose withdrawal mode
 * 3. Configure destination (address/settlement class)
 * 4. Confirm with fee breakdown
 * 5. Completion
 */
class WithdrawWizard : public QWizard
{
    Q_OBJECT

public:
    enum Page {
        Page_SelectLock,
        Page_SelectMode,
        Page_Configure,
        Page_Confirm,
        Page_Processing,
        Page_Complete
    };

    enum WithdrawMode {
        Mode_Exit,      // Settle to L1 address
        Mode_Rotate,    // Create new lock with fresh keys
        Mode_Jump       // Emergency key rotation
    };

    explicit WithdrawWizard(const PlatformStyle *platformStyle,
                            WalletModel *walletModel,
                            L2WalletModel *l2WalletModel,
                            QWidget *parent = nullptr);

    // Pre-select a lock
    void setSelectedLock(const QString& lockId);

    // Getters
    QString selectedLockId() const { return m_lockId; }
    WithdrawMode selectedMode() const { return m_mode; }
    QString destinationAddress() const { return m_destination; }
    QString batchId() const { return m_batchId; }
    QString resultTxid() const { return m_resultTxid; }
    L2WalletModel* getL2WalletModel() const { return l2WalletModel; }

public Q_SLOTS:
    void setLockId(const QString& lockId);
    void setMode(WithdrawMode mode);
    void setDestination(const QString& address);

    // Withdrawal progress
    void onWithdrawalRequested(const QString& batchId);
    void onWithdrawalComplete(const QString& lockId, const QString& txid);
    void onWithdrawalError(const QString& error);

Q_SIGNALS:
    void withdrawalComplete(const QString& lockId, const QString& txid);
    void withdrawalCancelled();

private:
    WalletModel *walletModel;
    L2WalletModel *l2WalletModel;
    const PlatformStyle *platformStyle;

    QString m_lockId;
    WithdrawMode m_mode{Mode_Exit};
    QString m_destination;
    QString m_batchId;
    QString m_resultTxid;
};

// ===== Wizard Pages =====

class SelectLockPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit SelectLockPage(L2WalletModel *l2WalletModel, QWidget *parent = nullptr);

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

class SelectModePage : public QWizardPage
{
    Q_OBJECT

public:
    explicit SelectModePage(QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;

    WithdrawWizard::WithdrawMode selectedMode() const;

private Q_SLOTS:
    void onModeChanged();

private:
    QButtonGroup *modeGroup;
    QRadioButton *exitButton;
    QRadioButton *rotateButton;
    QRadioButton *jumpButton;
    QLabel *exitInfoLabel;
    QLabel *rotateInfoLabel;
    QLabel *jumpInfoLabel;
};

class ConfigurePage : public QWizardPage
{
    Q_OBJECT

public:
    explicit ConfigurePage(WalletModel *walletModel, QWidget *parent = nullptr);

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
    QComboBox *settlementClassCombo;
    QLabel *validationLabel;
    bool m_addressValid{false};
};

class ConfirmPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit ConfirmPage(QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;

private:
    QLabel *summaryLabel;
    QLabel *lockIdLabel;
    QLabel *modeLabel;
    QLabel *destinationLabel;
    QLabel *balanceLabel;
    QLabel *feeLabel;
    QLabel *receiveLabel;
};

class ProcessingPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit ProcessingPage(L2WalletModel *l2WalletModel, QWidget *parent = nullptr);

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

class WithdrawCompletePage : public QWizardPage
{
    Q_OBJECT

public:
    explicit WithdrawCompletePage(QWidget *parent = nullptr);

    void initializePage() override;
    int nextId() const override;

private:
    QLabel *successLabel;
    QLabel *txidLabel;
    QLabel *amountLabel;
    QLabel *infoLabel;
};

#endif // GHOST_QT_WITHDRAWWIZARD_H
