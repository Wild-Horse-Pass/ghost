// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_CREATELOCKWIZARD_H
#define GHOST_QT_CREATELOCKWIZARD_H

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
class QRadioButton;
class QButtonGroup;
QT_END_NAMESPACE

/**
 * Create Lock Wizard - Create a new Ghost Lock
 *
 * Steps:
 * 1. Select Denomination (Micro/Tiny/Small/Medium/Large/XL)
 * 2. Timelock Tier (Short/Standard/Long)
 * 3. Optional Label (text input)
 * 4. Confirm Summary
 * 5. Complete (show lock ID)
 *
 * API: POST /api/v1/locks/create with { amount_sats, timelock_tier, label }
 */
class CreateLockWizard : public QWizard
{
    Q_OBJECT

public:
    enum Page {
        Page_Denomination,
        Page_Timelock,
        Page_Label,
        Page_Confirm,
        Page_Complete
    };

    explicit CreateLockWizard(const PlatformStyle *platformStyle,
                              WalletModel *walletModel,
                              L2WalletModel *l2WalletModel,
                              QWidget *parent = nullptr);

    // Selected parameters
    GhostPay::Denomination selectedDenomination() const { return m_denomination; }
    GhostPay::TimelockTier selectedTimelockTier() const { return m_timelockTier; }
    QString lockLabel() const { return m_label; }
    QString newLockId() const { return m_lockId; }

    // Model access
    WalletModel* getWalletModel() const { return walletModel; }
    L2WalletModel* getL2WalletModel() const { return l2WalletModel; }

public Q_SLOTS:
    void setDenomination(GhostPay::Denomination denom);
    void setTimelockTier(GhostPay::TimelockTier tier);
    void setLabel(const QString& label);

    // Creation progress
    void onLockCreated(const QString& lockId);
    void onLockCreationError(const QString& error);

Q_SIGNALS:
    void operationComplete(const QString& lockId);
    void operationCancelled();

private:
    WalletModel *walletModel;
    L2WalletModel *l2WalletModel;
    const PlatformStyle *platformStyle;

    GhostPay::Denomination m_denomination{GhostPay::Denomination::Small};
    GhostPay::TimelockTier m_timelockTier{GhostPay::TimelockTier::Standard};
    QString m_label;
    QString m_lockId;
};

// ===== Wizard Pages =====

class CreateLockDenominationPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit CreateLockDenominationPage(QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;

    GhostPay::Denomination selectedDenomination() const;

private:
    void updateInfo();

    QButtonGroup *denomGroup;
    QRadioButton *microButton;
    QRadioButton *tinyButton;
    QRadioButton *smallButton;
    QRadioButton *mediumButton;
    QRadioButton *largeButton;
    QRadioButton *xlButton;
    QLabel *infoLabel;
};

class TimelockTierPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit TimelockTierPage(QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;

    GhostPay::TimelockTier selectedTier() const;

private:
    void updateInfo();

    QButtonGroup *tierGroup;
    QRadioButton *shortButton;
    QRadioButton *standardButton;
    QRadioButton *longButton;
    QLabel *infoLabel;
};

class LockLabelPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit LockLabelPage(QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;

    QString lockLabel() const;

private:
    QLineEdit *labelEdit;
    QLabel *hintLabel;
};

class CreateLockConfirmPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit CreateLockConfirmPage(QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;
    bool isComplete() const override;

public Q_SLOTS:
    void onCreated(const QString& lockId);
    void onError(const QString& error);

private:
    QLabel *summaryLabel;
    QLabel *denominationLabel;
    QLabel *timelockLabel;
    QLabel *labelLabel;
    QLabel *amountLabel;
    QLabel *statusLabel;
    QProgressBar *progressBar;
    bool m_submitted{false};
    bool m_complete{false};
    QString m_error;
};

class CreateLockCompletePage : public QWizardPage
{
    Q_OBJECT

public:
    explicit CreateLockCompletePage(QWidget *parent = nullptr);

    void initializePage() override;
    int nextId() const override;

private:
    QLabel *successLabel;
    QLabel *lockIdLabel;
    QLabel *denominationLabel;
    QLabel *timelockLabel;
    QLabel *infoLabel;
};

#endif // GHOST_QT_CREATELOCKWIZARD_H
