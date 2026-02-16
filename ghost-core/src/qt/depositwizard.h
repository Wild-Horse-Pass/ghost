// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_DEPOSITWIZARD_H
#define GHOST_QT_DEPOSITWIZARD_H

#include <qt/ghostpaytypes.h>

#include <QWizard>
#include <QWizardPage>

class L2WalletModel;
class WalletModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QComboBox;
class QLabel;
class QProgressBar;
class QRadioButton;
class QButtonGroup;
class QListWidget;
QT_END_NAMESPACE

namespace GhostPay {
struct WraithSessionInfo;
}

/**
 * Deposit Wizard - L1 to L2 via Wraith Protocol
 *
 * Steps:
 * 1. Select denomination tier
 * 2. Select L1 UTXO to deposit
 * 3. Join Wraith session
 * 4. Wait for phase transitions
 * 5. Completion with new Ghost Lock
 */
class DepositWizard : public QWizard
{
    Q_OBJECT

public:
    enum Page {
        Page_Denomination,
        Page_SelectUTXO,
        Page_JoinWraith,
        Page_Signing,
        Page_Complete
    };

    explicit DepositWizard(const PlatformStyle *platformStyle,
                           WalletModel *walletModel,
                           L2WalletModel *l2WalletModel,
                           QWidget *parent = nullptr);

    // Selected deposit parameters
    GhostPay::Denomination selectedDenomination() const { return m_denomination; }
    QString selectedUtxoTxid() const { return m_utxoTxid; }
    uint32_t selectedUtxoVout() const { return m_utxoVout; }
    int64_t selectedUtxoAmount() const { return m_utxoAmount; }

    // Wraith session info
    QString wraithSessionId() const { return m_sessionId; }
    QString newLockId() const { return m_newLockId; }

    // Model access
    WalletModel* getWalletModel() const { return walletModel; }

public Q_SLOTS:
    void setDenomination(GhostPay::Denomination denom);
    void setSelectedUtxo(const QString& txid, uint32_t vout, int64_t amount);

    // Wraith progress updates
    void onWraithJoined(const QString& sessionId);
    void onWraithPhaseChanged(const QString& sessionId, GhostPay::WraithPhase phase);
    void onWraithComplete(const QString& sessionId, const QString& lockId);
    void onWraithError(const QString& error);

Q_SIGNALS:
    void depositComplete(const QString& lockId);
    void depositCancelled();

private:
    WalletModel *walletModel;
    L2WalletModel *l2WalletModel;
    const PlatformStyle *platformStyle;

    GhostPay::Denomination m_denomination{GhostPay::Denomination::Small};
    QString m_utxoTxid;
    uint32_t m_utxoVout{0};
    int64_t m_utxoAmount{0};
    QString m_sessionId;
    QString m_newLockId;
};

// ===== Wizard Pages =====

class DenominationPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit DenominationPage(QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;

    GhostPay::Denomination selectedDenomination() const;

private:
    QButtonGroup *denomGroup;
    QRadioButton *microButton;
    QRadioButton *tinyButton;
    QRadioButton *smallButton;
    QRadioButton *mediumButton;
    QRadioButton *largeButton;
    QRadioButton *xlButton;
    QLabel *infoLabel;

    void updateInfo();
};

class SelectUTXOPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit SelectUTXOPage(WalletModel *walletModel, QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;
    bool isComplete() const override;

    QString selectedTxid() const;
    uint32_t selectedVout() const;
    int64_t selectedAmount() const;

private Q_SLOTS:
    void onUtxoSelected();

private:
    void populateUtxoList();

    WalletModel *walletModel;
    QListWidget *utxoList;
    QLabel *requiredLabel;
    QLabel *selectedLabel;

    struct UtxoEntry {
        QString txid;
        uint32_t vout;
        int64_t amount;
    };
    QList<UtxoEntry> m_utxos;
    int m_selectedIndex{-1};
};

class JoinWraithPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit JoinWraithPage(L2WalletModel *l2WalletModel, QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;
    bool isComplete() const override;

public Q_SLOTS:
    void onJoinClicked();
    void onWraithJoined(const QString& sessionId);
    void onWraithError(const QString& error);

private:
    L2WalletModel *l2WalletModel;
    QPushButton *joinButton;
    QLabel *statusLabel;
    QLabel *participantLabel;
    QProgressBar *progressBar;
    bool m_joined{false};
};

class SigningPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit SigningPage(QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;
    bool isComplete() const override;

public Q_SLOTS:
    void onPhaseChanged(GhostPay::WraithPhase phase);
    void onComplete(const QString& lockId);
    void onError(const QString& error);

private:
    QLabel *phaseLabel;
    QLabel *statusLabel;
    QProgressBar *progressBar;
    QLabel *phase1Label;
    QLabel *phase2Label;
    bool m_complete{false};
    QString m_error;
};

class CompletePage : public QWizardPage
{
    Q_OBJECT

public:
    explicit CompletePage(QWidget *parent = nullptr);

    void initializePage() override;
    int nextId() const override;

private:
    QLabel *successLabel;
    QLabel *lockIdLabel;
    QLabel *denominationLabel;
    QLabel *balanceLabel;
};

#endif // GHOST_QT_DEPOSITWIZARD_H
