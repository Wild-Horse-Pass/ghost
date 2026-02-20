// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_GHOSTIDWIZARD_H
#define GHOST_QT_GHOSTIDWIZARD_H

#include <qt/ghostpaytypes.h>

#include <QWizard>
#include <QWizardPage>

class L2WalletModel;
class WalletModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QLabel;
class QProgressBar;
class QPushButton;
QT_END_NAMESPACE

/**
 * Ghost ID Wizard - Generate a new Ghost ID (Silent Payment address)
 *
 * Steps:
 * 1. Welcome - Explain what a Ghost ID is
 * 2. Generate - Confirm key generation
 * 3. Complete - Show Ghost ID + backup reminder
 *
 * API: POST /api/v1/keys/generate
 */
class GhostIdWizard : public QWizard
{
    Q_OBJECT

public:
    enum Page {
        Page_Welcome,
        Page_Generate,
        Page_Complete
    };

    explicit GhostIdWizard(const PlatformStyle *platformStyle,
                           WalletModel *walletModel,
                           L2WalletModel *l2WalletModel,
                           QWidget *parent = nullptr);

    // Result accessors
    QString generatedGhostId() const { return m_ghostId; }
    QString scanPubkey() const { return m_scanPubkey; }
    QString spendPubkey() const { return m_spendPubkey; }

    // Model access
    WalletModel* getWalletModel() const { return walletModel; }
    L2WalletModel* getL2WalletModel() const { return l2WalletModel; }

public Q_SLOTS:
    void onKeyGenerated(const QString& ghostId, const QString& scanPubkey, const QString& spendPubkey);
    void onKeyGenerationError(const QString& error);

Q_SIGNALS:
    void operationComplete(const QString& ghostId);
    void operationCancelled();

private:
    WalletModel *walletModel;
    L2WalletModel *l2WalletModel;
    const PlatformStyle *platformStyle;

    QString m_ghostId;
    QString m_scanPubkey;
    QString m_spendPubkey;
};

// ===== Wizard Pages =====

class GhostIdWelcomePage : public QWizardPage
{
    Q_OBJECT

public:
    explicit GhostIdWelcomePage(QWidget *parent = nullptr);

    void initializePage() override;
    int nextId() const override;

private:
    QLabel *infoLabel;
};

class GhostIdGeneratePage : public QWizardPage
{
    Q_OBJECT

public:
    explicit GhostIdGeneratePage(L2WalletModel *l2WalletModel, QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;
    bool isComplete() const override;

public Q_SLOTS:
    void onGenerateClicked();
    void onGenerated(const QString& ghostId, const QString& scanPubkey, const QString& spendPubkey);
    void onError(const QString& error);

private:
    L2WalletModel *l2WalletModel;
    QPushButton *generateButton;
    QLabel *statusLabel;
    QProgressBar *progressBar;
    bool m_generated{false};
};

class GhostIdCompletePage : public QWizardPage
{
    Q_OBJECT

public:
    explicit GhostIdCompletePage(QWidget *parent = nullptr);

    void initializePage() override;
    int nextId() const override;

private:
    QLabel *successLabel;
    QLabel *ghostIdLabel;
    QLabel *scanPubkeyLabel;
    QLabel *spendPubkeyLabel;
    QLabel *backupReminderLabel;
};

#endif // GHOST_QT_GHOSTIDWIZARD_H
