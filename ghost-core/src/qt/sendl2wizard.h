// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_SENDL2WIZARD_H
#define GHOST_QT_SENDL2WIZARD_H

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
class QSpinBox;
QT_END_NAMESPACE

/**
 * Send L2 Payment Wizard - Send an instant L2 payment
 *
 * Steps:
 * 1. Recipient (Ghost ID or address input)
 * 2. Amount (in sats)
 * 3. Memo (optional, max 59 chars)
 * 4. Confirm summary
 * 5. Complete (payment ID)
 *
 * API: POST /api/v1/payments/send with { recipient, amount_sats, memo }
 */
class SendL2Wizard : public QWizard
{
    Q_OBJECT

public:
    enum Page {
        Page_Recipient,
        Page_Amount,
        Page_Memo,
        Page_Confirm,
        Page_Complete
    };

    explicit SendL2Wizard(const PlatformStyle *platformStyle,
                          WalletModel *walletModel,
                          L2WalletModel *l2WalletModel,
                          QWidget *parent = nullptr);

    // Getters
    QString recipient() const { return m_recipient; }
    int64_t amountSats() const { return m_amountSats; }
    QString memo() const { return m_memo; }
    QString paymentId() const { return m_paymentId; }

    // Model access
    WalletModel* getWalletModel() const { return walletModel; }
    L2WalletModel* getL2WalletModel() const { return l2WalletModel; }

public Q_SLOTS:
    void setRecipient(const QString& recipient);
    void setAmountSats(int64_t amount);
    void setMemo(const QString& memo);

    // Payment progress
    void onPaymentSent(const QString& paymentId);
    void onPaymentError(const QString& error);

Q_SIGNALS:
    void operationComplete(const QString& paymentId);
    void operationCancelled();

private:
    WalletModel *walletModel;
    L2WalletModel *l2WalletModel;
    const PlatformStyle *platformStyle;

    QString m_recipient;
    int64_t m_amountSats{0};
    QString m_memo;
    QString m_paymentId;
};

// ===== Wizard Pages =====

class RecipientPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit RecipientPage(QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;
    bool isComplete() const override;

    QString recipient() const;

private Q_SLOTS:
    void onRecipientChanged();

private:
    QLabel *instructionLabel;
    QLineEdit *recipientEdit;
    QLabel *validationLabel;
    bool m_valid{false};
};

class AmountPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit AmountPage(L2WalletModel *l2WalletModel, QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;
    bool isComplete() const override;

    int64_t amountSats() const;

private Q_SLOTS:
    void onAmountChanged();

private:
    L2WalletModel *l2WalletModel;
    QLabel *balanceLabel;
    QLineEdit *amountEdit;
    QLabel *btcEquivLabel;
    QLabel *validationLabel;
    bool m_valid{false};
};

class MemoPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit MemoPage(QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;

    QString memo() const;

private Q_SLOTS:
    void onMemoChanged();

private:
    QLineEdit *memoEdit;
    QLabel *charCountLabel;
    QLabel *hintLabel;
};

class SendL2ConfirmPage : public QWizardPage
{
    Q_OBJECT

public:
    explicit SendL2ConfirmPage(QWidget *parent = nullptr);

    void initializePage() override;
    bool validatePage() override;
    int nextId() const override;
    bool isComplete() const override;

public Q_SLOTS:
    void onSent(const QString& paymentId);
    void onError(const QString& error);

private:
    QLabel *recipientLabel;
    QLabel *amountLabel;
    QLabel *memoLabel;
    QLabel *statusLabel;
    QProgressBar *progressBar;
    bool m_submitted{false};
    bool m_complete{false};
    QString m_error;
};

class SendL2CompletePage : public QWizardPage
{
    Q_OBJECT

public:
    explicit SendL2CompletePage(QWidget *parent = nullptr);

    void initializePage() override;
    int nextId() const override;

private:
    QLabel *successLabel;
    QLabel *paymentIdLabel;
    QLabel *recipientLabel;
    QLabel *amountLabel;
    QLabel *memoLabel;
    QLabel *infoLabel;
};

#endif // GHOST_QT_SENDL2WIZARD_H
