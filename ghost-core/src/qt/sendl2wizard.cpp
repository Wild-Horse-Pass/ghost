// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/sendl2wizard.h>

#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>
#include <qt/l2walletmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <QGridLayout>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QProgressBar>
#include <QRegularExpression>
#include <QSpinBox>
#include <QVBoxLayout>

// ===== SendL2Wizard =====

SendL2Wizard::SendL2Wizard(const PlatformStyle *_platformStyle,
                           WalletModel *_walletModel,
                           L2WalletModel *_l2WalletModel,
                           QWidget *parent)
    : QWizard(parent),
      walletModel(_walletModel),
      l2WalletModel(_l2WalletModel),
      platformStyle(_platformStyle)
{
    setWindowTitle(tr("Send L2 Payment"));
    setWizardStyle(QWizard::ModernStyle);
    setOption(QWizard::NoBackButtonOnStartPage);

    setPage(Page_Recipient, new RecipientPage(this));
    setPage(Page_Amount, new AmountPage(l2WalletModel, this));
    setPage(Page_Memo, new MemoPage(this));
    setPage(Page_Confirm, new SendL2ConfirmPage(this));
    setPage(Page_Complete, new SendL2CompletePage(this));

    setStartId(Page_Recipient);

    if (l2WalletModel) {
        connect(l2WalletModel, &L2WalletModel::paymentSent, this, &SendL2Wizard::onPaymentSent);
        connect(l2WalletModel, &L2WalletModel::paymentError, this, &SendL2Wizard::onPaymentError);
    }

    connect(this, &QWizard::rejected, this, &SendL2Wizard::operationCancelled);
}

void SendL2Wizard::setRecipient(const QString& recipient)
{
    m_recipient = recipient;
}

void SendL2Wizard::setAmountSats(int64_t amount)
{
    m_amountSats = amount;
}

void SendL2Wizard::setMemo(const QString& memo)
{
    m_memo = memo;
}

void SendL2Wizard::onPaymentSent(const QString& paymentId)
{
    m_paymentId = paymentId;
    SendL2ConfirmPage* confirmPage = qobject_cast<SendL2ConfirmPage*>(page(Page_Confirm));
    if (confirmPage) {
        confirmPage->onSent(paymentId);
    }
}

void SendL2Wizard::onPaymentError(const QString& error)
{
    SendL2ConfirmPage* confirmPage = qobject_cast<SendL2ConfirmPage*>(page(Page_Confirm));
    if (confirmPage && currentId() == Page_Confirm) {
        confirmPage->onError(error);
    }
}

// ===== RecipientPage =====

RecipientPage::RecipientPage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Recipient"));
    setSubTitle(tr("Enter the recipient's Ghost ID or L2 address."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    instructionLabel = new QLabel(tr(
        "Enter the recipient's Ghost ID (silent payment address). "
        "Ghost IDs start with 'sp1' and provide privacy for the recipient.\n\n"
        "You can also enter a standard L2 lock address if you know the recipient's lock ID."
    ), this);
    instructionLabel->setWordWrap(true);
    layout->addWidget(instructionLabel);

    layout->addSpacing(10);

    QLabel *recipientLabel = new QLabel(tr("Recipient:"), this);
    layout->addWidget(recipientLabel);

    recipientEdit = new QLineEdit(this);
    recipientEdit->setPlaceholderText(tr("Ghost ID (sp1...) or Lock ID"));
    layout->addWidget(recipientEdit);

    validationLabel = new QLabel(this);
    layout->addWidget(validationLabel);

    layout->addStretch();

    connect(recipientEdit, &QLineEdit::textChanged, this, &RecipientPage::onRecipientChanged);
}

void RecipientPage::initializePage()
{
    m_valid = false;
    recipientEdit->clear();
    validationLabel->clear();
    Q_EMIT completeChanged();
}

void RecipientPage::onRecipientChanged()
{
    QString text = recipientEdit->text().trimmed();
    if (text.isEmpty()) {
        validationLabel->clear();
        m_valid = false;
        Q_EMIT completeChanged();
        return;
    }

    // Basic validation: Ghost IDs start with sp1 and are at least 62 chars,
    // Lock IDs are 64-char hex strings
    bool looksLikeGhostId = text.startsWith(QStringLiteral("sp1")) && text.length() >= 62;
    bool looksLikeLockId = text.length() == 64 && text.contains(QRegularExpression(QStringLiteral("^[0-9a-fA-F]{64}$")));

    if (looksLikeGhostId) {
        validationLabel->setText(tr("Ghost ID detected"));
        validationLabel->setStyleSheet(QStringLiteral("QLabel { color: green; }"));
        m_valid = true;
    } else if (looksLikeLockId) {
        validationLabel->setText(tr("Lock ID detected"));
        validationLabel->setStyleSheet(QStringLiteral("QLabel { color: green; }"));
        m_valid = true;
    } else if (text.length() < 62) {
        validationLabel->setText(tr("Keep typing..."));
        validationLabel->setStyleSheet(QStringLiteral("QLabel { color: #666666; }"));
        m_valid = false;
    } else {
        validationLabel->setText(tr("Invalid recipient format"));
        validationLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));
        m_valid = false;
    }

    Q_EMIT completeChanged();
}

bool RecipientPage::validatePage()
{
    SendL2Wizard *wiz = qobject_cast<SendL2Wizard*>(wizard());
    if (wiz) {
        wiz->setRecipient(recipient());
    }
    return m_valid;
}

int RecipientPage::nextId() const
{
    return SendL2Wizard::Page_Amount;
}

bool RecipientPage::isComplete() const
{
    return m_valid;
}

QString RecipientPage::recipient() const
{
    return recipientEdit->text().trimmed();
}

// ===== AmountPage =====

AmountPage::AmountPage(L2WalletModel *_l2WalletModel, QWidget *parent)
    : QWizardPage(parent),
      l2WalletModel(_l2WalletModel)
{
    setTitle(tr("Amount"));
    setSubTitle(tr("Enter the amount to send in satoshis."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    balanceLabel = new QLabel(this);
    balanceLabel->setStyleSheet(QStringLiteral("QLabel { font-weight: bold; }"));
    layout->addWidget(balanceLabel);

    layout->addSpacing(10);

    QLabel *amountPrompt = new QLabel(tr("Amount (satoshis):"), this);
    layout->addWidget(amountPrompt);

    amountEdit = new QLineEdit(this);
    amountEdit->setPlaceholderText(tr("Enter amount in sats (e.g., 50000)"));
    layout->addWidget(amountEdit);

    btcEquivLabel = new QLabel(this);
    btcEquivLabel->setStyleSheet(QStringLiteral("QLabel { color: #666666; }"));
    layout->addWidget(btcEquivLabel);

    validationLabel = new QLabel(this);
    layout->addWidget(validationLabel);

    layout->addStretch();

    connect(amountEdit, &QLineEdit::textChanged, this, &AmountPage::onAmountChanged);
}

void AmountPage::initializePage()
{
    m_valid = false;
    amountEdit->clear();
    btcEquivLabel->clear();
    validationLabel->clear();

    // Show available balance
    if (l2WalletModel) {
        GhostPay::L2Balance bal = l2WalletModel->getTotalBalance();
        balanceLabel->setText(tr("Available L2 Balance: %1")
            .arg(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, bal.available, false, BitcoinUnits::SeparatorStyle::ALWAYS)));
    } else {
        balanceLabel->setText(tr("Available L2 Balance: Unknown"));
    }

    Q_EMIT completeChanged();
}

void AmountPage::onAmountChanged()
{
    QString text = amountEdit->text().trimmed();
    if (text.isEmpty()) {
        btcEquivLabel->clear();
        validationLabel->clear();
        m_valid = false;
        Q_EMIT completeChanged();
        return;
    }

    bool ok;
    int64_t sats = text.toLongLong(&ok);

    if (!ok || sats <= 0) {
        btcEquivLabel->clear();
        validationLabel->setText(tr("Please enter a valid positive number"));
        validationLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));
        m_valid = false;
        Q_EMIT completeChanged();
        return;
    }

    // Show BTC equivalent
    btcEquivLabel->setText(tr("= %1")
        .arg(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, sats, false, BitcoinUnits::SeparatorStyle::ALWAYS)));

    // Check against available balance
    int64_t available = 0;
    if (l2WalletModel) {
        GhostPay::L2Balance bal = l2WalletModel->getTotalBalance();
        available = bal.available;
    }

    if (sats > available && available > 0) {
        validationLabel->setText(tr("Amount exceeds available balance"));
        validationLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));
        m_valid = false;
    } else if (sats < 546) {
        validationLabel->setText(tr("Amount is below dust threshold (546 sats)"));
        validationLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));
        m_valid = false;
    } else {
        validationLabel->setText(tr("Valid amount"));
        validationLabel->setStyleSheet(QStringLiteral("QLabel { color: green; }"));
        m_valid = true;
    }

    Q_EMIT completeChanged();
}

bool AmountPage::validatePage()
{
    SendL2Wizard *wiz = qobject_cast<SendL2Wizard*>(wizard());
    if (wiz) {
        wiz->setAmountSats(amountSats());
    }
    return m_valid;
}

int AmountPage::nextId() const
{
    return SendL2Wizard::Page_Memo;
}

bool AmountPage::isComplete() const
{
    return m_valid;
}

int64_t AmountPage::amountSats() const
{
    bool ok;
    int64_t sats = amountEdit->text().trimmed().toLongLong(&ok);
    return ok ? sats : 0;
}

// ===== MemoPage =====

MemoPage::MemoPage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Memo (Optional)"));
    setSubTitle(tr("Add an optional memo to your payment. The recipient will see this message."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    QLabel *memoPrompt = new QLabel(tr("Memo:"), this);
    layout->addWidget(memoPrompt);

    memoEdit = new QLineEdit(this);
    memoEdit->setPlaceholderText(tr("e.g., Coffee, Invoice #123, Thanks!"));
    memoEdit->setMaxLength(59);
    layout->addWidget(memoEdit);

    charCountLabel = new QLabel(tr("0 / 59 characters"), this);
    charCountLabel->setStyleSheet(QStringLiteral("QLabel { color: #666666; }"));
    layout->addWidget(charCountLabel);

    hintLabel = new QLabel(tr(
        "Memos are optional and limited to 59 characters.\n"
        "They are encrypted and only visible to you and the recipient.\n\n"
        "Leave empty to skip."
    ), this);
    hintLabel->setWordWrap(true);
    hintLabel->setStyleSheet(QStringLiteral("QLabel { color: #666666; }"));
    layout->addWidget(hintLabel);

    layout->addStretch();

    connect(memoEdit, &QLineEdit::textChanged, this, &MemoPage::onMemoChanged);
}

void MemoPage::initializePage()
{
    memoEdit->clear();
    charCountLabel->setText(tr("0 / 59 characters"));
}

void MemoPage::onMemoChanged()
{
    int len = memoEdit->text().length();
    charCountLabel->setText(tr("%1 / 59 characters").arg(len));

    if (len >= 55) {
        charCountLabel->setStyleSheet(QStringLiteral("QLabel { color: #cc6600; }"));
    } else {
        charCountLabel->setStyleSheet(QStringLiteral("QLabel { color: #666666; }"));
    }
}

bool MemoPage::validatePage()
{
    SendL2Wizard *wiz = qobject_cast<SendL2Wizard*>(wizard());
    if (wiz) {
        wiz->setMemo(memo());
    }
    return true;
}

int MemoPage::nextId() const
{
    return SendL2Wizard::Page_Confirm;
}

QString MemoPage::memo() const
{
    return memoEdit->text().trimmed();
}

// ===== SendL2ConfirmPage =====

SendL2ConfirmPage::SendL2ConfirmPage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Confirm Payment"));
    setSubTitle(tr("Review the payment details before sending."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    QGridLayout *detailsGrid = new QGridLayout();

    detailsGrid->addWidget(new QLabel(tr("Recipient:"), this), 0, 0);
    recipientLabel = new QLabel(this);
    recipientLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    recipientLabel->setWordWrap(true);
    detailsGrid->addWidget(recipientLabel, 0, 1);

    detailsGrid->addWidget(new QLabel(tr("Amount:"), this), 1, 0);
    amountLabel = new QLabel(this);
    amountLabel->setStyleSheet(QStringLiteral("QLabel { font-weight: bold; }"));
    detailsGrid->addWidget(amountLabel, 1, 1);

    detailsGrid->addWidget(new QLabel(tr("Memo:"), this), 2, 0);
    memoLabel = new QLabel(this);
    memoLabel->setWordWrap(true);
    detailsGrid->addWidget(memoLabel, 2, 1);

    layout->addLayout(detailsGrid);

    layout->addSpacing(20);

    statusLabel = new QLabel(this);
    statusLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(statusLabel);

    progressBar = new QProgressBar(this);
    progressBar->setRange(0, 0);
    progressBar->setVisible(false);
    layout->addWidget(progressBar);

    layout->addStretch();
}

void SendL2ConfirmPage::initializePage()
{
    m_submitted = false;
    m_complete = false;
    m_error.clear();
    statusLabel->clear();
    statusLabel->setStyleSheet(QString());
    progressBar->setVisible(false);

    SendL2Wizard *wiz = qobject_cast<SendL2Wizard*>(wizard());
    if (!wiz) return;

    recipientLabel->setText(wiz->recipient());
    amountLabel->setText(tr("%1 sats (%2)")
        .arg(wiz->amountSats())
        .arg(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, wiz->amountSats(), false, BitcoinUnits::SeparatorStyle::ALWAYS)));

    QString memo = wiz->memo();
    memoLabel->setText(memo.isEmpty() ? tr("(none)") : memo);
}

bool SendL2ConfirmPage::validatePage()
{
    if (m_complete) return true;

    if (!m_submitted) {
        m_submitted = true;
        statusLabel->setText(tr("Sending payment..."));
        progressBar->setVisible(true);

        SendL2Wizard *wiz = qobject_cast<SendL2Wizard*>(wizard());
        if (!wiz || !wiz->getL2WalletModel() || !wiz->getL2WalletModel()->client()
            || !wiz->getL2WalletModel()->client()->isConfigured()) {
            onError(tr("Ghost Pay node not connected"));
            return false;
        }

        // POST /api/v1/payments/send via QNetworkAccessManager
        QNetworkAccessManager *nam = new QNetworkAccessManager(this);
        QNetworkRequest request(QUrl(QStringLiteral("http://127.0.0.1:8800/api/v1/payments/send")));
        request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

        QJsonObject body;
        body[QStringLiteral("recipient")] = wiz->recipient();
        body[QStringLiteral("amount_sats")] = static_cast<double>(wiz->amountSats());
        if (!wiz->memo().isEmpty()) {
            body[QStringLiteral("memo")] = wiz->memo();
        }

        QByteArray payload = QJsonDocument(body).toJson(QJsonDocument::Compact);
        QNetworkReply *reply = nam->post(request, payload);
        connect(reply, &QNetworkReply::finished, this, [this, reply, nam]() {
            reply->deleteLater();
            nam->deleteLater();

            if (reply->error() != QNetworkReply::NoError) {
                SendL2Wizard *w = qobject_cast<SendL2Wizard*>(wizard());
                if (w) w->onPaymentError(reply->errorString());
                return;
            }

            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QJsonObject obj = doc.object();
            QString paymentId = obj[QStringLiteral("payment_id")].toString();

            SendL2Wizard *w = qobject_cast<SendL2Wizard*>(wizard());
            if (w) w->onPaymentSent(paymentId);
        });

        return false;  // Wait for async response
    }

    return m_complete && m_error.isEmpty();
}

void SendL2ConfirmPage::onSent(const QString& paymentId)
{
    Q_UNUSED(paymentId)
    m_complete = true;
    progressBar->setVisible(false);
    statusLabel->setText(tr("Payment sent successfully!"));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { color: green; }"));

    Q_EMIT completeChanged();
}

void SendL2ConfirmPage::onError(const QString& error)
{
    m_error = error;
    m_submitted = false;
    progressBar->setVisible(false);
    statusLabel->setText(tr("Error: %1").arg(error));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));

    Q_EMIT completeChanged();
}

int SendL2ConfirmPage::nextId() const
{
    return m_complete ? SendL2Wizard::Page_Complete : -1;
}

bool SendL2ConfirmPage::isComplete() const
{
    return m_complete;
}

// ===== SendL2CompletePage =====

SendL2CompletePage::SendL2CompletePage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Payment Sent"));
    setSubTitle(tr("Your L2 payment has been successfully submitted."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    successLabel = new QLabel(this);
    successLabel->setAlignment(Qt::AlignCenter);
    successLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 18pt; color: green; }"));
    successLabel->setText(tr("Success!"));
    layout->addWidget(successLabel);

    layout->addSpacing(20);

    QGridLayout *detailsGrid = new QGridLayout();

    detailsGrid->addWidget(new QLabel(tr("Payment ID:"), this), 0, 0);
    paymentIdLabel = new QLabel(this);
    paymentIdLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    paymentIdLabel->setWordWrap(true);
    detailsGrid->addWidget(paymentIdLabel, 0, 1);

    detailsGrid->addWidget(new QLabel(tr("Recipient:"), this), 1, 0);
    recipientLabel = new QLabel(this);
    recipientLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    recipientLabel->setWordWrap(true);
    detailsGrid->addWidget(recipientLabel, 1, 1);

    detailsGrid->addWidget(new QLabel(tr("Amount:"), this), 2, 0);
    amountLabel = new QLabel(this);
    detailsGrid->addWidget(amountLabel, 2, 1);

    detailsGrid->addWidget(new QLabel(tr("Memo:"), this), 3, 0);
    memoLabel = new QLabel(this);
    memoLabel->setWordWrap(true);
    detailsGrid->addWidget(memoLabel, 3, 1);

    layout->addLayout(detailsGrid);

    layout->addSpacing(20);

    infoLabel = new QLabel(tr(
        "Your L2 payment has been submitted and will be confirmed in the next L2 block.\n"
        "L2 payments are instant and private.\n\n"
        "You can view payment status from the Ghost Pay transactions page."
    ), this);
    infoLabel->setWordWrap(true);
    infoLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(infoLabel);

    layout->addStretch();
}

void SendL2CompletePage::initializePage()
{
    SendL2Wizard *wiz = qobject_cast<SendL2Wizard*>(wizard());
    if (!wiz) return;

    paymentIdLabel->setText(wiz->paymentId());
    recipientLabel->setText(wiz->recipient());
    amountLabel->setText(tr("%1 sats (%2)")
        .arg(wiz->amountSats())
        .arg(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, wiz->amountSats(), false, BitcoinUnits::SeparatorStyle::ALWAYS)));

    QString memo = wiz->memo();
    memoLabel->setText(memo.isEmpty() ? tr("(none)") : memo);

    Q_EMIT wiz->operationComplete(wiz->paymentId());
}

int SendL2CompletePage::nextId() const
{
    return -1;  // End of wizard
}
