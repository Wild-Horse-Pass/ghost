// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/sendl2dialog.h>
#include <qt/l2walletmodel.h>
#include <qt/walletmodel.h>
#include <qt/guiutil.h>

#include <interfaces/wallet.h>
#include <key_io.h>
#include <util/strencodings.h>

#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QVBoxLayout>

SendL2Dialog::SendL2Dialog(WalletModel* walletModel, L2WalletModel* l2Model, QWidget* parent)
    : QDialog(parent, GUIUtil::dialog_flags)
    , m_walletModel(walletModel)
    , m_l2Model(l2Model)
{
    setWindowTitle(tr("Send L2 Payment"));
    setMinimumWidth(500);

    auto* mainLayout = new QVBoxLayout(this);

    // Source lock selector
    auto* sourceGroup = new QGroupBox(tr("Source Lock"), this);
    auto* sourceLayout = new QVBoxLayout(sourceGroup);

    m_lockSelector = new QComboBox(this);
    m_lockSelector->setMinimumWidth(400);
    sourceLayout->addWidget(m_lockSelector);

    m_lockBalanceLabel = new QLabel(tr("Available: --"), this);
    sourceLayout->addWidget(m_lockBalanceLabel);
    mainLayout->addWidget(sourceGroup);

    // Payment details
    auto* detailsGroup = new QGroupBox(tr("Payment Details"), this);
    auto* formLayout = new QFormLayout(detailsGroup);

    m_recipientInput = new QLineEdit(this);
    m_recipientInput->setPlaceholderText(tr("ghost1... or sghost1... (recipient Ghost ID)"));
    formLayout->addRow(tr("Recipient:"), m_recipientInput);

    m_amountInput = new QLineEdit(this);
    m_amountInput->setPlaceholderText(tr("Amount in satoshis"));
    formLayout->addRow(tr("Amount (sats):"), m_amountInput);

    mainLayout->addWidget(detailsGroup);

    // Summary
    m_summaryLabel = new QLabel(this);
    m_summaryLabel->setWordWrap(true);
    mainLayout->addWidget(m_summaryLabel);

    // Progress and status
    m_progress = new QProgressBar(this);
    m_progress->setVisible(false);
    m_progress->setRange(0, 0); // indeterminate
    mainLayout->addWidget(m_progress);

    m_statusLabel = new QLabel(this);
    m_statusLabel->setVisible(false);
    mainLayout->addWidget(m_statusLabel);

    // Buttons
    auto* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();

    m_cancelButton = new QPushButton(tr("Cancel"), this);
    buttonLayout->addWidget(m_cancelButton);

    m_sendButton = new QPushButton(tr("Send Payment"), this);
    m_sendButton->setEnabled(false);
    m_sendButton->setDefault(true);
    buttonLayout->addWidget(m_sendButton);

    mainLayout->addLayout(buttonLayout);

    // Connections
    connect(m_lockSelector, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SendL2Dialog::onLockSelectionChanged);
    connect(m_sendButton, &QPushButton::clicked, this, &SendL2Dialog::onSendClicked);
    connect(m_cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    connect(m_recipientInput, &QLineEdit::textChanged, this, [this]{ validateInputs(); });
    connect(m_amountInput, &QLineEdit::textChanged, this, [this]{ validateInputs(); });

    // L2 model signals
    connect(m_l2Model, &L2WalletModel::paymentSent, this, &SendL2Dialog::onPaymentSent);
    connect(m_l2Model, &L2WalletModel::paymentError, this, &SendL2Dialog::onPaymentError);

    populateLocks();
}

SendL2Dialog::~SendL2Dialog() = default;

void SendL2Dialog::populateLocks()
{
    m_lockSelector->clear();
    m_lockAddresses.clear();

    auto* locksModel = m_l2Model->locksModel();
    for (int i = 0; i < locksModel->rowCount(); ++i) {
        const auto* lock = locksModel->getLock(i);
        if (!lock) continue;
        // Only show locks that can send payments
        if (!GhostPay::stateAllowsL2Activity(lock->state)) continue;

        QString label = QString("%1 | %2 | %3 sats")
            .arg(lock->lockId.left(12) + "...")
            .arg(GhostPay::denominationName(lock->denomination))
            .arg(lock->l2Balance);

        m_lockSelector->addItem(label, lock->lockId);

        // Store the lockPubkey as the address for signing
        m_lockAddresses[lock->lockId] = lock->lockPubkey;
    }

    if (m_lockSelector->count() == 0) {
        m_lockSelector->addItem(tr("No active locks available"));
        m_sendButton->setEnabled(false);
    }
}

void SendL2Dialog::onLockSelectionChanged(int index)
{
    if (index < 0 || index >= m_lockSelector->count()) {
        m_lockBalanceLabel->setText(tr("Available: --"));
        return;
    }

    QString lockId = m_lockSelector->currentData().toString();
    const auto* lock = m_l2Model->locksModel()->getLockById(lockId);
    if (lock) {
        m_lockBalanceLabel->setText(tr("Available: %1 sats").arg(lock->l2Balance));
    }

    validateInputs();
}

void SendL2Dialog::validateInputs()
{
    bool valid = true;

    // Check lock selection
    QString lockId = m_lockSelector->currentData().toString();
    if (lockId.isEmpty()) valid = false;

    // Check recipient (must start with ghost1/sghost1/tghost1/rghost1)
    QString recipient = m_recipientInput->text().trimmed();
    if (recipient.isEmpty() ||
        !(recipient.startsWith("ghost1") || recipient.startsWith("sghost1") ||
          recipient.startsWith("tghost1") || recipient.startsWith("rghost1"))) {
        valid = false;
    }

    // Check amount
    bool amountOk = false;
    int64_t amount = m_amountInput->text().toLongLong(&amountOk);
    if (!amountOk || amount <= 0) valid = false;

    // Check sufficient balance
    if (valid) {
        const auto* lock = m_l2Model->locksModel()->getLockById(lockId);
        if (!lock || lock->l2Balance < amount) {
            valid = false;
        }
    }

    // Update summary
    if (valid) {
        m_summaryLabel->setText(
            tr("Send %1 sats from lock %2 to %3")
                .arg(amount)
                .arg(lockId.left(12) + "...")
                .arg(recipient.left(20) + "..."));
    } else {
        m_summaryLabel->setText(QString());
    }

    m_sendButton->setEnabled(valid);
}

void SendL2Dialog::onSendClicked()
{
    QString lockId = m_lockSelector->currentData().toString();
    QString recipient = m_recipientInput->text().trimmed();
    int64_t amount = m_amountInput->text().toLongLong();

    // Confirm
    auto reply = QMessageBox::question(this, tr("Confirm Payment"),
        tr("Send %1 sats to %2?\n\nThis action cannot be reversed.")
            .arg(amount).arg(recipient),
        QMessageBox::Yes | QMessageBox::No);

    if (reply != QMessageBox::Yes) return;

    // Sign the payment
    QString signature = signPaymentMessage(lockId, recipient, amount);
    if (signature.isEmpty()) {
        QMessageBox::critical(this, tr("Signing Error"),
            tr("Failed to sign the payment. Ensure the wallet is unlocked."));
        return;
    }

    // Disable UI during send
    m_sendButton->setEnabled(false);
    m_cancelButton->setEnabled(false);
    m_progress->setVisible(true);
    m_statusLabel->setText(tr("Submitting payment..."));
    m_statusLabel->setVisible(true);

    // Submit via Ghost Pay client
    m_l2Model->client()->submitPayment(lockId, recipient, amount, signature);
}

QString SendL2Dialog::signPaymentMessage(const QString& fromLockId, const QString& toGhostId, int64_t amount)
{
    // Build canonical message for signing: "ghost-l2-payment:{fromLockId}:{toGhostId}:{amount}"
    std::string message = "ghost-l2-payment:" +
        fromLockId.toStdString() + ":" +
        toGhostId.toStdString() + ":" +
        std::to_string(amount);

    // Look up the address associated with this lock
    QString lockPubkey = m_lockAddresses.value(fromLockId);
    if (lockPubkey.isEmpty()) {
        return {};
    }

    // Try to sign with the wallet's key for this lock's pubkey
    // The lock pubkey was derived from a wallet key at registration time
    CTxDestination dest = DecodeDestination(lockPubkey.toStdString());
    if (!IsValidDestination(dest)) {
        // Try interpreting as raw hex pubkey → derive the PKHash
        auto pubkey_bytes = ParseHex(lockPubkey.toStdString());
        if (pubkey_bytes.size() == 33 || pubkey_bytes.size() == 65) {
            CPubKey pubkey(pubkey_bytes);
            if (pubkey.IsValid()) {
                dest = PKHash(pubkey);
            }
        }
    }

    const PKHash* pkhash = std::get_if<PKHash>(&dest);
    if (!pkhash) return {};

    std::string signature;
    auto result = m_walletModel->wallet().signMessage(message, *pkhash, signature);
    if (result != SigningResult::OK) {
        return {};
    }

    return QString::fromStdString(signature);
}

void SendL2Dialog::onPaymentSent(const QString& paymentId)
{
    m_progress->setVisible(false);
    m_statusLabel->setText(tr("Payment sent! ID: %1").arg(paymentId.left(16) + "..."));
    m_sendButton->setVisible(false);
    m_cancelButton->setText(tr("Close"));
    m_cancelButton->setEnabled(true);
}

void SendL2Dialog::onPaymentError(const QString& error)
{
    m_progress->setVisible(false);
    m_statusLabel->setText(tr("Payment failed: %1").arg(error));
    m_statusLabel->setStyleSheet("color: red;");
    m_sendButton->setEnabled(true);
    m_cancelButton->setEnabled(true);
}
