// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/withdrawwizard.h>

#include <qt/bitcoinunits.h>
#include <qt/ghostaddressvalidator.h>
#include <qt/guiutil.h>
#include <qt/l2walletmodel.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <interfaces/wallet.h>
#include <key_io.h>
#include <outputtype.h>

#include <QButtonGroup>
#include <QComboBox>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QRadioButton>
#include <QTableView>
#include <QVBoxLayout>

// ===== WithdrawWizard =====

WithdrawWizard::WithdrawWizard(const PlatformStyle *_platformStyle,
                               WalletModel *_walletModel,
                               L2WalletModel *_l2WalletModel,
                               QWidget *parent)
    : QWizard(parent),
      walletModel(_walletModel),
      l2WalletModel(_l2WalletModel),
      platformStyle(_platformStyle)
{
    setWindowTitle(tr("Withdraw from Ghost Pay"));
    setWizardStyle(QWizard::ModernStyle);
    setOption(QWizard::NoBackButtonOnStartPage);

    // Add pages
    setPage(Page_SelectLock, new SelectLockPage(l2WalletModel, this));
    setPage(Page_SelectMode, new SelectModePage(this));
    setPage(Page_Configure, new ConfigurePage(walletModel, this));
    setPage(Page_Confirm, new ConfirmPage(this));
    setPage(Page_Processing, new ProcessingPage(l2WalletModel, this));
    setPage(Page_Complete, new WithdrawCompletePage(this));

    setStartId(Page_SelectLock);

    // Connect L2 model signals
    if (l2WalletModel) {
        connect(l2WalletModel, &L2WalletModel::withdrawalRequested, this, &WithdrawWizard::onWithdrawalRequested);
        connect(l2WalletModel, &L2WalletModel::withdrawalComplete, this, &WithdrawWizard::onWithdrawalComplete);
        connect(l2WalletModel, &L2WalletModel::withdrawalError, this, &WithdrawWizard::onWithdrawalError);
    }

    connect(this, &QWizard::rejected, this, &WithdrawWizard::withdrawalCancelled);
}

void WithdrawWizard::setSelectedLock(const QString& lockId)
{
    m_lockId = lockId;
}

void WithdrawWizard::setLockId(const QString& lockId)
{
    m_lockId = lockId;
}

void WithdrawWizard::setMode(WithdrawMode mode)
{
    m_mode = mode;
}

void WithdrawWizard::setDestination(const QString& address)
{
    m_destination = address;
}

void WithdrawWizard::onWithdrawalRequested(const QString& batchId)
{
    m_batchId = batchId;
    ProcessingPage* procPage = qobject_cast<ProcessingPage*>(page(Page_Processing));
    if (procPage) {
        procPage->onRequested(batchId);
    }
}

void WithdrawWizard::onWithdrawalComplete(const QString& lockId, const QString& txid)
{
    if (lockId != m_lockId) return;

    m_resultTxid = txid;
    ProcessingPage* procPage = qobject_cast<ProcessingPage*>(page(Page_Processing));
    if (procPage) {
        procPage->onComplete(lockId, txid);
    }
}

void WithdrawWizard::onWithdrawalError(const QString& error)
{
    ProcessingPage* procPage = qobject_cast<ProcessingPage*>(page(Page_Processing));
    if (procPage && currentId() == Page_Processing) {
        procPage->onError(error);
    }
}

// ===== SelectLockPage =====

SelectLockPage::SelectLockPage(L2WalletModel *_l2WalletModel, QWidget *parent)
    : QWizardPage(parent),
      l2WalletModel(_l2WalletModel)
{
    setTitle(tr("Select Ghost Lock"));
    setSubTitle(tr("Choose which Ghost Lock to withdraw from."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    locksTable = new QTableView(this);
    locksTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    locksTable->setSelectionMode(QAbstractItemView::SingleSelection);
    locksTable->verticalHeader()->hide();
    locksTable->setShowGrid(false);
    locksTable->setAlternatingRowColors(true);
    layout->addWidget(locksTable);

    QHBoxLayout *infoLayout = new QHBoxLayout();
    selectedLabel = new QLabel(tr("No lock selected"), this);
    infoLayout->addWidget(selectedLabel);
    infoLayout->addStretch();
    balanceLabel = new QLabel(this);
    balanceLabel->setStyleSheet(QStringLiteral("QLabel { font-weight: bold; }"));
    infoLayout->addWidget(balanceLabel);
    layout->addLayout(infoLayout);

    connect(locksTable, &QTableView::clicked, this, &SelectLockPage::onLockSelected);
}

void SelectLockPage::initializePage()
{
    if (l2WalletModel && l2WalletModel->locksModel()) {
        locksTable->setModel(l2WalletModel->locksModel());
        locksTable->horizontalHeader()->setSectionResizeMode(GhostLocksModel::LockId, QHeaderView::Stretch);
        locksTable->horizontalHeader()->setSectionResizeMode(GhostLocksModel::Denomination, QHeaderView::ResizeToContents);
        locksTable->horizontalHeader()->setSectionResizeMode(GhostLocksModel::L2Balance, QHeaderView::ResizeToContents);
        locksTable->horizontalHeader()->setSectionResizeMode(GhostLocksModel::State, QHeaderView::ResizeToContents);
    }

    // Check if lock was pre-selected
    WithdrawWizard *wiz = qobject_cast<WithdrawWizard*>(wizard());
    if (wiz && !wiz->selectedLockId().isEmpty()) {
        selectedLabel->setText(tr("Pre-selected: %1").arg(wiz->selectedLockId().left(16) + QStringLiteral("...")));
    }
}

void SelectLockPage::onLockSelected()
{
    QModelIndexList selection = locksTable->selectionModel()->selectedRows();
    if (selection.isEmpty()) {
        m_selectedRow = -1;
        selectedLabel->setText(tr("No lock selected"));
        balanceLabel->clear();
        return;
    }

    m_selectedRow = selection.first().row();

    if (l2WalletModel && l2WalletModel->locksModel()) {
        const GhostPay::GhostLockInfo* lock = l2WalletModel->locksModel()->getLock(m_selectedRow);
        if (lock) {
            selectedLabel->setText(tr("Selected: %1").arg(lock->lockId.left(16) + QStringLiteral("...")));
            balanceLabel->setText(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, lock->l2Balance, false, BitcoinUnits::SeparatorStyle::ALWAYS));
        }
    }

    Q_EMIT completeChanged();
}

bool SelectLockPage::validatePage()
{
    WithdrawWizard *wiz = qobject_cast<WithdrawWizard*>(wizard());
    if (wiz) {
        wiz->setLockId(selectedLockId());
    }
    return true;
}

int SelectLockPage::nextId() const
{
    return WithdrawWizard::Page_SelectMode;
}

bool SelectLockPage::isComplete() const
{
    WithdrawWizard *wiz = qobject_cast<WithdrawWizard*>(wizard());
    if (wiz && !wiz->selectedLockId().isEmpty()) {
        return true;
    }
    return m_selectedRow >= 0;
}

QString SelectLockPage::selectedLockId() const
{
    WithdrawWizard *wiz = qobject_cast<WithdrawWizard*>(wizard());
    if (wiz && !wiz->selectedLockId().isEmpty()) {
        return wiz->selectedLockId();
    }

    if (m_selectedRow >= 0 && l2WalletModel && l2WalletModel->locksModel()) {
        const GhostPay::GhostLockInfo* lock = l2WalletModel->locksModel()->getLock(m_selectedRow);
        if (lock) {
            return lock->lockId;
        }
    }
    return QString();
}

// ===== SelectModePage =====

SelectModePage::SelectModePage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Select Withdrawal Mode"));
    setSubTitle(tr("Choose how you want to withdraw your funds."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    modeGroup = new QButtonGroup(this);

    // Exit mode
    exitButton = new QRadioButton(tr("Exit - Withdraw to L1 address"), this);
    exitButton->setChecked(true);
    modeGroup->addButton(exitButton, static_cast<int>(WithdrawWizard::Mode_Exit));
    layout->addWidget(exitButton);

    exitInfoLabel = new QLabel(tr("Settle your Ghost Lock to a Bitcoin address on Layer 1. "
                                   "Your funds will be available after the settlement batch is confirmed."), this);
    exitInfoLabel->setWordWrap(true);
    exitInfoLabel->setStyleSheet(QStringLiteral("QLabel { color: #666666; margin-left: 20px; margin-bottom: 10px; }"));
    layout->addWidget(exitInfoLabel);

    // Rotate mode
    rotateButton = new QRadioButton(tr("Rotate - Create new lock with fresh keys"), this);
    modeGroup->addButton(rotateButton, static_cast<int>(WithdrawWizard::Mode_Rotate));
    layout->addWidget(rotateButton);

    rotateInfoLabel = new QLabel(tr("Create a new Ghost Lock with fresh cryptographic keys. "
                                     "Recommended for long-term holdings to maintain key hygiene."), this);
    rotateInfoLabel->setWordWrap(true);
    rotateInfoLabel->setStyleSheet(QStringLiteral("QLabel { color: #666666; margin-left: 20px; margin-bottom: 10px; }"));
    layout->addWidget(rotateInfoLabel);

    // Jump mode
    jumpButton = new QRadioButton(tr("Jump - Emergency key rotation"), this);
    modeGroup->addButton(jumpButton, static_cast<int>(WithdrawWizard::Mode_Jump));
    layout->addWidget(jumpButton);

    jumpInfoLabel = new QLabel(tr("Emergency option for when you believe your keys may be compromised. "
                                   "Higher fees but immediate queue priority."), this);
    jumpInfoLabel->setWordWrap(true);
    jumpInfoLabel->setStyleSheet(QStringLiteral("QLabel { color: #666666; margin-left: 20px; }"));
    layout->addWidget(jumpInfoLabel);

    layout->addStretch();

    connect(modeGroup, &QButtonGroup::idClicked, this, &SelectModePage::onModeChanged);
}

void SelectModePage::initializePage()
{
    onModeChanged();
}

void SelectModePage::onModeChanged()
{
    // Could update UI based on mode selection
}

bool SelectModePage::validatePage()
{
    WithdrawWizard *wiz = qobject_cast<WithdrawWizard*>(wizard());
    if (wiz) {
        wiz->setMode(selectedMode());
    }
    return true;
}

int SelectModePage::nextId() const
{
    return WithdrawWizard::Page_Configure;
}

WithdrawWizard::WithdrawMode SelectModePage::selectedMode() const
{
    return static_cast<WithdrawWizard::WithdrawMode>(modeGroup->checkedId());
}

// ===== ConfigurePage =====

ConfigurePage::ConfigurePage(WalletModel *_walletModel, QWidget *parent)
    : QWizardPage(parent),
      walletModel(_walletModel)
{
    setTitle(tr("Configure Withdrawal"));
    setSubTitle(tr("Enter the destination for your funds."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    instructionLabel = new QLabel(this);
    instructionLabel->setWordWrap(true);
    layout->addWidget(instructionLabel);

    layout->addSpacing(10);

    QHBoxLayout *addressLayout = new QHBoxLayout();
    QLabel *addressLabel = new QLabel(tr("Destination Address:"), this);
    addressLayout->addWidget(addressLabel);
    addressEdit = new QLineEdit(this);
    addressEdit->setPlaceholderText(tr("Enter a Ghost address..."));
    addressLayout->addWidget(addressEdit, 1);
    newAddressButton = new QPushButton(tr("New Address"), this);
    addressLayout->addWidget(newAddressButton);
    layout->addLayout(addressLayout);

    validationLabel = new QLabel(this);
    validationLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));
    layout->addWidget(validationLabel);

    layout->addSpacing(10);

    QHBoxLayout *settlementLayout = new QHBoxLayout();
    QLabel *settlementLabel = new QLabel(tr("Settlement Class:"), this);
    settlementLayout->addWidget(settlementLabel);
    settlementClassCombo = new QComboBox(this);
    settlementClassCombo->addItem(tr("Standard (lower fee, may take longer)"), 0);
    settlementClassCombo->addItem(tr("Priority (higher fee, faster)"), 1);
    settlementLayout->addWidget(settlementClassCombo, 1);
    layout->addLayout(settlementLayout);

    layout->addStretch();

    connect(addressEdit, &QLineEdit::textChanged, this, &ConfigurePage::onAddressChanged);
    connect(newAddressButton, &QPushButton::clicked, this, &ConfigurePage::onUseNewAddress);
}

void ConfigurePage::initializePage()
{
    WithdrawWizard *wiz = qobject_cast<WithdrawWizard*>(wizard());
    WithdrawWizard::WithdrawMode mode = wiz ? wiz->selectedMode() : WithdrawWizard::Mode_Exit;

    switch (mode) {
    case WithdrawWizard::Mode_Exit:
        instructionLabel->setText(tr("Enter the Bitcoin address where you want to receive your funds. "
                                      "The funds will be sent to this address after the settlement batch confirms."));
        addressEdit->setVisible(true);
        newAddressButton->setVisible(true);
        settlementClassCombo->setVisible(true);
        break;

    case WithdrawWizard::Mode_Rotate:
        instructionLabel->setText(tr("A new Ghost Lock will be created with fresh keys derived from your wallet. "
                                      "Your L2 balance will be transferred to the new lock."));
        addressEdit->setVisible(false);
        newAddressButton->setVisible(false);
        settlementClassCombo->setVisible(false);
        m_addressValid = true;  // No address needed
        break;

    case WithdrawWizard::Mode_Jump:
        instructionLabel->setText(tr("Emergency key rotation will immediately queue your lock for rotation "
                                      "with higher priority. A new lock will be created with fresh keys."));
        addressEdit->setVisible(false);
        newAddressButton->setVisible(false);
        settlementClassCombo->setVisible(false);
        m_addressValid = true;  // No address needed
        break;
    }

    Q_EMIT completeChanged();
}

void ConfigurePage::onAddressChanged()
{
    QString address = addressEdit->text().trimmed();
    if (address.isEmpty()) {
        validationLabel->clear();
        m_addressValid = false;
        Q_EMIT completeChanged();
        return;
    }

    if (IsValidDestinationString(address.toStdString())) {
        validationLabel->setText(tr("Valid address"));
        validationLabel->setStyleSheet(QStringLiteral("QLabel { color: green; }"));
        m_addressValid = true;
    } else {
        validationLabel->setText(tr("Invalid address"));
        validationLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));
        m_addressValid = false;
    }

    Q_EMIT completeChanged();
}

void ConfigurePage::onUseNewAddress()
{
    if (!walletModel) return;

    auto dest = walletModel->wallet().getNewDestination(
        OutputType::BECH32M, "Ghost Lock Settlement");
    if (dest) {
        addressEdit->setText(QString::fromStdString(EncodeDestination(*dest)));
    } else {
        validationLabel->setText(tr("Failed to generate address from wallet"));
        validationLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));
    }
}

bool ConfigurePage::validatePage()
{
    WithdrawWizard *wiz = qobject_cast<WithdrawWizard*>(wizard());
    if (wiz) {
        wiz->setDestination(destinationAddress());
    }
    return true;
}

int ConfigurePage::nextId() const
{
    return WithdrawWizard::Page_Confirm;
}

bool ConfigurePage::isComplete() const
{
    return m_addressValid;
}

QString ConfigurePage::destinationAddress() const
{
    return addressEdit->text().trimmed();
}

// ===== ConfirmPage =====

ConfirmPage::ConfirmPage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Confirm Withdrawal"));
    setSubTitle(tr("Review the details before confirming."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    summaryLabel = new QLabel(tr("Please verify the withdrawal details:"), this);
    layout->addWidget(summaryLabel);

    layout->addSpacing(10);

    QGridLayout *detailsGrid = new QGridLayout();

    detailsGrid->addWidget(new QLabel(tr("Ghost Lock:"), this), 0, 0);
    lockIdLabel = new QLabel(this);
    lockIdLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    detailsGrid->addWidget(lockIdLabel, 0, 1);

    detailsGrid->addWidget(new QLabel(tr("Mode:"), this), 1, 0);
    modeLabel = new QLabel(this);
    detailsGrid->addWidget(modeLabel, 1, 1);

    detailsGrid->addWidget(new QLabel(tr("Destination:"), this), 2, 0);
    destinationLabel = new QLabel(this);
    destinationLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    destinationLabel->setWordWrap(true);
    detailsGrid->addWidget(destinationLabel, 2, 1);

    detailsGrid->addWidget(new QLabel(tr("Current Balance:"), this), 3, 0);
    balanceLabel = new QLabel(this);
    detailsGrid->addWidget(balanceLabel, 3, 1);

    detailsGrid->addWidget(new QLabel(tr("Estimated Fee:"), this), 4, 0);
    feeLabel = new QLabel(this);
    detailsGrid->addWidget(feeLabel, 4, 1);

    detailsGrid->addWidget(new QLabel(tr("You will receive:"), this), 5, 0);
    receiveLabel = new QLabel(this);
    receiveLabel->setStyleSheet(QStringLiteral("QLabel { font-weight: bold; }"));
    detailsGrid->addWidget(receiveLabel, 5, 1);

    layout->addLayout(detailsGrid);

    layout->addStretch();

    QLabel *warningLabel = new QLabel(tr("This action cannot be undone. Make sure the destination address is correct."), this);
    warningLabel->setWordWrap(true);
    warningLabel->setStyleSheet(QStringLiteral("QLabel { color: #cc6600; }"));
    layout->addWidget(warningLabel);
}

void ConfirmPage::initializePage()
{
    WithdrawWizard *wiz = qobject_cast<WithdrawWizard*>(wizard());
    if (!wiz) return;

    lockIdLabel->setText(wiz->selectedLockId());

    QString modeText;
    switch (wiz->selectedMode()) {
    case WithdrawWizard::Mode_Exit:
        modeText = tr("Exit to L1");
        break;
    case WithdrawWizard::Mode_Rotate:
        modeText = tr("Key Rotation");
        break;
    case WithdrawWizard::Mode_Jump:
        modeText = tr("Emergency Jump");
        break;
    }
    modeLabel->setText(modeText);

    if (wiz->selectedMode() == WithdrawWizard::Mode_Exit) {
        destinationLabel->setText(wiz->destinationAddress());
    } else {
        destinationLabel->setText(tr("New Ghost Lock (fresh keys)"));
    }

    // Get balance from lock
    int64_t balance = 0;
    if (wiz->getL2WalletModel() && wiz->getL2WalletModel()->locksModel()) {
        const GhostPay::GhostLockInfo* lock = wiz->getL2WalletModel()->locksModel()->getLockById(wiz->selectedLockId());
        if (lock) {
            balance = lock->l2Balance;
        }
    }

    balanceLabel->setText(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, balance, false, BitcoinUnits::SeparatorStyle::ALWAYS));

    // Estimate fee (placeholder - real implementation would query node)
    int64_t fee = 1000;  // 1000 sats placeholder
    if (wiz->selectedMode() == WithdrawWizard::Mode_Jump) {
        fee = 5000;  // Higher fee for emergency
    }

    feeLabel->setText(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, fee, false, BitcoinUnits::SeparatorStyle::ALWAYS));
    receiveLabel->setText(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, balance - fee, false, BitcoinUnits::SeparatorStyle::ALWAYS));
}

bool ConfirmPage::validatePage()
{
    return true;
}

int ConfirmPage::nextId() const
{
    return WithdrawWizard::Page_Processing;
}

// ===== ProcessingPage =====

ProcessingPage::ProcessingPage(L2WalletModel *_l2WalletModel, QWidget *parent)
    : QWizardPage(parent),
      l2WalletModel(_l2WalletModel)
{
    setTitle(tr("Processing Withdrawal"));
    setSubTitle(tr("Your withdrawal is being processed."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    layout->addStretch();

    statusLabel = new QLabel(tr("Submitting withdrawal request..."), this);
    statusLabel->setAlignment(Qt::AlignCenter);
    statusLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 14pt; }"));
    layout->addWidget(statusLabel);

    layout->addSpacing(20);

    progressBar = new QProgressBar(this);
    progressBar->setRange(0, 0);  // Indeterminate
    layout->addWidget(progressBar);

    layout->addSpacing(10);

    batchIdLabel = new QLabel(this);
    batchIdLabel->setAlignment(Qt::AlignCenter);
    batchIdLabel->setStyleSheet(QStringLiteral("QLabel { color: #666666; }"));
    layout->addWidget(batchIdLabel);

    layout->addStretch();
}

void ProcessingPage::initializePage()
{
    m_complete = false;
    m_error.clear();
    statusLabel->setText(tr("Submitting withdrawal request..."));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 14pt; }"));
    batchIdLabel->clear();
    progressBar->setRange(0, 0);

    WithdrawWizard *wiz = qobject_cast<WithdrawWizard*>(wizard());
    if (!wiz || !l2WalletModel) return;

    l2WalletModel->requestWithdrawal(wiz->selectedLockId(), wiz->destinationAddress());
}

void ProcessingPage::onRequested(const QString& batchId)
{
    statusLabel->setText(tr("Withdrawal queued in batch"));
    batchIdLabel->setText(tr("Batch ID: %1").arg(batchId));
}

void ProcessingPage::onComplete(const QString& lockId, const QString& txid)
{
    Q_UNUSED(lockId)
    m_complete = true;
    statusLabel->setText(tr("Withdrawal Complete!"));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 14pt; color: green; }"));
    progressBar->setRange(0, 100);
    progressBar->setValue(100);
    batchIdLabel->setText(tr("Transaction: %1").arg(txid.left(20) + QStringLiteral("...")));

    Q_EMIT completeChanged();
}

void ProcessingPage::onError(const QString& error)
{
    m_error = error;
    statusLabel->setText(tr("Error: %1").arg(error));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 14pt; color: red; }"));
    progressBar->setRange(0, 100);
    progressBar->setValue(0);
}

bool ProcessingPage::validatePage()
{
    return m_complete && m_error.isEmpty();
}

int ProcessingPage::nextId() const
{
    return m_complete ? WithdrawWizard::Page_Complete : -1;
}

bool ProcessingPage::isComplete() const
{
    return m_complete;
}

// ===== WithdrawCompletePage =====

WithdrawCompletePage::WithdrawCompletePage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Withdrawal Complete"));
    setSubTitle(tr("Your withdrawal has been successfully processed."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    successLabel = new QLabel(this);
    successLabel->setAlignment(Qt::AlignCenter);
    successLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 18pt; color: green; }"));
    successLabel->setText(tr("Success!"));
    layout->addWidget(successLabel);

    layout->addSpacing(20);

    QGridLayout *detailsGrid = new QGridLayout();

    detailsGrid->addWidget(new QLabel(tr("Transaction ID:"), this), 0, 0);
    txidLabel = new QLabel(this);
    txidLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    detailsGrid->addWidget(txidLabel, 0, 1);

    detailsGrid->addWidget(new QLabel(tr("Amount:"), this), 1, 0);
    amountLabel = new QLabel(this);
    detailsGrid->addWidget(amountLabel, 1, 1);

    layout->addLayout(detailsGrid);

    layout->addSpacing(20);

    infoLabel = new QLabel(this);
    infoLabel->setWordWrap(true);
    infoLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(infoLabel);

    layout->addStretch();
}

void WithdrawCompletePage::initializePage()
{
    WithdrawWizard *wiz = qobject_cast<WithdrawWizard*>(wizard());
    if (!wiz) return;

    txidLabel->setText(wiz->resultTxid());

    // Get withdrawal amount
    int64_t amount = 0;
    if (wiz->getL2WalletModel() && wiz->getL2WalletModel()->locksModel()) {
        const GhostPay::GhostLockInfo* lock = wiz->getL2WalletModel()->locksModel()->getLockById(wiz->selectedLockId());
        if (lock) {
            amount = lock->l2Balance;
        }
    }
    amountLabel->setText(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, amount, false, BitcoinUnits::SeparatorStyle::ALWAYS));

    QString info;
    switch (wiz->selectedMode()) {
    case WithdrawWizard::Mode_Exit:
        info = tr("Your funds have been settled to the specified address. "
                  "The transaction should confirm within the next few blocks.");
        break;
    case WithdrawWizard::Mode_Rotate:
        info = tr("Your funds have been moved to a new Ghost Lock with fresh keys. "
                  "You can continue using L2 payments with the new lock.");
        break;
    case WithdrawWizard::Mode_Jump:
        info = tr("Emergency key rotation complete. Your funds are now secured "
                  "with fresh cryptographic keys in a new Ghost Lock.");
        break;
    }
    infoLabel->setText(info);

    Q_EMIT wiz->withdrawalComplete(wiz->selectedLockId(), wiz->resultTxid());
}

int WithdrawCompletePage::nextId() const
{
    return -1;  // End of wizard
}
