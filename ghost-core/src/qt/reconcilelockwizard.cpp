// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/reconcilelockwizard.h>

#include <qt/bitcoinunits.h>
#include <qt/ghostaddressvalidator.h>
#include <qt/guiutil.h>
#include <qt/l2walletmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <interfaces/wallet.h>
#include <key_io.h>
#include <outputtype.h>

#include <QButtonGroup>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRadioButton>
#include <QTableView>
#include <QVBoxLayout>

// ===== ReconcileLockWizard =====

ReconcileLockWizard::ReconcileLockWizard(const PlatformStyle *_platformStyle,
                                         WalletModel *_walletModel,
                                         L2WalletModel *_l2WalletModel,
                                         QWidget *parent)
    : QWizard(parent),
      walletModel(_walletModel),
      l2WalletModel(_l2WalletModel),
      platformStyle(_platformStyle)
{
    setWindowTitle(tr("Reconcile Ghost Lock"));
    setWizardStyle(QWizard::ModernStyle);
    setOption(QWizard::NoBackButtonOnStartPage);

    setPage(Page_SelectLock, new ReconcileSelectLockPage(l2WalletModel, this));
    setPage(Page_Destination, new ReconcileDestinationPage(walletModel, this));
    setPage(Page_SettlementClass, new SettlementClassPage(this));
    setPage(Page_Confirm, new ReconcileConfirmPage(this));
    setPage(Page_Processing, new ReconcileProcessingPage(l2WalletModel, this));
    setPage(Page_Complete, new ReconcileCompletePage(this));

    setStartId(Page_SelectLock);

    if (l2WalletModel) {
        connect(l2WalletModel, &L2WalletModel::withdrawalRequested, this, &ReconcileLockWizard::onReconcileRequested);
        connect(l2WalletModel, &L2WalletModel::withdrawalComplete, this, &ReconcileLockWizard::onReconcileComplete);
        connect(l2WalletModel, &L2WalletModel::withdrawalError, this, &ReconcileLockWizard::onReconcileError);
    }

    connect(this, &QWizard::rejected, this, &ReconcileLockWizard::operationCancelled);
}

void ReconcileLockWizard::setSelectedLock(const QString& lockId)
{
    m_lockId = lockId;
}

void ReconcileLockWizard::setLockId(const QString& lockId)
{
    m_lockId = lockId;
}

void ReconcileLockWizard::setDestination(const QString& address)
{
    m_destination = address;
}

void ReconcileLockWizard::setSettlementClass(SettlementClass sc)
{
    m_settlementClass = sc;
}

void ReconcileLockWizard::onReconcileRequested(const QString& batchId)
{
    m_batchId = batchId;
    ReconcileProcessingPage* procPage = qobject_cast<ReconcileProcessingPage*>(page(Page_Processing));
    if (procPage) {
        procPage->onRequested(batchId);
    }
}

void ReconcileLockWizard::onReconcileComplete(const QString& lockId, const QString& txid)
{
    if (lockId != m_lockId) return;

    m_resultTxid = txid;
    ReconcileProcessingPage* procPage = qobject_cast<ReconcileProcessingPage*>(page(Page_Processing));
    if (procPage) {
        procPage->onComplete(lockId, txid);
    }
}

void ReconcileLockWizard::onReconcileError(const QString& error)
{
    ReconcileProcessingPage* procPage = qobject_cast<ReconcileProcessingPage*>(page(Page_Processing));
    if (procPage && currentId() == Page_Processing) {
        procPage->onError(error);
    }
}

// ===== ReconcileSelectLockPage =====

ReconcileSelectLockPage::ReconcileSelectLockPage(L2WalletModel *_l2WalletModel, QWidget *parent)
    : QWizardPage(parent),
      l2WalletModel(_l2WalletModel)
{
    setTitle(tr("Select Ghost Lock"));
    setSubTitle(tr("Choose which Ghost Lock to reconcile (settle to L1)."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    QLabel *infoLabel = new QLabel(tr(
        "Reconciliation settles your Ghost Lock balance to a Bitcoin L1 address. "
        "Once reconciled, the lock will be closed and your funds will appear on-chain "
        "after the settlement transaction confirms."
    ), this);
    infoLabel->setWordWrap(true);
    layout->addWidget(infoLabel);

    layout->addSpacing(10);

    locksTable = new QTableView(this);
    locksTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    locksTable->setSelectionMode(QAbstractItemView::SingleSelection);
    locksTable->verticalHeader()->hide();
    locksTable->setShowGrid(false);
    locksTable->setAlternatingRowColors(true);
    layout->addWidget(locksTable);

    QHBoxLayout *statusLayout = new QHBoxLayout();
    selectedLabel = new QLabel(tr("No lock selected"), this);
    statusLayout->addWidget(selectedLabel);
    statusLayout->addStretch();
    balanceLabel = new QLabel(this);
    balanceLabel->setStyleSheet(QStringLiteral("QLabel { font-weight: bold; }"));
    statusLayout->addWidget(balanceLabel);
    layout->addLayout(statusLayout);

    connect(locksTable, &QTableView::clicked, this, &ReconcileSelectLockPage::onLockSelected);
}

void ReconcileSelectLockPage::initializePage()
{
    if (l2WalletModel && l2WalletModel->locksModel()) {
        locksTable->setModel(l2WalletModel->locksModel());
        locksTable->horizontalHeader()->setSectionResizeMode(GhostLocksModel::LockId, QHeaderView::Stretch);
        locksTable->horizontalHeader()->setSectionResizeMode(GhostLocksModel::Denomination, QHeaderView::ResizeToContents);
        locksTable->horizontalHeader()->setSectionResizeMode(GhostLocksModel::L2Balance, QHeaderView::ResizeToContents);
        locksTable->horizontalHeader()->setSectionResizeMode(GhostLocksModel::State, QHeaderView::ResizeToContents);
    }

    ReconcileLockWizard *wiz = qobject_cast<ReconcileLockWizard*>(wizard());
    if (wiz && !wiz->selectedLockId().isEmpty()) {
        selectedLabel->setText(tr("Pre-selected: %1").arg(wiz->selectedLockId().left(16) + QStringLiteral("...")));
    }
}

void ReconcileSelectLockPage::onLockSelected()
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

bool ReconcileSelectLockPage::validatePage()
{
    ReconcileLockWizard *wiz = qobject_cast<ReconcileLockWizard*>(wizard());
    if (wiz) {
        wiz->setLockId(selectedLockId());
    }
    return true;
}

int ReconcileSelectLockPage::nextId() const
{
    return ReconcileLockWizard::Page_Destination;
}

bool ReconcileSelectLockPage::isComplete() const
{
    ReconcileLockWizard *wiz = qobject_cast<ReconcileLockWizard*>(wizard());
    if (wiz && !wiz->selectedLockId().isEmpty()) {
        return true;
    }
    return m_selectedRow >= 0;
}

QString ReconcileSelectLockPage::selectedLockId() const
{
    ReconcileLockWizard *wiz = qobject_cast<ReconcileLockWizard*>(wizard());
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

// ===== ReconcileDestinationPage =====

ReconcileDestinationPage::ReconcileDestinationPage(WalletModel *_walletModel, QWidget *parent)
    : QWizardPage(parent),
      walletModel(_walletModel)
{
    setTitle(tr("Destination Address"));
    setSubTitle(tr("Enter the Bitcoin address where your reconciled funds will be sent."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    instructionLabel = new QLabel(tr(
        "Enter a valid bech32 or bech32m Bitcoin address. "
        "This is where your funds will appear on L1 after settlement confirms."
    ), this);
    instructionLabel->setWordWrap(true);
    layout->addWidget(instructionLabel);

    layout->addSpacing(10);

    QHBoxLayout *addressLayout = new QHBoxLayout();
    QLabel *addressLabel = new QLabel(tr("Destination Address:"), this);
    addressLayout->addWidget(addressLabel);
    addressEdit = new QLineEdit(this);
    addressEdit->setPlaceholderText(tr("Enter a Ghost address (bech32/bech32m)..."));
    addressLayout->addWidget(addressEdit, 1);
    newAddressButton = new QPushButton(tr("New Address"), this);
    addressLayout->addWidget(newAddressButton);
    layout->addLayout(addressLayout);

    validationLabel = new QLabel(this);
    layout->addWidget(validationLabel);

    layout->addStretch();

    connect(addressEdit, &QLineEdit::textChanged, this, &ReconcileDestinationPage::onAddressChanged);
    connect(newAddressButton, &QPushButton::clicked, this, &ReconcileDestinationPage::onUseNewAddress);
}

void ReconcileDestinationPage::initializePage()
{
    m_addressValid = false;
    addressEdit->clear();
    validationLabel->clear();
    Q_EMIT completeChanged();
}

void ReconcileDestinationPage::onAddressChanged()
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

void ReconcileDestinationPage::onUseNewAddress()
{
    if (!walletModel) return;

    auto dest = walletModel->wallet().getNewDestination(
        OutputType::BECH32M, "Ghost Lock Reconciliation");
    if (dest) {
        addressEdit->setText(QString::fromStdString(EncodeDestination(*dest)));
    } else {
        validationLabel->setText(tr("Failed to generate address from wallet"));
        validationLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));
    }
}

bool ReconcileDestinationPage::validatePage()
{
    ReconcileLockWizard *wiz = qobject_cast<ReconcileLockWizard*>(wizard());
    if (wiz) {
        wiz->setDestination(destinationAddress());
    }
    return m_addressValid;
}

int ReconcileDestinationPage::nextId() const
{
    return ReconcileLockWizard::Page_SettlementClass;
}

bool ReconcileDestinationPage::isComplete() const
{
    return m_addressValid;
}

QString ReconcileDestinationPage::destinationAddress() const
{
    return addressEdit->text().trimmed();
}

// ===== SettlementClassPage =====

SettlementClassPage::SettlementClassPage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Settlement Class"));
    setSubTitle(tr("Choose how the reconciliation should be settled on L1."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    classGroup = new QButtonGroup(this);

    standardButton = new QRadioButton(tr("Standard"), this);
    standardButton->setChecked(true);
    classGroup->addButton(standardButton, static_cast<int>(ReconcileLockWizard::Settlement_Standard));
    layout->addWidget(standardButton);

    QLabel *standardInfo = new QLabel(tr(
        "Standard settlement processes your reconciliation in the next available batch. "
        "Lower fees but may take longer to confirm, as it waits for a full batch to form."
    ), this);
    standardInfo->setWordWrap(true);
    standardInfo->setStyleSheet(QStringLiteral("QLabel { color: #666666; margin-left: 20px; margin-bottom: 10px; }"));
    layout->addWidget(standardInfo);

    batchedButton = new QRadioButton(tr("Batched"), this);
    classGroup->addButton(batchedButton, static_cast<int>(ReconcileLockWizard::Settlement_Batched));
    layout->addWidget(batchedButton);

    QLabel *batchedInfo = new QLabel(tr(
        "Batched settlement groups your reconciliation with other settlements for efficiency. "
        "This may result in slightly higher fees but optimizes the on-chain footprint."
    ), this);
    batchedInfo->setWordWrap(true);
    batchedInfo->setStyleSheet(QStringLiteral("QLabel { color: #666666; margin-left: 20px; }"));
    layout->addWidget(batchedInfo);

    layout->addSpacing(20);

    infoLabel = new QLabel(this);
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet(QStringLiteral("QLabel { color: #666666; }"));
    layout->addWidget(infoLabel);

    layout->addStretch();

    connect(classGroup, &QButtonGroup::idClicked, this, [this]() { updateInfo(); });
    updateInfo();
}

void SettlementClassPage::initializePage()
{
    updateInfo();
}

bool SettlementClassPage::validatePage()
{
    ReconcileLockWizard *wiz = qobject_cast<ReconcileLockWizard*>(wizard());
    if (wiz) {
        wiz->setSettlementClass(selectedClass());
    }
    return true;
}

int SettlementClassPage::nextId() const
{
    return ReconcileLockWizard::Page_Confirm;
}

ReconcileLockWizard::SettlementClass SettlementClassPage::selectedClass() const
{
    return static_cast<ReconcileLockWizard::SettlementClass>(classGroup->checkedId());
}

void SettlementClassPage::updateInfo()
{
    ReconcileLockWizard::SettlementClass sc = selectedClass();
    if (sc == ReconcileLockWizard::Settlement_Standard) {
        infoLabel->setText(tr("Standard settlement is recommended for most reconciliations."));
    } else {
        infoLabel->setText(tr("Batched settlement optimizes for on-chain efficiency."));
    }
}

// ===== ReconcileConfirmPage =====

ReconcileConfirmPage::ReconcileConfirmPage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Confirm Reconciliation"));
    setSubTitle(tr("Review the details before submitting."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    QGridLayout *detailsGrid = new QGridLayout();

    detailsGrid->addWidget(new QLabel(tr("Lock ID:"), this), 0, 0);
    lockIdLabel = new QLabel(this);
    lockIdLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    lockIdLabel->setWordWrap(true);
    detailsGrid->addWidget(lockIdLabel, 0, 1);

    detailsGrid->addWidget(new QLabel(tr("Destination:"), this), 1, 0);
    destinationLabel = new QLabel(this);
    destinationLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    destinationLabel->setWordWrap(true);
    detailsGrid->addWidget(destinationLabel, 1, 1);

    detailsGrid->addWidget(new QLabel(tr("Settlement Class:"), this), 2, 0);
    settlementLabel = new QLabel(this);
    detailsGrid->addWidget(settlementLabel, 2, 1);

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

    layout->addSpacing(20);

    warningLabel = new QLabel(tr(
        "This action cannot be undone. Once reconciled, the Ghost Lock will be closed "
        "and your funds will be sent to the specified L1 address.\n\n"
        "Make sure the destination address is correct."
    ), this);
    warningLabel->setWordWrap(true);
    warningLabel->setStyleSheet(QStringLiteral("QLabel { color: #cc6600; }"));
    layout->addWidget(warningLabel);

    layout->addStretch();
}

void ReconcileConfirmPage::initializePage()
{
    ReconcileLockWizard *wiz = qobject_cast<ReconcileLockWizard*>(wizard());
    if (!wiz) return;

    lockIdLabel->setText(wiz->selectedLockId());
    destinationLabel->setText(wiz->destinationAddress());

    QString scName = (wiz->selectedSettlementClass() == ReconcileLockWizard::Settlement_Standard)
        ? tr("Standard") : tr("Batched");
    settlementLabel->setText(scName);

    int64_t balance = 0;
    if (wiz->getL2WalletModel() && wiz->getL2WalletModel()->locksModel()) {
        const GhostPay::GhostLockInfo* lock = wiz->getL2WalletModel()->locksModel()->getLockById(wiz->selectedLockId());
        if (lock) {
            balance = lock->l2Balance;
        }
    }

    balanceLabel->setText(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, balance, false, BitcoinUnits::SeparatorStyle::ALWAYS));

    int64_t fee = 1000;  // 1000 sats placeholder
    feeLabel->setText(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, fee, false, BitcoinUnits::SeparatorStyle::ALWAYS));
    receiveLabel->setText(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, balance - fee, false, BitcoinUnits::SeparatorStyle::ALWAYS));
}

bool ReconcileConfirmPage::validatePage()
{
    return true;
}

int ReconcileConfirmPage::nextId() const
{
    return ReconcileLockWizard::Page_Processing;
}

// ===== ReconcileProcessingPage =====

ReconcileProcessingPage::ReconcileProcessingPage(L2WalletModel *_l2WalletModel, QWidget *parent)
    : QWizardPage(parent),
      l2WalletModel(_l2WalletModel)
{
    setTitle(tr("Processing Reconciliation"));
    setSubTitle(tr("Your reconciliation is being processed."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    layout->addStretch();

    statusLabel = new QLabel(tr("Submitting reconciliation request..."), this);
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

void ReconcileProcessingPage::initializePage()
{
    m_complete = false;
    m_error.clear();
    statusLabel->setText(tr("Submitting reconciliation request..."));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 14pt; }"));
    batchIdLabel->clear();
    progressBar->setRange(0, 0);

    ReconcileLockWizard *wiz = qobject_cast<ReconcileLockWizard*>(wizard());
    if (!wiz || !l2WalletModel || !l2WalletModel->client()) return;

    // POST /api/v1/locks/:id/reconcile
    QString settlementClass = (wiz->selectedSettlementClass() == ReconcileLockWizard::Settlement_Standard)
        ? QStringLiteral("standard") : QStringLiteral("batched");
    l2WalletModel->client()->requestReconciliation(
        wiz->selectedLockId(),
        wiz->destinationAddress(),
        settlementClass);
}

void ReconcileProcessingPage::onRequested(const QString& batchId)
{
    statusLabel->setText(tr("Reconciliation queued in batch"));
    batchIdLabel->setText(tr("Batch ID: %1").arg(batchId));
}

void ReconcileProcessingPage::onComplete(const QString& lockId, const QString& txid)
{
    Q_UNUSED(lockId)
    m_complete = true;
    statusLabel->setText(tr("Reconciliation Complete!"));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 14pt; color: green; }"));
    progressBar->setRange(0, 100);
    progressBar->setValue(100);
    batchIdLabel->setText(tr("Transaction: %1").arg(txid.left(20) + QStringLiteral("...")));

    Q_EMIT completeChanged();
}

void ReconcileProcessingPage::onError(const QString& error)
{
    m_error = error;
    statusLabel->setText(tr("Error: %1").arg(error));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 14pt; color: red; }"));
    progressBar->setRange(0, 100);
    progressBar->setValue(0);
}

bool ReconcileProcessingPage::validatePage()
{
    return m_complete && m_error.isEmpty();
}

int ReconcileProcessingPage::nextId() const
{
    return m_complete ? ReconcileLockWizard::Page_Complete : -1;
}

bool ReconcileProcessingPage::isComplete() const
{
    return m_complete;
}

// ===== ReconcileCompletePage =====

ReconcileCompletePage::ReconcileCompletePage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Reconciliation Complete"));
    setSubTitle(tr("Your Ghost Lock has been successfully reconciled."));

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
    txidLabel->setWordWrap(true);
    detailsGrid->addWidget(txidLabel, 0, 1);

    detailsGrid->addWidget(new QLabel(tr("Destination:"), this), 1, 0);
    destinationLabel = new QLabel(this);
    destinationLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    destinationLabel->setWordWrap(true);
    detailsGrid->addWidget(destinationLabel, 1, 1);

    detailsGrid->addWidget(new QLabel(tr("Amount:"), this), 2, 0);
    amountLabel = new QLabel(this);
    detailsGrid->addWidget(amountLabel, 2, 1);

    layout->addLayout(detailsGrid);

    layout->addSpacing(20);

    infoLabel = new QLabel(tr(
        "Your funds have been settled to the specified L1 address.\n"
        "The transaction should confirm within the next few blocks.\n\n"
        "The Ghost Lock has been closed and is no longer usable."
    ), this);
    infoLabel->setWordWrap(true);
    infoLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(infoLabel);

    layout->addStretch();
}

void ReconcileCompletePage::initializePage()
{
    ReconcileLockWizard *wiz = qobject_cast<ReconcileLockWizard*>(wizard());
    if (!wiz) return;

    txidLabel->setText(wiz->resultTxid());
    destinationLabel->setText(wiz->destinationAddress());

    int64_t amount = 0;
    if (wiz->getL2WalletModel() && wiz->getL2WalletModel()->locksModel()) {
        const GhostPay::GhostLockInfo* lock = wiz->getL2WalletModel()->locksModel()->getLockById(wiz->selectedLockId());
        if (lock) {
            amount = lock->l2Balance;
        }
    }
    amountLabel->setText(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, amount, false, BitcoinUnits::SeparatorStyle::ALWAYS));

    Q_EMIT wiz->operationComplete(wiz->resultTxid());
}

int ReconcileCompletePage::nextId() const
{
    return -1;  // End of wizard
}
