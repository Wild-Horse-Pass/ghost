// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/jumplockwizard.h>

#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>
#include <qt/l2walletmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QProgressBar>
#include <QTableView>
#include <QVBoxLayout>

// ===== JumpLockWizard =====

JumpLockWizard::JumpLockWizard(const PlatformStyle *_platformStyle,
                               WalletModel *_walletModel,
                               L2WalletModel *_l2WalletModel,
                               QWidget *parent)
    : QWizard(parent),
      walletModel(_walletModel),
      l2WalletModel(_l2WalletModel),
      platformStyle(_platformStyle)
{
    setWindowTitle(tr("Jump Ghost Lock"));
    setWizardStyle(QWizard::ModernStyle);
    setOption(QWizard::NoBackButtonOnStartPage);

    setPage(Page_SelectLock, new JumpSelectLockPage(l2WalletModel, this));
    setPage(Page_ConfirmJump, new ConfirmJumpPage(this));
    setPage(Page_Processing, new JumpProcessingPage(l2WalletModel, this));
    setPage(Page_Complete, new JumpCompletePage(this));

    setStartId(Page_SelectLock);

    if (l2WalletModel && l2WalletModel->client()) {
        connect(l2WalletModel->client(), &GhostPayClient::jumpEnqueued, this, &JumpLockWizard::onJumpEnqueued);
        connect(l2WalletModel->client(), &GhostPayClient::jumpError, this, &JumpLockWizard::onJumpError);
    }

    connect(this, &QWizard::rejected, this, &JumpLockWizard::operationCancelled);
}

void JumpLockWizard::setSelectedLock(const QString& lockId)
{
    m_lockId = lockId;
}

void JumpLockWizard::setLockId(const QString& lockId)
{
    m_lockId = lockId;
}

void JumpLockWizard::onJumpEnqueued(const QString& lockId)
{
    if (lockId != m_lockId) return;

    JumpProcessingPage* procPage = qobject_cast<JumpProcessingPage*>(page(Page_Processing));
    if (procPage) {
        procPage->onEnqueued(lockId);
    }
}

void JumpLockWizard::onJumpComplete(const QString& lockId, const QString& newLockId, const QString& txid)
{
    if (lockId != m_lockId) return;

    m_newLockId = newLockId;
    m_resultTxid = txid;
    JumpProcessingPage* procPage = qobject_cast<JumpProcessingPage*>(page(Page_Processing));
    if (procPage) {
        procPage->onComplete(lockId, newLockId, txid);
    }
}

void JumpLockWizard::onJumpError(const QString& error)
{
    JumpProcessingPage* procPage = qobject_cast<JumpProcessingPage*>(page(Page_Processing));
    if (procPage && currentId() == Page_Processing) {
        procPage->onError(error);
    }
}

// ===== JumpSelectLockPage =====

JumpSelectLockPage::JumpSelectLockPage(L2WalletModel *_l2WalletModel, QWidget *parent)
    : QWizardPage(parent),
      l2WalletModel(_l2WalletModel)
{
    setTitle(tr("Select Ghost Lock"));
    setSubTitle(tr("Choose which Ghost Lock to jump (rotate keys)."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    QLabel *infoLabel = new QLabel(tr(
        "A jump rotates your lock's cryptographic keys by creating a new lock and "
        "transferring your balance. This is useful for maintaining key hygiene or "
        "if you suspect your keys may be compromised."
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

    jumpStatusLabel = new QLabel(this);
    jumpStatusLabel->setStyleSheet(QStringLiteral("QLabel { color: #666666; }"));
    layout->addWidget(jumpStatusLabel);

    connect(locksTable, &QTableView::clicked, this, &JumpSelectLockPage::onLockSelected);
}

void JumpSelectLockPage::initializePage()
{
    if (l2WalletModel && l2WalletModel->locksModel()) {
        locksTable->setModel(l2WalletModel->locksModel());
        locksTable->horizontalHeader()->setSectionResizeMode(GhostLocksModel::LockId, QHeaderView::Stretch);
        locksTable->horizontalHeader()->setSectionResizeMode(GhostLocksModel::Denomination, QHeaderView::ResizeToContents);
        locksTable->horizontalHeader()->setSectionResizeMode(GhostLocksModel::L2Balance, QHeaderView::ResizeToContents);
        locksTable->horizontalHeader()->setSectionResizeMode(GhostLocksModel::State, QHeaderView::ResizeToContents);
    }

    // Check if lock was pre-selected
    JumpLockWizard *wiz = qobject_cast<JumpLockWizard*>(wizard());
    if (wiz && !wiz->selectedLockId().isEmpty()) {
        selectedLabel->setText(tr("Pre-selected: %1").arg(wiz->selectedLockId().left(16) + QStringLiteral("...")));
    }
}

void JumpSelectLockPage::onLockSelected()
{
    QModelIndexList selection = locksTable->selectionModel()->selectedRows();
    if (selection.isEmpty()) {
        m_selectedRow = -1;
        selectedLabel->setText(tr("No lock selected"));
        balanceLabel->clear();
        jumpStatusLabel->clear();
        return;
    }

    m_selectedRow = selection.first().row();

    if (l2WalletModel && l2WalletModel->locksModel()) {
        const GhostPay::GhostLockInfo* lock = l2WalletModel->locksModel()->getLock(m_selectedRow);
        if (lock) {
            selectedLabel->setText(tr("Selected: %1").arg(lock->lockId.left(16) + QStringLiteral("...")));
            balanceLabel->setText(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, lock->l2Balance, false, BitcoinUnits::SeparatorStyle::ALWAYS));

            if (lock->state == GhostPay::LockState::Active || lock->state == GhostPay::LockState::Idle) {
                jumpStatusLabel->setText(tr("This lock is eligible for jumping."));
                jumpStatusLabel->setStyleSheet(QStringLiteral("QLabel { color: green; }"));
            } else {
                jumpStatusLabel->setText(tr("This lock is in state '%1' and may not be eligible for jumping.")
                    .arg(GhostPay::lockStateName(lock->state)));
                jumpStatusLabel->setStyleSheet(QStringLiteral("QLabel { color: #cc6600; }"));
            }
        }
    }

    Q_EMIT completeChanged();
}

bool JumpSelectLockPage::validatePage()
{
    JumpLockWizard *wiz = qobject_cast<JumpLockWizard*>(wizard());
    if (wiz) {
        wiz->setLockId(selectedLockId());
    }
    return true;
}

int JumpSelectLockPage::nextId() const
{
    return JumpLockWizard::Page_ConfirmJump;
}

bool JumpSelectLockPage::isComplete() const
{
    JumpLockWizard *wiz = qobject_cast<JumpLockWizard*>(wizard());
    if (wiz && !wiz->selectedLockId().isEmpty()) {
        return true;
    }
    return m_selectedRow >= 0;
}

QString JumpSelectLockPage::selectedLockId() const
{
    JumpLockWizard *wiz = qobject_cast<JumpLockWizard*>(wizard());
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

// ===== ConfirmJumpPage =====

ConfirmJumpPage::ConfirmJumpPage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Confirm Jump"));
    setSubTitle(tr("Review the jump details before proceeding."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    QGridLayout *detailsGrid = new QGridLayout();

    detailsGrid->addWidget(new QLabel(tr("Lock ID:"), this), 0, 0);
    lockIdLabel = new QLabel(this);
    lockIdLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    lockIdLabel->setWordWrap(true);
    detailsGrid->addWidget(lockIdLabel, 0, 1);

    detailsGrid->addWidget(new QLabel(tr("Current Balance:"), this), 1, 0);
    balanceLabel = new QLabel(this);
    detailsGrid->addWidget(balanceLabel, 1, 1);

    detailsGrid->addWidget(new QLabel(tr("Jump Fee:"), this), 2, 0);
    feeLabel = new QLabel(this);
    detailsGrid->addWidget(feeLabel, 2, 1);

    detailsGrid->addWidget(new QLabel(tr("New Lock Balance:"), this), 3, 0);
    receiveLabel = new QLabel(this);
    receiveLabel->setStyleSheet(QStringLiteral("QLabel { font-weight: bold; }"));
    detailsGrid->addWidget(receiveLabel, 3, 1);

    layout->addLayout(detailsGrid);

    layout->addSpacing(20);

    warningLabel = new QLabel(tr(
        "After the jump completes, your current lock will be closed and a new lock "
        "with fresh keys will be created. The old lock ID will no longer be usable.\n\n"
        "This operation cannot be undone."
    ), this);
    warningLabel->setWordWrap(true);
    warningLabel->setStyleSheet(QStringLiteral("QLabel { color: #cc6600; }"));
    layout->addWidget(warningLabel);

    layout->addStretch();
}

void ConfirmJumpPage::initializePage()
{
    JumpLockWizard *wiz = qobject_cast<JumpLockWizard*>(wizard());
    if (!wiz) return;

    lockIdLabel->setText(wiz->selectedLockId());

    int64_t balance = 0;
    if (wiz->getL2WalletModel() && wiz->getL2WalletModel()->locksModel()) {
        const GhostPay::GhostLockInfo* lock = wiz->getL2WalletModel()->locksModel()->getLockById(wiz->selectedLockId());
        if (lock) {
            balance = lock->l2Balance;
        }
    }

    balanceLabel->setText(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, balance, false, BitcoinUnits::SeparatorStyle::ALWAYS));

    // Jump fee estimate
    int64_t fee = 2000;  // 2000 sats placeholder for jump fee
    feeLabel->setText(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, fee, false, BitcoinUnits::SeparatorStyle::ALWAYS));
    receiveLabel->setText(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, balance - fee, false, BitcoinUnits::SeparatorStyle::ALWAYS));
}

bool ConfirmJumpPage::validatePage()
{
    return true;
}

int ConfirmJumpPage::nextId() const
{
    return JumpLockWizard::Page_Processing;
}

// ===== JumpProcessingPage =====

JumpProcessingPage::JumpProcessingPage(L2WalletModel *_l2WalletModel, QWidget *parent)
    : QWizardPage(parent),
      l2WalletModel(_l2WalletModel)
{
    setTitle(tr("Processing Jump"));
    setSubTitle(tr("Your lock jump is being processed."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    layout->addStretch();

    statusLabel = new QLabel(tr("Submitting jump request..."), this);
    statusLabel->setAlignment(Qt::AlignCenter);
    statusLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 14pt; }"));
    layout->addWidget(statusLabel);

    layout->addSpacing(20);

    progressBar = new QProgressBar(this);
    progressBar->setRange(0, 0);  // Indeterminate
    layout->addWidget(progressBar);

    layout->addSpacing(10);

    detailLabel = new QLabel(this);
    detailLabel->setAlignment(Qt::AlignCenter);
    detailLabel->setStyleSheet(QStringLiteral("QLabel { color: #666666; }"));
    layout->addWidget(detailLabel);

    layout->addStretch();
}

void JumpProcessingPage::initializePage()
{
    m_complete = false;
    m_error.clear();
    statusLabel->setText(tr("Submitting jump request..."));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 14pt; }"));
    detailLabel->clear();
    progressBar->setRange(0, 0);

    JumpLockWizard *wiz = qobject_cast<JumpLockWizard*>(wizard());
    if (!wiz || !l2WalletModel || !l2WalletModel->client()) return;

    // POST /api/v1/locks/:id/jump
    l2WalletModel->client()->jumpEnqueue(wiz->selectedLockId());
}

void JumpProcessingPage::onEnqueued(const QString& lockId)
{
    statusLabel->setText(tr("Jump enqueued"));
    detailLabel->setText(tr("Lock %1 is in the jump queue. Waiting for rotation...").arg(lockId.left(16) + QStringLiteral("...")));
}

void JumpProcessingPage::onComplete(const QString& lockId, const QString& newLockId, const QString& txid)
{
    Q_UNUSED(lockId)
    m_complete = true;
    statusLabel->setText(tr("Jump Complete!"));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 14pt; color: green; }"));
    progressBar->setRange(0, 100);
    progressBar->setValue(100);
    detailLabel->setText(tr("New Lock: %1 | Tx: %2")
        .arg(newLockId.left(16) + QStringLiteral("..."))
        .arg(txid.left(16) + QStringLiteral("...")));

    Q_EMIT completeChanged();
}

void JumpProcessingPage::onError(const QString& error)
{
    m_error = error;
    statusLabel->setText(tr("Error: %1").arg(error));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 14pt; color: red; }"));
    progressBar->setRange(0, 100);
    progressBar->setValue(0);
}

bool JumpProcessingPage::validatePage()
{
    return m_complete && m_error.isEmpty();
}

int JumpProcessingPage::nextId() const
{
    return m_complete ? JumpLockWizard::Page_Complete : -1;
}

bool JumpProcessingPage::isComplete() const
{
    return m_complete;
}

// ===== JumpCompletePage =====

JumpCompletePage::JumpCompletePage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Jump Complete"));
    setSubTitle(tr("Your Ghost Lock has been successfully jumped."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    successLabel = new QLabel(this);
    successLabel->setAlignment(Qt::AlignCenter);
    successLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 18pt; color: green; }"));
    successLabel->setText(tr("Success!"));
    layout->addWidget(successLabel);

    layout->addSpacing(20);

    QGridLayout *detailsGrid = new QGridLayout();

    detailsGrid->addWidget(new QLabel(tr("Old Lock ID:"), this), 0, 0);
    oldLockIdLabel = new QLabel(this);
    oldLockIdLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    oldLockIdLabel->setWordWrap(true);
    detailsGrid->addWidget(oldLockIdLabel, 0, 1);

    detailsGrid->addWidget(new QLabel(tr("New Lock ID:"), this), 1, 0);
    newLockIdLabel = new QLabel(this);
    newLockIdLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    newLockIdLabel->setWordWrap(true);
    detailsGrid->addWidget(newLockIdLabel, 1, 1);

    detailsGrid->addWidget(new QLabel(tr("Transaction ID:"), this), 2, 0);
    txidLabel = new QLabel(this);
    txidLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    txidLabel->setWordWrap(true);
    detailsGrid->addWidget(txidLabel, 2, 1);

    layout->addLayout(detailsGrid);

    layout->addSpacing(20);

    infoLabel = new QLabel(tr(
        "Your balance has been transferred to a new Ghost Lock with fresh cryptographic keys.\n"
        "The old lock has been closed and is no longer usable.\n\n"
        "You can continue using L2 payments with your new lock."
    ), this);
    infoLabel->setWordWrap(true);
    infoLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(infoLabel);

    layout->addStretch();
}

void JumpCompletePage::initializePage()
{
    JumpLockWizard *wiz = qobject_cast<JumpLockWizard*>(wizard());
    if (!wiz) return;

    oldLockIdLabel->setText(wiz->selectedLockId());
    newLockIdLabel->setText(wiz->newLockId());
    txidLabel->setText(wiz->resultTxid());

    Q_EMIT wiz->operationComplete(wiz->newLockId());
}

int JumpCompletePage::nextId() const
{
    return -1;  // End of wizard
}
