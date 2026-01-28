// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/ghostlockspage.h>
#include <qt/forms/ui_ghostlockspage.h>

#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>
#include <qt/l2walletmodel.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <QApplication>
#include <QClipboard>
#include <QMessageBox>
#include <QSortFilterProxyModel>

GhostLocksPage::GhostLocksPage(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::GhostLocksPage),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    // Setup denomination filter combo
    ui->denominationFilter->addItem(tr("All Denominations"), -1);
    ui->denominationFilter->addItem(tr("Micro (10k sats)"), static_cast<int>(GhostPay::Denomination::Micro));
    ui->denominationFilter->addItem(tr("Tiny (100k sats)"), static_cast<int>(GhostPay::Denomination::Tiny));
    ui->denominationFilter->addItem(tr("Small (1M sats)"), static_cast<int>(GhostPay::Denomination::Small));
    ui->denominationFilter->addItem(tr("Medium (10M sats)"), static_cast<int>(GhostPay::Denomination::Medium));
    ui->denominationFilter->addItem(tr("Large (100M sats)"), static_cast<int>(GhostPay::Denomination::Large));
    ui->denominationFilter->addItem(tr("XL (1B sats)"), static_cast<int>(GhostPay::Denomination::XL));

    connect(ui->denominationFilter, qOverload<int>(&QComboBox::currentIndexChanged),
            this, &GhostLocksPage::filterByDenomination);

    connect(ui->refreshButton, &QPushButton::clicked, this, &GhostLocksPage::refreshLocks);

    // Setup table view
    ui->locksTableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->locksTableView->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->locksTableView->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->locksTableView->verticalHeader()->hide();
    ui->locksTableView->setShowGrid(false);
    ui->locksTableView->setAlternatingRowColors(true);

    connect(ui->locksTableView, &QTableView::clicked, this, &GhostLocksPage::onLockClicked);
    connect(ui->locksTableView, &QTableView::doubleClicked, this, &GhostLocksPage::onLockDoubleClicked);
    connect(ui->locksTableView, &QTableView::customContextMenuRequested, this, &GhostLocksPage::showContextMenu);

    setupContextMenu();
}

GhostLocksPage::~GhostLocksPage()
{
    delete ui;
}

void GhostLocksPage::setupContextMenu()
{
    contextMenu = new QMenu(this);

    copyLockIdAction = contextMenu->addAction(tr("Copy Lock ID"), this, &GhostLocksPage::copyLockId);
    viewDetailsAction = contextMenu->addAction(tr("View Details"), this, &GhostLocksPage::viewLockDetails);
    contextMenu->addSeparator();
    withdrawAction = contextMenu->addAction(tr("Withdraw..."), this, &GhostLocksPage::withdrawFromLock);
    rotateAction = contextMenu->addAction(tr("Rotate Keys..."), this, &GhostLocksPage::rotateLockKeys);

    if (platformStyle && platformStyle->getImagesOnButtons()) {
        copyLockIdAction->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/editcopy")));
        viewDetailsAction->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/eye")));
        withdrawAction->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/send")));
    }
}

void GhostLocksPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
}

void GhostLocksPage::setL2WalletModel(L2WalletModel *l2Model)
{
    this->l2WalletModel = l2Model;

    if (l2Model) {
        // Setup proxy model for filtering
        proxyModel = new QSortFilterProxyModel(this);
        proxyModel->setSourceModel(l2Model->locksModel());
        proxyModel->setFilterKeyColumn(GhostLocksModel::Denomination);

        ui->locksTableView->setModel(proxyModel);
        ui->locksTableView->horizontalHeader()->setSectionResizeMode(GhostLocksModel::LockId, QHeaderView::Stretch);
        ui->locksTableView->horizontalHeader()->setSectionResizeMode(GhostLocksModel::Denomination, QHeaderView::ResizeToContents);
        ui->locksTableView->horizontalHeader()->setSectionResizeMode(GhostLocksModel::L2Balance, QHeaderView::ResizeToContents);
        ui->locksTableView->horizontalHeader()->setSectionResizeMode(GhostLocksModel::State, QHeaderView::ResizeToContents);
        ui->locksTableView->horizontalHeader()->setSectionResizeMode(GhostLocksModel::RecoveryHeight, QHeaderView::ResizeToContents);

        // Connect to L2 model signals
        connect(l2Model, &L2WalletModel::lockRegistered, this, &GhostLocksPage::onLockRegistered);
        connect(l2Model, &L2WalletModel::lockUpdated, this, &GhostLocksPage::onLockUpdated);
        connect(l2Model, &L2WalletModel::balanceChanged, this, &GhostLocksPage::onBalanceChanged);

        // Initial update
        updateTotals();
    }
}

void GhostLocksPage::refreshLocks()
{
    if (l2WalletModel) {
        l2WalletModel->refreshLocks();
    }
}

void GhostLocksPage::filterByDenomination(int index)
{
    if (!proxyModel) return;

    int denomination = ui->denominationFilter->itemData(index).toInt();
    if (denomination < 0) {
        // Show all
        proxyModel->setFilterRegularExpression(QString());
    } else {
        // Filter by denomination name
        QString denomName = GhostPay::denominationName(static_cast<GhostPay::Denomination>(denomination));
        proxyModel->setFilterFixedString(denomName);
    }
}

void GhostLocksPage::updateTotals()
{
    if (!l2WalletModel || !walletModel) return;

    GhostPay::L2Balance totalBalance = l2WalletModel->getTotalBalance();
    int lockCount = 0;
    int activeLockCount = 0;

    if (l2WalletModel->locksModel()) {
        lockCount = l2WalletModel->locksModel()->rowCount();
        activeLockCount = l2WalletModel->locksModel()->getActiveLockCount();
    }

    BitcoinUnit unit = BitcoinUnit::BTC;
    if (walletModel->getOptionsModel()) {
        unit = walletModel->getOptionsModel()->getDisplayUnit();
    }

    ui->labelTotalBalance->setText(BitcoinUnits::formatWithUnit(unit, totalBalance.available + totalBalance.pending, false, BitcoinUnits::SeparatorStyle::ALWAYS));
    ui->labelAvailableBalance->setText(BitcoinUnits::formatWithUnit(unit, totalBalance.available, false, BitcoinUnits::SeparatorStyle::ALWAYS));
    ui->labelPendingBalance->setText(BitcoinUnits::formatWithUnit(unit, totalBalance.pending, false, BitcoinUnits::SeparatorStyle::ALWAYS));
    ui->labelLockCount->setText(QString::number(activeLockCount) + tr(" active") +
                                 (lockCount > activeLockCount ? QStringLiteral(" / ") + QString::number(lockCount) + tr(" total") : QString()));
}

QString GhostLocksPage::getSelectedLockId() const
{
    QModelIndexList selection = ui->locksTableView->selectionModel()->selectedRows();
    if (selection.isEmpty()) return QString();

    QModelIndex sourceIndex = proxyModel ? proxyModel->mapToSource(selection.first()) : selection.first();

    if (l2WalletModel && l2WalletModel->locksModel()) {
        const GhostPay::GhostLockInfo* lock = l2WalletModel->locksModel()->getLock(sourceIndex.row());
        if (lock) {
            return lock->lockId;
        }
    }
    return QString();
}

void GhostLocksPage::onLockClicked(const QModelIndex& /*index*/)
{
    // Update action availability based on selection
    QString lockId = getSelectedLockId();
    bool hasSelection = !lockId.isEmpty();

    if (withdrawAction) withdrawAction->setEnabled(hasSelection);
    if (rotateAction) rotateAction->setEnabled(hasSelection);
    if (viewDetailsAction) viewDetailsAction->setEnabled(hasSelection);
    if (copyLockIdAction) copyLockIdAction->setEnabled(hasSelection);
}

void GhostLocksPage::onLockDoubleClicked(const QModelIndex& /*index*/)
{
    viewLockDetails();
}

void GhostLocksPage::showContextMenu(const QPoint& point)
{
    QModelIndex index = ui->locksTableView->indexAt(point);
    if (!index.isValid()) return;

    ui->locksTableView->selectRow(index.row());
    onLockClicked(index);

    contextMenu->exec(ui->locksTableView->viewport()->mapToGlobal(point));
}

void GhostLocksPage::copyLockId()
{
    QString lockId = getSelectedLockId();
    if (!lockId.isEmpty()) {
        QApplication::clipboard()->setText(lockId);
    }
}

void GhostLocksPage::viewLockDetails()
{
    QString lockId = getSelectedLockId();
    if (!lockId.isEmpty()) {
        Q_EMIT viewLockRequested(lockId);
    }
}

void GhostLocksPage::withdrawFromLock()
{
    QString lockId = getSelectedLockId();
    if (lockId.isEmpty()) return;

    if (l2WalletModel && l2WalletModel->locksModel()) {
        const GhostPay::GhostLockInfo* lock = l2WalletModel->locksModel()->getLockById(lockId);
        if (lock && !GhostPay::stateAllowsL2Activity(lock->state)) {
            QMessageBox::warning(this, tr("Cannot Withdraw"),
                tr("This lock is in state '%1' and cannot be withdrawn from at this time.")
                    .arg(GhostPay::lockStateName(lock->state)));
            return;
        }
    }

    Q_EMIT withdrawRequested(lockId);
}

void GhostLocksPage::rotateLockKeys()
{
    QString lockId = getSelectedLockId();
    if (!lockId.isEmpty()) {
        Q_EMIT rotateRequested(lockId);
    }
}

void GhostLocksPage::onLockRegistered(const QString& /*lockId*/)
{
    updateTotals();
}

void GhostLocksPage::onLockUpdated(const QString& /*lockId*/)
{
    updateTotals();
}

void GhostLocksPage::onBalanceChanged()
{
    updateTotals();
}
