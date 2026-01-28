// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_GHOSTLOCKSPAGE_H
#define GHOST_QT_GHOSTLOCKSPAGE_H

#include <qt/ghostpaytypes.h>

#include <QWidget>
#include <QMenu>

class L2WalletModel;
class WalletModel;
class PlatformStyle;
class GhostLocksModel;

namespace Ui {
    class GhostLocksPage;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
class QSortFilterProxyModel;
QT_END_NAMESPACE

/**
 * Ghost Locks Manager Page
 * Displays and manages Ghost Locks (L2 UTXO pools)
 */
class GhostLocksPage : public QWidget
{
    Q_OBJECT

public:
    explicit GhostLocksPage(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~GhostLocksPage();

    void setWalletModel(WalletModel *walletModel);
    void setL2WalletModel(L2WalletModel *l2Model);

public Q_SLOTS:
    /** Refresh locks from the node */
    void refreshLocks();

    /** Filter by denomination */
    void filterByDenomination(int denominationIndex);

    /** Update total balance display */
    void updateTotals();

Q_SIGNALS:
    /** Request to withdraw from a lock */
    void withdrawRequested(const QString& lockId);

    /** Request to rotate keys for a lock */
    void rotateRequested(const QString& lockId);

    /** Request to view lock details */
    void viewLockRequested(const QString& lockId);

private Q_SLOTS:
    void onLockClicked(const QModelIndex& index);
    void onLockDoubleClicked(const QModelIndex& index);
    void showContextMenu(const QPoint& point);

    // Context menu actions
    void copyLockId();
    void viewLockDetails();
    void withdrawFromLock();
    void rotateLockKeys();

    // L2 model signals
    void onLockRegistered(const QString& lockId);
    void onLockUpdated(const QString& lockId);
    void onBalanceChanged();

private:
    void setupContextMenu();
    QString getSelectedLockId() const;

    Ui::GhostLocksPage *ui;
    WalletModel *walletModel{nullptr};
    L2WalletModel *l2WalletModel{nullptr};
    const PlatformStyle *platformStyle;

    QMenu *contextMenu{nullptr};
    QAction *copyLockIdAction{nullptr};
    QAction *viewDetailsAction{nullptr};
    QAction *withdrawAction{nullptr};
    QAction *rotateAction{nullptr};

    QSortFilterProxyModel *proxyModel{nullptr};
};

#endif // GHOST_QT_GHOSTLOCKSPAGE_H
