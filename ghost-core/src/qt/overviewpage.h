// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_OVERVIEWPAGE_H
#define GHOST_QT_OVERVIEWPAGE_H

#include <interfaces/wallet.h>
#include <qt/ghostpaytypes.h>

#include <QPixmap>
#include <QWidget>
#include <memory>

class ClientModel;
class TransactionFilterProxy;
class TxViewDelegate;
class PlatformStyle;
class WalletModel;
class L2WalletModel;

namespace Ui {
    class OverviewPage;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Overview ("home") page widget */
class OverviewPage : public QWidget
{
    Q_OBJECT

public:
    explicit OverviewPage(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~OverviewPage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);
    void setL2WalletModel(L2WalletModel *l2Model);
    void showOutOfSyncWarning(bool fShow);

public Q_SLOTS:
    void setBalance(const interfaces::WalletBalances& balances);
    void setL2Balance(const GhostPay::L2Balance& balance);
    void setL2ConnectionStatus(bool connected);
    void setPrivacy(bool privacy);

Q_SIGNALS:
    void transactionClicked(const QModelIndex &index);
    void outOfSyncWarningClicked();

protected:
    void changeEvent(QEvent* e) override;
    void paintEvent(QPaintEvent* event) override;

private:
    Ui::OverviewPage *ui;
    ClientModel* clientModel{nullptr};
    WalletModel* walletModel{nullptr};
    L2WalletModel* l2WalletModel{nullptr};
    bool m_privacy{false};
    bool m_l2Connected{false};
    GhostPay::L2Balance m_l2Balance;

    const PlatformStyle* m_platform_style;

    TxViewDelegate *txdelegate;
    std::unique_ptr<TransactionFilterProxy> filter;
    QPixmap m_watermark;

private Q_SLOTS:
    void LimitTransactionRows();
    void updateDisplayUnit();
    void handleTransactionClicked(const QModelIndex &index);
    void updateAlerts(const QString &warnings);
    void setMonospacedFont(const QFont&);
};

#endif // BITCOIN_QT_OVERVIEWPAGE_H
