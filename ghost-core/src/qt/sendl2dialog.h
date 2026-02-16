// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_SENDL2DIALOG_H
#define GHOST_QT_SENDL2DIALOG_H

#include <qt/ghostpaytypes.h>

#include <QDialog>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QProgressBar>

class L2WalletModel;
class WalletModel;

/**
 * Dialog for sending L2 payments between Ghost Locks.
 *
 * Flow:
 * 1. User selects source lock from dropdown (shows lock ID + denomination + balance)
 * 2. Enters destination Ghost ID
 * 3. Enters amount
 * 4. Reviews summary and confirms
 * 5. Dialog signs the payment and submits via Ghost Pay client
 */
class SendL2Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit SendL2Dialog(WalletModel* walletModel, L2WalletModel* l2Model, QWidget* parent = nullptr);
    ~SendL2Dialog();

private Q_SLOTS:
    void onLockSelectionChanged(int index);
    void onSendClicked();
    void onPaymentSent(const QString& paymentId);
    void onPaymentError(const QString& error);
    void validateInputs();

private:
    void populateLocks();
    QString signPaymentMessage(const QString& fromLockId, const QString& toGhostId, int64_t amount);

    WalletModel* m_walletModel;
    L2WalletModel* m_l2Model;

    // UI elements
    QComboBox* m_lockSelector;
    QLabel* m_lockBalanceLabel;
    QLineEdit* m_recipientInput;
    QLineEdit* m_amountInput;
    QLabel* m_summaryLabel;
    QPushButton* m_sendButton;
    QPushButton* m_cancelButton;
    QProgressBar* m_progress;
    QLabel* m_statusLabel;

    // Lock-key mapping: lockId -> address used when registering the lock
    QMap<QString, QString> m_lockAddresses;
};

#endif // GHOST_QT_SENDL2DIALOG_H
