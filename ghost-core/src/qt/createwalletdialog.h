// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_CREATEWALLETDIALOG_H
#define BITCOIN_QT_CREATEWALLETDIALOG_H

#include <qt/mnemonicwidget.h>

#include <QDialog>

#include <memory>

class QCheckBox;

namespace interfaces {
class ExternalSigner;
} // namespace interfaces

class WalletModel;

namespace Ui {
    class CreateWalletDialog;
}

/** Dialog for creating wallets
 */
class CreateWalletDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CreateWalletDialog(QWidget* parent);
    virtual ~CreateWalletDialog();

    void setSigners(const std::vector<std::unique_ptr<interfaces::ExternalSigner>>& signers);

    QString walletName() const;
    bool isEncryptWalletChecked() const;
    bool isDisablePrivateKeysChecked() const;
    bool isMakeBlankWalletChecked() const;
    bool isExternalSignerChecked() const;
    bool isGenerateMnemonicChecked() const;
    QString generatedMnemonic() const;

private:
    Ui::CreateWalletDialog *ui;
    bool m_has_signers = false;
    QCheckBox* m_mnemonicCheckbox{nullptr};
    MnemonicWidget* m_mnemonicWidget{nullptr};
    QString m_generatedMnemonic;
};

#endif // BITCOIN_QT_CREATEWALLETDIALOG_H
