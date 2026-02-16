// Copyright (c) 2024-present The Ghost Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MNEMONICWIDGET_H
#define BITCOIN_QT_MNEMONICWIDGET_H

#include <QWidget>

class QLabel;
class QLineEdit;
class QPushButton;
class QTextEdit;

class MnemonicWidget : public QWidget
{
    Q_OBJECT

public:
    enum Mode { Display, Verify };

    explicit MnemonicWidget(QWidget* parent = nullptr);
    ~MnemonicWidget();

    /// Set the mnemonic to display (Display mode)
    void setMnemonic(const QString& mnemonic);

    /// Get the displayed mnemonic
    QString mnemonic() const;

    /// Switch to verification mode - user must type words to confirm
    void setVerifyMode();

    /// Check if verification is complete and correct
    bool isVerified() const;

Q_SIGNALS:
    void verificationComplete(bool success);

private Q_SLOTS:
    void onVerifyTextChanged();

private:
    void setupDisplayMode();
    void setupVerifyMode();

    Mode m_mode{Display};
    QString m_mnemonic;
    QTextEdit* m_displayArea{nullptr};
    QTextEdit* m_verifyInput{nullptr};
    QLabel* m_statusLabel{nullptr};
    QPushButton* m_copyButton{nullptr};
    bool m_verified{false};
};

#endif // BITCOIN_QT_MNEMONICWIDGET_H
