// Copyright (c) 2024-present The Ghost Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/mnemonicwidget.h>
#include <qt/guiutil.h>
#include <support/cleanse.h>

#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>

MnemonicWidget::MnemonicWidget(QWidget* parent)
    : QWidget(parent)
{
    setupDisplayMode();
}

MnemonicWidget::~MnemonicWidget()
{
    // Securely wipe mnemonic from memory
    if (!m_mnemonic.isEmpty()) {
        QByteArray data = m_mnemonic.toUtf8();
        memory_cleanse(data.data(), data.size());
        m_mnemonic.clear();
    }
}

void MnemonicWidget::setupDisplayMode()
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    auto* warningLabel = new QLabel(
        tr("<b>Write down these 24 words in order.</b> "
           "This is your only backup. Anyone with these words can access your funds."),
        this);
    warningLabel->setWordWrap(true);
    warningLabel->setStyleSheet("color: #cc6600; padding: 6px;");
    layout->addWidget(warningLabel);

    m_displayArea = new QTextEdit(this);
    m_displayArea->setReadOnly(true);
    m_displayArea->setMinimumHeight(180);
    m_displayArea->setFont(QFont("Courier", 11));
    layout->addWidget(m_displayArea);

    auto* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    m_copyButton = new QPushButton(tr("Copy to Clipboard"), this);
    connect(m_copyButton, &QPushButton::clicked, this, [this] {
        GUIUtil::setClipboard(m_mnemonic);
    });
    buttonLayout->addWidget(m_copyButton);
    layout->addLayout(buttonLayout);

    m_statusLabel = new QLabel(this);
    m_statusLabel->setVisible(false);
    layout->addWidget(m_statusLabel);
}

void MnemonicWidget::setMnemonic(const QString& mnemonic)
{
    m_mnemonic = mnemonic;
    if (m_displayArea) {
        // Format as numbered grid
        QStringList words = mnemonic.split(' ', Qt::SkipEmptyParts);
        QString formatted;
        for (int i = 0; i < words.size(); ++i) {
            formatted += QString("%1. %2").arg(i + 1, 2).arg(words[i]);
            if ((i + 1) % 4 == 0) {
                formatted += "\n";
            } else {
                formatted += "    ";
            }
        }
        m_displayArea->setPlainText(formatted.trimmed());
    }
}

QString MnemonicWidget::mnemonic() const
{
    return m_mnemonic;
}

void MnemonicWidget::setVerifyMode()
{
    m_mode = Verify;

    // Hide display elements
    if (m_displayArea) m_displayArea->setVisible(false);
    if (m_copyButton) m_copyButton->setVisible(false);

    // Create verify input
    auto* layout = qobject_cast<QVBoxLayout*>(this->layout());
    if (!layout) return;

    auto* instructionLabel = new QLabel(
        tr("Please re-enter your 24-word recovery phrase to confirm you saved it correctly:"),
        this);
    instructionLabel->setWordWrap(true);
    layout->insertWidget(1, instructionLabel);

    m_verifyInput = new QTextEdit(this);
    m_verifyInput->setMinimumHeight(100);
    m_verifyInput->setPlaceholderText(tr("Type your 24 words separated by spaces..."));
    m_verifyInput->setFont(QFont("Courier", 11));
    layout->insertWidget(2, m_verifyInput);

    connect(m_verifyInput, &QTextEdit::textChanged, this, &MnemonicWidget::onVerifyTextChanged);

    if (m_statusLabel) {
        m_statusLabel->setVisible(true);
        m_statusLabel->setText(tr("Enter your recovery phrase above"));
    }
}

void MnemonicWidget::onVerifyTextChanged()
{
    if (!m_verifyInput || m_mnemonic.isEmpty()) return;

    QString input = m_verifyInput->toPlainText().simplified().trimmed();
    QStringList inputWords = input.split(' ', Qt::SkipEmptyParts);

    if (inputWords.size() < 24) {
        m_statusLabel->setText(tr("%1 of 24 words entered").arg(inputWords.size()));
        m_statusLabel->setStyleSheet("");
        m_verified = false;
        return;
    }

    // Compare
    QString normalizedInput = inputWords.join(' ');
    if (normalizedInput == m_mnemonic) {
        m_statusLabel->setText(tr("Recovery phrase verified correctly!"));
        m_statusLabel->setStyleSheet("color: green; font-weight: bold;");
        m_verified = true;
        Q_EMIT verificationComplete(true);
    } else {
        m_statusLabel->setText(tr("Recovery phrase does not match. Please check your words."));
        m_statusLabel->setStyleSheet("color: red;");
        m_verified = false;
        Q_EMIT verificationComplete(false);
    }
}

bool MnemonicWidget::isVerified() const
{
    return m_verified;
}
