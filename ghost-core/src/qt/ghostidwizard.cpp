// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/ghostidwizard.h>

#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>
#include <qt/l2walletmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <QGridLayout>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QProgressBar>
#include <QPushButton>
#include <QVBoxLayout>

// ===== GhostIdWizard =====

GhostIdWizard::GhostIdWizard(const PlatformStyle *_platformStyle,
                               WalletModel *_walletModel,
                               L2WalletModel *_l2WalletModel,
                               QWidget *parent)
    : QWizard(parent),
      walletModel(_walletModel),
      l2WalletModel(_l2WalletModel),
      platformStyle(_platformStyle)
{
    setWindowTitle(tr("Generate Ghost ID"));
    setWizardStyle(QWizard::ModernStyle);
    setOption(QWizard::NoBackButtonOnStartPage);

    setPage(Page_Welcome, new GhostIdWelcomePage(this));
    setPage(Page_Generate, new GhostIdGeneratePage(l2WalletModel, this));
    setPage(Page_Complete, new GhostIdCompletePage(this));

    setStartId(Page_Welcome);

    connect(this, &QWizard::rejected, this, &GhostIdWizard::operationCancelled);
}

void GhostIdWizard::onKeyGenerated(const QString& ghostId, const QString& scanPubkey, const QString& spendPubkey)
{
    m_ghostId = ghostId;
    m_scanPubkey = scanPubkey;
    m_spendPubkey = spendPubkey;

    GhostIdGeneratePage* genPage = qobject_cast<GhostIdGeneratePage*>(page(Page_Generate));
    if (genPage) {
        genPage->onGenerated(ghostId, scanPubkey, spendPubkey);
    }
}

void GhostIdWizard::onKeyGenerationError(const QString& error)
{
    GhostIdGeneratePage* genPage = qobject_cast<GhostIdGeneratePage*>(page(Page_Generate));
    if (genPage) {
        genPage->onError(error);
    }
}

// ===== GhostIdWelcomePage =====

GhostIdWelcomePage::GhostIdWelcomePage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Welcome"));
    setSubTitle(tr("This wizard will generate a new Ghost ID for receiving private L2 payments."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    infoLabel = new QLabel(tr(
        "A Ghost ID is a silent payment address derived from your wallet's keys.\n\n"
        "With a Ghost ID, you can:\n"
        "  - Receive instant L2 payments from anyone\n"
        "  - Maintain privacy (each payment creates a unique derived address)\n"
        "  - Share one address publicly without linking payments\n\n"
        "The generation process will:\n"
        "  1. Derive a scan and spend key pair from your wallet\n"
        "  2. Register the keys with the Ghost Pay network\n"
        "  3. Produce your shareable Ghost ID\n\n"
        "You should back up your wallet after generating a Ghost ID."
    ), this);
    infoLabel->setWordWrap(true);
    layout->addWidget(infoLabel);

    layout->addStretch();
}

void GhostIdWelcomePage::initializePage()
{
    // Nothing to initialize
}

int GhostIdWelcomePage::nextId() const
{
    return GhostIdWizard::Page_Generate;
}

// ===== GhostIdGeneratePage =====

GhostIdGeneratePage::GhostIdGeneratePage(L2WalletModel *_l2WalletModel, QWidget *parent)
    : QWizardPage(parent),
      l2WalletModel(_l2WalletModel)
{
    setTitle(tr("Generate Ghost ID"));
    setSubTitle(tr("Click the button below to generate your Ghost ID."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    layout->addStretch();

    generateButton = new QPushButton(tr("Generate Ghost ID"), this);
    generateButton->setMinimumHeight(40);
    layout->addWidget(generateButton, 0, Qt::AlignCenter);

    layout->addSpacing(20);

    statusLabel = new QLabel(tr("Ready to generate"), this);
    statusLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(statusLabel);

    progressBar = new QProgressBar(this);
    progressBar->setRange(0, 0);  // Indeterminate
    progressBar->setVisible(false);
    layout->addWidget(progressBar);

    layout->addStretch();

    connect(generateButton, &QPushButton::clicked, this, &GhostIdGeneratePage::onGenerateClicked);
}

void GhostIdGeneratePage::initializePage()
{
    m_generated = false;
    generateButton->setEnabled(true);
    statusLabel->setText(tr("Ready to generate"));
    statusLabel->setStyleSheet(QString());
    progressBar->setVisible(false);
}

void GhostIdGeneratePage::onGenerateClicked()
{
    if (!l2WalletModel || !l2WalletModel->client() || !l2WalletModel->client()->isConfigured()) {
        statusLabel->setText(tr("Ghost Pay node not connected"));
        statusLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));
        return;
    }

    generateButton->setEnabled(false);
    statusLabel->setText(tr("Generating keys..."));
    progressBar->setVisible(true);

    // POST /api/v1/keys/generate via QNetworkAccessManager
    QNetworkAccessManager *nam = new QNetworkAccessManager(this);
    QNetworkRequest request(QUrl(QStringLiteral("http://127.0.0.1:8800/api/v1/keys/generate")));
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

    QJsonObject body;
    QByteArray payload = QJsonDocument(body).toJson(QJsonDocument::Compact);

    QNetworkReply *reply = nam->post(request, payload);
    connect(reply, &QNetworkReply::finished, this, [this, reply, nam]() {
        reply->deleteLater();
        nam->deleteLater();

        if (reply->error() != QNetworkReply::NoError) {
            GhostIdWizard *wiz = qobject_cast<GhostIdWizard*>(wizard());
            if (wiz) wiz->onKeyGenerationError(reply->errorString());
            return;
        }

        QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        QJsonObject obj = doc.object();

        QString ghostId = obj[QStringLiteral("ghost_id")].toString();
        QString scanPub = obj[QStringLiteral("scan_pubkey")].toString();
        QString spendPub = obj[QStringLiteral("spend_pubkey")].toString();

        GhostIdWizard *wiz = qobject_cast<GhostIdWizard*>(wizard());
        if (wiz) wiz->onKeyGenerated(ghostId, scanPub, spendPub);
    });
}

void GhostIdGeneratePage::onGenerated(const QString& ghostId, const QString& scanPubkey, const QString& spendPubkey)
{
    Q_UNUSED(scanPubkey)
    Q_UNUSED(spendPubkey)

    m_generated = true;
    progressBar->setVisible(false);
    statusLabel->setText(tr("Ghost ID generated: %1").arg(ghostId.left(20) + QStringLiteral("...")));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { color: green; }"));

    Q_EMIT completeChanged();
}

void GhostIdGeneratePage::onError(const QString& error)
{
    m_generated = false;
    generateButton->setEnabled(true);
    progressBar->setVisible(false);
    statusLabel->setText(tr("Error: %1").arg(error));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));
}

bool GhostIdGeneratePage::validatePage()
{
    return m_generated;
}

int GhostIdGeneratePage::nextId() const
{
    return m_generated ? GhostIdWizard::Page_Complete : -1;
}

bool GhostIdGeneratePage::isComplete() const
{
    return m_generated;
}

// ===== GhostIdCompletePage =====

GhostIdCompletePage::GhostIdCompletePage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Ghost ID Generated"));
    setSubTitle(tr("Your Ghost ID has been successfully generated."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    successLabel = new QLabel(this);
    successLabel->setAlignment(Qt::AlignCenter);
    successLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 18pt; color: green; }"));
    successLabel->setText(tr("Success!"));
    layout->addWidget(successLabel);

    layout->addSpacing(20);

    QGridLayout *detailsLayout = new QGridLayout();

    detailsLayout->addWidget(new QLabel(tr("Ghost ID:"), this), 0, 0);
    ghostIdLabel = new QLabel(this);
    ghostIdLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    ghostIdLabel->setWordWrap(true);
    detailsLayout->addWidget(ghostIdLabel, 0, 1);

    detailsLayout->addWidget(new QLabel(tr("Scan Pubkey:"), this), 1, 0);
    scanPubkeyLabel = new QLabel(this);
    scanPubkeyLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    scanPubkeyLabel->setWordWrap(true);
    detailsLayout->addWidget(scanPubkeyLabel, 1, 1);

    detailsLayout->addWidget(new QLabel(tr("Spend Pubkey:"), this), 2, 0);
    spendPubkeyLabel = new QLabel(this);
    spendPubkeyLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    spendPubkeyLabel->setWordWrap(true);
    detailsLayout->addWidget(spendPubkeyLabel, 2, 1);

    layout->addLayout(detailsLayout);

    layout->addSpacing(20);

    backupReminderLabel = new QLabel(tr(
        "IMPORTANT: Back up your wallet now!\n\n"
        "Your Ghost ID keys are derived from your wallet. If you lose your wallet "
        "without a backup, you will lose access to all funds sent to this Ghost ID.\n\n"
        "You can share your Ghost ID with anyone to receive private L2 payments."
    ), this);
    backupReminderLabel->setWordWrap(true);
    backupReminderLabel->setStyleSheet(QStringLiteral("QLabel { color: #cc6600; border: 1px solid #cc6600; padding: 10px; }"));
    layout->addWidget(backupReminderLabel);

    layout->addStretch();
}

void GhostIdCompletePage::initializePage()
{
    GhostIdWizard *wiz = qobject_cast<GhostIdWizard*>(wizard());
    if (!wiz) return;

    ghostIdLabel->setText(wiz->generatedGhostId());
    scanPubkeyLabel->setText(wiz->scanPubkey());
    spendPubkeyLabel->setText(wiz->spendPubkey());

    Q_EMIT wiz->operationComplete(wiz->generatedGhostId());
}

int GhostIdCompletePage::nextId() const
{
    return -1;  // End of wizard
}
