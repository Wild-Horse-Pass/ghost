// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/createlockwizard.h>

#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>
#include <qt/l2walletmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <QButtonGroup>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QProgressBar>
#include <QRadioButton>
#include <QVBoxLayout>

// ===== CreateLockWizard =====

CreateLockWizard::CreateLockWizard(const PlatformStyle *_platformStyle,
                                   WalletModel *_walletModel,
                                   L2WalletModel *_l2WalletModel,
                                   QWidget *parent)
    : QWizard(parent),
      walletModel(_walletModel),
      l2WalletModel(_l2WalletModel),
      platformStyle(_platformStyle)
{
    setWindowTitle(tr("Create Ghost Lock"));
    setWizardStyle(QWizard::ModernStyle);
    setOption(QWizard::NoBackButtonOnStartPage);

    setPage(Page_Denomination, new CreateLockDenominationPage(this));
    setPage(Page_Timelock, new TimelockTierPage(this));
    setPage(Page_Label, new LockLabelPage(this));
    setPage(Page_Confirm, new CreateLockConfirmPage(this));
    setPage(Page_Complete, new CreateLockCompletePage(this));

    setStartId(Page_Denomination);

    connect(this, &QWizard::rejected, this, &CreateLockWizard::operationCancelled);
}

void CreateLockWizard::setDenomination(GhostPay::Denomination denom)
{
    m_denomination = denom;
}

void CreateLockWizard::setTimelockTier(GhostPay::TimelockTier tier)
{
    m_timelockTier = tier;
}

void CreateLockWizard::setLabel(const QString& label)
{
    m_label = label;
}

void CreateLockWizard::onLockCreated(const QString& lockId)
{
    m_lockId = lockId;
    CreateLockConfirmPage* confirmPage = qobject_cast<CreateLockConfirmPage*>(page(Page_Confirm));
    if (confirmPage) {
        confirmPage->onCreated(lockId);
    }
}

void CreateLockWizard::onLockCreationError(const QString& error)
{
    CreateLockConfirmPage* confirmPage = qobject_cast<CreateLockConfirmPage*>(page(Page_Confirm));
    if (confirmPage) {
        confirmPage->onError(error);
    }
}

// ===== CreateLockDenominationPage =====

CreateLockDenominationPage::CreateLockDenominationPage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Select Denomination"));
    setSubTitle(tr("Choose the denomination tier for your new Ghost Lock."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    denomGroup = new QButtonGroup(this);

    microButton = new QRadioButton(tr("Micro - 10,000 sats (0.0001 BTC)"));
    tinyButton = new QRadioButton(tr("Tiny - 100,000 sats (0.001 BTC)"));
    smallButton = new QRadioButton(tr("Small - 1,000,000 sats (0.01 BTC)"));
    mediumButton = new QRadioButton(tr("Medium - 10,000,000 sats (0.1 BTC)"));
    largeButton = new QRadioButton(tr("Large - 100,000,000 sats (1 BTC)"));
    xlButton = new QRadioButton(tr("XL - 1,000,000,000 sats (10 BTC)"));

    denomGroup->addButton(microButton, static_cast<int>(GhostPay::Denomination::Micro));
    denomGroup->addButton(tinyButton, static_cast<int>(GhostPay::Denomination::Tiny));
    denomGroup->addButton(smallButton, static_cast<int>(GhostPay::Denomination::Small));
    denomGroup->addButton(mediumButton, static_cast<int>(GhostPay::Denomination::Medium));
    denomGroup->addButton(largeButton, static_cast<int>(GhostPay::Denomination::Large));
    denomGroup->addButton(xlButton, static_cast<int>(GhostPay::Denomination::XL));

    smallButton->setChecked(true);

    layout->addWidget(microButton);
    layout->addWidget(tinyButton);
    layout->addWidget(smallButton);
    layout->addWidget(mediumButton);
    layout->addWidget(largeButton);
    layout->addWidget(xlButton);

    layout->addSpacing(20);

    infoLabel = new QLabel(this);
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet(QStringLiteral("QLabel { color: #666666; }"));
    layout->addWidget(infoLabel);

    layout->addStretch();

    connect(denomGroup, &QButtonGroup::idClicked, this, [this]() { updateInfo(); });
    updateInfo();
}

void CreateLockDenominationPage::initializePage()
{
    updateInfo();
}

bool CreateLockDenominationPage::validatePage()
{
    CreateLockWizard *wiz = qobject_cast<CreateLockWizard*>(wizard());
    if (wiz) {
        wiz->setDenomination(selectedDenomination());
    }
    return true;
}

int CreateLockDenominationPage::nextId() const
{
    return CreateLockWizard::Page_Timelock;
}

GhostPay::Denomination CreateLockDenominationPage::selectedDenomination() const
{
    return static_cast<GhostPay::Denomination>(denomGroup->checkedId());
}

void CreateLockDenominationPage::updateInfo()
{
    GhostPay::Denomination denom = selectedDenomination();
    int64_t sats = GhostPay::denominationSats(denom);

    QString info = tr("Selected: %1\n\n"
                      "This lock will hold exactly %2 sats. Ghost Locks use fixed "
                      "denominations to enhance privacy through uniformity in the anonymity set.")
        .arg(GhostPay::denominationName(denom))
        .arg(sats);

    infoLabel->setText(info);
}

// ===== TimelockTierPage =====

TimelockTierPage::TimelockTierPage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Select Timelock Tier"));
    setSubTitle(tr("Choose how long the recovery timelock should be. Longer timelocks provide better security."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    tierGroup = new QButtonGroup(this);

    shortButton = new QRadioButton(tr("Short - ~3 months (26,280 blocks)"), this);
    standardButton = new QRadioButton(tr("Standard - ~6 months (52,560 blocks)"), this);
    longButton = new QRadioButton(tr("Long - ~1 year (105,120 blocks)"), this);

    tierGroup->addButton(shortButton, static_cast<int>(GhostPay::TimelockTier::Short));
    tierGroup->addButton(standardButton, static_cast<int>(GhostPay::TimelockTier::Standard));
    tierGroup->addButton(longButton, static_cast<int>(GhostPay::TimelockTier::Long));

    standardButton->setChecked(true);

    layout->addWidget(shortButton);

    QLabel *shortInfo = new QLabel(tr("Lower security, but faster recovery if needed. "
                                       "Suitable for smaller amounts or frequent rotation."), this);
    shortInfo->setWordWrap(true);
    shortInfo->setStyleSheet(QStringLiteral("QLabel { color: #666666; margin-left: 20px; margin-bottom: 10px; }"));
    layout->addWidget(shortInfo);

    layout->addWidget(standardButton);

    QLabel *standardInfo = new QLabel(tr("Recommended for most users. Balanced security and recovery time. "
                                          "Suitable for medium-term holdings."), this);
    standardInfo->setWordWrap(true);
    standardInfo->setStyleSheet(QStringLiteral("QLabel { color: #666666; margin-left: 20px; margin-bottom: 10px; }"));
    layout->addWidget(standardInfo);

    layout->addWidget(longButton);

    QLabel *longInfo = new QLabel(tr("Maximum security. Best for large, long-term holdings. "
                                      "Recovery will take approximately one year if keys are lost."), this);
    longInfo->setWordWrap(true);
    longInfo->setStyleSheet(QStringLiteral("QLabel { color: #666666; margin-left: 20px; }"));
    layout->addWidget(longInfo);

    layout->addSpacing(20);

    infoLabel = new QLabel(this);
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet(QStringLiteral("QLabel { color: #666666; }"));
    layout->addWidget(infoLabel);

    layout->addStretch();

    connect(tierGroup, &QButtonGroup::idClicked, this, [this]() { updateInfo(); });
    updateInfo();
}

void TimelockTierPage::initializePage()
{
    updateInfo();
}

bool TimelockTierPage::validatePage()
{
    CreateLockWizard *wiz = qobject_cast<CreateLockWizard*>(wizard());
    if (wiz) {
        wiz->setTimelockTier(selectedTier());
    }
    return true;
}

int TimelockTierPage::nextId() const
{
    return CreateLockWizard::Page_Label;
}

GhostPay::TimelockTier TimelockTierPage::selectedTier() const
{
    return static_cast<GhostPay::TimelockTier>(tierGroup->checkedId());
}

void TimelockTierPage::updateInfo()
{
    GhostPay::TimelockTier tier = selectedTier();
    uint32_t blocks = GhostPay::timelockBlocks(tier);

    infoLabel->setText(tr("The recovery timelock will expire after %1 blocks from the lock's creation height.")
        .arg(blocks));
}

// ===== LockLabelPage =====

LockLabelPage::LockLabelPage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Label (Optional)"));
    setSubTitle(tr("Add an optional label to identify this lock. This is stored locally and not shared on the network."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    QLabel *labelPrompt = new QLabel(tr("Lock Label:"), this);
    layout->addWidget(labelPrompt);

    labelEdit = new QLineEdit(this);
    labelEdit->setPlaceholderText(tr("e.g., Savings, Trading, Donations..."));
    labelEdit->setMaxLength(64);
    layout->addWidget(labelEdit);

    hintLabel = new QLabel(tr("Labels are stored only on your device and help you organize your locks. "
                               "You can leave this empty."), this);
    hintLabel->setWordWrap(true);
    hintLabel->setStyleSheet(QStringLiteral("QLabel { color: #666666; }"));
    layout->addWidget(hintLabel);

    layout->addStretch();
}

void LockLabelPage::initializePage()
{
    // Nothing to initialize
}

bool LockLabelPage::validatePage()
{
    CreateLockWizard *wiz = qobject_cast<CreateLockWizard*>(wizard());
    if (wiz) {
        wiz->setLabel(lockLabel());
    }
    return true;
}

int LockLabelPage::nextId() const
{
    return CreateLockWizard::Page_Confirm;
}

QString LockLabelPage::lockLabel() const
{
    return labelEdit->text().trimmed();
}

// ===== CreateLockConfirmPage =====

CreateLockConfirmPage::CreateLockConfirmPage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Confirm Lock Creation"));
    setSubTitle(tr("Review the details and confirm to create your Ghost Lock."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    summaryLabel = new QLabel(tr("Lock details:"), this);
    layout->addWidget(summaryLabel);

    layout->addSpacing(10);

    QGridLayout *detailsGrid = new QGridLayout();

    detailsGrid->addWidget(new QLabel(tr("Denomination:"), this), 0, 0);
    denominationLabel = new QLabel(this);
    detailsGrid->addWidget(denominationLabel, 0, 1);

    detailsGrid->addWidget(new QLabel(tr("Amount:"), this), 1, 0);
    amountLabel = new QLabel(this);
    amountLabel->setStyleSheet(QStringLiteral("QLabel { font-weight: bold; }"));
    detailsGrid->addWidget(amountLabel, 1, 1);

    detailsGrid->addWidget(new QLabel(tr("Timelock Tier:"), this), 2, 0);
    timelockLabel = new QLabel(this);
    detailsGrid->addWidget(timelockLabel, 2, 1);

    detailsGrid->addWidget(new QLabel(tr("Label:"), this), 3, 0);
    labelLabel = new QLabel(this);
    detailsGrid->addWidget(labelLabel, 3, 1);

    layout->addLayout(detailsGrid);

    layout->addSpacing(20);

    statusLabel = new QLabel(this);
    statusLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(statusLabel);

    progressBar = new QProgressBar(this);
    progressBar->setRange(0, 0);
    progressBar->setVisible(false);
    layout->addWidget(progressBar);

    layout->addStretch();
}

void CreateLockConfirmPage::initializePage()
{
    m_submitted = false;
    m_complete = false;
    m_error.clear();
    statusLabel->clear();
    statusLabel->setStyleSheet(QString());
    progressBar->setVisible(false);

    CreateLockWizard *wiz = qobject_cast<CreateLockWizard*>(wizard());
    if (!wiz) return;

    denominationLabel->setText(GhostPay::denominationName(wiz->selectedDenomination()));

    int64_t sats = GhostPay::denominationSats(wiz->selectedDenomination());
    amountLabel->setText(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, sats, false, BitcoinUnits::SeparatorStyle::ALWAYS));

    GhostPay::TimelockTier tier = wiz->selectedTimelockTier();
    QString tierName;
    switch (tier) {
    case GhostPay::TimelockTier::Short:
        tierName = tr("Short (~3 months)");
        break;
    case GhostPay::TimelockTier::Standard:
        tierName = tr("Standard (~6 months)");
        break;
    case GhostPay::TimelockTier::Long:
        tierName = tr("Long (~1 year)");
        break;
    }
    timelockLabel->setText(tierName);

    QString label = wiz->lockLabel();
    labelLabel->setText(label.isEmpty() ? tr("(none)") : label);
}

bool CreateLockConfirmPage::validatePage()
{
    if (m_complete) return true;

    if (!m_submitted) {
        m_submitted = true;
        statusLabel->setText(tr("Creating lock..."));
        progressBar->setVisible(true);

        CreateLockWizard *wiz = qobject_cast<CreateLockWizard*>(wizard());
        if (!wiz || !wiz->getL2WalletModel() || !wiz->getL2WalletModel()->client()
            || !wiz->getL2WalletModel()->client()->isConfigured()) {
            onError(tr("Ghost Pay node not connected"));
            return false;
        }

        // POST /api/v1/locks/create via QNetworkAccessManager
        QNetworkAccessManager *nam = new QNetworkAccessManager(this);
        QNetworkRequest request(QUrl(QStringLiteral("http://127.0.0.1:8800/api/v1/locks/create")));
        request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));

        QJsonObject body;
        body[QStringLiteral("amount_sats")] = GhostPay::denominationSats(wiz->selectedDenomination());
        body[QStringLiteral("timelock_tier")] = static_cast<int>(wiz->selectedTimelockTier());
        if (!wiz->lockLabel().isEmpty()) {
            body[QStringLiteral("label")] = wiz->lockLabel();
        }

        QByteArray payload = QJsonDocument(body).toJson(QJsonDocument::Compact);
        QNetworkReply *reply = nam->post(request, payload);
        connect(reply, &QNetworkReply::finished, this, [this, reply, nam]() {
            reply->deleteLater();
            nam->deleteLater();

            if (reply->error() != QNetworkReply::NoError) {
                CreateLockWizard *w = qobject_cast<CreateLockWizard*>(wizard());
                if (w) w->onLockCreationError(reply->errorString());
                return;
            }

            QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
            QJsonObject obj = doc.object();
            QString lockId = obj[QStringLiteral("lock_id")].toString();

            CreateLockWizard *w = qobject_cast<CreateLockWizard*>(wizard());
            if (w) w->onLockCreated(lockId);
        });

        return false;  // Wait for async response
    }

    return m_complete && m_error.isEmpty();
}

void CreateLockConfirmPage::onCreated(const QString& lockId)
{
    Q_UNUSED(lockId)
    m_complete = true;
    progressBar->setVisible(false);
    statusLabel->setText(tr("Lock created successfully!"));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { color: green; }"));

    Q_EMIT completeChanged();
}

void CreateLockConfirmPage::onError(const QString& error)
{
    m_error = error;
    m_submitted = false;
    progressBar->setVisible(false);
    statusLabel->setText(tr("Error: %1").arg(error));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));

    Q_EMIT completeChanged();
}

int CreateLockConfirmPage::nextId() const
{
    return m_complete ? CreateLockWizard::Page_Complete : -1;
}

bool CreateLockConfirmPage::isComplete() const
{
    return m_complete;
}

// ===== CreateLockCompletePage =====

CreateLockCompletePage::CreateLockCompletePage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Lock Created"));
    setSubTitle(tr("Your new Ghost Lock has been successfully created."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    successLabel = new QLabel(this);
    successLabel->setAlignment(Qt::AlignCenter);
    successLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 18pt; color: green; }"));
    successLabel->setText(tr("Success!"));
    layout->addWidget(successLabel);

    layout->addSpacing(20);

    QGridLayout *detailsGrid = new QGridLayout();

    detailsGrid->addWidget(new QLabel(tr("Lock ID:"), this), 0, 0);
    lockIdLabel = new QLabel(this);
    lockIdLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    lockIdLabel->setWordWrap(true);
    detailsGrid->addWidget(lockIdLabel, 0, 1);

    detailsGrid->addWidget(new QLabel(tr("Denomination:"), this), 1, 0);
    denominationLabel = new QLabel(this);
    detailsGrid->addWidget(denominationLabel, 1, 1);

    detailsGrid->addWidget(new QLabel(tr("Timelock:"), this), 2, 0);
    timelockLabel = new QLabel(this);
    detailsGrid->addWidget(timelockLabel, 2, 1);

    layout->addLayout(detailsGrid);

    layout->addSpacing(20);

    infoLabel = new QLabel(tr(
        "Your Ghost Lock is now active on the L2 network.\n"
        "You can use it for instant private payments and manage it from the Ghost Locks page."
    ), this);
    infoLabel->setWordWrap(true);
    infoLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(infoLabel);

    layout->addStretch();
}

void CreateLockCompletePage::initializePage()
{
    CreateLockWizard *wiz = qobject_cast<CreateLockWizard*>(wizard());
    if (!wiz) return;

    lockIdLabel->setText(wiz->newLockId());
    denominationLabel->setText(GhostPay::denominationName(wiz->selectedDenomination()));

    GhostPay::TimelockTier tier = wiz->selectedTimelockTier();
    uint32_t blocks = GhostPay::timelockBlocks(tier);
    QString tierName;
    switch (tier) {
    case GhostPay::TimelockTier::Short:
        tierName = tr("Short (~3 months, %1 blocks)").arg(blocks);
        break;
    case GhostPay::TimelockTier::Standard:
        tierName = tr("Standard (~6 months, %1 blocks)").arg(blocks);
        break;
    case GhostPay::TimelockTier::Long:
        tierName = tr("Long (~1 year, %1 blocks)").arg(blocks);
        break;
    }
    timelockLabel->setText(tierName);

    Q_EMIT wiz->operationComplete(wiz->newLockId());
}

int CreateLockCompletePage::nextId() const
{
    return -1;  // End of wizard
}
