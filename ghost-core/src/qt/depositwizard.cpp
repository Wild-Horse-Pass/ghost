// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/depositwizard.h>

#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>
#include <qt/l2walletmodel.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <interfaces/wallet.h>
#include <key_io.h>
#include <outputtype.h>

#include <QButtonGroup>
#include <QComboBox>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QRadioButton>
#include <QVBoxLayout>

// ===== DepositWizard =====

DepositWizard::DepositWizard(const PlatformStyle *_platformStyle,
                             WalletModel *_walletModel,
                             L2WalletModel *_l2WalletModel,
                             QWidget *parent)
    : QWizard(parent),
      walletModel(_walletModel),
      l2WalletModel(_l2WalletModel),
      platformStyle(_platformStyle)
{
    setWindowTitle(tr("Deposit to Ghost Pay"));
    setWizardStyle(QWizard::ModernStyle);
    setOption(QWizard::NoBackButtonOnStartPage);

    // Add pages
    setPage(Page_Denomination, new DenominationPage(this));
    setPage(Page_SelectUTXO, new SelectUTXOPage(walletModel, this));
    setPage(Page_JoinWraith, new JoinWraithPage(l2WalletModel, this));
    setPage(Page_Signing, new SigningPage(this));
    setPage(Page_Complete, new CompletePage(this));

    setStartId(Page_Denomination);

    // Connect L2 model signals
    if (l2WalletModel) {
        connect(l2WalletModel, &L2WalletModel::wraithJoined, this, &DepositWizard::onWraithJoined);
        connect(l2WalletModel, &L2WalletModel::wraithPhaseChanged, this, &DepositWizard::onWraithPhaseChanged);
        connect(l2WalletModel, &L2WalletModel::wraithComplete, this, &DepositWizard::onWraithComplete);
        connect(l2WalletModel, &L2WalletModel::wraithError, this, &DepositWizard::onWraithError);
    }

    connect(this, &QWizard::rejected, this, &DepositWizard::depositCancelled);
}

void DepositWizard::setDenomination(GhostPay::Denomination denom)
{
    m_denomination = denom;
}

void DepositWizard::setSelectedUtxo(const QString& txid, uint32_t vout, int64_t amount)
{
    m_utxoTxid = txid;
    m_utxoVout = vout;
    m_utxoAmount = amount;
}

void DepositWizard::onWraithJoined(const QString& sessionId)
{
    m_sessionId = sessionId;
    JoinWraithPage* joinPage = qobject_cast<JoinWraithPage*>(page(Page_JoinWraith));
    if (joinPage) {
        joinPage->onWraithJoined(sessionId);
    }
}

void DepositWizard::onWraithPhaseChanged(const QString& sessionId, GhostPay::WraithPhase phase)
{
    if (sessionId != m_sessionId) return;

    SigningPage* signPage = qobject_cast<SigningPage*>(page(Page_Signing));
    if (signPage) {
        signPage->onPhaseChanged(phase);
    }
}

void DepositWizard::onWraithComplete(const QString& sessionId, const QString& lockId)
{
    if (sessionId != m_sessionId) return;

    m_newLockId = lockId;
    SigningPage* signPage = qobject_cast<SigningPage*>(page(Page_Signing));
    if (signPage) {
        signPage->onComplete(lockId);
    }
}

void DepositWizard::onWraithError(const QString& error)
{
    JoinWraithPage* joinPage = qobject_cast<JoinWraithPage*>(page(Page_JoinWraith));
    if (joinPage && currentId() == Page_JoinWraith) {
        joinPage->onWraithError(error);
        return;
    }

    SigningPage* signPage = qobject_cast<SigningPage*>(page(Page_Signing));
    if (signPage && currentId() == Page_Signing) {
        signPage->onError(error);
    }
}

// ===== DenominationPage =====

DenominationPage::DenominationPage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Select Denomination"));
    setSubTitle(tr("Choose the denomination tier for your Ghost Lock. Larger denominations have lower fees but require more funds."));

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

void DenominationPage::initializePage()
{
    updateInfo();
}

bool DenominationPage::validatePage()
{
    DepositWizard *wiz = qobject_cast<DepositWizard*>(wizard());
    if (wiz) {
        wiz->setDenomination(selectedDenomination());
    }
    return true;
}

int DenominationPage::nextId() const
{
    return DepositWizard::Page_SelectUTXO;
}

GhostPay::Denomination DenominationPage::selectedDenomination() const
{
    return static_cast<GhostPay::Denomination>(denomGroup->checkedId());
}

void DenominationPage::updateInfo()
{
    GhostPay::Denomination denom = selectedDenomination();
    int64_t sats = GhostPay::denominationSats(denom);

    QString info = tr("Selected: %1\n\n"
                      "You will need a UTXO with at least %2 sats to create this lock. "
                      "The Wraith protocol will mix your deposit with other participants "
                      "for enhanced privacy.")
        .arg(GhostPay::denominationName(denom))
        .arg(sats);

    infoLabel->setText(info);
}

// ===== SelectUTXOPage =====

SelectUTXOPage::SelectUTXOPage(WalletModel *_walletModel, QWidget *parent)
    : QWizardPage(parent),
      walletModel(_walletModel)
{
    setTitle(tr("Select UTXO"));
    setSubTitle(tr("Choose a UTXO to deposit into Ghost Pay."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    requiredLabel = new QLabel(this);
    layout->addWidget(requiredLabel);

    utxoList = new QListWidget(this);
    utxoList->setSelectionMode(QAbstractItemView::SingleSelection);
    layout->addWidget(utxoList);

    selectedLabel = new QLabel(this);
    selectedLabel->setStyleSheet(QStringLiteral("QLabel { font-weight: bold; }"));
    layout->addWidget(selectedLabel);

    connect(utxoList, &QListWidget::itemSelectionChanged, this, &SelectUTXOPage::onUtxoSelected);
}

void SelectUTXOPage::initializePage()
{
    DepositWizard *wiz = qobject_cast<DepositWizard*>(wizard());
    GhostPay::Denomination denom = wiz ? wiz->selectedDenomination() : GhostPay::Denomination::Small;
    int64_t required = GhostPay::denominationSats(denom);

    requiredLabel->setText(tr("Required: at least %1 sats for %2 denomination")
        .arg(required)
        .arg(GhostPay::denominationName(denom)));

    populateUtxoList();
}

void SelectUTXOPage::populateUtxoList()
{
    utxoList->clear();
    m_utxos.clear();
    m_selectedIndex = -1;

    DepositWizard *wiz = qobject_cast<DepositWizard*>(wizard());
    GhostPay::Denomination denom = wiz ? wiz->selectedDenomination() : GhostPay::Denomination::Small;
    int64_t required = GhostPay::denominationSats(denom);

    if (!walletModel) return;

    for (const auto& coins : walletModel->wallet().listCoins()) {
        for (const auto& outpair : coins.second) {
            const COutPoint& output = std::get<0>(outpair);
            const interfaces::WalletTxOut& out = std::get<1>(outpair);

            if (out.is_spent) continue;
            if (out.txout.nValue < required) continue;

            UtxoEntry entry{
                QString::fromStdString(output.hash.ToString()),
                output.n,
                out.txout.nValue
            };
            m_utxos.append(entry);

            QString text = QStringLiteral("%1:%2 - %3")
                .arg(entry.txid.left(16) + QStringLiteral("..."))
                .arg(entry.vout)
                .arg(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, entry.amount, false, BitcoinUnits::SeparatorStyle::ALWAYS));
            utxoList->addItem(text);
        }
    }

    if (m_utxos.isEmpty()) {
        QListWidgetItem *noCoins = new QListWidgetItem(
            tr("No UTXOs available with at least %1 sats").arg(required));
        noCoins->setFlags(noCoins->flags() & ~Qt::ItemIsSelectable);
        utxoList->addItem(noCoins);
    }

    selectedLabel->setText(tr("No UTXO selected"));
}

void SelectUTXOPage::onUtxoSelected()
{
    QList<QListWidgetItem*> selected = utxoList->selectedItems();
    if (selected.isEmpty() || m_utxos.isEmpty()) {
        m_selectedIndex = -1;
        selectedLabel->setText(tr("No UTXO selected"));
        return;
    }

    m_selectedIndex = utxoList->row(selected.first());
    if (m_selectedIndex >= 0 && m_selectedIndex < m_utxos.size()) {
        const UtxoEntry& entry = m_utxos[m_selectedIndex];
        selectedLabel->setText(tr("Selected: %1 sats").arg(entry.amount));
    }

    Q_EMIT completeChanged();
}

bool SelectUTXOPage::validatePage()
{
    if (m_selectedIndex < 0 || m_selectedIndex >= m_utxos.size()) {
        return false;
    }

    DepositWizard *wiz = qobject_cast<DepositWizard*>(wizard());
    if (wiz) {
        const UtxoEntry& entry = m_utxos[m_selectedIndex];
        wiz->setSelectedUtxo(entry.txid, entry.vout, entry.amount);
    }
    return true;
}

int SelectUTXOPage::nextId() const
{
    return DepositWizard::Page_JoinWraith;
}

bool SelectUTXOPage::isComplete() const
{
    return m_selectedIndex >= 0;
}

QString SelectUTXOPage::selectedTxid() const
{
    if (m_selectedIndex >= 0 && m_selectedIndex < m_utxos.size()) {
        return m_utxos[m_selectedIndex].txid;
    }
    return QString();
}

uint32_t SelectUTXOPage::selectedVout() const
{
    if (m_selectedIndex >= 0 && m_selectedIndex < m_utxos.size()) {
        return m_utxos[m_selectedIndex].vout;
    }
    return 0;
}

int64_t SelectUTXOPage::selectedAmount() const
{
    if (m_selectedIndex >= 0 && m_selectedIndex < m_utxos.size()) {
        return m_utxos[m_selectedIndex].amount;
    }
    return 0;
}

// ===== JoinWraithPage =====

JoinWraithPage::JoinWraithPage(L2WalletModel *_l2WalletModel, QWidget *parent)
    : QWizardPage(parent),
      l2WalletModel(_l2WalletModel)
{
    setTitle(tr("Join Wraith Session"));
    setSubTitle(tr("Join a Wraith mixing session to deposit your funds privately."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    QLabel *infoLabel = new QLabel(tr(
        "The Wraith protocol mixes your deposit with other participants in two phases:\n\n"
        "Phase 1 (Split): Your UTXO is split into denomination-sized outputs\n"
        "Phase 2 (Merge): Outputs are shuffled and merged into Ghost Locks\n\n"
        "This process typically takes 1-2 minutes."
    ), this);
    infoLabel->setWordWrap(true);
    layout->addWidget(infoLabel);

    layout->addSpacing(20);

    joinButton = new QPushButton(tr("Join Session"), this);
    layout->addWidget(joinButton, 0, Qt::AlignCenter);

    layout->addSpacing(10);

    statusLabel = new QLabel(tr("Not joined"), this);
    statusLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(statusLabel);

    participantLabel = new QLabel(this);
    participantLabel->setAlignment(Qt::AlignCenter);
    participantLabel->setVisible(false);
    layout->addWidget(participantLabel);

    progressBar = new QProgressBar(this);
    progressBar->setRange(0, 0);  // Indeterminate
    progressBar->setVisible(false);
    layout->addWidget(progressBar);

    layout->addStretch();

    connect(joinButton, &QPushButton::clicked, this, &JoinWraithPage::onJoinClicked);
}

void JoinWraithPage::initializePage()
{
    m_joined = false;
    joinButton->setEnabled(true);
    statusLabel->setText(tr("Not joined"));
    participantLabel->setVisible(false);
    progressBar->setVisible(false);
}

void JoinWraithPage::onJoinClicked()
{
    DepositWizard *wiz = qobject_cast<DepositWizard*>(wizard());
    if (!wiz || !l2WalletModel) return;

    // Generate a new destination for the Ghost Lock output
    auto dest = wiz->getWalletModel()->wallet().getNewDestination(
        OutputType::BECH32M, "Ghost Lock Deposit");
    if (!dest) {
        statusLabel->setText(tr("Failed to generate deposit address"));
        statusLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));
        return;
    }
    QString outputPubkey = QString::fromStdString(EncodeDestination(*dest));

    joinButton->setEnabled(false);
    statusLabel->setText(tr("Joining session..."));
    progressBar->setVisible(true);

    l2WalletModel->joinWraithDeposit(
        wiz->selectedDenomination(),
        wiz->selectedUtxoTxid(),
        wiz->selectedUtxoVout(),
        wiz->selectedUtxoAmount(),
        outputPubkey);
}

void JoinWraithPage::onWraithJoined(const QString& sessionId)
{
    m_joined = true;
    statusLabel->setText(tr("Joined session: %1").arg(sessionId.left(16) + QStringLiteral("...")));
    participantLabel->setText(tr("Waiting for participants..."));
    participantLabel->setVisible(true);

    Q_EMIT completeChanged();
}

void JoinWraithPage::onWraithError(const QString& error)
{
    m_joined = false;
    joinButton->setEnabled(true);
    progressBar->setVisible(false);
    statusLabel->setText(tr("Error: %1").arg(error));
    statusLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));
}

bool JoinWraithPage::validatePage()
{
    return m_joined;
}

int JoinWraithPage::nextId() const
{
    return DepositWizard::Page_Signing;
}

bool JoinWraithPage::isComplete() const
{
    return m_joined;
}

// ===== SigningPage =====

SigningPage::SigningPage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Wraith Protocol"));
    setSubTitle(tr("The mixing protocol is in progress."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    phaseLabel = new QLabel(tr("Current Phase: Waiting"), this);
    phaseLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 14pt; font-weight: bold; }"));
    layout->addWidget(phaseLabel);

    layout->addSpacing(20);

    QHBoxLayout *phase1Layout = new QHBoxLayout();
    phase1Label = new QLabel(tr("Phase 1 (Split): Pending"), this);
    phase1Layout->addWidget(phase1Label);
    layout->addLayout(phase1Layout);

    QHBoxLayout *phase2Layout = new QHBoxLayout();
    phase2Label = new QLabel(tr("Phase 2 (Merge): Pending"), this);
    phase2Layout->addWidget(phase2Label);
    layout->addLayout(phase2Layout);

    layout->addSpacing(20);

    progressBar = new QProgressBar(this);
    progressBar->setRange(0, 100);
    progressBar->setValue(0);
    layout->addWidget(progressBar);

    statusLabel = new QLabel(tr("Waiting for protocol to begin..."), this);
    statusLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(statusLabel);

    layout->addStretch();
}

void SigningPage::initializePage()
{
    m_complete = false;
    m_error.clear();
    progressBar->setValue(0);
    phaseLabel->setText(tr("Current Phase: Waiting"));
    phase1Label->setText(tr("Phase 1 (Split): Pending"));
    phase2Label->setText(tr("Phase 2 (Merge): Pending"));
    statusLabel->setText(tr("Waiting for protocol to begin..."));
}

void SigningPage::onPhaseChanged(GhostPay::WraithPhase phase)
{
    switch (phase) {
    case GhostPay::WraithPhase::Forming:
        phaseLabel->setText(tr("Current Phase: Forming"));
        statusLabel->setText(tr("Waiting for participants..."));
        progressBar->setValue(10);
        break;

    case GhostPay::WraithPhase::Phase1Ready:
        phaseLabel->setText(tr("Current Phase: Phase 1 (Split)"));
        phase1Label->setText(tr("Phase 1 (Split): Ready to sign"));
        phase1Label->setStyleSheet(QStringLiteral("QLabel { color: orange; }"));
        progressBar->setValue(25);
        statusLabel->setText(tr("Signing split transaction..."));
        break;

    case GhostPay::WraithPhase::Phase1Signed:
        phase1Label->setText(tr("Phase 1 (Split): Signed"));
        phase1Label->setStyleSheet(QStringLiteral("QLabel { color: green; }"));
        progressBar->setValue(50);
        statusLabel->setText(tr("Waiting for Phase 2..."));
        break;

    case GhostPay::WraithPhase::Phase2Ready:
        phaseLabel->setText(tr("Current Phase: Phase 2 (Merge)"));
        phase2Label->setText(tr("Phase 2 (Merge): Ready to sign"));
        phase2Label->setStyleSheet(QStringLiteral("QLabel { color: orange; }"));
        progressBar->setValue(65);
        statusLabel->setText(tr("Signing merge transaction..."));
        break;

    case GhostPay::WraithPhase::Phase2Signed:
        phase2Label->setText(tr("Phase 2 (Merge): Signed"));
        phase2Label->setStyleSheet(QStringLiteral("QLabel { color: green; }"));
        progressBar->setValue(85);
        statusLabel->setText(tr("Broadcasting..."));
        break;

    case GhostPay::WraithPhase::Complete:
        phase2Label->setText(tr("Phase 2 (Merge): Complete"));
        phase2Label->setStyleSheet(QStringLiteral("QLabel { color: green; }"));
        progressBar->setValue(100);
        break;

    case GhostPay::WraithPhase::Failed:
        phaseLabel->setText(tr("Failed"));
        phaseLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));
        break;
    }
}

void SigningPage::onComplete(const QString& lockId)
{
    m_complete = true;
    phaseLabel->setText(tr("Complete!"));
    phaseLabel->setStyleSheet(QStringLiteral("QLabel { color: green; font-size: 14pt; font-weight: bold; }"));
    phase2Label->setText(tr("Phase 2 (Merge): Complete"));
    phase2Label->setStyleSheet(QStringLiteral("QLabel { color: green; }"));
    progressBar->setValue(100);
    statusLabel->setText(tr("Ghost Lock created: %1").arg(lockId.left(16) + QStringLiteral("...")));

    Q_EMIT completeChanged();
}

void SigningPage::onError(const QString& error)
{
    m_error = error;
    phaseLabel->setText(tr("Error"));
    phaseLabel->setStyleSheet(QStringLiteral("QLabel { color: red; font-size: 14pt; font-weight: bold; }"));
    statusLabel->setText(error);
    statusLabel->setStyleSheet(QStringLiteral("QLabel { color: red; }"));
}

bool SigningPage::validatePage()
{
    return m_complete && m_error.isEmpty();
}

int SigningPage::nextId() const
{
    return m_complete ? DepositWizard::Page_Complete : -1;
}

bool SigningPage::isComplete() const
{
    return m_complete;
}

// ===== CompletePage =====

CompletePage::CompletePage(QWidget *parent)
    : QWizardPage(parent)
{
    setTitle(tr("Deposit Complete"));
    setSubTitle(tr("Your deposit has been successfully processed."));

    QVBoxLayout *layout = new QVBoxLayout(this);

    successLabel = new QLabel(this);
    successLabel->setAlignment(Qt::AlignCenter);
    successLabel->setStyleSheet(QStringLiteral("QLabel { font-size: 18pt; color: green; }"));
    successLabel->setText(tr("Success!"));
    layout->addWidget(successLabel);

    layout->addSpacing(20);

    QGridLayout *detailsLayout = new QGridLayout();

    detailsLayout->addWidget(new QLabel(tr("Ghost Lock ID:"), this), 0, 0);
    lockIdLabel = new QLabel(this);
    lockIdLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    detailsLayout->addWidget(lockIdLabel, 0, 1);

    detailsLayout->addWidget(new QLabel(tr("Denomination:"), this), 1, 0);
    denominationLabel = new QLabel(this);
    detailsLayout->addWidget(denominationLabel, 1, 1);

    detailsLayout->addWidget(new QLabel(tr("Initial Balance:"), this), 2, 0);
    balanceLabel = new QLabel(this);
    detailsLayout->addWidget(balanceLabel, 2, 1);

    layout->addLayout(detailsLayout);

    layout->addSpacing(20);

    QLabel *infoLabel = new QLabel(tr(
        "Your funds are now available for instant private L2 payments.\n"
        "You can manage your Ghost Locks from the Ghost Locks page."
    ), this);
    infoLabel->setWordWrap(true);
    infoLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(infoLabel);

    layout->addStretch();
}

void CompletePage::initializePage()
{
    DepositWizard *wiz = qobject_cast<DepositWizard*>(wizard());
    if (!wiz) return;

    lockIdLabel->setText(wiz->newLockId());
    denominationLabel->setText(GhostPay::denominationName(wiz->selectedDenomination()));

    int64_t balance = GhostPay::denominationSats(wiz->selectedDenomination());
    balanceLabel->setText(BitcoinUnits::formatWithUnit(BitcoinUnit::BTC, balance, false, BitcoinUnits::SeparatorStyle::ALWAYS));

    Q_EMIT wiz->depositComplete(wiz->newLockId());
}

int CompletePage::nextId() const
{
    return -1;  // End of wizard
}
