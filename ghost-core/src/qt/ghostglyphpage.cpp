// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/ghostglyphpage.h>
#include <qt/ghostpayclient.h>
#include <qt/platformstyle.h>

#include <QCryptographicHash>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPainter>
#include <QPushButton>
#include <QVBoxLayout>

// 26-color ghost-themed palette (matches crates/ghost-glyph/src/palette.rs)
const QColor GhostGlyphPage::s_palette[26] = {
    QColor(0, 0, 0),         //  0: Void Black
    QColor(255, 255, 255),    //  1: Phantom White
    QColor(28, 28, 36),       //  2: Midnight
    QColor(48, 48, 64),       //  3: Shadow
    QColor(80, 80, 104),      //  4: Dusk
    QColor(128, 128, 160),    //  5: Fog
    QColor(192, 192, 212),    //  6: Mist
    QColor(24, 32, 80),       //  7: Deep Haunt
    QColor(40, 60, 140),      //  8: Specter Blue
    QColor(64, 100, 200),     //  9: Wraith Blue
    QColor(120, 160, 230),    // 10: Ether
    QColor(16, 48, 32),       // 11: Crypt Green
    QColor(32, 100, 64),      // 12: Ectoplasm
    QColor(80, 200, 120),     // 13: Poltergeist
    QColor(160, 240, 180),    // 14: Spirit Glow
    QColor(80, 16, 16),       // 15: Blood Shadow
    QColor(160, 40, 24),      // 16: Ember
    QColor(220, 80, 40),      // 17: Hellfire
    QColor(255, 160, 80),     // 18: Lantern
    QColor(48, 16, 80),       // 19: Abyss Purple
    QColor(100, 40, 160),     // 20: Phantom Violet
    QColor(160, 80, 220),     // 21: Arcane
    QColor(200, 160, 255),    // 22: Spectral Lilac
    QColor(255, 220, 60),     // 23: Soul Gold
    QColor(0, 200, 200),      // 24: Ghost Teal
    QColor(255, 100, 160),    // 25: Banshee Pink
};

// ========== GlyphGridWidget ==========

GlyphGridWidget::GlyphGridWidget(QWidget* parent)
    : QWidget(parent)
{
    setFixedSize(GRID_SIZE * CELL_SIZE, GRID_SIZE * CELL_SIZE);
    setCursor(Qt::CrossCursor);
    m_pixels.fill(0);
}

void GlyphGridWidget::setPixels(const std::array<uint8_t, 256>& px)
{
    m_pixels = px;
    update();
}

void GlyphGridWidget::clear()
{
    m_pixels.fill(0);
    update();
    Q_EMIT pixelsChanged();
}

void GlyphGridWidget::paintEvent(QPaintEvent* /*event*/)
{
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, false);

    for (int i = 0; i < 256; ++i) {
        int x = (i % GRID_SIZE) * CELL_SIZE;
        int y = (i / GRID_SIZE) * CELL_SIZE;
        uint8_t colorIdx = m_pixels[i];
        if (colorIdx >= 26) colorIdx = 0;
        painter.fillRect(x, y, CELL_SIZE, CELL_SIZE, GhostGlyphPage::s_palette[colorIdx]);
    }

    // Draw grid lines
    painter.setPen(QPen(QColor(60, 60, 70), 1));
    for (int i = 0; i <= GRID_SIZE; ++i) {
        painter.drawLine(i * CELL_SIZE, 0, i * CELL_SIZE, GRID_SIZE * CELL_SIZE);
        painter.drawLine(0, i * CELL_SIZE, GRID_SIZE * CELL_SIZE, i * CELL_SIZE);
    }
}

int GlyphGridWidget::cellIndexAt(const QPoint& pos) const
{
    int col = pos.x() / CELL_SIZE;
    int row = pos.y() / CELL_SIZE;
    if (col < 0 || col >= GRID_SIZE || row < 0 || row >= GRID_SIZE) return -1;
    return row * GRID_SIZE + col;
}

void GlyphGridWidget::paintCell(int index)
{
    if (index < 0 || index >= 256) return;
    if (m_pixels[index] == static_cast<uint8_t>(m_selectedColor)) return;
    m_pixels[index] = static_cast<uint8_t>(m_selectedColor);
    update();
    Q_EMIT pixelsChanged();
}

void GlyphGridWidget::mousePressEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton) {
        m_painting = true;
        paintCell(cellIndexAt(event->pos()));
    }
}

void GlyphGridWidget::mouseMoveEvent(QMouseEvent* event)
{
    if (m_painting) {
        paintCell(cellIndexAt(event->pos()));
    }
}

void GlyphGridWidget::mouseReleaseEvent(QMouseEvent* /*event*/)
{
    m_painting = false;
}

// ========== GlyphPreviewWidget ==========

GlyphPreviewWidget::GlyphPreviewWidget(QWidget* parent)
    : QWidget(parent)
{
    setFixedSize(PREVIEW_SIZE, PREVIEW_SIZE);
    m_pixels.fill(0);
}

void GlyphPreviewWidget::setPixels(const std::array<uint8_t, 256>& px)
{
    m_pixels = px;
    update();
}

void GlyphPreviewWidget::paintEvent(QPaintEvent* /*event*/)
{
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, false);

    int cellSize = PREVIEW_SIZE / GRID_SIZE; // 8
    for (int i = 0; i < 256; ++i) {
        int x = (i % GRID_SIZE) * cellSize;
        int y = (i / GRID_SIZE) * cellSize;
        uint8_t colorIdx = m_pixels[i];
        if (colorIdx >= 26) colorIdx = 0;
        painter.fillRect(x, y, cellSize, cellSize, GhostGlyphPage::s_palette[colorIdx]);
    }
}

// ========== GhostGlyphPage ==========

GhostGlyphPage::GhostGlyphPage(const PlatformStyle* /*platformStyle*/, QWidget* parent)
    : QWidget(parent)
{
    auto* mainLayout = new QVBoxLayout(this);

    // Title
    auto* titleLabel = new QLabel(tr("Ghost Glyphs"));
    titleLabel->setStyleSheet(QStringLiteral("font-size: 18px; font-weight: bold;"));
    mainLayout->addWidget(titleLabel);

    auto* subtitleLabel = new QLabel(tr("Design and claim a unique 16x16 pixel glyph for your Ghost identity"));
    subtitleLabel->setStyleSheet(QStringLiteral("color: gray;"));
    mainLayout->addWidget(subtitleLabel);

    mainLayout->addSpacing(10);

    // Content area: grid+palette on left, preview+controls on right
    auto* contentLayout = new QHBoxLayout();

    // Left column
    auto* leftLayout = new QVBoxLayout();

    auto* editorLabel = new QLabel(tr("Editor"));
    editorLabel->setStyleSheet(QStringLiteral("font-weight: bold;"));
    leftLayout->addWidget(editorLabel);

    m_gridWidget = new GlyphGridWidget(this);
    leftLayout->addWidget(m_gridWidget);

    // Palette
    auto* paletteLabel = new QLabel(tr("Palette"));
    paletteLabel->setStyleSheet(QStringLiteral("font-weight: bold;"));
    leftLayout->addWidget(paletteLabel);

    auto* paletteLayout = new QGridLayout();
    paletteLayout->setSpacing(2);
    for (int i = 0; i < 26; ++i) {
        auto* btn = new QPushButton(this);
        btn->setFixedSize(20, 20);
        btn->setStyleSheet(QStringLiteral("background-color: %1; border: 2px solid %2;")
            .arg(s_palette[i].name(), i == m_selectedColor ? QStringLiteral("#ffffff") : QStringLiteral("#444444")));
        btn->setToolTip(QStringLiteral("Color %1").arg(i));
        connect(btn, &QPushButton::clicked, this, [this, i]() { onPaletteSelected(i); });
        paletteLayout->addWidget(btn, i / 13, i % 13);
        m_paletteButtons.append(btn);
    }
    leftLayout->addLayout(paletteLayout);
    leftLayout->addStretch();

    contentLayout->addLayout(leftLayout);

    // Right column
    auto* rightLayout = new QVBoxLayout();

    auto* previewLabel = new QLabel(tr("Preview"));
    previewLabel->setStyleSheet(QStringLiteral("font-weight: bold;"));
    rightLayout->addWidget(previewLabel);

    m_previewWidget = new GlyphPreviewWidget(this);
    rightLayout->addWidget(m_previewWidget);

    rightLayout->addSpacing(10);

    // Ghost ID input
    auto* ghostIdLabel = new QLabel(tr("Ghost ID"));
    rightLayout->addWidget(ghostIdLabel);

    m_ghostIdEdit = new QLineEdit(this);
    m_ghostIdEdit->setPlaceholderText(tr("Enter ghost ID..."));
    rightLayout->addWidget(m_ghostIdEdit);

    rightLayout->addSpacing(10);

    // Buttons
    auto* buttonLayout = new QHBoxLayout();

    auto* checkBtn = new QPushButton(tr("Check Availability"), this);
    connect(checkBtn, &QPushButton::clicked, this, &GhostGlyphPage::onCheckAvailability);
    buttonLayout->addWidget(checkBtn);

    auto* claimBtn = new QPushButton(tr("Claim"), this);
    connect(claimBtn, &QPushButton::clicked, this, &GhostGlyphPage::onClaim);
    buttonLayout->addWidget(claimBtn);

    auto* loadBtn = new QPushButton(tr("Load Existing"), this);
    connect(loadBtn, &QPushButton::clicked, this, &GhostGlyphPage::onLoadExisting);
    buttonLayout->addWidget(loadBtn);

    auto* clearBtn = new QPushButton(tr("Clear"), this);
    connect(clearBtn, &QPushButton::clicked, this, &GhostGlyphPage::onClear);
    buttonLayout->addWidget(clearBtn);

    rightLayout->addLayout(buttonLayout);

    // Status
    m_statusLabel = new QLabel(this);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setStyleSheet(QStringLiteral("color: gray; padding: 5px;"));
    rightLayout->addWidget(m_statusLabel);

    rightLayout->addStretch();

    contentLayout->addLayout(rightLayout);
    mainLayout->addLayout(contentLayout);

    // Connect grid changes to preview
    connect(m_gridWidget, &GlyphGridWidget::pixelsChanged, this, &GhostGlyphPage::onPixelsChanged);
}

void GhostGlyphPage::setGhostPayClient(GhostPayClient* client)
{
    if (m_client) {
        disconnect(m_client, nullptr, this, nullptr);
    }
    m_client = client;
    if (m_client) {
        connect(m_client, &GhostPayClient::glyphClaimed, this, &GhostGlyphPage::onGlyphClaimed);
        connect(m_client, &GhostPayClient::glyphReceived, this, &GhostGlyphPage::onGlyphReceived);
        connect(m_client, &GhostPayClient::glyphAvailabilityChecked, this, &GhostGlyphPage::onGlyphAvailabilityChecked);
        connect(m_client, &GhostPayClient::glyphError, this, &GhostGlyphPage::onGlyphError);
    }
}

QByteArray GhostGlyphPage::computeBitmapHash(const std::array<uint8_t, 256>& pixels)
{
    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData("GhostGlyphBitmap/v1", 19);
    hash.addData(reinterpret_cast<const char*>(pixels.data()), 256);
    return hash.result().toHex();
}

void GhostGlyphPage::onPaletteSelected(int index)
{
    m_selectedColor = index;
    m_gridWidget->setSelectedColor(index);

    // Update button borders
    for (int i = 0; i < m_paletteButtons.size(); ++i) {
        m_paletteButtons[i]->setStyleSheet(QStringLiteral("background-color: %1; border: 2px solid %2;")
            .arg(s_palette[i].name(), i == m_selectedColor ? QStringLiteral("#ffffff") : QStringLiteral("#444444")));
    }
}

void GhostGlyphPage::onPixelsChanged()
{
    m_previewWidget->setPixels(m_gridWidget->pixels());
}

void GhostGlyphPage::onCheckAvailability()
{
    if (!m_client) {
        m_statusLabel->setText(tr("Ghost Pay client not configured."));
        return;
    }

    QByteArray hashHex = computeBitmapHash(m_gridWidget->pixels());
    m_statusLabel->setText(tr("Checking availability..."));
    m_client->checkGlyphAvailability(QString::fromLatin1(hashHex));
}

void GhostGlyphPage::onClaim()
{
    if (!m_client) {
        m_statusLabel->setText(tr("Ghost Pay client not configured."));
        return;
    }

    QString ghostId = m_ghostIdEdit->text().trimmed();
    if (ghostId.isEmpty()) {
        m_statusLabel->setText(tr("Enter a Ghost ID first."));
        return;
    }

    const auto& px = m_gridWidget->pixels();
    QByteArray pixelData(reinterpret_cast<const char*>(px.data()), 256);
    m_statusLabel->setText(tr("Claiming glyph..."));
    m_client->claimGlyph(ghostId, pixelData);
}

void GhostGlyphPage::onLoadExisting()
{
    if (!m_client) {
        m_statusLabel->setText(tr("Ghost Pay client not configured."));
        return;
    }

    QString ghostId = m_ghostIdEdit->text().trimmed();
    if (ghostId.isEmpty()) {
        m_statusLabel->setText(tr("Enter a Ghost ID to load."));
        return;
    }

    m_statusLabel->setText(tr("Loading glyph..."));
    m_client->getGlyph(ghostId);
}

void GhostGlyphPage::onClear()
{
    m_gridWidget->clear();
    m_previewWidget->setPixels(m_gridWidget->pixels());
    m_statusLabel->setText(tr("Grid cleared."));
}

void GhostGlyphPage::onGlyphClaimed(const QString& commitment, const QString& /*bitmapHash*/)
{
    m_statusLabel->setText(tr("Claimed! Commitment: %1...").arg(commitment.left(16)));
}

void GhostGlyphPage::onGlyphReceived(const QString& ghostId, const QByteArray& pixels,
                                       const QString& /*bitmapHash*/, const QString& /*commitment*/,
                                       const QString& /*status*/)
{
    if (pixels.size() == 256) {
        std::array<uint8_t, 256> px;
        for (int i = 0; i < 256; ++i) {
            px[i] = static_cast<uint8_t>(pixels.at(i));
        }
        m_gridWidget->setPixels(px);
        m_previewWidget->setPixels(px);
        m_statusLabel->setText(tr("Loaded glyph for %1").arg(ghostId));
    } else {
        m_statusLabel->setText(tr("Invalid glyph data received."));
    }
}

void GhostGlyphPage::onGlyphAvailabilityChecked(bool available)
{
    if (available) {
        m_statusLabel->setText(tr("Design is available!"));
    } else {
        m_statusLabel->setText(tr("Design is already claimed."));
    }
}

void GhostGlyphPage::onGlyphError(const QString& error)
{
    m_statusLabel->setText(tr("Error: %1").arg(error));
}
