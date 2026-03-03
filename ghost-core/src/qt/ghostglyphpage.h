// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_GHOSTGLYPHPAGE_H
#define GHOST_QT_GHOSTGLYPHPAGE_H

#include <QWidget>
#include <QColor>
#include <array>

class GhostPayClient;
class PlatformStyle;
class QLabel;
class QLineEdit;
class QPushButton;

class GlyphGridWidget : public QWidget
{
    Q_OBJECT

public:
    explicit GlyphGridWidget(QWidget* parent = nullptr);

    void setPixels(const std::array<uint8_t, 256>& px);
    const std::array<uint8_t, 256>& pixels() const { return m_pixels; }
    void setSelectedColor(int color) { m_selectedColor = color; }
    void clear();

Q_SIGNALS:
    void pixelsChanged();

protected:
    void paintEvent(QPaintEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;

private:
    static constexpr int GRID_SIZE = 16;
    static constexpr int CELL_SIZE = 20;

    void paintCell(int index);
    int cellIndexAt(const QPoint& pos) const;

    std::array<uint8_t, 256> m_pixels{};
    int m_selectedColor{1};
    bool m_painting{false};
};

class GlyphPreviewWidget : public QWidget
{
    Q_OBJECT

public:
    explicit GlyphPreviewWidget(QWidget* parent = nullptr);

    void setPixels(const std::array<uint8_t, 256>& px);

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    static constexpr int PREVIEW_SIZE = 128;
    static constexpr int GRID_SIZE = 16;

    std::array<uint8_t, 256> m_pixels{};
};

class GhostGlyphPage : public QWidget
{
    Q_OBJECT

public:
    explicit GhostGlyphPage(const PlatformStyle* platformStyle, QWidget* parent = nullptr);

    void setGhostPayClient(GhostPayClient* client);

    static const QColor s_palette[26];

private Q_SLOTS:
    void onCheckAvailability();
    void onClaim();
    void onLoadExisting();
    void onClear();
    void onPaletteSelected(int index);
    void onPixelsChanged();

    void onGlyphClaimed(const QString& commitment, const QString& bitmapHash);
    void onGlyphReceived(const QString& ghostId, const QByteArray& pixels,
                         const QString& bitmapHash, const QString& commitment,
                         const QString& status);
    void onGlyphAvailabilityChecked(bool available);
    void onGlyphError(const QString& error);

private:
    static QByteArray computeBitmapHash(const std::array<uint8_t, 256>& pixels);

    GhostPayClient* m_client{nullptr};
    GlyphGridWidget* m_gridWidget;
    GlyphPreviewWidget* m_previewWidget;
    QLineEdit* m_ghostIdEdit;
    QLabel* m_statusLabel;
    QList<QPushButton*> m_paletteButtons;
    int m_selectedColor{1};
};

#endif // GHOST_QT_GHOSTGLYPHPAGE_H
