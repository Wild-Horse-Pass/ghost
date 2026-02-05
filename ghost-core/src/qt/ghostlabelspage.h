// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOST_QT_GHOSTLABELSPAGE_H
#define GHOST_QT_GHOSTLABELSPAGE_H

#include <QWidget>
#include <QMenu>

class WalletModel;
class PlatformStyle;

namespace Ui {
    class GhostLabelsPage;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
class QStandardItemModel;
QT_END_NAMESPACE

/**
 * Ghost Labels Manager Page
 * Manages payment labels for categorizing transactions
 *
 * Ghost Labels are encrypted, client-side only metadata that help users
 * organize their transactions. Label names never leave the device.
 */
class GhostLabelsPage : public QWidget
{
    Q_OBJECT

public:
    explicit GhostLabelsPage(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~GhostLabelsPage();

    void setWalletModel(WalletModel *walletModel);

public Q_SLOTS:
    /** Refresh labels from wallet storage */
    void refreshLabels();

private Q_SLOTS:
    void onCreateClicked();
    void onRenameClicked();
    void onDeleteClicked();
    void onExportClicked();
    void onImportClicked();
    void onLabelSelected(const QModelIndex& index);
    void showContextMenu(const QPoint& point);

    // Context menu actions
    void copyLabelName();
    void renameLabelFromMenu();
    void deleteLabelFromMenu();

private:
    void setupContextMenu();
    int getSelectedLabelIndex() const;
    QString getSelectedLabelName() const;
    void updateButtonStates();

    Ui::GhostLabelsPage *ui;
    WalletModel *walletModel{nullptr};
    const PlatformStyle *platformStyle;

    QStandardItemModel *labelsModel{nullptr};
    QMenu *contextMenu{nullptr};

    QAction *copyNameAction{nullptr};
    QAction *renameAction{nullptr};
    QAction *deleteAction{nullptr};
};

#endif // GHOST_QT_GHOSTLABELSPAGE_H
