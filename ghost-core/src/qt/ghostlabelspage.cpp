// Copyright (c) 2024 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/ghostlabelspage.h>
#include <qt/forms/ui_ghostlabelspage.h>

#include <qt/guiutil.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <QApplication>
#include <QClipboard>
#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QStandardItemModel>

// Default label index (Uncategorized) - cannot be renamed or deleted
static const int DEFAULT_LABEL_INDEX = 0;

GhostLabelsPage::GhostLabelsPage(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::GhostLabelsPage),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    // Setup labels model
    labelsModel = new QStandardItemModel(this);
    labelsModel->setHorizontalHeaderLabels({tr("Index"), tr("Label Name")});
    ui->labelsTableView->setModel(labelsModel);

    // Setup table view
    ui->labelsTableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->labelsTableView->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->labelsTableView->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->labelsTableView->verticalHeader()->hide();
    ui->labelsTableView->setShowGrid(false);
    ui->labelsTableView->setAlternatingRowColors(true);
    ui->labelsTableView->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->labelsTableView->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);

    // Connect signals
    connect(ui->labelsTableView->selectionModel(), &QItemSelectionModel::currentChanged,
            this, &GhostLabelsPage::onLabelSelected);
    connect(ui->labelsTableView, &QTableView::customContextMenuRequested,
            this, &GhostLabelsPage::showContextMenu);

    connect(ui->createButton, &QPushButton::clicked, this, &GhostLabelsPage::onCreateClicked);
    connect(ui->renameButton, &QPushButton::clicked, this, &GhostLabelsPage::onRenameClicked);
    connect(ui->deleteButton, &QPushButton::clicked, this, &GhostLabelsPage::onDeleteClicked);
    connect(ui->exportButton, &QPushButton::clicked, this, &GhostLabelsPage::onExportClicked);
    connect(ui->importButton, &QPushButton::clicked, this, &GhostLabelsPage::onImportClicked);

    setupContextMenu();
    updateButtonStates();
}

GhostLabelsPage::~GhostLabelsPage()
{
    delete ui;
}

void GhostLabelsPage::setupContextMenu()
{
    contextMenu = new QMenu(this);

    copyNameAction = contextMenu->addAction(tr("Copy Label Name"), this, &GhostLabelsPage::copyLabelName);
    contextMenu->addSeparator();
    renameAction = contextMenu->addAction(tr("Rename..."), this, &GhostLabelsPage::renameLabelFromMenu);
    deleteAction = contextMenu->addAction(tr("Delete"), this, &GhostLabelsPage::deleteLabelFromMenu);

    if (platformStyle && platformStyle->getImagesOnButtons()) {
        copyNameAction->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/editcopy")));
        deleteAction->setIcon(platformStyle->SingleColorIcon(QStringLiteral(":/icons/remove")));
    }
}

void GhostLabelsPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;

    if (model) {
        refreshLabels();
    }
}

void GhostLabelsPage::refreshLabels()
{
    if (!walletModel) return;

    labelsModel->removeRows(0, labelsModel->rowCount());

    // Get labels from wallet model
    QList<QPair<int, QString>> labels = walletModel->getGhostLabels();

    for (const auto& [index, name] : labels) {
        QList<QStandardItem*> row;

        QStandardItem* indexItem = new QStandardItem(QString::number(index));
        indexItem->setData(index, Qt::UserRole);
        indexItem->setEditable(false);
        indexItem->setTextAlignment(Qt::AlignCenter);

        QStandardItem* nameItem = new QStandardItem(name);
        nameItem->setEditable(false);
        if (index == DEFAULT_LABEL_INDEX) {
            // Style default label differently
            QFont font = nameItem->font();
            font.setItalic(true);
            nameItem->setFont(font);
            nameItem->setText(name + tr(" (default)"));
        }

        row << indexItem << nameItem;
        labelsModel->appendRow(row);
    }

    ui->labelCount->setText(tr("%n label(s)", "", labels.size()));
    updateButtonStates();
}

int GhostLabelsPage::getSelectedLabelIndex() const
{
    QModelIndexList selection = ui->labelsTableView->selectionModel()->selectedRows();
    if (selection.isEmpty()) return -1;

    return labelsModel->item(selection.first().row(), 0)->data(Qt::UserRole).toInt();
}

QString GhostLabelsPage::getSelectedLabelName() const
{
    QModelIndexList selection = ui->labelsTableView->selectionModel()->selectedRows();
    if (selection.isEmpty()) return QString();

    int index = getSelectedLabelIndex();
    if (index == DEFAULT_LABEL_INDEX) {
        return tr("Uncategorized");
    }
    return labelsModel->item(selection.first().row(), 1)->text();
}

void GhostLabelsPage::updateButtonStates()
{
    int selectedIndex = getSelectedLabelIndex();
    bool hasSelection = selectedIndex >= 0;
    bool isDefault = selectedIndex == DEFAULT_LABEL_INDEX;

    ui->renameButton->setEnabled(hasSelection && !isDefault);
    ui->deleteButton->setEnabled(hasSelection && !isDefault);

    if (renameAction) renameAction->setEnabled(hasSelection && !isDefault);
    if (deleteAction) deleteAction->setEnabled(hasSelection && !isDefault);
    if (copyNameAction) copyNameAction->setEnabled(hasSelection);
}

void GhostLabelsPage::onLabelSelected(const QModelIndex& /*index*/)
{
    updateButtonStates();
}

void GhostLabelsPage::onCreateClicked()
{
    if (!walletModel) return;

    bool ok;
    QString name = QInputDialog::getText(this, tr("Create Label"),
        tr("Enter name for the new label:"), QLineEdit::Normal, QString(), &ok);

    if (ok && !name.trimmed().isEmpty()) {
        int index = walletModel->createGhostLabel(name.trimmed());
        if (index >= 0) {
            refreshLabels();
            // Select the new label
            for (int row = 0; row < labelsModel->rowCount(); ++row) {
                if (labelsModel->item(row, 0)->data(Qt::UserRole).toInt() == index) {
                    ui->labelsTableView->selectRow(row);
                    break;
                }
            }
        } else {
            QMessageBox::warning(this, tr("Error"), tr("Failed to create label."));
        }
    }
}

void GhostLabelsPage::onRenameClicked()
{
    renameLabelFromMenu();
}

void GhostLabelsPage::onDeleteClicked()
{
    deleteLabelFromMenu();
}

void GhostLabelsPage::onExportClicked()
{
    if (!walletModel) return;

    QString filename = GUIUtil::getSaveFileName(this,
        tr("Export Labels"), QString(),
        tr("JSON Files") + QLatin1String(" (*.json)"), nullptr);

    if (filename.isEmpty()) return;

    if (walletModel->exportGhostLabels(filename)) {
        QMessageBox::information(this, tr("Export Successful"),
            tr("Labels exported successfully to %1").arg(filename));
    } else {
        QMessageBox::warning(this, tr("Export Failed"),
            tr("Failed to export labels to %1").arg(filename));
    }
}

void GhostLabelsPage::onImportClicked()
{
    if (!walletModel) return;

    QString filename = GUIUtil::getOpenFileName(this,
        tr("Import Labels"), QString(),
        tr("JSON Files") + QLatin1String(" (*.json)"), nullptr);

    if (filename.isEmpty()) return;

    QMessageBox::StandardButton reply = QMessageBox::question(this,
        tr("Import Labels"),
        tr("This will merge the imported labels with your existing labels. Continue?"),
        QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        if (walletModel->importGhostLabels(filename)) {
            refreshLabels();
            QMessageBox::information(this, tr("Import Successful"),
                tr("Labels imported successfully from %1").arg(filename));
        } else {
            QMessageBox::warning(this, tr("Import Failed"),
                tr("Failed to import labels from %1").arg(filename));
        }
    }
}

void GhostLabelsPage::showContextMenu(const QPoint& point)
{
    QModelIndex index = ui->labelsTableView->indexAt(point);
    if (!index.isValid()) return;

    ui->labelsTableView->selectRow(index.row());
    updateButtonStates();

    contextMenu->exec(ui->labelsTableView->viewport()->mapToGlobal(point));
}

void GhostLabelsPage::copyLabelName()
{
    QString name = getSelectedLabelName();
    if (!name.isEmpty()) {
        // Remove " (default)" suffix if present
        if (name.endsWith(tr(" (default)"))) {
            name = name.left(name.length() - tr(" (default)").length());
        }
        QApplication::clipboard()->setText(name);
    }
}

void GhostLabelsPage::renameLabelFromMenu()
{
    if (!walletModel) return;

    int index = getSelectedLabelIndex();
    if (index < 0 || index == DEFAULT_LABEL_INDEX) return;

    QString currentName = getSelectedLabelName();
    // Remove " (default)" suffix if present
    if (currentName.endsWith(tr(" (default)"))) {
        currentName = currentName.left(currentName.length() - tr(" (default)").length());
    }

    bool ok;
    QString newName = QInputDialog::getText(this, tr("Rename Label"),
        tr("Enter new name for the label:"), QLineEdit::Normal, currentName, &ok);

    if (ok && !newName.trimmed().isEmpty() && newName.trimmed() != currentName) {
        if (walletModel->renameGhostLabel(index, newName.trimmed())) {
            refreshLabels();
        } else {
            QMessageBox::warning(this, tr("Error"), tr("Failed to rename label."));
        }
    }
}

void GhostLabelsPage::deleteLabelFromMenu()
{
    if (!walletModel) return;

    int index = getSelectedLabelIndex();
    if (index < 0 || index == DEFAULT_LABEL_INDEX) return;

    QString name = getSelectedLabelName();

    QMessageBox::StandardButton reply = QMessageBox::question(this,
        tr("Delete Label"),
        tr("Are you sure you want to delete the label '%1'?\n\n"
           "Transactions using this label will show as 'Orphaned Label #%2'.")
            .arg(name).arg(index),
        QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        if (walletModel->deleteGhostLabel(index)) {
            refreshLabels();
        } else {
            QMessageBox::warning(this, tr("Error"), tr("Failed to delete label."));
        }
    }
}
