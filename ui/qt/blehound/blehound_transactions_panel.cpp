/* blehound_transactions_panel.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "blehound_transactions_panel.h"

#include "blehound_i18n.h"
#include "blehound_ll_tap.h"

#include "main_application.h"
#include "main_window.h"

#include <QAction>
#include <QCloseEvent>
#include <QComboBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMainWindow>
#include <QMenu>
#include <QSettings>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QVBoxLayout>

namespace BLEhound {

namespace {

class TransactionProxy : public QSortFilterProxyModel
{
public:
    explicit TransactionProxy(QObject *parent) : QSortFilterProxyModel(parent) {}

    QString layer;

protected:
    bool lessThan(const QModelIndex &left, const QModelIndex &right) const override
    {
        int col = left.column();
        if (col == TransactionModel::ColTime || col == TransactionModel::ColRequest ||
                col == TransactionModel::ColResponse || col == TransactionModel::ColDuration) {
            return left.data(Qt::UserRole).toDouble() < right.data(Qt::UserRole).toDouble();
        }
        return QSortFilterProxyModel::lessThan(left, right);
    }

    bool filterAcceptsRow(int row, const QModelIndex &parent) const override
    {
        if (layer.isEmpty()) {
            return true;
        }
        return sourceModel()->index(row, TransactionModel::ColLayer, parent).data().toString() == layer;
    }
};

} // namespace

TransactionsPanel::TransactionsPanel(QWidget *parent) :
    QDockWidget(localized("Transactions", "事务"), parent)
{
    setObjectName(QStringLiteral("blehoundTransactionsPanel"));
    setAllowedAreas(Qt::LeftDockWidgetArea | Qt::RightDockWidgetArea | Qt::BottomDockWidgetArea);

    QWidget *content = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(content);
    QHBoxLayout *top = new QHBoxLayout();

    top->addWidget(new QLabel(localized("Layer:", "层："), content));
    layer_ = new QComboBox(content);
    layer_->addItem(localized("All", "全部"), QString());
    layer_->addItem(QStringLiteral("LLCP"), QStringLiteral("LLCP"));
    layer_->addItem(QStringLiteral("ATT"), QStringLiteral("ATT"));
    layer_->addItem(QStringLiteral("SMP"), QStringLiteral("SMP"));
    layer_->addItem(QStringLiteral("L2CAP"), QStringLiteral("L2CAP"));
    top->addWidget(layer_);
    top->addStretch();
    layout->addLayout(top);

    TransactionProxy *proxy = new TransactionProxy(this);
    proxy->setSourceModel(LinkTap::instance()->transactions());
    proxy->setDynamicSortFilter(true);
    proxy_ = proxy;

    table_ = new QTableView(content);
    table_->setModel(proxy_);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setSortingEnabled(true);
    table_->sortByColumn(TransactionModel::ColTime, Qt::AscendingOrder);
    table_->verticalHeader()->hide();
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setToolTip(localized("Double-click a row to jump to the request; the response frame is in its own column.",
                                 "双击一行跳到请求帧；响应帧号在单独一列。"));
    layout->addWidget(table_, 1);
    setWidget(content);

    connect(layer_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this, proxy](int) {
        proxy->layer = layer_->currentData().toString();
        proxy->invalidate();
    });
    connect(table_, &QTableView::activated, this, &TransactionsPanel::gotoRow);
}

void TransactionsPanel::closeEvent(QCloseEvent *event)
{
    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
    settings.setValue(QStringLiteral("ui/transactionsPanelVisible"), false);
    QDockWidget::closeEvent(event);
}

void TransactionsPanel::gotoRow(const QModelIndex &index)
{
    const Transaction *t = LinkTap::instance()->transactions()->at(proxy_->mapToSource(index).row());
    MainWindow *window = mainApp->mainWindow();

    if (!t || !window) {
        return;
    }
    /* Response column: jump to the response, anywhere else the request. */
    uint32_t frame = index.column() == TransactionModel::ColResponse && t->rsp_frame ? t->rsp_frame : t->req_frame;
    window->gotoFrame((int)frame);
}

void installTransactionsPanel(QMainWindow *window, QMenu *view_menu, QAction *before)
{
    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
    LinkTap::instance()->install();
    TransactionsPanel *panel = new TransactionsPanel(window);

    /* Bottom row, left; the connection panel is split in to its right. */
    window->addDockWidget(Qt::BottomDockWidgetArea, panel);
    panel->setMinimumHeight(160);
    panel->setVisible(settings.value(QStringLiteral("ui/transactionsPanelVisible"), true).toBool());
    window->resizeDocks({ panel }, { 240 }, Qt::Vertical);

    QAction *toggle = panel->toggleViewAction();
    toggle->setObjectName(QStringLiteral("actionBlehoundTransactionsPanel"));
    toggle->setText(localized("Transactions", "事务"));
    view_menu->insertAction(before, toggle);
    QObject::connect(toggle, &QAction::triggered, panel, [](bool visible) {
        QSettings s(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
        s.setValue(QStringLiteral("ui/transactionsPanelVisible"), visible);
    });
}

} // namespace BLEhound
