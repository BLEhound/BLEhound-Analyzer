/** @file
 *
 * Dock listing link-layer / ATT / SMP / L2CAP transactions, one row per
 * request with its response, fed by the "blehound" tap.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QDockWidget>

class QAction;
class QCloseEvent;
class QComboBox;
class QMainWindow;
class QMenu;
class QSortFilterProxyModel;
class QTableView;

namespace BLEhound {

class TransactionsPanel : public QDockWidget
{
    Q_OBJECT

public:
    explicit TransactionsPanel(QWidget *parent = nullptr);

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void gotoRow(const QModelIndex &index);

private:
    QTableView *table_;
    QSortFilterProxyModel *proxy_;
    QComboBox *layer_;
};

void installTransactionsPanel(QMainWindow *window, QMenu *view_menu, QAction *before);

} // namespace BLEhound
