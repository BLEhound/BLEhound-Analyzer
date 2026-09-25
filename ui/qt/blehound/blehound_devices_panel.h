/** @file
 *
 * Dock panel listing the devices heard advertising, with one-click
 * follow: pick a device and the dongles are told to follow only it.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QDockWidget>

class QAction;
class QCheckBox;
class QCloseEvent;
class QLabel;
class QLineEdit;
class QMainWindow;
class QMenu;
class QPushButton;
class QSortFilterProxyModel;
class QTableView;

namespace BLEhound {

class DevicesPanel : public QDockWidget
{
    Q_OBJECT

public:
    explicit DevicesPanel(QWidget *parent = nullptr);

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void followSelected();
    void clearTarget();
    void updateTarget();
    void applyTrafficFilter();
    void selectionChanged();
    void editKeys();
    void rowsAdded(const QModelIndex &parent, int first, int last);

private:
    QByteArray selectedAddress() const;
    /** Identity the target resolves to (via its IRK), or empty. */
    QString targetIdentity() const;

    QTableView *table_;
    QSortFilterProxyModel *proxy_;
    QLineEdit *search_;
    QLabel *target_label_;
    QPushButton *follow_button_;
    QPushButton *clear_button_;
    QCheckBox *only_target_;
};

/** Add the panel to the main window with a toggle in the View menu. */
void installDevicesPanel(QMainWindow *window, QMenu *view_menu, QAction *before);

} // namespace BLEhound
