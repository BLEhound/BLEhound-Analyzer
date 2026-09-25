/** @file
 *
 * Dock panel listing the connected BLEhound dongles and the capture
 * settings that apply to the next capture.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QDockWidget>

class QAction;
class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QMainWindow;
class QMenu;
class QTableWidget;

namespace BLEhound {

class DevicePanel : public QDockWidget
{
    Q_OBJECT

public:
    explicit DevicePanel(QWidget *parent = nullptr);

private slots:
    void refreshBoards();
    void loadSettings();
    void saveSettings();

private:
    QWidget *buildBoardList();
    QWidget *buildSettings();

    QTableWidget *table_;
    QLabel *empty_label_;
    QCheckBox *hop_;
    QComboBox *channel_;
    QLineEdit *target_;
    QLabel *target_hint_;
    QCheckBox *include_crc_;
    QCheckBox *single_target_;
    QCheckBox *follow_relay_;
    bool loading_ = false;
};

/** Add the panel to the main window with a toggle in the View menu. */
void installDevicePanel(QMainWindow *window, QMenu *view_menu, QAction *before);

} // namespace BLEhound
