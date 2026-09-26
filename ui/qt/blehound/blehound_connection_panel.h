/** @file
 *
 * Dock showing the followed connection: peers, parameters, PHY,
 * encryption, and a per-channel heat map of packets and CRC errors.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QDockWidget>
#include <QWidget>

#include "blehound_ll_tap.h"

class QAction;
class QCloseEvent;
class QComboBox;
class QLabel;
class QMainWindow;
class QMenu;

namespace BLEhound {

/** 37 data channels as coloured cells: packets (shade) and CRC errors (red), unused channels hatched. */
class ChannelHeatmap : public QWidget
{
    Q_OBJECT

public:
    explicit ChannelHeatmap(QWidget *parent = nullptr);
    void setConnection(const ConnectionInfo *info);
    QSize minimumSizeHint() const override;

protected:
    void paintEvent(QPaintEvent *event) override;
    bool event(QEvent *event) override;

private:
    ConnectionInfo info_;
    bool have_ = false;
};

class ConnectionPanel : public QDockWidget
{
    Q_OBJECT

public:
    explicit ConnectionPanel(QWidget *parent = nullptr);

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void refresh();

private:
    QComboBox *selector_;
    QLabel *summary_;
    ChannelHeatmap *heatmap_;
    bool follow_latest_ = true;
};

void installConnectionPanel(QMainWindow *window, QMenu *view_menu, QAction *before);

} // namespace BLEhound
