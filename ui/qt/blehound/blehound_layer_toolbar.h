/** @file
 *
 * Layer toolbar: look at the same capture as packets, link-layer items,
 * LLCP / L2CAP / SMP / ATT packets or transactions. Each view is a display
 * filter preset plus the columns that matter for it.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QString>

class MainWindow;
namespace Ui { class WiresharkMainWindow; }

namespace BLEhound {

/** Add the toolbar to the main window once. */
void installLayerToolbar(MainWindow *window, Ui::WiresharkMainWindow *ui);

/**
 * The display filter is shared between the layer view and the devices
 * panel's "only the target" switch; both go through here and are AND-ed.
 */
void setLayerFilter(const QString &filter);
void setTargetFilter(const QString &filter);

} // namespace BLEhound
