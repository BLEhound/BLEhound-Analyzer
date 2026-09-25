/** @file
 *
 * BLEhound Analyzer main window branding.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#ifdef BLEHOUND_BRANDING

class QMainWindow;

namespace Ui {
class WiresharkMainWindow;
}

namespace BLEhound {

/**
 * Replace Wireshark-branded action texts and the trademarked shark-fin
 * capture icons, keep only the menu items and toolbar buttons that are
 * useful for Bluetooth LE sniffing, and add BLEhound help links.
 * Call after setupUi() and after every retranslateUi().
 */
void brandMainWindow(QMainWindow *window, Ui::WiresharkMainWindow *ui);

} // namespace BLEhound

#endif /* BLEHOUND_BRANDING */
