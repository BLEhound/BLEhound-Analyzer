/** @file
 *
 * BLEhound Analyzer main window branding.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#ifdef BLEHOUND_BRANDING

namespace Ui {
class WiresharkMainWindow;
}

namespace BLEhound {

/**
 * Replace Wireshark-branded action texts and the trademarked shark-fin
 * capture icons. Call after setupUi() and after every retranslateUi().
 */
void brandMainWindow(Ui::WiresharkMainWindow *ui);

} // namespace BLEhound

#endif /* BLEHOUND_BRANDING */
