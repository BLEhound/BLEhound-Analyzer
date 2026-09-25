/* blehound_branding.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "blehound_branding.h"

#ifdef BLEHOUND_BRANDING

#include <wsutil/application_flavor.h>

#include <ui/qt/utils/stock_icon.h>

#include "ui_wireshark_main_window.h"

namespace BLEhound {

void brandMainWindow(Ui::WiresharkMainWindow *ui)
{
    const QString name = QString::fromUtf8(application_flavor_name_proper());

    // The shark-fin icons are part of the Wireshark trademark.
    ui->actionCaptureStart->setIcon(StockIcon("blehound-capture-start"));
    ui->actionCaptureRestart->setIcon(StockIcon("blehound-capture-restart"));

    ui->actionHelpAbout->setText(QObject::tr("&About %1").arg(name));
    ui->actionFileQuit->setText(QObject::tr("Quit %1").arg(name));
}

} // namespace BLEhound

#endif /* BLEHOUND_BRANDING */
