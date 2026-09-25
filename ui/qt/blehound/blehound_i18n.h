/** @file
 *
 * Minimal English/Chinese switch for BLEhound-specific UI strings, which
 * are not part of Wireshark's translation catalogues.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QLocale>
#include <QString>

namespace BLEhound {

inline bool isChinese()
{
    return QLocale().language() == QLocale::Chinese;
}

inline QString localized(const char *en, const char *zh)
{
    return QString::fromUtf8(isChinese() ? zh : en);
}

} // namespace BLEhound
