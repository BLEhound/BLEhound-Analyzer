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
#include <QStringList>

namespace BLEhound {

/* Same signal Wireshark's translator uses (QTranslator::load(locale, ...)
 * picks from uiLanguages()), so our strings follow Wireshark's own. */
inline bool isChinese()
{
    const QStringList languages = QLocale().uiLanguages();

    if (!languages.isEmpty()) {
        return languages.first().startsWith(QLatin1String("zh"), Qt::CaseInsensitive);
    }
    return QLocale().language() == QLocale::Chinese;
}

inline QString localized(const char *en, const char *zh)
{
    return QString::fromUtf8(isChinese() ? zh : en);
}

} // namespace BLEhound
