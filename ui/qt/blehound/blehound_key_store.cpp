/* blehound_key_store.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "blehound_key_store.h"

#include <QRegularExpression>
#include <QSettings>

#include <blehound/blehound.h>

namespace BLEhound {

static const char *kOrg = "BLEhound";
static const char *kApp = "Analyzer";

QString DeviceKey::label() const
{
    if (!name.isEmpty()) {
        return name;
    }
    if (!identity.isEmpty()) {
        return identity;
    }
    if (hasIrk()) {
        return QStringLiteral("IRK %1…").arg(QString::fromLatin1(irk_le.left(3).toHex().toUpper()));
    }
    return QString();
}

KeyStore *KeyStore::instance()
{
    static KeyStore *store = new KeyStore();
    return store;
}

KeyStore::KeyStore(QObject *parent) :
    QObject(parent),
    version_(1)
{
    load();
}

QList<DeviceKey> KeyStore::keys() const
{
    QMutexLocker locker(&mutex_);
    return keys_;
}

void KeyStore::setKeys(const QList<DeviceKey> &keys)
{
    {
        QMutexLocker locker(&mutex_);
        keys_ = keys;
    }
    version_.fetchAndAddRelaxed(1);
    save();
    emit changed();
}

bool KeyStore::resolve(const QByteArray &adva_le, DeviceKey *key) const
{
    if (adva_le.size() != 6) {
        return false;
    }
    const uint8_t *addr = reinterpret_cast<const uint8_t *>(adva_le.constData());
    if (!bh_rpa_is_resolvable(addr)) {
        return false;
    }
    QMutexLocker locker(&mutex_);
    foreach (const DeviceKey &k, keys_) {
        if (k.hasIrk() && bh_rpa_matches(reinterpret_cast<const uint8_t *>(k.irk_le.constData()), addr)) {
            if (key) {
                *key = k;
            }
            return true;
        }
    }
    return false;
}

QList<QByteArray> KeyStore::ltks() const
{
    QList<QByteArray> out;
    QMutexLocker locker(&mutex_);
    foreach (const DeviceKey &k, keys_) {
        if (k.hasLtk()) {
            out.append(k.ltk_le);
        }
    }
    return out;
}

QString KeyStore::hex(const QByteArray &bytes)
{
    return QString::fromLatin1(bytes.toHex().toUpper());
}

QByteArray KeyStore::keyFromHex(const QString &text, bool *ok)
{
    QString trimmed = text.trimmed();
    uint8_t key[16];

    if (trimmed.isEmpty()) {
        if (ok) *ok = true;
        return QByteArray();
    }
    if (!bh_parse_hex(trimmed.toUtf8().constData(), key, sizeof(key))) {
        if (ok) *ok = false;
        return QByteArray();
    }
    if (ok) *ok = true;
    return QByteArray(reinterpret_cast<const char *>(key), sizeof(key));
}

static QByteArray reversed(const QByteArray &bytes)
{
    QByteArray out(bytes.size(), 0);
    for (int i = 0; i < bytes.size(); i++) {
        out[i] = bytes.at(bytes.size() - 1 - i);
    }
    return out;
}

QList<DeviceKey> KeyStore::parseDeviceLog(const QString &text)
{
    static const QRegularExpression identity_re(
        QStringLiteral("identity\\[\\d+\\]\\s*:\\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"));
    static const QRegularExpression peer_re(
        QStringLiteral("\\[\\d+\\]\\s*peer\\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"));
    static const QRegularExpression key_re(
        QStringLiteral("\\b(IRK|LTK)\\s+(wire|reversed)\\S*\\s*:\\s*([0-9A-Fa-f]{32})\\b"));

    QList<DeviceKey> found;
    DeviceKey current;
    bool have_current = false;
    bool irk_from_wire = false;
    bool ltk_from_wire = false;

    auto flush = [&]() {
        if (have_current && (current.hasIrk() || current.hasLtk())) {
            found.append(current);
        }
        current = DeviceKey();
        have_current = false;
        irk_from_wire = ltk_from_wire = false;
    };

    foreach (const QString &line, text.split(QLatin1Char('\n'))) {
        QRegularExpressionMatch m = identity_re.match(line);
        if (!m.hasMatch()) {
            m = peer_re.match(line);
        }
        if (m.hasMatch()) {
            flush();
            have_current = true;
            current.identity = m.captured(1).toUpper();
            continue;
        }
        m = key_re.match(line);
        if (!m.hasMatch()) {
            continue;
        }
        if (!have_current) {
            have_current = true;            /* keys with no address header still count */
        }
        bool wire = m.captured(2).compare(QStringLiteral("wire"), Qt::CaseInsensitive) == 0;
        QByteArray value = keyFromHex(m.captured(3));
        if (!wire) {
            value = reversed(value);
        }
        if (m.captured(1).compare(QStringLiteral("IRK"), Qt::CaseInsensitive) == 0) {
            if (wire || !irk_from_wire) {
                current.irk_le = value;
                irk_from_wire = irk_from_wire || wire;
            }
        } else if (wire || !ltk_from_wire) {
            current.ltk_le = value;
            ltk_from_wire = ltk_from_wire || wire;
        }
    }
    flush();
    return found;
}

void KeyStore::load()
{
    QSettings settings(QString::fromUtf8(kOrg), QString::fromUtf8(kApp));
    QList<DeviceKey> keys;

    int count = settings.beginReadArray(QStringLiteral("keys"));
    for (int i = 0; i < count; i++) {
        settings.setArrayIndex(i);
        DeviceKey key;
        key.name = settings.value(QStringLiteral("name")).toString();
        key.identity = settings.value(QStringLiteral("identity")).toString();
        key.irk_le = keyFromHex(settings.value(QStringLiteral("irk")).toString());
        key.ltk_le = keyFromHex(settings.value(QStringLiteral("ltk")).toString());
        if (key.hasIrk() || key.hasLtk()) {
            keys.append(key);
        }
    }
    settings.endArray();
    QMutexLocker locker(&mutex_);
    keys_ = keys;
}

void KeyStore::save() const
{
    QSettings settings(QString::fromUtf8(kOrg), QString::fromUtf8(kApp));
    QList<DeviceKey> keys = this->keys();

    settings.beginWriteArray(QStringLiteral("keys"), keys.size());
    for (int i = 0; i < keys.size(); i++) {
        settings.setArrayIndex(i);
        settings.setValue(QStringLiteral("name"), keys.at(i).name);
        settings.setValue(QStringLiteral("identity"), keys.at(i).identity);
        settings.setValue(QStringLiteral("irk"), hex(keys.at(i).irk_le));
        settings.setValue(QStringLiteral("ltk"), hex(keys.at(i).ltk_le));
    }
    settings.endArray();
}

} // namespace BLEhound
