/** @file
 *
 * Keys the user has for specific devices (IRK to recognise rotating
 * addresses, LTK for later decryption), kept across runs.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QAtomicInt>
#include <QByteArray>
#include <QList>
#include <QMutex>
#include <QObject>
#include <QString>

namespace BLEhound {

/** Keys of one device. Byte arrays are in air / SMP order (LSO first). */
struct DeviceKey {
    QString name;               /**< user label, may be empty */
    QString identity;           /**< identity address as text, may be empty */
    QByteArray irk_le;          /**< 16 bytes or empty */
    QByteArray ltk_le;          /**< 16 bytes or empty */

    bool hasIrk() const { return irk_le.size() == 16; }
    bool hasLtk() const { return ltk_le.size() == 16; }
    /** Label to show for it: name, else identity, else "IRK …". */
    QString label() const;
};

class KeyStore : public QObject
{
    Q_OBJECT

public:
    static KeyStore *instance();

    QList<DeviceKey> keys() const;                 /**< thread-safe copy */
    /** Bumps whenever the keys change; capture threads use it to drop their caches. */
    int version() const { return version_.loadRelaxed(); }

    /** Main thread. Saves and emits changed(). */
    void setKeys(const QList<DeviceKey> &keys);

    /**
     * The key whose IRK resolves this resolvable private address, if any.
     * Any thread; one AES block per stored IRK.
     */
    bool resolve(const QByteArray &adva_le, DeviceKey *key) const;

    /**
     * Pull keys out of a device's console log: blocks starting with
     * "identity[n] : ADDR (type)" or "[n] peer ADDR (type)" followed by
     * "IRK wire/LSO-first : HEX" / "LTK wire/LSO-first : HEX" lines
     * (the "reversed/MSO" variants are accepted when no wire line is given).
     */
    static QList<DeviceKey> parseDeviceLog(const QString &text);

    static QString hex(const QByteArray &bytes);
    /** 16-byte key from hex text (separators allowed); empty result if malformed or blank. */
    static QByteArray keyFromHex(const QString &text, bool *ok = nullptr);

signals:
    void changed();

private:
    explicit KeyStore(QObject *parent = nullptr);
    void load();
    void save() const;

    mutable QMutex mutex_;
    QList<DeviceKey> keys_;
    QAtomicInt version_;
};

} // namespace BLEhound
