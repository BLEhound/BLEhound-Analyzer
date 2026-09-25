/** @file
 *
 * Tracks connected BLEhound dongles and exposes each one as a capture
 * interface backed by a Streamer.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QMap>
#include <QObject>
#include <QStringList>
#include <QTimer>

namespace BLEhound {

class Streamer;

class DeviceManager : public QObject
{
    Q_OBJECT

public:
    /** Create the manager and hook it into interface scans. Main thread only. */
    static void install();

    /** Append one pipe interface per connected dongle to the global list. */
    void appendInterfaces();

private slots:
    void pollPorts();

private:
    explicit DeviceManager(QObject *parent = nullptr);
    ~DeviceManager();

    static QStringList connectedPorts();
    QString socketPathFor(const QString &location) const;
    void syncStreamers(const QStringList &ports);

    QString socket_dir_;
    QMap<QString, Streamer *> streamers_;   /**< keyed by serial port location */
    QStringList known_ports_;
    QTimer poll_timer_;
};

} // namespace BLEhound
