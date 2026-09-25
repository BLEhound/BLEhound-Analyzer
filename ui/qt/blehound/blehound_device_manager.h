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
#include <QSet>
#include <QStringList>
#include <QTimer>

namespace BLEhound {

class Streamer;
class TriStreamer;

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
    static void ensureInterface(const QByteArray &name, const QByteArray &display);
    void removeStaleInterfaces(const QSet<QString> &valid_names);

    QString socket_dir_;
    QMap<QString, Streamer *> streamers_;   /**< keyed by serial port location */
    TriStreamer *tri_streamer_;             /**< all dongles merged into one capture */
    QStringList known_ports_;
    QTimer poll_timer_;
};

} // namespace BLEhound
