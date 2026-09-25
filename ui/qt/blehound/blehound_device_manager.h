/** @file
 *
 * Tracks connected BLEhound dongles and exposes each one as a capture
 * interface backed by a Streamer.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QList>
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
    struct BoardInfo {
        QString location;
        int board_id = -1;          /**< learnt from the first captured frame */
        bool capturing = false;
        quint64 packets = 0;
    };

    /** Create the manager. Main thread, before the main window. */
    static void install();
    static DeviceManager *instance();

    /** Take over interface discovery and watch for hot-plug; after capture_opts_init(). */
    void startWatching();

    /** Append one pipe interface per connected dongle to the global list. */
    void appendInterfaces();

    /** Connected boards in port order. */
    QList<BoardInfo> boards() const;

    /**
     * Advertising channel this board guards: from its board_id once a
     * capture has revealed it, otherwise by port order (the three radios
     * sit behind one hub, so the lowest port is CH37). 0 if unknown.
     */
    int channelFor(const QString &location) const;

public slots:
    /* Called (queued) from the capture threads. */
    void reportCaptureState(const QString &location, bool capturing);
    void reportFrames(const QString &location, int board_id, quint64 packets);

signals:
    void boardsChanged();

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
    QMap<QString, BoardInfo> boards_;       /**< keyed by serial port location */
    TriStreamer *tri_streamer_;             /**< all dongles merged into one capture */
    QStringList known_ports_;
    QTimer poll_timer_;
};

} // namespace BLEhound
