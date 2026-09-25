/** @file
 *
 * Streams one BLEhound dongle to dumpcap.
 *
 * The streamer listens on a Unix socket that is registered as a pipe
 * interface. When dumpcap starts a capture it connects; the streamer then
 * opens the serial port, configures the dongle and writes a pcap stream
 * until dumpcap disconnects, at which point the serial port is released.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QAtomicInt>
#include <QByteArray>
#include <QString>
#include <QThread>

class QSerialPort;

namespace BLEhound {

/** Capture configuration pushed to the dongle when a capture starts. */
struct CaptureConfig {
    bool hopping = true;            /**< hop 37/38/39; otherwise stay on channel */
    quint8 channel = 37;
    QByteArray target_mac_le;       /**< 6 bytes, air order; empty = no filter */
    bool single_target = true;
    bool include_crc_errors = false;
};

class Streamer : public QThread
{
    Q_OBJECT

public:
    Streamer(const QString &serial_location, const QString &socket_path, QObject *parent = nullptr);
    ~Streamer();

    QString serialLocation() const { return serial_location_; }
    QString socketPath() const { return socket_path_; }

    /** Ask the thread to finish; returns immediately. */
    void requestStop() { stop_requested_.storeRelaxed(1); }

protected:
    void run() override;

private:
    enum class Result { ClientGone, Stopped };

    int listen();
    Result streamToClient(int client_fd);
    bool openAndConfigure(QSerialPort &port);
    bool sendAll(int fd, const QByteArray &data);
    bool clientClosed(int fd);
    bool stopping() const { return stop_requested_.loadRelaxed() != 0; }

    const QString serial_location_;
    const QString socket_path_;
    CaptureConfig config_;
    QAtomicInt stop_requested_;
};

} // namespace BLEhound
