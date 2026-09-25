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
#include <QMutex>
#include <QThread>

#include "blehound_advertiser_model.h"

class QSerialPort;

namespace BLEhound {

class DeviceManager;

/** Capture configuration pushed to the dongle when a capture starts. */
struct CaptureConfig {
    bool hopping = true;            /**< hop 37/38/39; otherwise stay on channel */
    quint8 channel = 37;
    QByteArray target_mac_le;       /**< 6 bytes, air order; empty = no filter */
    bool single_target = true;
    bool include_crc_errors = false;
    bool follow_relay = false;      /**< aggregated capture: hand a CONNECT_IND to the other boards */
};

class Streamer : public QThread
{
    Q_OBJECT

public:
    struct FrameStats {
        quint64 frames = 0;
        int board_id = -1;      /**< from the first frame; -1 until then */
    };

    Streamer(const QString &serial_location, const QString &socket_path, DeviceManager *manager);
    ~Streamer();

    QString serialLocation() const { return serial_location_; }
    QString socketPath() const { return socket_path_; }

    /** Ask the thread to finish; returns immediately. */
    void requestStop() { stop_requested_.storeRelaxed(1); }

    /** Report a parsed status frame to the device manager (queued). */
    void reportStatus(const bh_status &status);

    /** Change the target while capturing (6 bytes air order, empty = none); any thread. */
    void setTarget(const QByteArray &mac_le);

    /** Stop the idle scan and release the port (aggregated capture needs it); any thread. */
    void setScanPaused(bool paused) { scan_paused_.storeRelaxed(paused ? 1 : 0); }

protected:
    void run() override;

private:
    enum class Result { ClientGone, Stopped };

    Result streamToClient(int client_fd);
    Result captureLoop(int client_fd);
    bool openAndConfigure(QSerialPort &port, const CaptureConfig &config);
    void stopScan(QSerialPort &port);
    void reportState(bool capturing);
    void reportScan(bool scanning);
    void reportFrames();
    bool stopping() const { return stop_requested_.loadRelaxed() != 0; }

    const QString serial_location_;
    const QString socket_path_;
    DeviceManager *manager_;
    CaptureConfig config_;
    FrameStats stats_;
    AdvertiserCollector collector_;
    QAtomicInt stop_requested_;
    QAtomicInt scan_paused_;

    QMutex target_mutex_;
    QByteArray pending_target_;
    bool has_pending_target_ = false;
};

} // namespace BLEhound
