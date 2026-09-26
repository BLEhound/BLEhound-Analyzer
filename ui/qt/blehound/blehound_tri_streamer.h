/** @file
 *
 * Streams several BLEhound dongles to dumpcap as one aggregated capture.
 *
 * Each board is pinned to its guard channel (37/38/39) and read by its own
 * thread; the streamer thread merges the boards through libblehound's
 * aggregator (clock alignment, reorder, dedup) and writes one pcap stream
 * to the Unix socket dumpcap connects to. With follow_relay on, a
 * CONNECT_IND heard by one board is handed to the others so that all of
 * them follow the connection.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QAtomicInt>
#include <QByteArray>
#include <QMap>
#include <QMutex>
#include <QQueue>
#include <QStringList>
#include <QThread>
#include <QWaitCondition>

#include <blehound/blehound.h>

#include "blehound_serial.h"
#include "blehound_streamer.h"

namespace BLEhound {

class DeviceManager;
class TriStreamer;

/** Reads one dongle, pinned to its guard channel, for a TriStreamer. */
class BoardReader : public QThread
{
    Q_OBJECT

public:
    BoardReader(const QString &location, TriStreamer *owner);
    ~BoardReader();

    QString location() const { return location_; }
    TriStreamer *owner() const { return owner_; }

    void requestStop() { stop_requested_.storeRelaxed(1); }

    /** Frame and write a host command; safe from any thread. */
    bool sendCommand(uint8_t cmd, const uint8_t *arg, size_t arg_len);

    /** Pin the board to its guard channel once per open. */
    void pinGuardChannel(uint8_t board_id);

    /** Count a parsed frame for the device panel and the devices list. */
    void countFrame(const bh_packet &pkt, int64_t host_us);

protected:
    void run() override;

private:
    bool openAndConfigure();
    bool stopping() const { return stop_requested_.loadRelaxed() != 0; }

    const QString serial_location_;
    const QString location_;
    void reportFrames();

    TriStreamer *owner_;
    PosixSerial serial_;
    QAtomicInt stop_requested_;
    bool pinned_ = false;
    Streamer::FrameStats stats_;
    AdvertiserCollector collector_;
    qint64 last_report_us_ = 0;
};

class TriStreamer : public QThread
{
    Q_OBJECT

public:
    TriStreamer(const QString &socket_path, DeviceManager *manager);
    ~TriStreamer();

    QString socketPath() const { return socket_path_; }
    CaptureConfig config() const;               /**< thread-safe copy */
    DeviceManager *manager() const { return manager_; }

    /** Change the target while capturing (6 bytes air order, empty = none); any thread. */
    void setTarget(const QByteArray &mac_le, const QByteArray &irk_le);

    /** Dongles to use for the next capture; any thread. */
    void setPorts(const QStringList &ports);

    void requestStop() { stop_requested_.storeRelaxed(1); }

    /** Called by board readers for every parsed frame. */
    void onFrame(BoardReader *reader, const bh_packet &pkt, int64_t host_us);

protected:
    void run() override;

private:
    static bool relaySend(void *ctx, uint8_t board_id, const uint8_t *params, size_t params_len);
    static void emitPacket(void *ctx, const bh_agg_packet *pkt);

    void streamToClient(int client_fd);
    bool stopping() const { return stop_requested_.loadRelaxed() != 0; }

    void reportState(const QStringList &ports, bool capturing);

    const QString socket_path_;
    DeviceManager *manager_;
    mutable QMutex config_mutex_;
    CaptureConfig config_;
    QAtomicInt stop_requested_;

    QMutex readers_mutex_;
    QList<BoardReader *> readers_;

    QMutex ports_mutex_;
    QStringList ports_;

    /* Readers -> aggregator thread. */
    QMutex queue_mutex_;
    QWaitCondition queue_cond_;
    QQueue<bh_agg_packet> queue_;
    quint64 dropped_ = 0;

    /* Follow relay, used from reader threads. */
    QMutex relay_mutex_;
    bh_follow_relay relay_;
    QMap<uint8_t, BoardReader *> boards_;   /**< board_id -> reader, for relay commands */

    /* Aggregator thread only. */
    bh_ts_mapper ts_;
    QByteArray out_;
    bh_decryptor decryptor_;
};

} // namespace BLEhound
