/* blehound_streamer.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_CAPTURE

#include "blehound_streamer.h"
#include "blehound_socket.h"
#include "blehound_capture_settings.h"
#include "blehound_device_manager.h"

#include <string.h>
#include <unistd.h>

#include <glib.h>

#include <wsutil/wslog.h>

#include <QSerialPort>

#include <blehound/blehound.h>

namespace BLEhound {

static const int kAcceptPollMs = 200;
static const int kSerialWaitMs = 100;
static const int kReopenDelayMs = 500;
static const int kConfigSettleMs = 50;
static const gint64 kReportIntervalUs = 500000;

namespace {

/** State shared with the C deframer callback. */
struct FrameSink {
    const CaptureConfig *config;
    bh_ts_mapper *ts;
    QByteArray *out;
    Streamer::FrameStats *stats;
    AdvertiserCollector *collector;
    int64_t now_us;
};

void onFrame(void *ctx, const uint8_t *frame, size_t len)
{
    FrameSink *sink = static_cast<FrameSink *>(ctx);
    bh_packet pkt;
    uint8_t rec[BH_MAX_RECORD_LEN];
    uint8_t hdr[BH_PCAP_RECORD_HEADER_LEN];

    if (!bh_parse_frame(frame, len, &pkt)) {
        return;
    }
    sink->stats->frames++;
    sink->stats->board_id = pkt.board_id;
    sink->collector->onPacket(pkt, sink->now_us);
    if (sink->out == nullptr) {
        return;                                 /* idle scan: devices list only */
    }
    if (!pkt.crc_ok && !sink->config->include_crc_errors) {
        return;
    }
    size_t rec_len = bh_btle_rf_record(&pkt, rec, sizeof(rec));
    if (rec_len == 0) {
        return;
    }
    bh_pcap_record_header(bh_ts_mapper_map(sink->ts, pkt.ts_us), (uint32_t)rec_len, hdr);
    sink->out->append(reinterpret_cast<const char *>(hdr), sizeof(hdr));
    sink->out->append(reinterpret_cast<const char *>(rec), (qsizetype)rec_len);
}

bool writeCommand(QSerialPort &port, uint8_t cmd, const uint8_t *arg, size_t arg_len)
{
    uint8_t buf[64];
    size_t n = bh_cmd_build(cmd, arg, arg_len, buf, sizeof(buf));
    return n > 0 && port.write(reinterpret_cast<const char *>(buf), (qint64)n) == (qint64)n;
}

} // namespace

Streamer::Streamer(const QString &serial_location, const QString &socket_path, DeviceManager *manager) :
    QThread(nullptr),
    serial_location_(serial_location),
    socket_path_(socket_path),
    manager_(manager),
    stop_requested_(0),
    scan_paused_(0)
{
}

void Streamer::setTarget(const QByteArray &mac_le)
{
    QMutexLocker locker(&target_mutex_);
    pending_target_ = mac_le;
    has_pending_target_ = true;
}

void Streamer::reportScan(bool scanning)
{
    DeviceManager *manager = manager_;
    QString location = serial_location_;
    QMetaObject::invokeMethod(manager, [=]() { manager->reportScanState(location, scanning); },
                              Qt::QueuedConnection);
}

void Streamer::stopScan(QSerialPort &port)
{
    if (!port.isOpen()) {
        return;
    }
    port.close();
    port.clearError();
    collector_.flush();
    reportFrames();
    reportScan(false);
}

void Streamer::reportState(bool capturing)
{
    DeviceManager *manager = manager_;
    QString location = serial_location_;
    QMetaObject::invokeMethod(manager, [=]() { manager->reportCaptureState(location, capturing); },
                              Qt::QueuedConnection);
}

void Streamer::reportFrames()
{
    DeviceManager *manager = manager_;
    QString location = serial_location_;
    FrameStats stats = stats_;
    QMetaObject::invokeMethod(manager, [=]() { manager->reportFrames(location, stats.board_id, stats.frames); },
                              Qt::QueuedConnection);
}

Streamer::~Streamer()
{
    requestStop();
    wait();
}

void Streamer::run()
{
    int listen_fd = Socket::listenOn(socket_path_);
    if (listen_fd < 0) {
        return;
    }

    /* Between captures the dongle keeps listening so the devices list is
     * live as soon as it is plugged in; Start merely begins recording. */
    QSerialPort port;
    bh_deframer deframer;
    bh_ts_mapper ts;
    CaptureConfig scan_config;                  /* hop 37/38/39, no target, observe only */
    FrameSink sink = { &scan_config, &ts, nullptr, &stats_, &collector_, 0 };
    gint64 last_open_try = 0;
    gint64 last_report = 0;

    while (!stopping()) {
        int client_fd = Socket::acceptClient(listen_fd, port.isOpen() ? 0 : kAcceptPollMs);
        if (client_fd >= 0) {
            stopScan(port);
            ws_info("BLEhound capture started on %s", qUtf8Printable(serial_location_));
            streamToClient(client_fd);
            close(client_fd);
            ws_info("BLEhound capture ended on %s", qUtf8Printable(serial_location_));
            continue;
        }
        if (scan_paused_.loadRelaxed()) {
            stopScan(port);
            msleep(kSerialWaitMs);
            continue;
        }
        if (!port.isOpen()) {
            gint64 now = g_get_monotonic_time();
            if (now - last_open_try < (gint64)kReopenDelayMs * 1000) {
                msleep(kSerialWaitMs);
                continue;
            }
            last_open_try = now;
            if (!openAndConfigure(port, scan_config)) {
                continue;                       /* unplugged or busy: retry */
            }
            bh_deframer_init(&deframer);
            stats_ = FrameStats();
            reportScan(true);
        }

        if (port.waitForReadyRead(kSerialWaitMs)) {
            QByteArray data = port.readAll();
            sink.now_us = g_get_real_time();
            bh_deframer_feed(&deframer, reinterpret_cast<const uint8_t *>(data.constData()),
                             (size_t)data.size(), onFrame, &sink);
        } else if (port.error() != QSerialPort::NoError && port.error() != QSerialPort::TimeoutError) {
            stopScan(port);
            continue;
        }
        gint64 now = g_get_monotonic_time();
        if (now - last_report >= kReportIntervalUs) {
            reportFrames();
            last_report = now;
        }
        collector_.flushIfDue(now);
    }

    stopScan(port);
    close(listen_fd);
    unlink(socket_path_.toLocal8Bit().constData());
}

bool Streamer::openAndConfigure(QSerialPort &port, const CaptureConfig &config)
{
    port.setPortName(serial_location_);
    if (!port.open(QIODevice::ReadWrite)) {
        return false;
    }
    // The firmware only streams once the host asserts DTR.
    port.setDataTerminalReady(true);

    uint8_t flag = config.hopping ? 1 : 0;
    writeCommand(port, BH_CMD_SET_HOPPING, &flag, 1);
    if (!config.hopping) {
        writeCommand(port, BH_CMD_SET_CHANNEL, &config.channel, 1);
    }
    uint8_t mac[6] = { 0 };
    if (config.target_mac_le.size() == 6) {
        memcpy(mac, config.target_mac_le.constData(), sizeof(mac));
    }
    writeCommand(port, BH_CMD_SET_TARGET, mac, sizeof(mac));
    flag = config.single_target ? 1 : 0;
    writeCommand(port, BH_CMD_SET_SINGLE_TARGET, &flag, 1);
    port.waitForBytesWritten(kSerialWaitMs);

    // Frames queued before the configuration took effect are unfiltered; drop them.
    msleep(kConfigSettleMs);
    port.clear(QSerialPort::Input);
    port.readAll();
    return true;
}

Streamer::Result Streamer::streamToClient(int client_fd)
{
    // Settings edited in the device panel apply from the next capture on.
    config_ = CaptureSettings::instance()->config();
    stats_ = FrameStats();
    {
        QMutexLocker locker(&target_mutex_);
        has_pending_target_ = false;
    }
    reportState(true);
    Result result = captureLoop(client_fd);
    collector_.flush();
    reportFrames();
    reportState(false);
    return result;
}

Streamer::Result Streamer::captureLoop(int client_fd)
{
    QSerialPort port;
    bh_deframer deframer;
    bh_ts_mapper ts;
    QByteArray out;
    FrameSink sink = { &config_, &ts, &out, &stats_, &collector_, 0 };
    gint64 last_report = g_get_monotonic_time();

    uint8_t global_header[BH_PCAP_GLOBAL_HEADER_LEN];
    bh_pcap_global_header(global_header);
    if (!Socket::sendAll(client_fd, QByteArray(reinterpret_cast<const char *>(global_header), sizeof(global_header)))) {
        return Result::ClientGone;
    }
    bh_ts_mapper_init(&ts, (uint64_t)g_get_real_time());

    while (!stopping()) {
        if (!port.isOpen()) {
            if (!openAndConfigure(port, config_)) {
                // Unplugged or busy: keep the capture alive and retry.
                if (Socket::clientClosed(client_fd)) {
                    return Result::ClientGone;
                }
                msleep(kReopenDelayMs);
                continue;
            }
            bh_deframer_init(&deframer);
        }

        if (port.waitForReadyRead(kSerialWaitMs)) {
            QByteArray data = port.readAll();
            sink.now_us = g_get_real_time();
            bh_deframer_feed(&deframer, reinterpret_cast<const uint8_t *>(data.constData()),
                             (size_t)data.size(), onFrame, &sink);
        } else if (port.error() != QSerialPort::NoError && port.error() != QSerialPort::TimeoutError) {
            ws_info("BLEhound %s: %s, reopening", qUtf8Printable(serial_location_),
                    qUtf8Printable(port.errorString()));
            port.close();
            port.clearError();
            continue;
        }

        if (!out.isEmpty()) {
            if (!Socket::sendAll(client_fd, out)) {
                return Result::ClientGone;
            }
            out.clear();
        }
        if (Socket::clientClosed(client_fd)) {
            return Result::ClientGone;
        }
        gint64 now = g_get_monotonic_time();
        if (now - last_report >= kReportIntervalUs) {
            reportFrames();
            last_report = now;
        }
        collector_.flushIfDue(now);

        // A target picked in the devices panel takes effect without restarting.
        bool apply_target = false;
        {
            QMutexLocker locker(&target_mutex_);
            if (has_pending_target_) {
                config_.target_mac_le = pending_target_;
                has_pending_target_ = false;
                apply_target = true;
            }
        }
        if (apply_target && port.isOpen()) {
            uint8_t mac[6] = { 0 };
            if (config_.target_mac_le.size() == 6) {
                memcpy(mac, config_.target_mac_le.constData(), sizeof(mac));
            }
            writeCommand(port, BH_CMD_SET_TARGET, mac, sizeof(mac));
            ws_info("BLEhound %s: target %s", qUtf8Printable(serial_location_),
                    config_.target_mac_le.isEmpty() ? "cleared" : "set");
        }
    }
    return Result::Stopped;
}

} // namespace BLEhound
