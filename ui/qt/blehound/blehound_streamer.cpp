/* blehound_streamer.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_CAPTURE

#include "blehound_streamer.h"
#include "blehound_socket.h"

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

namespace {

/** State shared with the C deframer callback. */
struct FrameSink {
    const CaptureConfig *config;
    bh_ts_mapper *ts;
    QByteArray *out;
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

Streamer::Streamer(const QString &serial_location, const QString &socket_path, QObject *parent) :
    QThread(parent),
    serial_location_(serial_location),
    socket_path_(socket_path),
    stop_requested_(0)
{
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

    while (!stopping()) {
        int client_fd = Socket::acceptClient(listen_fd, kAcceptPollMs);
        if (client_fd < 0) {
            continue;
        }
        ws_info("BLEhound capture started on %s", qUtf8Printable(serial_location_));
        streamToClient(client_fd);
        close(client_fd);
        ws_info("BLEhound capture ended on %s", qUtf8Printable(serial_location_));
    }

    close(listen_fd);
    unlink(socket_path_.toLocal8Bit().constData());
}

bool Streamer::openAndConfigure(QSerialPort &port)
{
    port.setPortName(serial_location_);
    if (!port.open(QIODevice::ReadWrite)) {
        return false;
    }
    // The firmware only streams once the host asserts DTR.
    port.setDataTerminalReady(true);

    uint8_t flag = config_.hopping ? 1 : 0;
    writeCommand(port, BH_CMD_SET_HOPPING, &flag, 1);
    if (!config_.hopping) {
        writeCommand(port, BH_CMD_SET_CHANNEL, &config_.channel, 1);
    }
    uint8_t mac[6] = { 0 };
    if (config_.target_mac_le.size() == 6) {
        memcpy(mac, config_.target_mac_le.constData(), sizeof(mac));
    }
    writeCommand(port, BH_CMD_SET_TARGET, mac, sizeof(mac));
    flag = config_.single_target ? 1 : 0;
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
    QSerialPort port;
    bh_deframer deframer;
    bh_ts_mapper ts;
    QByteArray out;
    FrameSink sink = { &config_, &ts, &out };

    uint8_t global_header[BH_PCAP_GLOBAL_HEADER_LEN];
    bh_pcap_global_header(global_header);
    if (!Socket::sendAll(client_fd, QByteArray(reinterpret_cast<const char *>(global_header), sizeof(global_header)))) {
        return Result::ClientGone;
    }
    bh_ts_mapper_init(&ts, (uint64_t)g_get_real_time());

    while (!stopping()) {
        if (!port.isOpen()) {
            if (!openAndConfigure(port)) {
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
    }
    return Result::Stopped;
}

} // namespace BLEhound
