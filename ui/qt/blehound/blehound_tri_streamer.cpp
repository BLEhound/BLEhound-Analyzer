/* blehound_tri_streamer.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_CAPTURE

#include "blehound_tri_streamer.h"
#include "blehound_socket.h"
#include "blehound_capture_settings.h"
#include "blehound_device_manager.h"
#include "blehound_key_store.h"

#include <string.h>
#include <unistd.h>

#include <glib.h>

#include <wsutil/wslog.h>

namespace BLEhound {

static const int kAcceptPollMs = 200;
static const int kSerialPollMs = 100;
static const int kReopenDelayMs = 500;
static const int kConfigSettleMs = 50;
static const int kQueueWaitMs = 200;
static const int kQueueMax = 10000;
static const qint64 kReportIntervalUs = 500000;

/* ---------------------------------------------------------- BoardReader */

BoardReader::BoardReader(const QString &location, TriStreamer *owner) :
    QThread(nullptr),
    serial_location_(location),
    location_(location),
    owner_(owner),
    stop_requested_(0)
{
}

BoardReader::~BoardReader()
{
    requestStop();
    wait();
}

bool BoardReader::sendCommand(uint8_t cmd, const uint8_t *arg, size_t arg_len)
{
    uint8_t framed[64];
    size_t n = bh_cmd_build(cmd, arg, arg_len, framed, sizeof(framed));

    return n > 0 && serial_.write(framed, n);
}

void BoardReader::countFrame(const bh_packet &pkt, int64_t host_us)
{
    stats_.frames++;
    stats_.board_id = pkt.board_id;
    collector_.onPacket(pkt, host_us);

    /* Hint the dongle from here, before the reorder delay; the aggregated
     * output still decrypts on its own for the capture file. */
    if (hint_decryptor_.n_ltk > 0) {
        bh_packet copy = pkt;
        uint8_t plain[BH_MAX_PDU_LEN + 2];
        uint8_t direction;
        if (bh_decryptor_process(&hint_decryptor_, &copy, plain, sizeof(plain), &direction) &&
            bh_ll_ctrl_hint_wanted(&copy)) {
            uint8_t args[4 + BH_MAX_PDU_LEN];
            size_t n = bh_ll_ctrl_hint_args(&copy, args, sizeof(args));
            if (n) {
                sendCommand(BH_CMD_LL_CTRL_HINT, args, n);
            }
        }
    }
}

void BoardReader::reportFrames()
{
    DeviceManager *manager = owner_->manager();
    QString location = location_;
    Streamer::FrameStats stats = stats_;
    QMetaObject::invokeMethod(manager, [=]() { manager->reportFrames(location, stats.board_id, stats.frames); },
                              Qt::QueuedConnection);
}

void BoardReader::pinGuardChannel(uint8_t board_id)
{
    uint8_t channel;

    if (pinned_) {
        return;
    }
    // The firmware may have drifted off its strap channel while following
    // a connection, so pin it by board_id rather than trust its own state.
    if (bh_guard_channel_for_board(board_id, &channel)) {
        sendCommand(BH_CMD_SET_CHANNEL, &channel, 1);
    }
    pinned_ = true;
}

bool BoardReader::openAndConfigure()
{
    const CaptureConfig config = owner_->config();
    QString error;
    uint8_t flag;
    uint8_t mac[6] = { 0 };

    if (!serial_.open(serial_location_, &error)) {
        return false;
    }
    flag = 0;                                   /* guard one channel, no hopping */
    sendCommand(BH_CMD_SET_HOPPING, &flag, 1);
    uint8_t irk[16] = { 0 };
    if (config.target_mac_le.size() == (int)sizeof(mac)) {
        memcpy(mac, config.target_mac_le.constData(), sizeof(mac));
    }
    if (config.target_irk_le.size() == (int)sizeof(irk)) {
        memcpy(irk, config.target_irk_le.constData(), sizeof(irk));
    }
    sendCommand(BH_CMD_SET_TARGET, mac, sizeof(mac));
    sendCommand(BH_CMD_SET_IRK, irk, sizeof(irk));
    bh_decryptor_init(&hint_decryptor_);
    foreach (const QByteArray &ltk, KeyStore::instance()->ltks()) {
        bh_decryptor_add_ltk(&hint_decryptor_, reinterpret_cast<const uint8_t *>(ltk.constData()));
    }
    flag = config.single_target ? 1 : 0;
    sendCommand(BH_CMD_SET_SINGLE_TARGET, &flag, 1);
    // Frames queued before the configuration took effect are unfiltered.
    serial_.drainInput(kConfigSettleMs);
    pinned_ = false;
    return true;
}

namespace {

struct FrameContext {
    BoardReader *reader;
    int64_t host_us;
};

void onDecodedFrame(void *ctx, const uint8_t *frame, size_t len)
{
    FrameContext *c = static_cast<FrameContext *>(ctx);
    bh_packet pkt;
    bh_sync_frame sf;

    if (len > 0 && frame[0] == BH_FRAME_SYNC) {
        if (bh_parse_sync(frame, len, &sf)) {
            c->reader->owner()->onSyncFrame(c->reader, sf, c->host_us);
        }
        return;
    }
    if (!bh_parse_frame(frame, len, &pkt)) {
        return;
    }
    c->reader->pinGuardChannel(pkt.board_id);
    c->reader->countFrame(pkt, c->host_us);
    c->reader->owner()->onFrame(c->reader, pkt, c->host_us);
}

} // namespace

void BoardReader::run()
{
    bh_deframer deframer;
    uint8_t buf[4096];

    bh_deframer_init(&deframer);
    while (!stopping()) {
        if (!serial_.isOpen()) {
            if (!openAndConfigure()) {
                msleep(kReopenDelayMs);         /* unplugged or busy: keep trying */
                continue;
            }
            bh_deframer_init(&deframer);
        }
        ssize_t n = serial_.read(buf, sizeof(buf), kSerialPollMs);
        if (n < 0) {
            ws_info("BLEhound %s: read failed, reopening", qUtf8Printable(serial_location_));
            serial_.close();
            continue;
        }
        if (n == 0) {
            continue;
        }
        FrameContext ctx = { this, g_get_real_time() };
        bh_deframer_feed(&deframer, buf, (size_t)n, onDecodedFrame, &ctx);
        qint64 now = g_get_monotonic_time();
        if (now - last_report_us_ >= kReportIntervalUs) {
            reportFrames();
            last_report_us_ = now;
        }
        collector_.flushIfDue(now);
    }
    serial_.close();
    collector_.flush();
    reportFrames();
}

/* ---------------------------------------------------------- TriStreamer */

TriStreamer::TriStreamer(const QString &socket_path, DeviceManager *manager) :
    QThread(nullptr),
    socket_path_(socket_path),
    manager_(manager),
    stop_requested_(0)
{
    memset(&relay_, 0, sizeof(relay_));
    memset(&ts_, 0, sizeof(ts_));
}

TriStreamer::~TriStreamer()
{
    requestStop();
    wait();
}

CaptureConfig TriStreamer::config() const
{
    QMutexLocker locker(&config_mutex_);
    return config_;
}

void TriStreamer::setTarget(const QByteArray &mac_le, const QByteArray &irk_le)
{
    uint8_t mac[6] = { 0 };
    uint8_t irk[16] = { 0 };
    const bool have_irk = irk_le.size() == (int)sizeof(irk);

    if (mac_le.size() == (int)sizeof(mac)) {
        memcpy(mac, mac_le.constData(), sizeof(mac));
    }
    if (have_irk) {
        memcpy(irk, irk_le.constData(), sizeof(irk));
    }
    {
        QMutexLocker locker(&config_mutex_);
        config_.target_mac_le = mac_le;
        config_.target_irk_le = irk_le;
    }
    {
        QMutexLocker locker(&relay_mutex_);
        relay_.has_target = mac_le.size() == (int)sizeof(mac);
        memcpy(relay_.target, mac, sizeof(mac));
        bh_follow_relay_set_irk(&relay_, have_irk ? irk : nullptr);
    }
    QMutexLocker locker(&readers_mutex_);
    foreach (BoardReader *reader, readers_) {
        reader->sendCommand(BH_CMD_SET_TARGET, mac, sizeof(mac));
        reader->sendCommand(BH_CMD_SET_IRK, irk, sizeof(irk));
    }
}

void TriStreamer::reportState(const QStringList &ports, bool capturing)
{
    DeviceManager *manager = manager_;
    QMetaObject::invokeMethod(manager, [=]() {
        foreach (const QString &port, ports) {
            manager->reportCaptureState(port, capturing);
        }
    }, Qt::QueuedConnection);
}

void TriStreamer::setPorts(const QStringList &ports)
{
    QMutexLocker locker(&ports_mutex_);
    ports_ = ports;
}

bool TriStreamer::relaySend(void *ctx, uint8_t board_id, const uint8_t *params, size_t params_len)
{
    TriStreamer *self = static_cast<TriStreamer *>(ctx);
    BoardReader *reader = self->boards_.value(board_id);   /* relay_mutex_ held by caller */
    bool ok = reader != nullptr && reader->sendCommand(BH_CMD_FOLLOW, params, params_len);
    uint32_t aa = (uint32_t)params[0] | (uint32_t)params[1] << 8 | (uint32_t)params[2] << 16 | (uint32_t)params[3] << 24;
    uint32_t anchor = (uint32_t)params[21] | (uint32_t)params[22] << 8 | (uint32_t)params[23] << 16 | (uint32_t)params[24] << 24;

    ws_info("BLEhound relay: FOLLOW AA=%08x -> board %u (%s) anchor0=%u us %s", aa, board_id,
            reader ? qUtf8Printable(reader->location()) : "no reader", anchor, ok ? "sent" : "WRITE FAILED");
    return ok;
}

void TriStreamer::onSyncFrame(BoardReader *reader, const bh_sync_frame &sf, int64_t host_us)
{
    const CaptureConfig config = this->config();

    if (config.follow_relay && (!config.single_target || config.target_mac_le.size() == 6)) {
        QMutexLocker locker(&relay_mutex_);
        boards_[sf.board_id] = reader;
        bh_follow_relay_register(&relay_, sf.board_id);
        bh_follow_relay_observe(&relay_, sf.board_id, sf.sync_epoch, host_us);
    }
}

void TriStreamer::onFrame(BoardReader *reader, const bh_packet &pkt, int64_t host_us)
{
    const CaptureConfig config = this->config();

    // Relaying only makes sense when the boards would follow at all: in
    // single-target mode that needs a target.
    if (config.follow_relay && (!config.single_target || config.target_mac_le.size() == 6)) {
        QMutexLocker locker(&relay_mutex_);
        boards_[pkt.board_id] = reader;             /* re-registered after a reconnect */
        bh_follow_relay_register(&relay_, pkt.board_id);
        bh_follow_relay_observe(&relay_, pkt.board_id, pkt.sync_epoch, host_us);
        if (pkt.crc_ok) {
            bh_follow_relay_note_packet(&relay_, pkt.board_id, &pkt);
            if (bh_is_connect_ind(&pkt)) {
                bh_relay_stats before = relay_.stats;
                int sent = bh_follow_relay_maybe_relay(&relay_, pkt.board_id, &pkt, host_us, relaySend, this);
                uint32_t off[BH_MAX_BOARDS];
                bool have[BH_MAX_BOARDS];
                for (int b = 0; b < BH_MAX_BOARDS; b++) {
                    have[b] = bh_sync_clock_offset(&relay_.clock, (uint8_t)b, &off[b]);
                }
                uint32_t ref_tick = 0;
                bh_sync_clock_to_ref(&relay_.clock, pkt.board_id, pkt.ts_us, &ref_tick);
                ws_info("BLEhound relay: CONNECT_IND ts=%u on board %u (its sync_epoch=%u) -> ref tick %u; offsets b0=%u b1=%u b2=%u",
                        pkt.ts_us, pkt.board_id, pkt.sync_epoch, ref_tick, off[0], off[1], off[2]);
                ws_info("BLEhound relay: CONNECT_IND from board %u: sent %d, skipped target %u dup %u no-offset %u; "
                        "registered %d%d%d offsets %s/%s/%s trust=%d",
                        pkt.board_id, sent,
                        relay_.stats.skipped_target - before.skipped_target,
                        relay_.stats.skipped_dup - before.skipped_dup,
                        relay_.stats.skipped_no_offset - before.skipped_no_offset,
                        relay_.registered[0], relay_.registered[1], relay_.registered[2],
                        have[0] ? "ok" : "none", have[1] ? "ok" : "none", have[2] ? "ok" : "none",
                        relay_.trust_source);
            }
        }
        /* Boards that could not be reached yet, or did not pick the connection up, get it again. */
        bh_follow_relay_retry(&relay_, host_us, relaySend, this);
    }
    if (!pkt.crc_ok && !config.include_crc_errors) {
        return;
    }

    bh_agg_packet rec;
    bh_agg_packet_from(&rec, &pkt, host_us);

    QMutexLocker locker(&queue_mutex_);
    if (queue_.size() >= kQueueMax) {
        dropped_++;                                 /* never block a reader on the writer */
        return;
    }
    queue_.enqueue(rec);
    queue_cond_.wakeOne();
}

void TriStreamer::emitPacket(void *ctx, const bh_agg_packet *pkt)
{
    TriStreamer *self = static_cast<TriStreamer *>(ctx);
    bh_packet view;
    uint8_t rec[BH_MAX_RECORD_LEN];
    uint8_t hdr[BH_PCAP_RECORD_HEADER_LEN];

    uint8_t plain[BH_MAX_PDU_LEN + 2];
    uint8_t direction;
    uint16_t extra_flags = 0;

    bh_agg_packet_view(pkt, &view);
    if (bh_decryptor_process(&self->decryptor_, &view, plain, sizeof(plain), &direction)) {
        extra_flags = bh_rf_flags_for_decrypted(direction);
        /* Control-PDU hints go out from the reader threads (BoardReader::countFrame). */
    }
    size_t n = bh_btle_rf_record_ex(&view, extra_flags, rec, sizeof(rec));
    if (n == 0) {
        return;
    }
    bh_pcap_record_header((uint64_t)bh_ts_mapper_map_mono(&self->ts_, pkt->key64), (uint32_t)n, hdr);
    self->out_.append(reinterpret_cast<const char *>(hdr), sizeof(hdr));
    self->out_.append(reinterpret_cast<const char *>(rec), (qsizetype)n);
}

void TriStreamer::run()
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
        ws_info("BLEhound aggregated capture started");
        streamToClient(client_fd);
        close(client_fd);
        {
            QMutexLocker locker(&relay_mutex_);
            ws_info("BLEhound relay stats: relayed %u, commands %u, retried %u, skipped target %u dup %u no-offset %u",
                    relay_.stats.relayed, relay_.stats.sent_cmds, relay_.stats.retried,
                    relay_.stats.skipped_target, relay_.stats.skipped_dup, relay_.stats.skipped_no_offset);
        }
        ws_info("BLEhound aggregated capture ended (%llu packets dropped on the way to the aggregator)",
                (unsigned long long)dropped_);
    }
    close(listen_fd);
    unlink(socket_path_.toLocal8Bit().constData());
}

void TriStreamer::streamToClient(int client_fd)
{
    QStringList ports;
    QList<BoardReader *> readers;
    uint8_t global_header[BH_PCAP_GLOBAL_HEADER_LEN];

    {
        QMutexLocker locker(&ports_mutex_);
        ports = ports_;
    }
    // Settings edited in the device panel apply from the next capture on.
    {
        QMutexLocker locker(&config_mutex_);
        config_ = CaptureSettings::instance()->config();
    }
    reportState(ports, true);
    {
        /* The idle scanners hold the ports; readers retry until they let go. */
        DeviceManager *manager = manager_;
        QMetaObject::invokeMethod(manager, [manager]() { manager->setScanPaused(true); }, Qt::QueuedConnection);
    }
    {
        const CaptureConfig config = this->config();
        QMutexLocker locker(&relay_mutex_);
        const uint8_t *target = config.target_mac_le.size() == 6 ?
            reinterpret_cast<const uint8_t *>(config.target_mac_le.constData()) : nullptr;
        bh_follow_relay_init(&relay_, 0, target);
        /* Single-target mode: the catching board already let only the target's
         * CONNECT_IND through, so do not re-check it here with keys that may be stale. */
        bh_follow_relay_set_trust(&relay_, config.single_target && target != nullptr);
        ws_info("BLEhound aggregated capture: relay %s, single-target %d, target %s, irk %s",
                config.follow_relay ? "on" : "off", config.single_target, target ? "set" : "none",
                config.target_irk_le.isEmpty() ? "none" : "set");
        bh_decryptor_init(&decryptor_);
        foreach (const QByteArray &ltk, KeyStore::instance()->ltks()) {
            bh_decryptor_add_ltk(&decryptor_, reinterpret_cast<const uint8_t *>(ltk.constData()));
        }
        if (config.target_irk_le.size() == 16) {
            bh_follow_relay_set_irk(&relay_, reinterpret_cast<const uint8_t *>(config.target_irk_le.constData()));
        }
        boards_.clear();
    }
    {
        QMutexLocker locker(&queue_mutex_);
        queue_.clear();
        dropped_ = 0;
    }
    out_.clear();
    bh_ts_mapper_init(&ts_, (uint64_t)g_get_real_time());
    bh_aggregator *agg = bh_aggregator_new(BH_AGG_DEDUP_US, BH_AGG_REORDER_US, 0);
    if (agg == nullptr) {
        return;
    }

    bh_pcap_global_header(global_header);
    if (Socket::sendAll(client_fd, QByteArray(reinterpret_cast<const char *>(global_header), sizeof(global_header)))) {
        foreach (const QString &port, ports) {
            BoardReader *reader = new BoardReader(port, this);
            readers << reader;
        }
        {
            QMutexLocker locker(&readers_mutex_);
            readers_ = readers;
        }
        foreach (BoardReader *reader, readers) {
            reader->start();
        }

        while (!stopping()) {
            QList<bh_agg_packet> batch;
            {
                QMutexLocker locker(&queue_mutex_);
                if (queue_.isEmpty()) {
                    queue_cond_.wait(&queue_mutex_, kQueueWaitMs);
                }
                while (!queue_.isEmpty()) {
                    batch << queue_.dequeue();
                }
            }
            foreach (const bh_agg_packet &pkt, batch) {
                bh_aggregator_add(agg, &pkt, emitPacket, this);
            }
            if (!out_.isEmpty()) {
                if (!Socket::sendAll(client_fd, out_)) {
                    break;
                }
                out_.clear();
            }
            if (Socket::clientClosed(client_fd)) {
                break;
            }
        }
    }

    foreach (BoardReader *reader, readers) {
        reader->requestStop();
    }
    {
        QMutexLocker locker(&readers_mutex_);
        readers_.clear();
    }
    qDeleteAll(readers);                            /* waits for each thread */
    {
        QMutexLocker locker(&relay_mutex_);
        boards_.clear();
    }
    bh_aggregator_free(agg);
    reportState(ports, false);
    {
        DeviceManager *manager = manager_;
        QMetaObject::invokeMethod(manager, [manager]() { manager->setScanPaused(false); }, Qt::QueuedConnection);
    }
}

} // namespace BLEhound
