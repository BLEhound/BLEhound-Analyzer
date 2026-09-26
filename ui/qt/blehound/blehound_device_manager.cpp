/* blehound_device_manager.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_CAPTURE

#include "blehound_device_manager.h"
#include "blehound_streamer.h"
#include "blehound_tri_streamer.h"

#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <wsutil/wslog.h>

#include "ui/capture_globals.h"
#include "ui/capture_opts.h"
#include "ui/iface_lists.h"

#include "main_application.h"

#include <QDir>
#include <QFileInfo>
#include <QSerialPortInfo>
#include <QSet>

#include <blehound/blehound.h>

namespace BLEhound {

static const int kHotplugPollMs = 2000;
static DeviceManager *manager_instance;

static void appendExtraInterfaces(void)
{
    if (manager_instance) {
        manager_instance->appendInterfaces();
    }
}

/* BLEhound Analyzer lists only its dongles, so skip asking dumpcap for
 * network interfaces entirely. */
static GList *noSystemInterfaces(int *err, char **err_str)
{
    *err = 0;
    if (err_str) {
        *err_str = NULL;
    }
    return NULL;
}

DeviceManager *DeviceManager::instance()
{
    return manager_instance;
}

QList<DeviceManager::BoardInfo> DeviceManager::boards() const
{
    QList<BoardInfo> list;

    foreach (const QString &location, known_ports_) {
        list << boards_.value(location);
    }
    return list;
}

int DeviceManager::channelFor(const QString &location) const
{
    BoardInfo board = boards_.value(location);
    uint8_t channel;

    if (board.board_id >= 0) {
        return bh_guard_channel_for_board((uint8_t)board.board_id, &channel) ? channel : 0;
    }
    int rank = known_ports_.indexOf(location);
    return rank >= 0 && rank < 3 ? 37 + rank : 0;
}

void DeviceManager::applyTarget(const QByteArray &mac_le, const QByteArray &irk_le)
{
    foreach (Streamer *streamer, streamers_) {
        streamer->setTarget(mac_le, irk_le);
    }
    tri_streamer_->setTarget(mac_le, irk_le);
}

void DeviceManager::reportCaptureState(const QString &location, bool capturing)
{
    if (!boards_.contains(location)) {
        return;
    }
    BoardInfo &board = boards_[location];
    board.capturing = capturing;
    if (capturing) {
        board.packets = 0;
    }
    emit boardsChanged();
}

void DeviceManager::reportStatus(const QString &location, const bh_status &status)
{
    if (!boards_.contains(location)) {
        return;
    }
    BoardInfo &board = boards_[location];
    int old_channel = channelFor(location);
    board.have_status = true;
    board.board_id = status.board_id;
    board.fw_version = QString::fromUtf8(status.fw_version);
    board.sync_active = (status.flags & BH_STATUS_SYNC_ACTIVE) != 0;
    board.following = (status.flags & BH_STATUS_FOLLOWING) != 0;
    board.connects_seen = status.connects_seen;
    if (channelFor(location) != old_channel) {
        mainApp->refreshLocalInterfaces();
    }
    emit boardsChanged();
}

void DeviceManager::reportScanState(const QString &location, bool scanning)
{
    if (!boards_.contains(location)) {
        return;
    }
    boards_[location].scanning = scanning;
    emit boardsChanged();
}

void DeviceManager::setScanPaused(bool paused)
{
    foreach (Streamer *streamer, streamers_) {
        streamer->setScanPaused(paused);
    }
}

void DeviceManager::reportFrames(const QString &location, int board_id, quint64 packets)
{
    if (!boards_.contains(location)) {
        return;
    }
    BoardInfo &board = boards_[location];
    int old_channel = channelFor(location);
    board.packets = packets;
    board.board_id = board_id;
    if (channelFor(location) != old_channel) {
        mainApp->refreshLocalInterfaces();      /* rename the interface; deferred while capturing */
    }
    emit boardsChanged();
}

void DeviceManager::install()
{
    if (manager_instance) {
        return;
    }
    manager_instance = new DeviceManager(mainApp);
}

void DeviceManager::startWatching()
{
    global_capture_opts.get_iface_list = noSystemInterfaces;
    set_extra_interfaces_fn(appendExtraInterfaces);
    known_ports_ = connectedPorts();
    connect(&poll_timer_, &QTimer::timeout, this, &DeviceManager::pollPorts);
    poll_timer_.start(kHotplugPollMs);
}

DeviceManager::DeviceManager(QObject *parent) :
    QObject(parent)
{
    // Unix socket paths are limited to ~104 bytes, so avoid the long
    // per-user temp directory on macOS.
    socket_dir_ = QStringLiteral("/tmp/blehound-%1").arg(getuid());
    QByteArray dir = socket_dir_.toLocal8Bit();
    mkdir(dir.constData(), 0700);
    chmod(dir.constData(), 0700);

    tri_streamer_ = new TriStreamer(socket_dir_ + QStringLiteral("/aggregated.sock"), this);
    tri_streamer_->start();

}

DeviceManager::~DeviceManager()
{
    set_extra_interfaces_fn(nullptr);
    manager_instance = nullptr;
    qDeleteAll(streamers_);
    delete tri_streamer_;
}

QStringList DeviceManager::connectedPorts()
{
    QStringList ports;

    foreach (const QSerialPortInfo &info, QSerialPortInfo::availablePorts()) {
        if (!info.hasVendorIdentifier() || info.vendorIdentifier() != BH_USB_VID ||
                !info.hasProductIdentifier() || info.productIdentifier() != BH_USB_PID) {
            continue;
        }
#ifdef Q_OS_MAC
        // Each CDC device shows up as both tty.* and cu.*; cu.* does not wait for DCD.
        if (!info.portName().startsWith(QStringLiteral("cu."))) {
            continue;
        }
#endif
        ports << info.systemLocation();
    }
    ports.sort();
    return ports;
}

QString DeviceManager::socketPathFor(const QString &location) const
{
    return QStringLiteral("%1/%2.sock").arg(socket_dir_, QFileInfo(location).fileName());
}

void DeviceManager::syncStreamers(const QStringList &ports)
{
    tri_streamer_->setPorts(ports);
    foreach (const QString &location, streamers_.keys()) {
        if (!ports.contains(location)) {
            delete streamers_.take(location);
            boards_.remove(location);
        }
    }
    foreach (const QString &location, ports) {
        if (!streamers_.contains(location)) {
            Streamer *streamer = new Streamer(location, socketPathFor(location), this);
            streamers_.insert(location, streamer);
            streamer->start();
            BoardInfo board;
            board.location = location;
            boards_.insert(location, board);
        }
    }
}

/* The aggregated capture is what a user wants nearly always, so it is the
 * selection on the welcome page unless one of our interfaces was picked already. */
void DeviceManager::selectByDefault(const QByteArray &name, const QSet<QString> &ours)
{
    interface_t *target = nullptr;

    for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (device->selected && ours.contains(QString::fromUtf8(device->name))) {
            return;
        }
        if (strcmp(device->name, name.constData()) == 0) {
            target = device;
        }
    }
    if (target && !target->selected) {
        target->selected = true;
        global_capture_opts.num_selected++;
    }
}

void DeviceManager::ensureInterface(const QByteArray &name, const QByteArray &display)
{
    // A selected pipe is re-added by the scan itself; just refresh its name.
    for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (strcmp(device->name, name.constData()) == 0) {
            g_free(device->display_name);
            device->display_name = g_strdup(display.constData());
            return;
        }
    }

    interface_t device;
    memset(&device, 0, sizeof(device));
    device.name = g_strdup(name.constData());
    device.display_name = g_strdup(display.constData());
    device.hidden = false;
    device.selected = false;
    device.local = true;
    device.pmode = false;
    device.has_snaplen = global_capture_opts.default_options.has_snaplen;
    device.snaplen = global_capture_opts.default_options.snaplen;
    device.cfilter = g_strdup(global_capture_opts.default_options.cfilter);
    device.timestamp_type = g_strdup(global_capture_opts.default_options.timestamp_type);
    device.buffer = DEFAULT_CAPTURE_BUFFER_SIZE;
    link_row *link = g_new(link_row, 1);
    link->name = g_strdup("Bluetooth LE LL");
    link->dlt = BH_DLT_BTLE_LL_WITH_PHDR;
    device.links = g_list_append(NULL, link);
    device.active_dlt = BH_DLT_BTLE_LL_WITH_PHDR;
    device.if_info.name = g_strdup(name.constData());
    device.if_info.friendly_name = g_strdup(display.constData());
    device.if_info.vendor_description = g_strdup(BH_USB_PRODUCT);
    device.if_info.type = IF_PIPE;
    g_array_append_val(global_capture_opts.all_ifaces, device);
}

/* Wireshark's interface scan drops local devices it no longer finds, but
 * keeps pipes forever. Dongles that re-enumerate get new port names, so
 * remove our pipes whose socket is no longer served. */
void DeviceManager::removeStaleInterfaces(const QSet<QString> &valid_names)
{
    QByteArray prefix = (socket_dir_ + QStringLiteral("/")).toUtf8();

    for (int i = (int)global_capture_opts.all_ifaces->len - 1; i >= 0; i--) {
        interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (!g_str_has_prefix(device.name, prefix.constData()) ||
                valid_names.contains(QString::fromUtf8(device.name))) {
            continue;
        }
        ws_info("BLEhound: dropping stale interface %s", device.name);
        global_capture_opts.all_ifaces = g_array_remove_index(global_capture_opts.all_ifaces, i);
        if (device.selected) {
            global_capture_opts.num_selected--;
        }
        capture_opts_free_interface_t(&device);
    }
    // A selected stale pipe would otherwise be re-added by the next scan.
    for (int i = (int)global_capture_opts.ifaces->len - 1; i >= 0; i--) {
        interface_options *opts = &g_array_index(global_capture_opts.ifaces, interface_options, i);
        if (g_str_has_prefix(opts->name, prefix.constData()) &&
                !valid_names.contains(QString::fromUtf8(opts->name))) {
            capture_opts_del_iface(&global_capture_opts, (unsigned)i);
        }
    }
}

void DeviceManager::appendInterfaces()
{
    QStringList ports = connectedPorts();
    QSet<QString> valid_names;

    syncStreamers(ports);
    known_ports_ = ports;

    foreach (const QString &location, ports) {
        valid_names.insert(socketPathFor(location));
    }
    if (ports.size() >= 2) {
        valid_names.insert(tri_streamer_->socketPath());
    }
    removeStaleInterfaces(valid_names);

    foreach (const QString &location, ports) {
        int channel = channelFor(location);
        QString display = channel ?
            QStringLiteral("%1 CH%2: %3").arg(QStringLiteral(BH_USB_PRODUCT)).arg(channel)
                .arg(QFileInfo(location).fileName()) :
            QStringLiteral("%1: %2").arg(QStringLiteral(BH_USB_PRODUCT), QFileInfo(location).fileName());
        ensureInterface(socketPathFor(location).toUtf8(), display.toUtf8());
    }
    // One merged capture across all boards, each guarding its own channel.
    if (ports.size() >= 2) {
        QByteArray aggregated = tri_streamer_->socketPath().toUtf8();
        ensureInterface(aggregated,
                        QStringLiteral("%1 (%2ch aggregated)").arg(QStringLiteral(BH_USB_PRODUCT))
                            .arg(ports.size()).toUtf8());
        selectByDefault(aggregated, valid_names);
    }
    emit boardsChanged();
}

void DeviceManager::pollPorts()
{
    QStringList ports = connectedPorts();
    if (ports != known_ports_) {
        ws_info("BLEhound dongles changed: %s", qUtf8Printable(ports.join(", ")));
        known_ports_ = ports;
        mainApp->refreshLocalInterfaces();
    }
}

} // namespace BLEhound
