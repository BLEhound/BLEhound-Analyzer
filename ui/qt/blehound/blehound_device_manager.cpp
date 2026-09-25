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
#include "ui/iface_lists.h"

#include "main_application.h"

#include <QDir>
#include <QFileInfo>
#include <QSerialPortInfo>

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

void DeviceManager::install()
{
    if (manager_instance) {
        return;
    }
    manager_instance = new DeviceManager(mainApp);
    global_capture_opts.get_iface_list = noSystemInterfaces;
    set_extra_interfaces_fn(appendExtraInterfaces);
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

    tri_streamer_ = new TriStreamer(socket_dir_ + QStringLiteral("/aggregated.sock"));
    tri_streamer_->start();

    known_ports_ = connectedPorts();
    connect(&poll_timer_, &QTimer::timeout, this, &DeviceManager::pollPorts);
    poll_timer_.start(kHotplugPollMs);
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
        }
    }
    foreach (const QString &location, ports) {
        if (!streamers_.contains(location)) {
            Streamer *streamer = new Streamer(location, socketPathFor(location));
            streamers_.insert(location, streamer);
            streamer->start();
        }
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

void DeviceManager::appendInterfaces()
{
    QStringList ports = connectedPorts();
    syncStreamers(ports);
    known_ports_ = ports;

    foreach (const QString &location, ports) {
        ensureInterface(socketPathFor(location).toUtf8(),
                        QStringLiteral("%1: %2").arg(QStringLiteral(BH_USB_PRODUCT),
                                                     QFileInfo(location).fileName()).toUtf8());
    }
    // One merged capture across all boards, each guarding its own channel.
    if (ports.size() >= 2) {
        ensureInterface(tri_streamer_->socketPath().toUtf8(),
                        QStringLiteral("%1 (%2ch aggregated)").arg(QStringLiteral(BH_USB_PRODUCT))
                            .arg(ports.size()).toUtf8());
    }
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
