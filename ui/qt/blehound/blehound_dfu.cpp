/* blehound_dfu.cpp
 *
 * USB firmware update of BLEhound dongles over the firmware loader (SMP).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "blehound_dfu.h"

#include "blehound_device_manager.h"
#include "blehound_i18n.h"
#include "blehound_serial.h"

#include <blehound/blehound.h>

#include <QCheckBox>
#include <QElapsedTimer>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QSerialPortInfo>
#include <QSettings>
#include <QTimer>
#include <QCoreApplication>
#include <cstdio>
#include <QVBoxLayout>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace BLEhound {

namespace {

const int kLoaderWaitMs = 15000;        /**< loader enumeration after ENTER_DFU */
const int kAppWaitMs = 15000;           /**< app enumeration after the reset */
const int kReplyTimeoutMs = 5000;
const int kPollMs = 250;
const char kSettingsImageKey[] = "dfu/lastImage";

struct Reply {
    bool have = false;
    bh_smp_hdr hdr;
    QByteArray payload;
};

void onSmpPacket(void *ctx, const bh_smp_hdr *hdr, const uint8_t *payload, size_t len)
{
    Reply *r = static_cast<Reply *>(ctx);
    r->have = true;
    r->hdr = *hdr;
    r->payload = QByteArray(reinterpret_cast<const char *>(payload), (int)len);
}

QStringList portsWithPid(quint16 pid)
{
    QStringList ports;
    foreach (const QSerialPortInfo &info, QSerialPortInfo::availablePorts()) {
        if (!info.hasVendorIdentifier() || info.vendorIdentifier() != BH_USB_VID ||
                !info.hasProductIdentifier() || info.productIdentifier() != pid) {
            continue;
        }
#ifdef Q_OS_MAC
        if (!info.portName().startsWith(QStringLiteral("cu."))) {
            continue;
        }
#endif
        ports << info.systemLocation();
    }
    ports.sort();
    return ports;
}

} // namespace

/* ---- worker ------------------------------------------------------------- */

DfuWorker::DfuWorker(const QString &capture_port, const QByteArray &image, QObject *parent) :
    QThread(parent),
    capture_port_(capture_port),
    image_(image)
{
}

QStringList DfuWorker::loaderPorts()
{
    return portsWithPid(BH_USB_PID_LOADER);
}

void DfuWorker::run()
{
    QString loader_port;
    NativeSerial port;
    uint8_t seq = 0;

    if (!enterLoader(&loader_port)) {
        return;
    }
    if (!openLoader(port, loader_port)) {
        return;
    }
    if (!upload(port, &seq)) {
        port.close();
        return;
    }
    emit progress(100, localized("Restarting the board…", "正在重启板子…"));
    {
        uint8_t line[64];
        size_t n = bh_smp_req_reset(++seq, line, sizeof(line));
        QByteArray reply;
        /* The board resets right away; the reply may never arrive. */
        (void)transact(port, QByteArray(reinterpret_cast<const char *>(line), (int)n), seq, &reply, 1500);
    }
    port.close();
    if (!waitForApp(loader_port)) {
        return;
    }
    emit done(true, localized("Update complete.", "升级完成。"));
}

bool DfuWorker::enterLoader(QString *loader_port)
{
    const QStringList before = loaderPorts();

    if (before.contains(capture_port_)) {
        /* Already in the loader (an earlier update was interrupted). */
        *loader_port = capture_port_;
        emit progress(0, localized("Board is already in update mode.", "板子已处于升级模式。"));
        return true;
    }

    emit progress(0, localized("Switching the board to update mode…", "正在让板子进入升级模式…"));
    {
        NativeSerial app;
        QString error;
        if (!app.open(capture_port_, &error)) {
            emit done(false, localized("Cannot open the capture port: ", "打不开抓包串口：") + error);
            return false;
        }
        uint8_t line[16];
        size_t n = bh_cmd_build(BH_CMD_ENTER_DFU, nullptr, 0, line, sizeof(line));
        line[n++] = 0x00;
        bool ok = app.write(line, n);
        msleep(200);
        app.close();
        if (!ok) {
            emit done(false, localized("Failed to send the update command.", "发送升级命令失败。"));
            return false;
        }
    }

    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < kLoaderWaitMs) {
        msleep(kPollMs);
        const QStringList now = loaderPorts();
        if (now.contains(capture_port_)) {        /* macOS: same name for the same USB location */
            *loader_port = capture_port_;
            return true;
        }
        QStringList fresh;
        foreach (const QString &p, now) {
            if (!before.contains(p)) {
                fresh << p;
            }
        }
        if (fresh.size() == 1) {
            *loader_port = fresh.first();
            return true;
        }
    }
    emit done(false, localized("The board did not enter update mode (no \"BLEhound Loader\" appeared).",
                               "板子没有进入升级模式（没有出现 \"BLEhound Loader\"）。"));
    return false;
}

bool DfuWorker::openLoader(NativeSerial &port, const QString &path)
{
    QElapsedTimer timer;
    QString error;

    timer.start();
    while (timer.elapsed() < 3000) {
        if (port.open(path, &error)) {
            msleep(100);
            port.drainInput(50);
            return true;
        }
        msleep(kPollMs);
    }
    emit done(false, localized("Cannot open the loader port: ", "打不开加载器串口：") + error);
    return false;
}

bool DfuWorker::transact(NativeSerial &port, const QByteArray &request, uint8_t seq,
                         QByteArray *reply_payload, int timeout_ms)
{
    /* One line at a time with a pause: the loader has only two 128-byte line buffers. */
    const uint8_t *data = reinterpret_cast<const uint8_t *>(request.constData());
    int start = 0;
    for (int i = 0; i < request.size(); i++) {
        if (data[i] == '\n') {
            if (!port.write(data + start, (size_t)(i + 1 - start))) {
                return false;
            }
            start = i + 1;
            usleep(BH_SMP_LINE_DELAY_US);
        }
    }

    bh_smp_deframer deframer;
    bh_smp_deframer_init(&deframer);
    Reply reply;
    uint8_t buf[512];
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < timeout_ms) {
        ssize_t n = port.read(buf, sizeof(buf), 50);
        if (n < 0) {
            return false;
        }
        if (n == 0) {
            continue;
        }
        bh_smp_deframer_feed(&deframer, buf, (size_t)n, onSmpPacket, &reply);
        if (reply.have) {
            if (reply.hdr.seq == seq) {
                *reply_payload = reply.payload;
                return true;
            }
            reply.have = false;
        }
    }
    return false;
}

bool DfuWorker::upload(NativeSerial &port, uint8_t *seq)
{
    uint8_t line[BH_SMP_MAX_ENCODED];
    QByteArray reply;
    uint32_t buf_size = BH_SMP_DEFAULT_BUF_SIZE;

    size_t n = bh_smp_req_params(++*seq, line, sizeof(line));
    if (transact(port, QByteArray(reinterpret_cast<const char *>(line), (int)n), *seq, &reply, 2000)) {
        (void)bh_smp_rsp_params(reinterpret_cast<const uint8_t *>(reply.constData()),
                                (size_t)reply.size(), &buf_size, nullptr);
    }

    n = bh_smp_req_image_state(++*seq, line, sizeof(line));
    if (transact(port, QByteArray(reinterpret_cast<const char *>(line), (int)n), *seq, &reply, kReplyTimeoutMs)) {
        bh_smp_image images[4];
        int count = bh_smp_rsp_images(reinterpret_cast<const uint8_t *>(reply.constData()),
                                      (size_t)reply.size(), images, 4);
        for (int i = 0; i < count; i++) {
            if (images[i].slot == 0) {
                emit progress(0, localized("Current app image: ", "当前应用镜像：") +
                              QString::fromLatin1(images[i].version));
            }
        }
    } else {
        emit done(false, localized("The loader does not answer.", "加载器没有应答。"));
        return false;
    }

    const size_t chunk = bh_smp_upload_chunk_max(buf_size);
    const uint32_t total = (uint32_t)image_.size();
    const uint8_t *data = reinterpret_cast<const uint8_t *>(image_.constData());
    uint32_t off = 0;
    int last_percent = -1;
    QElapsedTimer timer;

    timer.start();
    while (off < total) {
        size_t len = total - off < chunk ? (size_t)(total - off) : chunk;
        n = bh_smp_req_image_upload(++*seq, off, total, data + off, len, line, sizeof(line));
        if (n == 0 || !transact(port, QByteArray(reinterpret_cast<const char *>(line), (int)n),
                                *seq, &reply, kReplyTimeoutMs)) {
            emit done(false, localized("No reply while uploading at offset %1.", "上传到偏移 %1 时没有应答。").arg(off));
            return false;
        }
        int32_t rc = 0;
        uint32_t next = off;
        if (!bh_smp_rsp_status(reinterpret_cast<const uint8_t *>(reply.constData()),
                               (size_t)reply.size(), &rc, &next) || rc != 0) {
            emit done(false, localized("The loader rejected the image at offset %1 (rc %2).",
                                       "加载器在偏移 %1 拒绝了镜像（rc %2）。").arg(off).arg(rc));
            return false;
        }
        if (next <= off) {
            emit done(false, localized("The loader did not advance (offset %1).", "加载器没有前进（偏移 %1）。").arg(off));
            return false;
        }
        off = next;
        int percent = (int)((quint64)off * 100 / total);
        if (percent != last_percent) {
            last_percent = percent;
            emit progress(percent, localized("Uploading %1 / %2 bytes", "上传中 %1 / %2 字节").arg(off).arg(total));
        }
    }
    emit progress(100, localized("Uploaded %1 bytes in %2 s.", "已上传 %1 字节，用时 %2 秒。")
                  .arg(total).arg(timer.elapsed() / 1000.0, 0, 'f', 1));
    return true;
}

bool DfuWorker::waitForApp(const QString &loader_port)
{
    QElapsedTimer timer;

    emit progress(100, localized("Waiting for the sniffer to come back…", "等待抓包固件重新枚举…"));
    timer.start();
    while (timer.elapsed() < kAppWaitMs) {
        msleep(kPollMs);
        if (portsWithPid(BH_USB_PID).contains(loader_port) || portsWithPid(BH_USB_PID).contains(capture_port_)) {
            return true;
        }
    }
    if (loaderPorts().contains(loader_port)) {
        emit done(false, localized("The board stayed in update mode: MCUboot did not accept the new image "
                                   "(wrong signing key or corrupt file).",
                                   "板子仍停在升级模式：MCUboot 没有接受新镜像（签名密钥不对或文件损坏）。"));
    } else {
        emit done(false, localized("The sniffer did not re-enumerate after the update.", "升级后没有重新枚举出抓包固件。"));
    }
    return false;
}

/* ---- dialog ------------------------------------------------------------- */

DfuDialog::DfuDialog(QWidget *parent) :
    QDialog(parent)
{
    setWindowTitle(localized("Update firmware", "升级固件"));
    setMinimumWidth(520);

    QVBoxLayout *layout = new QVBoxLayout(this);

    QLabel *intro = new QLabel(localized("Uploads a signed application image (blehound_ota.bin) to the selected "
                                         "boards over USB. Each board restarts into its firmware loader, "
                                         "receives the image and restarts into the new firmware.",
                                         "经 USB 把签名的应用镜像（blehound_ota.bin）写入选中的板子。每块板会先重启进入"
                                         "固件加载器，收完镜像后重启进入新固件。"), this);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    QHBoxLayout *file_row = new QHBoxLayout();
    image_path_ = new QLineEdit(this);
    image_path_->setPlaceholderText(localized("Firmware image (.bin)", "固件镜像（.bin）"));
    QPushButton *browse = new QPushButton(localized("Browse…", "浏览…"), this);
    file_row->addWidget(image_path_);
    file_row->addWidget(browse);
    layout->addLayout(file_row);

    layout->addWidget(new QLabel(localized("Boards to update:", "要升级的板子："), this));
    boards_ = new QListWidget(this);
    boards_->setSelectionMode(QAbstractItemView::NoSelection);
    boards_->setFixedHeight(90);
    foreach (const DeviceManager::BoardInfo &board, DeviceManager::instance()->boards()) {
        int channel = DeviceManager::instance()->channelFor(board.location);
        QString label = QStringLiteral("%1  %2  %3")
                .arg(channel ? QStringLiteral("CH%1").arg(channel) : QStringLiteral("?"),
                     QFileInfo(board.location).fileName(),
                     board.have_status ? board.fw_version : QStringLiteral("—"));
        QListWidgetItem *item = new QListWidgetItem(label, boards_);
        item->setFlags(Qt::ItemIsUserCheckable | Qt::ItemIsEnabled);
        item->setCheckState(board.capturing ? Qt::Unchecked : Qt::Checked);
        item->setData(Qt::UserRole, board.location);
        if (board.capturing) {
            item->setToolTip(localized("Capturing: stop the capture first.", "抓包中：先停止抓包。"));
        }
    }
    layout->addWidget(boards_);

    progress_ = new QProgressBar(this);
    progress_->setRange(0, 100);
    progress_->setValue(0);
    layout->addWidget(progress_);

    log_ = new QPlainTextEdit(this);
    log_->setReadOnly(true);
    log_->setMaximumBlockCount(500);
    log_->setFixedHeight(140);
    layout->addWidget(log_);

    QHBoxLayout *buttons = new QHBoxLayout();
    buttons->addStretch();
    start_ = new QPushButton(localized("Start update", "开始升级"), this);
    start_->setDefault(true);
    close_ = new QPushButton(localized("Close", "关闭"), this);
    buttons->addWidget(start_);
    buttons->addWidget(close_);
    layout->addLayout(buttons);

    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
    image_path_->setText(settings.value(QLatin1String(kSettingsImageKey)).toString());

    connect(browse, &QPushButton::clicked, this, &DfuDialog::browse);
    connect(start_, &QPushButton::clicked, this, &DfuDialog::start);
    connect(close_, &QPushButton::clicked, this, &QDialog::reject);
    connect(image_path_, &QLineEdit::textChanged, this, &DfuDialog::updateStartButton);
    connect(boards_, &QListWidget::itemChanged, this, &DfuDialog::updateStartButton);
    updateStartButton();
}

void DfuDialog::browse()
{
    QString start_dir = QFileInfo(image_path_->text()).absolutePath();
    QString path = QFileDialog::getOpenFileName(this, localized("Choose the firmware image", "选择固件镜像"),
                                                start_dir, QStringLiteral("BLEhound firmware (*.bin);;All files (*)"));
    if (!path.isEmpty()) {
        image_path_->setText(path);
    }
}

void DfuDialog::updateStartButton()
{
    if (running_) {
        start_->setEnabled(false);
        return;
    }
    bool any = false;
    for (int i = 0; i < boards_->count(); i++) {
        any = any || boards_->item(i)->checkState() == Qt::Checked;
    }
    start_->setEnabled(any && QFileInfo(image_path_->text()).isFile());
}

void DfuDialog::log(const QString &line)
{
    log_->appendPlainText(line);
    if (auto_test_) {
        fprintf(stderr, "[dfu] %s\n", qUtf8Printable(line));
        fflush(stderr);
    }
}

void DfuDialog::autoTestIfRequested(QWidget *parent)
{
    const QByteArray image = qgetenv("BLEHOUND_DFU_AUTOTEST");

    if (image.isEmpty()) {
        return;
    }
    /* Give the device manager a moment to enumerate the dongles first. */
    QTimer::singleShot(4000, parent, [parent, image]() {
        DfuDialog *dialog = new DfuDialog(parent);
        dialog->auto_test_ = true;
        dialog->image_path_->setText(QString::fromLocal8Bit(image));
        for (int i = 0; i < dialog->boards_->count(); i++) {
            dialog->boards_->item(i)->setCheckState(Qt::Checked);
        }
        dialog->show();
        if (dialog->boards_->count() == 0) {
            fprintf(stderr, "[dfu] no boards found\n");
            QCoreApplication::exit(1);
            return;
        }
        dialog->start();
    });
}

void DfuDialog::start()
{
    QFile file(image_path_->text());
    if (!file.open(QIODevice::ReadOnly)) {
        log(localized("Cannot read the image file.", "读不了镜像文件。"));
        if (auto_test_) { QCoreApplication::exit(1); return; }
        QMessageBox::warning(this, windowTitle(), localized("Cannot read the image file.", "读不了镜像文件。"));
        return;
    }
    image_ = file.readAll();
    if (image_.size() < 1024 || image_.size() > 1880 * 1024) {
        QMessageBox::warning(this, windowTitle(), localized("This does not look like a BLEhound application image.",
                                                            "这不像是 BLEhound 应用镜像。"));
        return;
    }
    /* MCUboot image header magic 0x96f3b83d, little-endian. */
    const uint8_t *hdr = reinterpret_cast<const uint8_t *>(image_.constData());
    if (!(hdr[0] == 0x3d && hdr[1] == 0xb8 && hdr[2] == 0xf3 && hdr[3] == 0x96)) {
        QMessageBox::warning(this, windowTitle(), localized("The file has no MCUboot image header. Use the signed "
                                                            "blehound_ota.bin from the firmware build.",
                                                            "文件没有 MCUboot 镜像头。请用固件构建产物里的签名镜像 "
                                                            "blehound_ota.bin。"));
        return;
    }
    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
    settings.setValue(QLatin1String(kSettingsImageKey), image_path_->text());

    queue_.clear();
    for (int i = 0; i < boards_->count(); i++) {
        if (boards_->item(i)->checkState() == Qt::Checked) {
            queue_ << boards_->item(i)->data(Qt::UserRole).toString();
        }
    }
    foreach (const DeviceManager::BoardInfo &board, DeviceManager::instance()->boards()) {
        if (board.capturing && queue_.contains(board.location)) {
            QMessageBox::warning(this, windowTitle(), localized("Stop the capture before updating.", "请先停止抓包再升级。"));
            return;
        }
    }
    total_ = queue_.size();
    failed_ = 0;
    running_ = true;
    boards_->setEnabled(false);
    image_path_->setEnabled(false);
    close_->setEnabled(false);
    updateStartButton();
    log(localized("Image: %1 (%2 bytes)", "镜像：%1（%2 字节）").arg(image_path_->text()).arg(image_.size()));
    /* Release the serial ports: the idle scanners hold them open. */
    DeviceManager::instance()->setScanPaused(true);
    QThread::msleep(300);
    nextBoard();
}

void DfuDialog::nextBoard()
{
    if (queue_.isEmpty()) {
        finish();
        return;
    }
    QString port = queue_.takeFirst();
    log(QStringLiteral("— %1 (%2/%3)").arg(QFileInfo(port).fileName()).arg(total_ - queue_.size()).arg(total_));
    progress_->setValue(0);
    worker_ = new DfuWorker(port, image_, this);
    connect(worker_, &DfuWorker::progress, this, &DfuDialog::onProgress);
    connect(worker_, &DfuWorker::done, this, &DfuDialog::onDone);
    worker_->start();
}

void DfuDialog::onProgress(int percent, const QString &message)
{
    progress_->setValue(percent);
    if (!message.startsWith(localized("Uploading", "上传中")) || percent == 100 || percent % 25 == 0) {
        log(message);
    }
}

void DfuDialog::onDone(bool ok, const QString &message)
{
    log((ok ? QStringLiteral("✓ ") : QStringLiteral("✗ ")) + message);
    if (!ok) {
        failed_++;
    }
    worker_->wait();
    worker_->deleteLater();
    worker_ = nullptr;
    nextBoard();
}

void DfuDialog::finish()
{
    DeviceManager::instance()->setScanPaused(false);
    running_ = false;
    boards_->setEnabled(true);
    image_path_->setEnabled(true);
    close_->setEnabled(true);
    updateStartButton();
    if (failed_ == 0) {
        log(localized("All %1 board(s) updated.", "%1 块板全部升级完成。").arg(total_));
    } else {
        log(localized("%1 of %2 board(s) failed.", "%2 块板中有 %1 块失败。").arg(failed_).arg(total_));
    }
    if (auto_test_) {
        QCoreApplication::exit(failed_ == 0 ? 0 : 1);
    }
}

} // namespace BLEhound
