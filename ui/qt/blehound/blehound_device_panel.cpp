/* blehound_device_panel.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "blehound_device_panel.h"

#include "blehound_capture_settings.h"
#include "blehound_device_manager.h"
#include "blehound_i18n.h"

#include <QAction>
#include <QCloseEvent>
#include <QCheckBox>
#include <QComboBox>
#include <QFileInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMenu>
#include <QSettings>
#include <QTableWidget>
#include <QVBoxLayout>

#include <blehound/blehound.h>

namespace BLEhound {

enum BoardColumn {
    ColBoard,
    ColPort,
    ColStatus,
    ColPackets,
    ColCount
};

DevicePanel::DevicePanel(QWidget *parent) :
    QDockWidget(localized("BLEhound Devices", "BLEhound 设备"), parent)
{
    setObjectName(QStringLiteral("blehoundDevicePanel"));
    setAllowedAreas(Qt::LeftDockWidgetArea | Qt::RightDockWidgetArea);

    QWidget *content = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(content);
    layout->addWidget(buildBoardList());
    layout->addWidget(buildSettings());
    layout->addStretch();
    setWidget(content);

    connect(DeviceManager::instance(), &DeviceManager::boardsChanged, this, &DevicePanel::refreshBoards);
    connect(CaptureSettings::instance(), &CaptureSettings::changed, this, &DevicePanel::loadSettings);
    refreshBoards();
    loadSettings();
}

QWidget *DevicePanel::buildBoardList()
{
    QWidget *box = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(box);
    layout->setContentsMargins(0, 0, 0, 0);

    empty_label_ = new QLabel(localized("No BLEhound dongle found. Plug one in and it will appear here.",
                                        "没有找到 BLEhound dongle，插上后会自动出现在这里。"), box);
    empty_label_->setWordWrap(true);
    layout->addWidget(empty_label_);

    table_ = new QTableWidget(0, ColCount, box);
    table_->setHorizontalHeaderLabels({
        localized("Board", "板子"), localized("Port", "串口"),
        localized("Status", "状态"), localized("Packets", "包数"),
    });
    table_->verticalHeader()->hide();
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionMode(QAbstractItemView::NoSelection);
    table_->setFocusPolicy(Qt::NoFocus);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(table_);
    return box;
}

QWidget *DevicePanel::buildSettings()
{
    QGroupBox *group = new QGroupBox(localized("Capture settings (apply at the next start)",
                                               "采集设置（下次开始抓包时生效）"), this);
    QFormLayout *form = new QFormLayout(group);

    hop_ = new QCheckBox(localized("Hop 37 / 38 / 39", "轮流扫描 37 / 38 / 39"), group);
    channel_ = new QComboBox(group);
    channel_->addItems({ QStringLiteral("37"), QStringLiteral("38"), QStringLiteral("39") });
    QWidget *channel_row = new QWidget(group);
    QHBoxLayout *channel_layout = new QHBoxLayout(channel_row);
    channel_layout->setContentsMargins(0, 0, 0, 0);
    channel_layout->addWidget(hop_);
    channel_layout->addWidget(new QLabel(localized("or stay on", "或固定在"), channel_row));
    channel_layout->addWidget(channel_);
    channel_layout->addStretch();
    form->addRow(localized("Single board", "单板"), channel_row);

    target_ = new QLineEdit(group);
    target_->setPlaceholderText(QStringLiteral("AA:BB:CC:DD:EE:FF"));
    target_->setToolTip(localized("Follow only connections to this device. Leave empty to follow any connection.",
                                  "只跟随与这个设备建立的连接；留空则跟随任意连接。"));
    target_hint_ = new QLabel(group);
    target_hint_->setStyleSheet(QStringLiteral("color: #E5484D"));
    target_hint_->hide();
    QWidget *target_row = new QWidget(group);
    QVBoxLayout *target_layout = new QVBoxLayout(target_row);
    target_layout->setContentsMargins(0, 0, 0, 0);
    target_layout->addWidget(target_);
    target_layout->addWidget(target_hint_);
    form->addRow(localized("Target device", "目标设备"), target_row);

    include_crc_ = new QCheckBox(localized("Include CRC-error packets", "包含 CRC 校验错误的包"), group);
    include_crc_->setToolTip(localized("Useful when diagnosing weak signals.", "排查信号弱的问题时有用。"));
    form->addRow(QString(), include_crc_);

    single_target_ = new QCheckBox(localized("Single-target mode", "单目标模式"), group);
    single_target_->setToolTip(localized("Follow one connection at a time and stop scanning while following. "
                                         "Off: keep scanning and follow up to 6 connections (evaluation).",
                                         "一次只跟一个连接，跟随期间不再扫描。关闭后持续扫描并最多同时跟 6 个连接（评估用）。"));
    form->addRow(QString(), single_target_);

    follow_relay_ = new QCheckBox(localized("Joint follow across boards (aggregated capture)",
                                            "多板联合跟随（聚合抓包）"), group);
    follow_relay_->setToolTip(localized("When one board sees a CONNECT_IND, hand the connection to the other boards "
                                        "so they follow it together and fill in each other's gaps.",
                                        "一块板抓到 CONNECT_IND 时把连接参数发给其他板，三块一起跟，互相补漏包。"));
    form->addRow(QString(), follow_relay_);

    connect(hop_, &QCheckBox::toggled, this, &DevicePanel::saveSettings);
    connect(channel_, &QComboBox::currentIndexChanged, this, &DevicePanel::saveSettings);
    connect(target_, &QLineEdit::editingFinished, this, &DevicePanel::saveSettings);
    connect(include_crc_, &QCheckBox::toggled, this, &DevicePanel::saveSettings);
    connect(single_target_, &QCheckBox::toggled, this, &DevicePanel::saveSettings);
    connect(follow_relay_, &QCheckBox::toggled, this, &DevicePanel::saveSettings);
    return group;
}

void DevicePanel::closeEvent(QCloseEvent *event)
{
    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
    settings.setValue(QStringLiteral("ui/devicePanelVisible"), false);
    QDockWidget::closeEvent(event);
}

void DevicePanel::refreshBoards()
{
    DeviceManager *manager = DeviceManager::instance();
    QList<DeviceManager::BoardInfo> boards = manager->boards();

    empty_label_->setVisible(boards.isEmpty());
    table_->setVisible(!boards.isEmpty());
    table_->setRowCount(boards.size());
    for (int row = 0; row < boards.size(); row++) {
        const DeviceManager::BoardInfo &board = boards.at(row);
        int channel = manager->channelFor(board.location);
        QString label = channel ? QStringLiteral("CH%1").arg(channel) : QStringLiteral("?");
        if (board.board_id < 0) {
            label += localized(" (by port order)", "（按串口顺序）");
        }
        QString status = board.capturing ? localized("Capturing", "抓包中") :
                         board.scanning ? localized("Scanning", "扫描中") : localized("Idle", "空闲");

        table_->setItem(row, ColBoard, new QTableWidgetItem(label));
        table_->setItem(row, ColPort, new QTableWidgetItem(QFileInfo(board.location).fileName()));
        table_->setItem(row, ColStatus, new QTableWidgetItem(status));
        table_->setItem(row, ColPackets, new QTableWidgetItem(QString::number(board.packets)));
    }
    int height = table_->horizontalHeader()->height() + 4;
    for (int row = 0; row < table_->rowCount(); row++) {
        height += table_->rowHeight(row);
    }
    table_->setFixedHeight(height);
}

void DevicePanel::loadSettings()
{
    CaptureConfig config = CaptureSettings::instance()->config();

    loading_ = true;
    hop_->setChecked(config.hopping);
    channel_->setCurrentIndex(config.channel - 37);
    channel_->setEnabled(!config.hopping);
    target_->setText(CaptureSettings::instance()->targetMacText());
    include_crc_->setChecked(config.include_crc_errors);
    single_target_->setChecked(config.single_target);
    follow_relay_->setChecked(config.follow_relay);
    loading_ = false;
}

void DevicePanel::saveSettings()
{
    if (loading_) {
        return;
    }
    CaptureConfig config;
    uint8_t mac[6];
    QString text = target_->text().trimmed();

    config.hopping = hop_->isChecked();
    config.channel = (quint8)(37 + channel_->currentIndex());
    channel_->setEnabled(!config.hopping);
    if (text.isEmpty()) {
        target_hint_->hide();
    } else if (bh_parse_mac(text.toUtf8().constData(), mac)) {
        config.target_mac_le = QByteArray(reinterpret_cast<const char *>(mac), sizeof(mac));
        target_hint_->hide();
    } else {
        target_hint_->setText(localized("Not a valid address, expected AA:BB:CC:DD:EE:FF; no target filter will be used.",
                                        "地址格式不对，应为 AA:BB:CC:DD:EE:FF；将不过滤目标。"));
        target_hint_->show();
    }
    config.include_crc_errors = include_crc_->isChecked();
    config.single_target = single_target_->isChecked();
    config.follow_relay = follow_relay_->isChecked();
    CaptureSettings::instance()->setConfig(config, text);
}

void installDevicePanel(QMainWindow *window, QMenu *view_menu, QAction *before)
{
    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
    DevicePanel *panel = new DevicePanel(window);

    window->addDockWidget(Qt::RightDockWidgetArea, panel);
    panel->setVisible(settings.value(QStringLiteral("ui/devicePanelVisible"), true).toBool());

    QAction *toggle = panel->toggleViewAction();
    toggle->setObjectName(QStringLiteral("actionBlehoundDevicePanel"));
    toggle->setText(localized("BLEhound Devices", "BLEhound 设备"));
    view_menu->insertAction(before, toggle);
    // triggered() fires only for the user's clicks; toggled() also fires when
    // Qt hides the dock at shutdown, which would remember "closed".
    QObject::connect(toggle, &QAction::triggered, panel, [](bool visible) {
        QSettings s(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
        s.setValue(QStringLiteral("ui/devicePanelVisible"), visible);
    });
}

} // namespace BLEhound
