/* blehound_devices_panel.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "blehound_devices_panel.h"

#include "blehound_advertiser_model.h"
#include "blehound_capture_settings.h"
#include "blehound_device_manager.h"
#include "blehound_i18n.h"
#include "blehound_key_store.h"
#include "blehound_keys_dialog.h"
#include "blehound_layer_toolbar.h"

#include "main_application.h"
#include "main_window.h"
#include "filter_action.h"

#include <QAction>
#include <QCheckBox>
#include <QCloseEvent>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QMenu>
#include <QPushButton>
#include <QSettings>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QVBoxLayout>

namespace BLEhound {

namespace {

/* Sort by the raw values the model exposes through UserRole, search by
 * name and address. */
class AdvertiserProxy : public QSortFilterProxyModel
{
public:
    explicit AdvertiserProxy(QObject *parent) : QSortFilterProxyModel(parent) {}

protected:
    bool lessThan(const QModelIndex &left, const QModelIndex &right) const override
    {
        int col = left.column();
        if (col == AdvertiserModel::ColRssi || col == AdvertiserModel::ColLastSeen) {
            return left.data(Qt::UserRole).toLongLong() < right.data(Qt::UserRole).toLongLong();
        }
        if (col == AdvertiserModel::ColPackets || col == AdvertiserModel::ColChannel) {
            return left.data(Qt::DisplayRole).toLongLong() < right.data(Qt::DisplayRole).toLongLong();
        }
        return QSortFilterProxyModel::lessThan(left, right);
    }

    bool filterAcceptsRow(int row, const QModelIndex &parent) const override
    {
        QString needle = filterRegularExpression().pattern();
        if (needle.isEmpty()) {
            return true;
        }
        for (int col : { AdvertiserModel::ColName, AdvertiserModel::ColAddress, AdvertiserModel::ColCompany }) {
            QString text = sourceModel()->index(row, col, parent).data().toString();
            if (text.contains(needle, Qt::CaseInsensitive)) {
                return true;
            }
        }
        return false;
    }
};

} // namespace

DevicesPanel::DevicesPanel(QWidget *parent) :
    QDockWidget(localized("Devices Seen", "看到的设备"), parent)
{
    setObjectName(QStringLiteral("blehoundDevicesPanel"));
    setAllowedAreas(Qt::LeftDockWidgetArea | Qt::RightDockWidgetArea | Qt::BottomDockWidgetArea);

    QWidget *content = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(content);

    QHBoxLayout *top = new QHBoxLayout();
    search_ = new QLineEdit(content);
    search_->setPlaceholderText(localized("Search name, address or company", "搜索名称、地址或厂商"));
    search_->setClearButtonEnabled(true);
    top->addWidget(search_, 1);
    QPushButton *clear_list = new QPushButton(localized("Clear list", "清空列表"), content);
    top->addWidget(clear_list);
    QPushButton *keys = new QPushButton(localized("Keys…", "密钥…"), content);
    keys->setToolTip(localized("Enter a device's IRK so its rotating private addresses are recognised and followed.",
                               "填入设备的 IRK，它轮换的私有地址就能被认出并持续跟随。"));
    top->addWidget(keys);
    layout->addLayout(top);

    proxy_ = new AdvertiserProxy(this);
    proxy_->setSourceModel(AdvertiserModel::instance());
    proxy_->setDynamicSortFilter(true);
    table_ = new QTableView(content);
    table_->setModel(proxy_);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setSortingEnabled(true);
    table_->sortByColumn(AdvertiserModel::ColRssi, Qt::DescendingOrder);
    table_->verticalHeader()->hide();
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setEditTriggers(QAbstractItemView::DoubleClicked | QAbstractItemView::EditKeyPressed);
    table_->setToolTip(localized("Select a device and press Follow; double-click the name to rename it.",
                                 "选中设备后点「跟随」；双击名称可以改名。"));
    layout->addWidget(table_, 1);

    target_label_ = new QLabel(content);
    target_label_->setWordWrap(true);
    layout->addWidget(target_label_);

    QHBoxLayout *bottom = new QHBoxLayout();
    follow_button_ = new QPushButton(localized("Follow selected", "跟随选中的设备"), content);
    follow_button_->setToolTip(localized("Tell the dongles to follow only this device: its advertising, "
                                         "who scans or connects to it, and the connection itself.",
                                         "让 dongle 只跟这个设备：它的广播、谁扫描/连接它，以及连接本身。"));
    follow_button_->setEnabled(false);
    clear_button_ = new QPushButton(localized("Clear target", "取消目标"), content);
    bottom->addWidget(follow_button_);
    bottom->addWidget(clear_button_);
    bottom->addStretch();
    layout->addLayout(bottom);

    only_target_ = new QCheckBox(localized("Show only the target's traffic", "只显示目标相关的包"), content);
    only_target_->setToolTip(localized("Applies a display filter on the target's address.",
                                       "按目标地址套一个显示过滤器。"));
    layout->addWidget(only_target_);
    setWidget(content);

    connect(search_, &QLineEdit::textChanged, proxy_, [this](const QString &text) {
        proxy_->setFilterRegularExpression(QRegularExpression::escape(text));
    });
    connect(clear_list, &QPushButton::clicked, AdvertiserModel::instance(), &AdvertiserModel::clear);
    connect(keys, &QPushButton::clicked, this, &DevicesPanel::editKeys);
    connect(AdvertiserModel::instance(), &QAbstractItemModel::rowsInserted, this, &DevicesPanel::rowsAdded);
    connect(KeyStore::instance(), &KeyStore::changed, this, &DevicesPanel::updateTarget);
    connect(table_->selectionModel(), &QItemSelectionModel::selectionChanged, this, &DevicesPanel::selectionChanged);
    connect(table_, &QTableView::activated, this, [this](const QModelIndex &index) {
        if (index.column() != AdvertiserModel::ColName) {
            followSelected();
        }
    });
    connect(follow_button_, &QPushButton::clicked, this, &DevicesPanel::followSelected);
    connect(clear_button_, &QPushButton::clicked, this, &DevicesPanel::clearTarget);
    connect(only_target_, &QCheckBox::toggled, this, &DevicesPanel::applyTrafficFilter);
    connect(CaptureSettings::instance(), &CaptureSettings::changed, this, &DevicesPanel::updateTarget);
    updateTarget();
}

void DevicesPanel::closeEvent(QCloseEvent *event)
{
    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
    settings.setValue(QStringLiteral("ui/devicesPanelVisible"), false);
    QDockWidget::closeEvent(event);
}

QByteArray DevicesPanel::selectedAddress() const
{
    QModelIndexList rows = table_->selectionModel()->selectedRows();
    if (rows.isEmpty()) {
        return QByteArray();
    }
    const Advertiser *a = AdvertiserModel::instance()->advertiserAt(proxy_->mapToSource(rows.first()).row());
    return a ? a->adva : QByteArray();
}

void DevicesPanel::selectionChanged()
{
    follow_button_->setEnabled(!selectedAddress().isEmpty());
}

void DevicesPanel::followSelected()
{
    QByteArray adva = selectedAddress();
    if (adva.isEmpty()) {
        return;
    }
    // Persists for the next capture and is pushed to running captures now
    // (setTargetMac attaches the IRK when a stored key resolves the address).
    CaptureSettings::instance()->setTargetMac(AdvertiserModel::formatAddress(adva));
    CaptureConfig config = CaptureSettings::instance()->config();
    DeviceManager::instance()->applyTarget(adva, config.target_irk_le);
}

void DevicesPanel::clearTarget()
{
    CaptureSettings::instance()->setTargetMac(QString());
    DeviceManager::instance()->applyTarget(QByteArray(), QByteArray());
}

void DevicesPanel::editKeys()
{
    KeysDialog dialog(this);
    dialog.exec();
}

QString DevicesPanel::targetIdentity() const
{
    CaptureConfig config = CaptureSettings::instance()->config();
    DeviceKey key;

    if (config.target_irk_le.isEmpty() || !KeyStore::instance()->resolve(config.target_mac_le, &key)) {
        return QString();
    }
    return key.identity.isEmpty() ? key.label() : key.identity;
}

/* A new address that resolves to the target's identity: the dongle already
 * switched to it; keep the traffic filter in step. */
void DevicesPanel::rowsAdded(const QModelIndex &parent, int first, int last)
{
    Q_UNUSED(parent);
    QString identity = targetIdentity();
    if (identity.isEmpty()) {
        return;
    }
    AdvertiserModel *model = AdvertiserModel::instance();
    for (int row = first; row <= last; row++) {
        const Advertiser *a = model->advertiserAt(row);
        if (a && a->identity.compare(identity, Qt::CaseInsensitive) == 0) {
            updateTarget();
            return;
        }
    }
}

void DevicesPanel::updateTarget()
{
    CaptureConfig config = CaptureSettings::instance()->config();
    QString text = CaptureSettings::instance()->targetMacText();

    if (config.target_mac_le.size() == 6) {
        QString name;
        AdvertiserModel *model = AdvertiserModel::instance();
        int row = model->rowFor(config.target_mac_le);
        if (row >= 0) {
            name = model->index(row, AdvertiserModel::ColName).data().toString();
        }
        QString label = localized("<b>Target:</b> %1 %2 — following only this device",
                                  "<b>目标：</b>%1 %2 —— 只跟这个设备")
                        .arg(text, name.isEmpty() ? QString() : QStringLiteral("(%1)").arg(name));
        QString identity = targetIdentity();
        if (!identity.isEmpty()) {
            QList<QByteArray> addresses = model->addressesForIdentity(identity);
            QString current = addresses.isEmpty() ? QString() : AdvertiserModel::formatAddress(addresses.first());
            label += localized("<br><b>IRK known:</b> identity %1, its rotating addresses are followed automatically",
                               "<br><b>IRK 已知：</b>身份 %1，它换出的新地址会自动跟上").arg(identity);
            if (!current.isEmpty() && current.compare(text, Qt::CaseInsensitive) != 0) {
                label += localized(" (now %1)", "（当前 %1）").arg(current);
            }
        }
        DeviceKey key;
        if (KeyStore::instance()->resolve(config.target_mac_le, &key) && key.hasLtk()) {
            label += localized("<br><b>LTK known:</b> its encrypted traffic is decrypted on the fly",
                               "<br><b>LTK 已知：</b>它的加密数据会实时解密");
        }
        target_label_->setText(label);
        clear_button_->setEnabled(true);
    } else {
        target_label_->setText(localized("<b>Target:</b> none — observing advertising only, no connection is followed",
                                         "<b>目标：</b>无 —— 只观察广播，不跟任何连接"));
        clear_button_->setEnabled(false);
    }
    applyTrafficFilter();
}

void DevicesPanel::applyTrafficFilter()
{
    CaptureConfig config = CaptureSettings::instance()->config();
    QString filter;

    if (only_target_->isChecked() && config.target_mac_le.size() == 6) {
        QStringList macs = { AdvertiserModel::formatAddress(config.target_mac_le) };
        /* With an IRK every address the device has rotated through counts. */
        foreach (const QByteArray &adva, AdvertiserModel::instance()->addressesForIdentity(targetIdentity())) {
            QString mac = AdvertiserModel::formatAddress(adva);
            if (!macs.contains(mac, Qt::CaseInsensitive)) {
                macs.append(mac);
            }
        }
        QStringList terms;
        foreach (const QString &mac, macs) {
            terms.append(QStringLiteral("btle.advertising_address == %1 || btle.central_bd_addr == %1 || btle.peripheral_bd_addr == %1").arg(mac));
        }
        filter = terms.join(QStringLiteral(" || "));
    }
    setTargetFilter(filter);
}

void installDevicesPanel(QMainWindow *window, QMenu *view_menu, QAction *before)
{
    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
    DevicesPanel *panel = new DevicesPanel(window);

    window->addDockWidget(Qt::RightDockWidgetArea, panel);
    panel->setVisible(settings.value(QStringLiteral("ui/devicesPanelVisible"), true).toBool());

    QAction *toggle = panel->toggleViewAction();
    toggle->setObjectName(QStringLiteral("actionBlehoundDevicesPanel"));
    toggle->setText(localized("Devices Seen", "看到的设备"));
    view_menu->insertAction(before, toggle);
    QObject::connect(toggle, &QAction::triggered, panel, [](bool visible) {
        QSettings s(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
        s.setValue(QStringLiteral("ui/devicesPanelVisible"), visible);
    });
}

} // namespace BLEhound
