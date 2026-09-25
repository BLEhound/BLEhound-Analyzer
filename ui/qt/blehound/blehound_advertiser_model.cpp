/* blehound_advertiser_model.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "blehound_advertiser_model.h"
#include "blehound_i18n.h"
#include "blehound_key_store.h"

#include <epan/addr_resolv.h>
#include <epan/dissectors/packet-bluetooth.h>

#include <QDateTime>
#include <algorithm>
#include <QMetaObject>
#include <QSettings>

namespace BLEhound {

static const qint64 kFlushIntervalUs = 250000;
static const int kMaxRows = 2000;

AdvertiserModel *AdvertiserModel::instance()
{
    static AdvertiserModel *model = new AdvertiserModel();
    return model;
}

AdvertiserModel::AdvertiserModel(QObject *parent) :
    QAbstractTableModel(parent)
{
    qRegisterMetaType<QList<Advertiser>>();
    loadAliases();

    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
    setStaleTimeout(settings.value(QStringLiteral("ui/deviceStaleSeconds"), 30).toInt());
    connect(&stale_timer_, &QTimer::timeout, this, &AdvertiserModel::dropStale);
    stale_timer_.start(2000);
    connect(KeyStore::instance(), &KeyStore::changed, this, &AdvertiserModel::reresolve);
}

QList<QByteArray> AdvertiserModel::addressesForIdentity(const QString &identity) const
{
    QList<const Advertiser *> matches;

    if (identity.isEmpty()) {
        return QList<QByteArray>();
    }
    for (const Advertiser &a : rows_) {
        if (a.identity.compare(identity, Qt::CaseInsensitive) == 0) {
            matches.append(&a);
        }
    }
    std::sort(matches.begin(), matches.end(), [](const Advertiser *x, const Advertiser *y) {
        return x->last_seen_us > y->last_seen_us;
    });
    QList<QByteArray> out;
    for (const Advertiser *a : matches) {
        out.append(a->adva);
    }
    return out;
}

void AdvertiserModel::reresolve()
{
    for (int row = 0; row < rows_.size(); row++) {
        Advertiser &a = rows_[row];
        DeviceKey key;
        QString identity, key_name;

        if (KeyStore::instance()->resolve(a.adva, &key)) {
            identity = key.identity;
            key_name = key.label();
        }
        if (identity != a.identity || key_name != a.key_name) {
            a.identity = identity;
            a.key_name = key_name;
            emit dataChanged(createIndex(row, 0), createIndex(row, ColCount - 1));
        }
    }
}

void AdvertiserModel::setStaleTimeout(int seconds)
{
    stale_us_ = (qint64)seconds * 1000000;
    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
    settings.setValue(QStringLiteral("ui/deviceStaleSeconds"), seconds);
}

void AdvertiserModel::reindex(int from)
{
    for (int i = from; i < rows_.size(); i++) {
        index_.insert(rows_.at(i).adva, i);
    }
}

// A rotated-away RPA stops advertising, so its row is dropped once it has
// not been heard for the timeout; that is why one physical device seems to
// spawn several rows (see IRK resolution to collapse them into one).
void AdvertiserModel::dropStale()
{
    if (stale_us_ <= 0 || rows_.isEmpty()) {
        return;
    }
    qint64 now = QDateTime::currentMSecsSinceEpoch() * 1000;
    for (int i = rows_.size() - 1; i >= 0; i--) {
        if (now - rows_.at(i).last_seen_us <= stale_us_) {
            continue;
        }
        beginRemoveRows(QModelIndex(), i, i);
        index_.remove(rows_.at(i).adva);
        rows_.removeAt(i);
        endRemoveRows();
        reindex(i);
    }
}

void AdvertiserModel::loadAliases()
{
    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));

    settings.beginGroup(QStringLiteral("aliases"));
    foreach (const QString &key, settings.childKeys()) {
        QByteArray adva = QByteArray::fromHex(key.toLatin1());
        if (adva.size() == 6) {
            aliases_.insert(adva, settings.value(key).toString());
        }
    }
    settings.endGroup();
}

QString AdvertiserModel::formatAddress(const QByteArray &adva)
{
    char text[18];

    if (adva.size() != 6) {
        return QString();
    }
    bh_format_mac(reinterpret_cast<const uint8_t *>(adva.constData()), text);
    return QString::fromLatin1(text);
}

QString AdvertiserModel::aliasFor(const QByteArray &adva) const
{
    return aliases_.value(adva);
}

int AdvertiserModel::rowFor(const QByteArray &adva) const
{
    return index_.value(adva, -1);
}

const Advertiser *AdvertiserModel::advertiserAt(int row) const
{
    return row >= 0 && row < rows_.size() ? &rows_.at(row) : nullptr;
}

int AdvertiserModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : rows_.size();
}

int AdvertiserModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : ColCount;
}

static QString addressKind(const Advertiser &a)
{
    switch (bh_addr_kind(reinterpret_cast<const uint8_t *>(a.adva.constData()), a.random)) {
    case BH_ADDR_PUBLIC:                return localized("Public", "公共");
    case BH_ADDR_RANDOM_STATIC:         return localized("Static", "静态随机");
    case BH_ADDR_RANDOM_RESOLVABLE:     return localized("RPA", "可解析随机");
    case BH_ADDR_RANDOM_NON_RESOLVABLE: return localized("NRPA", "不可解析随机");
    }
    return QString();
}

static QString phyName(uint8_t phy)
{
    switch (phy) {
    case BH_PHY_1M:       return QStringLiteral("1M");
    case BH_PHY_2M:       return QStringLiteral("2M");
    case BH_PHY_CODED_S8: return QStringLiteral("Coded S8");
    case BH_PHY_CODED_S2: return QStringLiteral("Coded S2");
    }
    return QString::number(phy);
}

static QString companyName(const Advertiser &a)
{
    if (a.has_company) {
        return QString::fromUtf8(val_to_str_ext_const(a.company, &bluetooth_company_id_vals_ext, "?"))
               + QStringLiteral(" (0x%1)").arg(a.company, 4, 16, QLatin1Char('0'));
    }
    if (!a.random) {
        /* Public addresses carry an OUI. */
        uint8_t be[6];
        for (int i = 0; i < 6; i++) {
            be[i] = (uint8_t)a.adva.at(5 - i);
        }
        const char *manuf = get_manuf_name_if_known(be, sizeof(be));
        if (manuf) {
            return QString::fromUtf8(manuf);
        }
    }
    return QString();
}

QVariant AdvertiserModel::data(const QModelIndex &index, int role) const
{
    const Advertiser *a = advertiserAt(index.row());

    if (!a) {
        return QVariant();
    }
    if (role == Qt::TextAlignmentRole) {
        int col = index.column();
        return (col == ColRssi || col == ColChannel || col == ColPackets) ?
            QVariant(Qt::AlignRight | Qt::AlignVCenter) : QVariant(Qt::AlignLeft | Qt::AlignVCenter);
    }
    if (role == Qt::ToolTipRole && index.column() == ColName) {
        return localized("Double-click to give this device your own name.", "双击可以给这个设备起名字。");
    }
    if (role != Qt::DisplayRole && role != Qt::EditRole && role != Qt::UserRole) {
        return QVariant();
    }
    switch (index.column()) {
    case ColName: {
        QString alias = aliases_.value(a->adva);
        if (role == Qt::EditRole) {
            return alias;
        }
        if (alias.isEmpty()) {
            alias = a->key_name;            /* the key's label stands in for a name */
        }
        if (!alias.isEmpty()) {
            return a->name.isEmpty() ? alias : QStringLiteral("%1 (%2)").arg(alias, a->name);
        }
        return a->name;
    }
    case ColAddress:  return formatAddress(a->adva);
    case ColType: {
        QString kind = addressKind(*a);
        if (!a->identity.isEmpty()) {
            kind = localized("RPA of %1", "%1 的可解析随机").arg(a->identity);
        } else if (!a->key_name.isEmpty()) {
            kind = localized("RPA, IRK known", "可解析随机，IRK 已知");
        }
        return kind + (a->extended ? localized(", extended", "，扩展广播") : QString());
    }
    case ColPhy:      return phyName(a->phy);
    case ColRssi:     return role == Qt::UserRole ? QVariant((int)a->rssi) : QVariant(QStringLiteral("%1 dBm").arg(a->rssi));
    case ColChannel:  return (int)a->channel;
    case ColPackets:  return (qulonglong)a->packets;
    case ColCompany:  return companyName(*a);
    case ColLastSeen: {
        if (role == Qt::UserRole) {
            return (qlonglong)a->last_seen_us;
        }
        qint64 age = (QDateTime::currentMSecsSinceEpoch() * 1000 - a->last_seen_us) / 1000000;
        return age < 2 ? localized("now", "刚刚") : localized("%1 s ago", "%1 秒前").arg(age);
    }
    }
    return QVariant();
}

QVariant AdvertiserModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QVariant();
    }
    switch (section) {
    case ColName:     return localized("Name", "名称");
    case ColAddress:  return localized("Address", "地址");
    case ColType:     return localized("Address type", "地址类型");
    case ColPhy:      return QStringLiteral("PHY");
    case ColRssi:     return QStringLiteral("RSSI");
    case ColChannel:  return localized("Ch", "信道");
    case ColPackets:  return localized("Packets", "包数");
    case ColCompany:  return localized("Company", "厂商");
    case ColLastSeen: return localized("Last seen", "最近出现");
    }
    return QVariant();
}

Qt::ItemFlags AdvertiserModel::flags(const QModelIndex &index) const
{
    Qt::ItemFlags f = QAbstractTableModel::flags(index);
    if (index.column() == ColName) {
        f |= Qt::ItemIsEditable;
    }
    return f;
}

bool AdvertiserModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    const Advertiser *a = advertiserAt(index.row());

    if (!a || index.column() != ColName || role != Qt::EditRole) {
        return false;
    }
    QString alias = value.toString().trimmed();
    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
    QString key = QStringLiteral("aliases/") + QString::fromLatin1(a->adva.toHex());
    if (alias.isEmpty()) {
        aliases_.remove(a->adva);
        settings.remove(key);
    } else {
        aliases_.insert(a->adva, alias);
        settings.setValue(key, alias);
    }
    emit dataChanged(index, index);
    return true;
}

void AdvertiserModel::merge(const QList<Advertiser> &batch)
{
    foreach (const Advertiser &s, batch) {
        int row = index_.value(s.adva, -1);
        if (row < 0) {
            if (rows_.size() >= kMaxRows) {
                continue;
            }
            beginInsertRows(QModelIndex(), rows_.size(), rows_.size());
            rows_.append(s);
            index_.insert(s.adva, rows_.size() - 1);
            endInsertRows();
            continue;
        }
        Advertiser &a = rows_[row];
        a.packets += s.packets;
        a.requests += s.requests;
        a.last_seen_us = qMax(a.last_seen_us, s.last_seen_us);
        if (s.packets > 0) {
            a.rssi = s.rssi;
            a.rssi_max = qMax(a.rssi_max, s.rssi_max);
            a.channel = s.channel;
            a.phy = s.phy;
            a.random = s.random;
            a.extended = a.extended || s.extended;
            a.connectable = a.connectable || s.connectable;
        }
        if (!s.name.isEmpty() && (a.name.isEmpty() || (s.name_complete && !a.name_complete))) {
            a.name = s.name;
            a.name_complete = s.name_complete;
        }
        if (s.has_company && !a.has_company) {
            a.has_company = true;
            a.company = s.company;
        }
        if (!s.key_name.isEmpty() && a.key_name.isEmpty()) {
            a.identity = s.identity;
            a.key_name = s.key_name;
        }
        emit dataChanged(createIndex(row, 0), createIndex(row, ColCount - 1));
    }
}

void AdvertiserModel::clear()
{
    beginResetModel();
    rows_.clear();
    index_.clear();
    endResetModel();
}

/* --------------------------------------------------- AdvertiserCollector */

void AdvertiserCollector::onPacket(const bh_packet &pkt, qint64 now_us)
{
    bh_adv_info info;

    if (!pkt.crc_ok || !bh_adv_parse(&pkt, &info)) {
        return;
    }
    QByteArray adva(reinterpret_cast<const char *>(info.adva), sizeof(info.adva));
    Advertiser &a = pending_[adva];
    if (a.adva.isEmpty()) {
        a.adva = adva;
        a.first_seen_us = now_us;
        if (info.adva_random) {
            resolveIdentity(a);
        }
    }
    a.last_seen_us = now_us;
    if (!info.from_advertiser) {
        a.requests++;
        return;
    }
    a.packets++;
    a.random = info.adva_random;
    a.extended = a.extended || info.extended;
    a.connectable = a.connectable || info.connectable;
    a.rssi = pkt.rssi;
    a.rssi_max = qMax(a.rssi_max, pkt.rssi);
    a.channel = pkt.channel;
    a.phy = pkt.phy;
    if (info.has_name && (a.name.isEmpty() || (info.name_complete && !a.name_complete))) {
        a.name = QString::fromUtf8(info.name);
        a.name_complete = info.name_complete;
    }
    if (info.has_company && !a.has_company) {
        a.has_company = true;
        a.company = info.company_id;
    }
}

/* One AES block per stored IRK the first time an address is seen; the
 * answer is cached until the keys change. */
void AdvertiserCollector::resolveIdentity(Advertiser &a)
{
    KeyStore *store = KeyStore::instance();
    int version = store->version();

    if (version != keys_version_) {
        resolved_.clear();
        keys_version_ = version;
    }
    auto cached = resolved_.constFind(a.adva);
    if (cached != resolved_.constEnd()) {
        a.identity = cached->first;
        a.key_name = cached->second;
        return;
    }
    DeviceKey key;
    if (store->resolve(a.adva, &key)) {
        a.identity = key.identity;
        a.key_name = key.label();
    }
    resolved_.insert(a.adva, qMakePair(a.identity, a.key_name));
}

void AdvertiserCollector::flushIfDue(qint64 now_us)
{
    if (now_us - last_flush_us_ >= kFlushIntervalUs) {
        flush();
        last_flush_us_ = now_us;
    }
}

void AdvertiserCollector::flush()
{
    if (pending_.isEmpty()) {
        return;
    }
    QList<Advertiser> batch = pending_.values();
    pending_.clear();
    AdvertiserModel *model = AdvertiserModel::instance();
    QMetaObject::invokeMethod(model, [model, batch]() { model->merge(batch); }, Qt::QueuedConnection);
}

} // namespace BLEhound
