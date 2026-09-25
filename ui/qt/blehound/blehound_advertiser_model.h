/** @file
 *
 * Devices heard advertising during a capture, and the per-thread
 * collector that feeds them from the capture streams.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QAbstractTableModel>
#include <QByteArray>
#include <QHash>
#include <QTimer>
#include <QList>
#include <QString>

#include <blehound/blehound.h>

namespace BLEhound {

/** One advertiser, merged over everything heard from it. */
struct Advertiser {
    QByteArray adva;            /**< 6 bytes, air order */
    bool random = false;
    bool extended = false;
    bool connectable = false;
    int8_t rssi = 0;            /**< latest */
    int8_t rssi_max = -128;
    uint8_t channel = 0;        /**< latest */
    uint8_t phy = 0;            /**< latest */
    quint64 packets = 0;        /**< PDUs sent by it */
    quint64 requests = 0;       /**< SCAN_REQ / CONNECT_IND aimed at it */
    QString name;
    bool name_complete = false;
    bool has_company = false;
    uint16_t company = 0;
    qint64 first_seen_us = 0;
    qint64 last_seen_us = 0;
};

class AdvertiserModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Column {
        ColName,
        ColAddress,
        ColType,
        ColPhy,
        ColRssi,
        ColChannel,
        ColPackets,
        ColCompany,
        ColLastSeen,
        ColCount
    };

    static AdvertiserModel *instance();

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    Qt::ItemFlags flags(const QModelIndex &index) const override;
    bool setData(const QModelIndex &index, const QVariant &value, int role) override;

    const Advertiser *advertiserAt(int row) const;
    int rowFor(const QByteArray &adva) const;

    /** User-given name for an address, kept across runs; empty if none. */
    QString aliasFor(const QByteArray &adva) const;
    static QString formatAddress(const QByteArray &adva);

    /** Drop rows not seen for this many seconds (0 = keep forever). */
    void setStaleTimeout(int seconds);

public slots:
    /** Fold a batch of sightings in; called (queued) from capture threads. */
    void merge(const QList<Advertiser> &batch);
    void clear();

private:
    explicit AdvertiserModel(QObject *parent = nullptr);
    void loadAliases();
    void reindex(int from);
    void dropStale();

    QList<Advertiser> rows_;
    QHash<QByteArray, int> index_;
    QHash<QByteArray, QString> aliases_;
    QTimer stale_timer_;
    qint64 stale_us_ = 0;
};

/**
 * Accumulates sightings inside a capture thread and posts them to the
 * model every flush interval, so the GUI never sees per-packet traffic.
 */
class AdvertiserCollector
{
public:
    void onPacket(const bh_packet &pkt, qint64 now_us);
    void flushIfDue(qint64 now_us);
    void flush();

private:
    QHash<QByteArray, Advertiser> pending_;
    qint64 last_flush_us_ = 0;
};

} // namespace BLEhound

Q_DECLARE_METATYPE(QList<BLEhound::Advertiser>)
