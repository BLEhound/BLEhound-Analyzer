/** @file
 *
 * Listens to the "blehound" tap and feeds the transactions model and the
 * connection tracker. One instance, installed with the panels.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QAbstractTableModel>
#include <QByteArray>
#include <QHash>
#include <QList>
#include <QObject>
#include <QString>

#include <epan/dissectors/packet-blehound.h>

namespace BLEhound {

/* ------------------------------------------------------------ transactions */

struct Transaction {
    QString layer;          /**< LLCP / ATT / SMP / L2CAP */
    QString name;
    uint8_t direction = 0;  /**< of the request */
    uint32_t aa = 0;
    uint32_t req_frame = 0;
    uint32_t rsp_frame = 0;
    double req_time = 0;
    double rsp_time = 0;
    QString status;         /**< pending / ok / error text */
    QString info;           /**< request payload summary */
    bool pending = false;
    uint8_t expect_opcode = 0;      /**< response opcode that completes it (0 = none) */
    uint8_t expect_opcode2 = 0;
    uint8_t req_opcode = 0;
};

class TransactionModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Column { ColTime, ColLayer, ColName, ColDirection, ColRequest, ColResponse, ColDuration, ColStatus, ColInfo, ColCount };

    explicit TransactionModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    const Transaction *at(int row) const { return row >= 0 && row < rows_.size() ? &rows_[row] : nullptr; }

    /** Tap callbacks (main thread). */
    void onPacket(const blehound_tap_info_t &info);
    void reset();

private:
    void addRow(const Transaction &t);
    int findPending(uint32_t aa, uint8_t opcode, uint8_t direction_of_response, uint8_t layer_kind);

    QList<Transaction> rows_;
    QHash<uint32_t, QList<int>> pending_;   /**< aa -> rows awaiting a response */
};

/* ------------------------------------------------------------- connections */

struct ConnectionInfo {
    uint32_t aa = 0;
    QByteArray central;         /**< air order */
    QByteArray peripheral;
    double start_time = 0;
    double last_time = 0;
    uint32_t connect_frame = 0;
    uint16_t interval = 0, latency = 0, timeout = 0;
    uint8_t chan_map[5] = { 0xff, 0xff, 0xff, 0xff, 0x1f };
    uint8_t hop = 0;
    bool csa2 = false;
    QString phy_c2p = QStringLiteral("1M"), phy_p2c = QStringLiteral("1M");
    bool encrypted = false;
    bool decrypting = false;
    bool terminated = false;
    uint32_t packets = 0, crc_errors = 0, empty = 0, ctrl = 0, l2cap = 0;
    uint32_t chan_packets[37] = { 0 };
    uint32_t chan_errors[37] = { 0 };
    int updates = 0;            /**< control procedures with an instant */
};

class ConnectionTracker : public QObject
{
    Q_OBJECT

public:
    explicit ConnectionTracker(QObject *parent = nullptr) : QObject(parent) {}

    QList<ConnectionInfo> connections() const { return conns_; }
    const ConnectionInfo *current() const { return conns_.isEmpty() ? nullptr : &conns_.last(); }

    void onPacket(const blehound_tap_info_t &info);
    void reset();

signals:
    void changed();

private:
    ConnectionInfo *find(uint32_t aa);

    QList<ConnectionInfo> conns_;
};

/* -------------------------------------------------------------------- tap */

class LinkTap : public QObject
{
    Q_OBJECT

public:
    static LinkTap *instance();

    TransactionModel *transactions() { return &transactions_; }
    ConnectionTracker *connections() { return &connections_; }

    /** Register the tap listener; call once after epan is initialised. */
    void install();

private:
    explicit LinkTap(QObject *parent = nullptr);

    TransactionModel transactions_;
    ConnectionTracker connections_;
    bool installed_ = false;
    bool pending_ = false;
};

QString formatAddressLE(const QByteArray &air);
QString hexSummary(const uint8_t *data, unsigned len, unsigned max_bytes = 12);

} // namespace BLEhound
