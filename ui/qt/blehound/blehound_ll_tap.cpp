/* blehound_ll_tap.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "blehound_ll_tap.h"
#include "blehound_i18n.h"

#include <epan/tap.h>
#include <wsutil/wslog.h>

#include "main_application.h"

#include <QDateTime>

#include <string.h>

namespace BLEhound {

QString formatAddressLE(const QByteArray &air)
{
    if (air.size() != 6) {
        return QString();
    }
    QStringList parts;
    for (int i = 5; i >= 0; i--) {
        parts.append(QStringLiteral("%1").arg((unsigned char)air.at(i), 2, 16, QLatin1Char('0')).toUpper());
    }
    return parts.join(QLatin1Char(':'));
}

QString hexSummary(const uint8_t *data, unsigned len, unsigned max_bytes)
{
    QStringList parts;
    unsigned n = len < max_bytes ? len : max_bytes;
    for (unsigned i = 0; i < n; i++) {
        parts.append(QStringLiteral("%1").arg(data[i], 2, 16, QLatin1Char('0')).toUpper());
    }
    QString s = parts.join(QLatin1Char(' '));
    if (len > n) {
        s += QStringLiteral(" …");
    }
    return s;
}

/* ------------------------------------------------------------ name tables */

namespace {

const char *llName(uint8_t op)
{
    static const char *const names[] = {
        "LL_CONNECTION_UPDATE_IND", "LL_CHANNEL_MAP_IND", "LL_TERMINATE_IND", "LL_ENC_REQ",
        "LL_ENC_RSP", "LL_START_ENC_REQ", "LL_START_ENC_RSP", "LL_UNKNOWN_RSP",
        "LL_FEATURE_REQ", "LL_FEATURE_RSP", "LL_PAUSE_ENC_REQ", "LL_PAUSE_ENC_RSP",
        "LL_VERSION_IND", "LL_REJECT_IND", "LL_PERIPHERAL_FEATURE_REQ", "LL_CONNECTION_PARAM_REQ",
        "LL_CONNECTION_PARAM_RSP", "LL_REJECT_EXT_IND", "LL_PING_REQ", "LL_PING_RSP",
        "LL_LENGTH_REQ", "LL_LENGTH_RSP", "LL_PHY_REQ", "LL_PHY_RSP",
        "LL_PHY_UPDATE_IND", "LL_MIN_USED_CHANNELS_IND", "LL_CTE_REQ", "LL_CTE_RSP",
        "LL_PERIODIC_SYNC_IND", "LL_CLOCK_ACCURACY_REQ", "LL_CLOCK_ACCURACY_RSP", "LL_CIS_REQ",
        "LL_CIS_RSP", "LL_CIS_IND", "LL_CIS_TERMINATE_IND", "LL_POWER_CONTROL_REQ",
        "LL_POWER_CONTROL_RSP", "LL_POWER_CHANGE_IND", "LL_SUBRATE_REQ", "LL_SUBRATE_IND",
        "LL_CHANNEL_REPORTING_IND", "LL_CHANNEL_STATUS_IND", "LL_PERIODIC_SYNC_WR_IND",
    };
    return op < sizeof(names) / sizeof(names[0]) ? names[op] : "LL_(unknown)";
}

/* LL request opcode -> response opcode(s); 0 = unsolicited, one row. */
void llResponse(uint8_t op, uint8_t *r1, uint8_t *r2)
{
    *r1 = 0; *r2 = 0;
    switch (op) {
    case 0x03: *r1 = 0x04; break;                 /* ENC_REQ -> ENC_RSP */
    case 0x05: *r1 = 0x06; break;                 /* START_ENC_REQ -> START_ENC_RSP */
    case 0x08: case 0x0E: *r1 = 0x09; break;      /* FEATURE_REQ / PERIPHERAL_FEATURE_REQ -> FEATURE_RSP */
    case 0x0A: *r1 = 0x0B; break;                 /* PAUSE_ENC */
    case 0x0C: *r1 = 0x0C; break;                 /* VERSION_IND <-> VERSION_IND */
    case 0x0F: *r1 = 0x10; *r2 = 0x00; break;     /* CONNECTION_PARAM_REQ -> RSP or CONNECTION_UPDATE_IND */
    case 0x12: *r1 = 0x13; break;                 /* PING */
    case 0x14: *r1 = 0x15; break;                 /* LENGTH */
    case 0x16: *r1 = 0x17; *r2 = 0x18; break;     /* PHY_REQ -> PHY_RSP or PHY_UPDATE_IND */
    case 0x1A: *r1 = 0x1B; break;                 /* CTE */
    case 0x1D: *r1 = 0x1E; break;                 /* CLOCK_ACCURACY */
    case 0x1F: *r1 = 0x20; break;                 /* CIS_REQ -> CIS_RSP */
    case 0x23: *r1 = 0x24; break;                 /* POWER_CONTROL */
    case 0x26: *r1 = 0x27; break;                 /* SUBRATE_REQ -> SUBRATE_IND */
    default: break;
    }
}

const char *attName(uint8_t op)
{
    switch (op) {
    case 0x01: return "Error Response";
    case 0x02: return "Exchange MTU";
    case 0x04: return "Find Information";
    case 0x06: return "Find By Type Value";
    case 0x08: return "Read By Type";
    case 0x0A: return "Read";
    case 0x0C: return "Read Blob";
    case 0x0E: return "Read Multiple";
    case 0x10: return "Read By Group Type";
    case 0x12: return "Write";
    case 0x16: return "Prepare Write";
    case 0x18: return "Execute Write";
    case 0x1B: return "Handle Value Notification";
    case 0x1D: return "Handle Value Indication";
    case 0x1E: return "Handle Value Confirmation";
    case 0x20: return "Read Multiple Variable";
    case 0x23: return "Multiple Handle Value Notification";
    case 0x52: return "Write Command";
    case 0xD2: return "Signed Write Command";
    default: return "ATT (unknown)";
    }
}

bool attIsRequest(uint8_t op)
{
    switch (op) {
    case 0x02: case 0x04: case 0x06: case 0x08: case 0x0A: case 0x0C: case 0x0E:
    case 0x10: case 0x12: case 0x16: case 0x18: case 0x1D: case 0x20:
        return true;
    default:
        return false;
    }
}

const char *smpName(uint8_t op)
{
    static const char *const names[] = {
        "", "Pairing Request", "Pairing Response", "Pairing Confirm", "Pairing Random",
        "Pairing Failed", "Encryption Information", "Central Identification", "Identity Information",
        "Identity Address Information", "Signing Information", "Security Request", "Pairing Public Key",
        "Pairing DHKey Check", "Pairing Keypress Notification",
    };
    return op < sizeof(names) / sizeof(names[0]) && op ? names[op] : "SMP (unknown)";
}

const char *l2capSigName(uint8_t code)
{
    switch (code) {
    case 0x01: return "Command Reject";
    case 0x06: return "Disconnection Request";
    case 0x07: return "Disconnection Response";
    case 0x12: return "Connection Parameter Update Request";
    case 0x13: return "Connection Parameter Update Response";
    case 0x14: return "LE Credit Based Connection Request";
    case 0x15: return "LE Credit Based Connection Response";
    case 0x16: return "Flow Control Credit";
    case 0x17: return "Credit Based Connection Request";
    case 0x18: return "Credit Based Connection Response";
    case 0x19: return "Credit Based Reconfigure Request";
    case 0x1A: return "Credit Based Reconfigure Response";
    default: return "L2CAP signalling";
    }
}

const char *attError(uint8_t code)
{
    switch (code) {
    case 0x01: return "Invalid Handle";
    case 0x02: return "Read Not Permitted";
    case 0x03: return "Write Not Permitted";
    case 0x05: return "Insufficient Authentication";
    case 0x06: return "Request Not Supported";
    case 0x07: return "Invalid Offset";
    case 0x08: return "Insufficient Authorization";
    case 0x0A: return "Attribute Not Found";
    case 0x0D: return "Invalid Attribute Value Length";
    case 0x0F: return "Insufficient Encryption";
    default: return "error";
    }
}

/* Per-layer key so LLCP and ATT pending lists do not cross. */
enum { LayerLL = 1, LayerAtt = 2, LayerSmp = 3, LayerSig = 4 };

uint8_t opposite(uint8_t dir)
{
    return dir == BLEHOUND_DIR_C2P ? BLEHOUND_DIR_P2C : dir == BLEHOUND_DIR_P2C ? BLEHOUND_DIR_C2P : BLEHOUND_DIR_UNKNOWN;
}

} // namespace

/* -------------------------------------------------------- TransactionModel */

TransactionModel::TransactionModel(QObject *parent) :
    QAbstractTableModel(parent)
{
}

int TransactionModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : rows_.size();
}

int TransactionModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : ColCount;
}

QVariant TransactionModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QVariant();
    }
    switch (section) {
    case ColTime:      return localized("Time", "时间");
    case ColLayer:     return localized("Layer", "层");
    case ColName:      return localized("Transaction", "事务");
    case ColDirection: return localized("Dir", "方向");
    case ColRequest:   return localized("Request", "请求帧");
    case ColResponse:  return localized("Response", "响应帧");
    case ColDuration:  return localized("Duration", "耗时");
    case ColStatus:    return localized("Status", "状态");
    case ColInfo:      return localized("Payload", "载荷");
    }
    return QVariant();
}

QVariant TransactionModel::data(const QModelIndex &index, int role) const
{
    const Transaction *t = at(index.row());

    if (!t) {
        return QVariant();
    }
    if (role == Qt::TextAlignmentRole) {
        int c = index.column();
        return (c == ColRequest || c == ColResponse || c == ColDuration) ?
            QVariant(Qt::AlignRight | Qt::AlignVCenter) : QVariant(Qt::AlignLeft | Qt::AlignVCenter);
    }
    if (role == Qt::UserRole) {
        switch (index.column()) {
        case ColTime:     return t->req_time;
        case ColRequest:  return t->req_frame;
        case ColResponse: return t->rsp_frame;
        case ColDuration: return t->rsp_frame ? (t->rsp_time - t->req_time) : -1.0;
        default: break;
        }
    }
    if (role != Qt::DisplayRole && role != Qt::UserRole) {
        return QVariant();
    }
    switch (index.column()) {
    case ColTime:      return QString::number(t->req_time, 'f', 6);
    case ColLayer:     return t->layer;
    case ColName:      return t->name;
    case ColDirection: return t->direction == BLEHOUND_DIR_C2P ? QStringLiteral("C → P") :
                              t->direction == BLEHOUND_DIR_P2C ? QStringLiteral("P → C") : QString();
    case ColRequest:   return t->req_frame;
    case ColResponse:  return t->rsp_frame ? QVariant(t->rsp_frame) : QVariant();
    case ColDuration:  return t->rsp_frame ? QStringLiteral("%1 ms").arg((t->rsp_time - t->req_time) * 1000.0, 0, 'f', 1) : QString();
    case ColStatus:    return t->status;
    case ColInfo:      return t->info;
    }
    return QVariant();
}

void TransactionModel::reset()
{
    beginResetModel();
    rows_.clear();
    pending_.clear();
    endResetModel();
}

void TransactionModel::addRow(const Transaction &t)
{
    beginInsertRows(QModelIndex(), rows_.size(), rows_.size());
    rows_.append(t);
    endInsertRows();
    if (t.pending) {
        pending_[t.aa].append(rows_.size() - 1);
    }
}

/* Oldest pending request on this connection that the response answers. */
int TransactionModel::findPending(uint32_t aa, uint8_t opcode, uint8_t direction_of_response, uint8_t layer_kind)
{
    QList<int> &list = pending_[aa];
    for (int i = 0; i < list.size(); i++) {
        const Transaction &t = rows_[list.at(i)];
        uint8_t kind = t.layer == QLatin1String("LLCP") ? LayerLL : t.layer == QLatin1String("ATT") ? LayerAtt :
                       t.layer == QLatin1String("SMP") ? LayerSmp : LayerSig;
        if (kind != layer_kind) {
            continue;
        }
        if (direction_of_response != BLEHOUND_DIR_UNKNOWN && t.direction != BLEHOUND_DIR_UNKNOWN &&
                direction_of_response != opposite(t.direction)) {
            continue;
        }
        if (t.expect_opcode == opcode || t.expect_opcode2 == opcode) {
            int row = list.at(i);
            list.removeAt(i);
            return row;
        }
    }
    return -1;
}

void TransactionModel::onPacket(const blehound_tap_info_t &info)
{
    if (!info.crc_ok || info.kind == BLEHOUND_KIND_ADV || info.kind == BLEHOUND_KIND_EMPTY ||
            info.kind == BLEHOUND_KIND_L2CAP_CONT) {
        return;
    }
    Transaction t;
    t.aa = info.aa;
    t.direction = info.direction;
    t.req_frame = info.frame_num;
    t.req_time = info.rel_ts;
    t.info = hexSummary(info.payload, info.payload_len);

    auto complete = [&](int row, const QString &status) {
        Transaction &r = rows_[row];
        r.rsp_frame = info.frame_num;
        r.rsp_time = info.rel_ts;
        r.status = status;
        r.pending = false;
        emit dataChanged(createIndex(row, 0), createIndex(row, ColCount - 1));
    };

    if (info.kind == BLEHOUND_KIND_LL_CTRL) {
        uint8_t op = info.ctrl_opcode;
        int row = findPending(info.aa, op, info.direction, LayerLL);
        if (row >= 0) {
            complete(row, op == 0x11 || op == 0x0D || op == 0x07 ? QString::fromUtf8(llName(op)) : localized("ok", "完成"));
            return;
        }
        if (op == 0x11 || op == 0x0D || op == 0x07) {
            /* Reject / unknown answering some request we did not pair by opcode. */
            QList<int> &list = pending_[info.aa];
            for (int i = 0; i < list.size(); i++) {
                if (rows_[list.at(i)].layer == QLatin1String("LLCP")) {
                    int r = list.at(i);
                    list.removeAt(i);
                    complete(r, QString::fromUtf8(llName(op)));
                    return;
                }
            }
        }
        t.layer = QStringLiteral("LLCP");
        t.name = QString::fromUtf8(llName(op));
        t.req_opcode = op;
        llResponse(op, &t.expect_opcode, &t.expect_opcode2);
        t.pending = t.expect_opcode != 0;
        t.status = t.pending ? localized("pending", "等待响应") : QString();
        addRow(t);
        return;
    }

    /* L2CAP start fragment */
    uint8_t op = info.l2cap_opcode;
    if (info.l2cap_cid == 0x0004) {                         /* ATT */
        if (op == 0x01 && info.payload_len >= 5) {           /* Error Response: [req opcode][handle][reason] */
            int row = findPending(info.aa, info.payload[1] + 1, info.direction, LayerAtt);
            if (row >= 0) {
                complete(row, QString::fromUtf8(attError(info.payload[4])));
                return;
            }
        }
        int row = findPending(info.aa, op, info.direction, LayerAtt);
        if (row >= 0) {
            complete(row, localized("ok", "完成"));
            return;
        }
        t.layer = QStringLiteral("ATT");
        t.name = QString::fromUtf8(attName(op));
        t.req_opcode = op;
        if (attIsRequest(op)) {
            t.expect_opcode = op == 0x1D ? 0x1E : (uint8_t)(op + 1);
            t.pending = true;
            t.status = localized("pending", "等待响应");
        }
        if (info.payload_len >= 3 && (op == 0x0A || op == 0x12 || op == 0x52 || op == 0x1B || op == 0x1D || op == 0x0C)) {
            t.name += QStringLiteral(" 0x%1").arg((unsigned)(info.payload[1] | info.payload[2] << 8), 4, 16, QLatin1Char('0'));
        }
        addRow(t);
        return;
    }
    if (info.l2cap_cid == 0x0006) {                         /* SMP */
        uint8_t expect = 0;
        switch (op) {
        case 0x01: expect = 0x02; break;                    /* Pairing Request -> Response */
        case 0x03: case 0x04: case 0x0C: case 0x0D: expect = op; break;   /* answered by the same PDU from the peer */
        default: break;
        }
        int row = findPending(info.aa, op, info.direction, LayerSmp);
        if (row >= 0) {
            complete(row, localized("ok", "完成"));
            return;
        }
        if (op == 0x05) {                                   /* Pairing Failed answers whatever is pending */
            QList<int> &list = pending_[info.aa];
            for (int i = 0; i < list.size(); i++) {
                if (rows_[list.at(i)].layer == QLatin1String("SMP")) {
                    int r = list.at(i);
                    list.removeAt(i);
                    complete(r, localized("Pairing Failed", "配对失败"));
                    return;
                }
            }
        }
        t.layer = QStringLiteral("SMP");
        t.name = QString::fromUtf8(smpName(op));
        t.req_opcode = op;
        t.expect_opcode = expect;
        t.pending = expect != 0;
        t.status = t.pending ? localized("pending", "等待响应") : QString();
        addRow(t);
        return;
    }
    if (info.l2cap_cid == 0x0005) {                         /* LE signalling */
        int row = findPending(info.aa, op, info.direction, LayerSig);
        if (row >= 0) {
            complete(row, localized("ok", "完成"));
            return;
        }
        t.layer = QStringLiteral("L2CAP");
        t.name = QString::fromUtf8(l2capSigName(op));
        t.req_opcode = op;
        if (op == 0x06 || op == 0x12 || op == 0x14 || op == 0x17 || op == 0x19) {
            t.expect_opcode = (uint8_t)(op + 1);
            t.expect_opcode2 = 0x01;
            t.pending = true;
            t.status = localized("pending", "等待响应");
        }
        addRow(t);
        return;
    }
    t.layer = QStringLiteral("L2CAP");
    t.name = QStringLiteral("CID 0x%1").arg(info.l2cap_cid, 4, 16, QLatin1Char('0'));
    addRow(t);
}

/* ------------------------------------------------------ ConnectionTracker */

ConnectionInfo *ConnectionTracker::find(uint32_t aa)
{
    for (int i = conns_.size() - 1; i >= 0; i--) {
        if (conns_[i].aa == aa) {
            return &conns_[i];
        }
    }
    return nullptr;
}

void ConnectionTracker::reset()
{
    conns_.clear();
    emit changed();
}

void ConnectionTracker::onPacket(const blehound_tap_info_t &info)
{
    if (info.kind == BLEHOUND_KIND_ADV) {
        if (!info.connect_ind || !info.crc_ok) {
            return;
        }
        ConnectionInfo c;
        c.aa = info.conn_aa;
        c.central = QByteArray(reinterpret_cast<const char *>(info.inita), 6);
        c.peripheral = QByteArray(reinterpret_cast<const char *>(info.adva), 6);
        c.start_time = c.last_time = info.rel_ts;
        c.connect_frame = info.frame_num;
        c.interval = info.interval;
        c.latency = info.latency;
        c.timeout = info.timeout;
        memcpy(c.chan_map, info.chan_map, 5);
        c.hop = info.hop;
        c.csa2 = info.csa2;
        if (conns_.size() >= 64) {
            conns_.removeFirst();
        }
        conns_.append(c);
        emit changed();
        return;
    }
    ConnectionInfo *c = find(info.aa);
    if (!c) {
        /* Capture started mid-connection: still track it. */
        ConnectionInfo n;
        n.aa = info.aa;
        n.start_time = info.rel_ts;
        conns_.append(n);
        c = &conns_.last();
    }
    c->last_time = info.rel_ts;
    c->packets++;
    if (info.channel < 37) {
        c->chan_packets[info.channel]++;
        if (!info.crc_ok) {
            c->chan_errors[info.channel]++;
        }
    }
    if (!info.crc_ok) {
        c->crc_errors++;
        return;
    }
    if (info.decrypted) {
        c->decrypting = true;
    }
    if (info.kind == BLEHOUND_KIND_EMPTY) {
        c->empty++;
    } else if (info.kind == BLEHOUND_KIND_LL_CTRL) {
        c->ctrl++;
        const uint8_t *p = info.payload;
        unsigned n = info.payload_len;
        switch (info.ctrl_opcode) {
        case 0x00:                                           /* CONNECTION_UPDATE_IND */
            if (n >= 12) {
                c->interval = (uint16_t)(p[3] | p[4] << 8);
                c->latency = (uint16_t)(p[5] | p[6] << 8);
                c->timeout = (uint16_t)(p[7] | p[8] << 8);
                c->updates++;
            }
            break;
        case 0x01:                                           /* CHANNEL_MAP_IND */
            if (n >= 8) {
                memcpy(c->chan_map, p + 1, 5);
                c->updates++;
            }
            break;
        case 0x02:
            c->terminated = true;
            break;
        case 0x03:                                           /* ENC_REQ */
            c->encrypted = true;
            break;
        case 0x18:                                           /* PHY_UPDATE_IND */
            if (n >= 5) {
                auto phy = [](uint8_t m, const QString &keep) {
                    return m & 0x04 ? QStringLiteral("Coded") : m & 0x02 ? QStringLiteral("2M") : m & 0x01 ? QStringLiteral("1M") : keep;
                };
                c->phy_c2p = phy(p[1], c->phy_c2p);
                c->phy_p2c = phy(p[2], c->phy_p2c);
                c->updates++;
            }
            break;
        default:
            break;
        }
    } else {
        c->l2cap++;
    }
    emit changed();
}

/* ------------------------------------------------------------------ LinkTap */

namespace {

void tapReset(void *ctx)
{
    LinkTap *tap = static_cast<LinkTap *>(ctx);
    tap->transactions()->reset();
    tap->connections()->reset();
}

tap_packet_status tapPacket(void *ctx, packet_info *, epan_dissect_t *, const void *data, tap_flags_t)
{
    LinkTap *tap = static_cast<LinkTap *>(ctx);
    const blehound_tap_info_t *info = static_cast<const blehound_tap_info_t *>(data);

    tap->transactions()->onPacket(*info);
    tap->connections()->onPacket(*info);
    return TAP_PACKET_REDRAW;
}

} // namespace

LinkTap *LinkTap::instance()
{
    static LinkTap *tap = new LinkTap();
    return tap;
}

LinkTap::LinkTap(QObject *parent) :
    QObject(parent)
{
}

/* The main window is built before epan is initialised, so the "blehound"
 * tap does not exist yet when the panels are created: register once the
 * application reports itself ready. */
void LinkTap::install()
{
    if (installed_ || pending_) {
        return;
    }
    pending_ = true;
    QObject::connect(mainApp, &MainApplication::appInitialized, this, [this]() {
        GString *error = register_tap_listener("blehound", this, nullptr, 0, tapReset, tapPacket, nullptr, nullptr);
        if (error) {
            ws_warning("BLEhound: tap listener not registered: %s", error->str);
            g_string_free(error, TRUE);
            return;
        }
        installed_ = true;
        ws_info("BLEhound: blehound tap listener registered");
    });
}

} // namespace BLEhound
