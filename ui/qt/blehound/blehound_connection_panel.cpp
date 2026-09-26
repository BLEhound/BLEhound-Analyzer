/* blehound_connection_panel.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "blehound_connection_panel.h"

#include "blehound_i18n.h"

#include <QAction>
#include <QCloseEvent>
#include <QComboBox>
#include <QDockWidget>
#include <QHBoxLayout>
#include <QHelpEvent>
#include <QLabel>
#include <QMainWindow>
#include <QMenu>
#include <QPainter>
#include <QSettings>
#include <QTimer>
#include <QToolTip>
#include <QVBoxLayout>

namespace BLEhound {

/* ---------------------------------------------------------- ChannelHeatmap */

static const int kCell = 22;
static const int kGap = 3;
static const int kCols = 13;     /* 3 rows of 13 = 39 cells, 37 used */

ChannelHeatmap::ChannelHeatmap(QWidget *parent) :
    QWidget(parent)
{
    setMinimumHeight(3 * (kCell + kGap) + kGap);
}

QSize ChannelHeatmap::minimumSizeHint() const
{
    return QSize(kCols * (kCell + kGap) + kGap, 3 * (kCell + kGap) + kGap);
}

void ChannelHeatmap::setConnection(const ConnectionInfo *info)
{
    have_ = info != nullptr;
    if (info) {
        info_ = *info;
    }
    update();
}

void ChannelHeatmap::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, false);
    QColor text = palette().color(QPalette::WindowText);
    QColor base = palette().color(QPalette::Window);
    bool dark = base.lightness() < 128;

    uint32_t peak = 1;
    if (have_) {
        for (int ch = 0; ch < 37; ch++) {
            peak = qMax(peak, info_.chan_packets[ch]);
        }
    }
    for (int ch = 0; ch < 37; ch++) {
        int col = ch % kCols, row = ch / kCols;
        QRect r(kGap + col * (kCell + kGap), kGap + row * (kCell + kGap), kCell, kCell);
        bool used = !have_ || (info_.chan_map[ch / 8] >> (ch % 8)) & 1;
        uint32_t n = have_ ? info_.chan_packets[ch] : 0;
        uint32_t e = have_ ? info_.chan_errors[ch] : 0;
        QColor fill;
        if (n == 0) {
            fill = dark ? QColor(60, 60, 60) : QColor(225, 225, 225);
        } else {
            double level = 0.25 + 0.75 * (double)n / peak;
            double bad = (double)e / n;
            if (bad > 0.2) {
                fill = QColor::fromHsvF(0.0, 0.7, dark ? 0.45 + 0.5 * level : 0.9);
            } else {
                fill = QColor::fromHsvF(0.36, 0.55, dark ? 0.35 + 0.55 * level : 0.85 - 0.35 * level + 0.35);
                fill = QColor::fromHsvF(0.36, 0.25 + 0.6 * level, dark ? 0.35 + 0.55 * level : 0.9);
            }
        }
        p.fillRect(r, fill);
        if (!used) {
            p.setPen(QPen(dark ? QColor(140, 140, 140) : QColor(120, 120, 120), 1));
            for (int x = -kCell; x < kCell; x += 5) {
                p.drawLine(r.left() + qMax(0, x), r.top() + qMax(0, -x), r.left() + qMin(kCell, x + kCell), r.top() + qMin(kCell, kCell - x));
            }
        }
        p.setPen(text);
        QFont f = font();
        f.setPointSizeF(f.pointSizeF() * 0.75);
        p.setFont(f);
        p.drawText(r, Qt::AlignCenter, QString::number(ch));
    }
}

bool ChannelHeatmap::event(QEvent *event)
{
    if (event->type() == QEvent::ToolTip) {
        QHelpEvent *he = static_cast<QHelpEvent *>(event);
        int col = (he->pos().x() - kGap) / (kCell + kGap);
        int row = (he->pos().y() - kGap) / (kCell + kGap);
        int ch = row * kCols + col;
        if (col >= 0 && col < kCols && row >= 0 && ch < 37 && have_) {
            bool used = (info_.chan_map[ch / 8] >> (ch % 8)) & 1;
            QToolTip::showText(he->globalPos(),
                               localized("Channel %1: %2 packets, %3 CRC errors%4", "信道 %1：%2 个包，%3 个 CRC 错误%4")
                               .arg(ch).arg(info_.chan_packets[ch]).arg(info_.chan_errors[ch])
                               .arg(used ? QString() : localized(" (not in the current channel map)", "（当前信道图未启用）")));
        } else {
            QToolTip::hideText();
        }
        return true;
    }
    return QWidget::event(event);
}

/* --------------------------------------------------------- ConnectionPanel */

ConnectionPanel::ConnectionPanel(QWidget *parent) :
    QDockWidget(localized("Connection", "连接"), parent)
{
    setObjectName(QStringLiteral("blehoundConnectionPanel"));
    setAllowedAreas(Qt::LeftDockWidgetArea | Qt::RightDockWidgetArea | Qt::BottomDockWidgetArea);

    QWidget *content = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(content);
    QHBoxLayout *top = new QHBoxLayout();
    top->addWidget(new QLabel(localized("Connection:", "连接："), content));
    selector_ = new QComboBox(content);
    selector_->setMinimumWidth(180);
    top->addWidget(selector_);
    top->addStretch();
    layout->addLayout(top);

    summary_ = new QLabel(content);
    summary_->setTextFormat(Qt::RichText);
    summary_->setWordWrap(true);
    summary_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(summary_);

    heatmap_ = new ChannelHeatmap(content);
    heatmap_->setToolTip(localized("Packets per data channel; red = many CRC errors, hatched = not in the channel map.",
                                   "每个数据信道的包数；红色 = CRC 错误多，斜线 = 当前信道图未启用。"));
    layout->addWidget(heatmap_);
    layout->addStretch();
    setWidget(content);

    connect(selector_, QOverload<int>::of(&QComboBox::activated), this, [this](int index) {
        follow_latest_ = index == selector_->count() - 1;
        refresh();
    });
    /* The tap fires per packet; redraw at most a few times a second. */
    QTimer *timer = new QTimer(this);
    timer->setInterval(300);
    connect(timer, &QTimer::timeout, this, &ConnectionPanel::refresh);
    timer->start();
    refresh();
}

void ConnectionPanel::closeEvent(QCloseEvent *event)
{
    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
    settings.setValue(QStringLiteral("ui/connectionPanelVisible"), false);
    QDockWidget::closeEvent(event);
}

void ConnectionPanel::refresh()
{
    QList<ConnectionInfo> conns = LinkTap::instance()->connections()->connections();

    if (selector_->count() != conns.size()) {
        selector_->blockSignals(true);
        selector_->clear();
        foreach (const ConnectionInfo &c, conns) {
            selector_->addItem(QStringLiteral("AA 0x%1  %2").arg(c.aa, 8, 16, QLatin1Char('0'))
                               .arg(QString::number(c.start_time, 'f', 1) + QStringLiteral(" s")));
        }
        selector_->blockSignals(false);
        if (follow_latest_) {
            selector_->setCurrentIndex(selector_->count() - 1);
        }
    }
    int idx = follow_latest_ ? conns.size() - 1 : selector_->currentIndex();
    if (idx < 0 || idx >= conns.size()) {
        summary_->setText(localized("No connection seen yet.", "还没有看到连接。"));
        heatmap_->setConnection(nullptr);
        return;
    }
    const ConnectionInfo &c = conns.at(idx);
    int used = 0;
    for (int ch = 0; ch < 37; ch++) {
        used += (c.chan_map[ch / 8] >> (ch % 8)) & 1;
    }
    QString state = c.terminated ? localized("terminated", "已断开") :
                    c.encrypted ? (c.decrypting ? localized("encrypted, decrypting", "已加密，正在解密") : localized("encrypted", "已加密")) :
                    localized("plaintext", "明文");
    QString html = QStringLiteral("<table cellspacing='2'>"
        "<tr><td><b>%1</b></td><td>%2 &nbsp; <b>%3</b> &nbsp; %4</td></tr>"
        "<tr><td><b>%5</b></td><td>%6 ms &nbsp; <b>%7</b> %8 &nbsp; <b>%9</b> %10 ms</td></tr>"
        "<tr><td><b>%11</b></td><td>%12 / %13 &nbsp; <b>%14</b> %15 &nbsp; <b>%16</b> %17</td></tr>"
        "<tr><td><b>%18</b></td><td>%19 &nbsp; %20</td></tr>"
        "<tr><td><b>%21</b></td><td>%22 (%23 %24, %25 %26, %27 %28, %29 %30)</td></tr>"
        "</table>")
        .arg(localized("Central", "中心"), c.central.isEmpty() ? localized("unknown", "未知") : formatAddressLE(c.central),
             localized("Peripheral", "外设"), c.peripheral.isEmpty() ? localized("unknown", "未知") : formatAddressLE(c.peripheral))
        .arg(localized("Interval", "间隔")).arg(c.interval * 1.25, 0, 'f', 2)
        .arg(localized("Latency", "潜伏期")).arg(c.latency)
        .arg(localized("Timeout", "超时")).arg(c.timeout * 10)
        .arg(localized("PHY", "PHY"), c.phy_c2p, c.phy_p2c, localized("Channels", "信道"))
        .arg(QStringLiteral("%1/37").arg(used))
        .arg(localized("CSA", "CSA"), c.csa2 ? QStringLiteral("#2") : (c.connect_frame ? QStringLiteral("#1") : QStringLiteral("?")))
        .arg(localized("State", "状态"), state,
             c.updates ? localized("%1 parameter/channel/PHY updates", "%1 次参数/信道图/PHY 更新").arg(c.updates) : QString())
        .arg(localized("Packets", "包数")).arg(c.packets)
        .arg(localized("empty", "空包")).arg(c.empty)
        .arg(localized("control", "控制")).arg(c.ctrl)
        .arg(localized("L2CAP", "L2CAP")).arg(c.l2cap)
        .arg(localized("CRC errors", "CRC 错误")).arg(c.crc_errors);
    summary_->setText(html);
    heatmap_->setConnection(&c);
}

void installConnectionPanel(QMainWindow *window, QMenu *view_menu, QAction *before)
{
    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
    LinkTap::instance()->install();
    ConnectionPanel *panel = new ConnectionPanel(window);

    /* Bottom of the right column, under the device panels; the right column
     * owns the bottom-right corner so its left edge lines up with the
     * transactions panel's right edge. */
    window->setCorner(Qt::BottomRightCorner, Qt::RightDockWidgetArea);
    window->addDockWidget(Qt::RightDockWidgetArea, panel);
    panel->setVisible(settings.value(QStringLiteral("ui/connectionPanelVisible"), true).toBool());

    QAction *toggle = panel->toggleViewAction();
    toggle->setObjectName(QStringLiteral("actionBlehoundConnectionPanel"));
    toggle->setText(localized("Connection", "连接"));
    view_menu->insertAction(before, toggle);
    QObject::connect(toggle, &QAction::triggered, panel, [](bool visible) {
        QSettings s(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
        s.setValue(QStringLiteral("ui/connectionPanelVisible"), visible);
    });
}

} // namespace BLEhound
