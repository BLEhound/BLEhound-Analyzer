/* blehound_layer_toolbar.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "blehound_layer_toolbar.h"

#include "blehound_i18n.h"

#include "main_application.h"
#include "main_window.h"
#include "filter_action.h"
#include "ui_wireshark_main_window.h"

#include <epan/column.h>
#include <epan/prefs.h>
#include <ui/preference_utils.h>

#include <QAction>
#include <QActionGroup>
#include <QIcon>
#include <QSettings>
#include <QToolBar>

namespace BLEhound {

namespace {

/* Custom columns the views switch on and off. Titles are the key they are
 * found by in the saved preferences, so they stay in English. */
struct LayerColumn {
    const char *title;
    const char *fields;
};
const LayerColumn kColumns[] = {
    { "Opcode",      "btle.control_opcode || btatt.opcode || btsmp.opcode || btl2cap.cmd_code" },
    { "Handle",      "btatt.handle" },
    { "Response in", "btle.response_in_frame || btatt.response_in_frame" },
    { "L2CAP ident", "btl2cap.cmd_ident" },
};
enum { ColOpcode = 1, ColHandle = 2, ColResponse = 4, ColIdent = 8 };

struct LayerView {
    const char *id;
    const char *icon;
    const char *en;
    const char *zh;
    const char *tip_en;
    const char *tip_zh;
    const char *filter;
    int columns;
};
const LayerView kViews[] = {
    { "all", "all", "All layers", "全部",
      "Everything, as captured.", "所有包，不过滤。", "", 0 },
    { "packets", "packets", "Packets", "包",
      "Every packet on the air, including empty and CRC-bad ones.", "空口上的每一个包，含空包和 CRC 错包。",
      "btle", 0 },
    { "link", "link", "Link Layer", "链路层",
      "Advertising, scanning, connection setup and link-layer control; empty data PDUs and higher layers hidden.",
      "广播、扫描、建连与链路层控制；隐藏空数据包和上层协议。",
      "btle && !btl2cap && !(btle.data_header.length == 0)", 0 },
    { "llcp", "llcp", "LLCP Packets", "LLCP 包",
      "Link-layer control PDUs only.", "只看链路层控制 PDU。",
      "btle.control_opcode", ColOpcode },
    { "llcp-tx", "llcp-tx", "LLCP Transactions", "LLCP 事务",
      "One row per control procedure: the request, with the frame its response is in.",
      "每个控制流程一行：请求包，并标出响应在哪一帧。",
      "btle.control_opcode && !btle.request_in_frame", ColOpcode | ColResponse },
    { "l2cap", "l2cap", "L2CAP Transactions", "L2CAP 事务",
      "L2CAP signalling commands.", "L2CAP 信令命令。",
      "btl2cap.cmd_code", ColOpcode | ColIdent },
    { "smp", "smp", "SMP Transactions", "SMP 事务",
      "Pairing: requests, confirms, key distribution.", "配对流程：请求、确认、密钥分发。",
      "btsmp", ColOpcode },
    { "att", "att", "ATT Packets", "ATT 包",
      "Attribute protocol PDUs only.", "只看 ATT PDU。",
      "btatt", ColOpcode | ColHandle },
    { "att-tx", "att-tx", "ATT Transactions", "ATT 事务",
      "One row per ATT request, with the frame its response is in.",
      "每个 ATT 请求一行，并标出响应在哪一帧。",
      "btatt && !btatt.request_in_frame", ColOpcode | ColHandle | ColResponse },
};

QString g_layer_filter;
QString g_target_filter;
QToolBar *g_toolbar = nullptr;
MainWindow *g_window = nullptr;

QIcon layerIcon(const char *name)
{
    QIcon icon;
    icon.addFile(QStringLiteral(":/wsicon/layers/%1.svg").arg(QLatin1String(name)), QSize(), QIcon::Normal, QIcon::Off);
    icon.addFile(QStringLiteral(":/wsicon/layers/%1.on.svg").arg(QLatin1String(name)), QSize(), QIcon::Normal, QIcon::On);
    return icon;
}

void applyFilter()
{
    MainWindow *window = g_window ? g_window : mainApp->mainWindow();
    QString filter;

    if (!window) {
        return;
    }
    if (!g_layer_filter.isEmpty() && !g_target_filter.isEmpty()) {
        filter = QStringLiteral("(%1) && (%2)").arg(g_layer_filter, g_target_filter);
    } else {
        filter = g_layer_filter.isEmpty() ? g_target_filter : g_layer_filter;
    }
    window->setDisplayFilter(filter, FilterAction::ActionApply, FilterAction::ActionTypePlain);
}

/* Index of our custom column with this title, adding it if missing. */
int ensureColumn(const LayerColumn &column)
{
    for (int i = 0; i < prefs.num_cols; i++) {
        if (get_column_format(i) == COL_CUSTOM && g_strcmp0(get_column_title(i), column.title) == 0) {
            return i;
        }
    }
    return column_prefs_add_custom(COL_CUSTOM, column.title, column.fields, -1);
}

void showColumns(int wanted)
{
    bool changed = false;

    for (size_t i = 0; i < sizeof(kColumns) / sizeof(kColumns[0]); i++) {
        bool show = (wanted & (1 << i)) != 0;
        int idx = ensureColumn(kColumns[i]);
        if (idx < 0) {
            continue;
        }
        if (get_column_visible(idx) != show) {
            set_column_visible(idx, show);
            changed = true;
        }
    }
    if (changed) {
        prefs_main_write();
        mainApp->emitAppSignal(MainApplication::ColumnsChanged);
    }
}

void selectView(const LayerView &view)
{
    g_layer_filter = QString::fromUtf8(view.filter);
    showColumns(view.columns);
    applyFilter();
    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
    settings.setValue(QStringLiteral("ui/layerView"), QString::fromUtf8(view.id));
}

} // namespace

void setLayerFilter(const QString &filter)
{
    g_layer_filter = filter;
    applyFilter();
}

void setTargetFilter(const QString &filter)
{
    g_target_filter = filter;
    applyFilter();
}

void installLayerToolbar(MainWindow *window, Ui::WiresharkMainWindow *ui)
{
    if (g_toolbar || !window) {
        return;
    }
    g_window = window;
    QToolBar *bar = new QToolBar(localized("Layers", "层级"), window);
    bar->setObjectName(QStringLiteral("blehoundLayerToolBar"));
    bar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    bar->setMovable(false);

    QSettings settings(QStringLiteral("BLEhound"), QStringLiteral("Analyzer"));
    QString saved = settings.value(QStringLiteral("ui/layerView"), QStringLiteral("all")).toString();
    QActionGroup *group = new QActionGroup(bar);
    group->setExclusive(true);
    const LayerView *initial = nullptr;

    for (const LayerView &view : kViews) {
        QAction *action = bar->addAction(layerIcon(view.icon), localized(view.en, view.zh));
        action->setCheckable(true);
        action->setToolTip(localized(view.tip_en, view.tip_zh));
        action->setStatusTip(action->toolTip());
        group->addAction(action);
        if (g_strcmp0(view.id, "all") == 0) {
            bar->addSeparator();
        }
        QObject::connect(action, &QAction::triggered, bar, [&view]() { selectView(view); });
        if (saved == QLatin1String(view.id)) {
            action->setChecked(true);
            initial = &view;
        }
    }
    if (!initial) {
        group->actions().first()->setChecked(true);
        initial = &kViews[0];
    }
    /* Own row under the filter bar, like the other toolbars. */
    window->addToolBarBreak(Qt::TopToolBarArea);
    window->addToolBar(Qt::TopToolBarArea, bar);
    if (ui) {
        QAction *toggle = bar->toggleViewAction();
        toggle->setObjectName(QStringLiteral("actionViewLayerToolbar"));   /* kept by the menu whitelist */
        ui->menuView->addAction(toggle);
    }
    g_toolbar = bar;

    /* Preferences (and so the column list) are not loaded yet while the main
     * window is being built: restore the saved view once the app is up. */
    const LayerView *restore = initial;
    QObject::connect(mainApp, &MainApplication::appInitialized, bar, [restore]() {
        g_layer_filter = QString::fromUtf8(restore->filter);
        showColumns(restore->columns);
        if (!g_layer_filter.isEmpty()) {
            applyFilter();
        }
    });
}

} // namespace BLEhound
