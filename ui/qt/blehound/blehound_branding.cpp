/* blehound_branding.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "blehound_branding.h"

#ifdef BLEHOUND_BRANDING

#include <wsutil/application_flavor.h>

#include <ui/qt/utils/stock_icon.h>

#include "blehound_i18n.h"
#include "blehound_layer_toolbar.h"

#include "main_window.h"

#include "ui_wireshark_main_window.h"

#include <QDesktopServices>
#include <QLocale>
#include <QMainWindow>
#include <QMenuBar>
#include <QSet>
#include <QUrl>

namespace BLEhound {

namespace {

const char *kPrunedProperty = "blehoundPruneHooked";
const char *kDocsBase = "https://blehound.github.io/";
const char *kRepoUrl = "https://github.com/BLEhound/BLEhound";

// Top-level menus that stay. Everything else (Telephony, Wireless, Tools,
// and menus added later by dissectors or plugins) is hidden.
const QSet<QString> kKeptMenus = {
    "menuFile", "menuEdit", "menuView", "menuGo", "menuCapture",
    "menuAnalyze", "menuStatistics", "menuHelp",
};

// Submenus kept as a whole.
const QSet<QString> kKeptSubmenus = {
    "menuOpenRecentCaptureFile", "menuFileExportPacketDissections",
    "menuEditCopy", "menuZoom", "menuTime_Display_Format",
    "menuApplyAsFilter", "menuPrepareAFilter",
};

// Individual actions kept inside the menus above. Anything else, including
// items registered at runtime (protocol statistics, Lua menus), is hidden.
const QSet<QString> kKeptActions = {
    // File
    "actionFileOpen", "actionFileMerge", "actionFileClose", "actionFileSave",
    "actionFileSaveAs", "actionFileExportPackets", "actionFilePrint", "actionFileQuit",
    // Edit
    "actionEditFindPacket", "actionEditFindNext", "actionEditFindPrevious",
    "actionEditMarkSelected", "actionEditMarkAllDisplayed", "actionEditUnmarkAllDisplayed",
    "actionEditNextMark", "actionEditPreviousMark",
    "actionEditSetTimeReference", "actionEditUnsetAllTimeReferences",
    "actionEditPreferences",
    // View
    "actionViewMainToolbar", "actionViewFilterToolbar", "actionViewLayerToolbar", "actionViewStatusBar",
    "actionViewFullScreen", "actionViewPacketList", "actionViewPacketDetails",
    "actionViewPacketBytes", "actionViewExpandSubtrees", "actionViewCollapseSubtrees",
    "actionViewExpandAll", "actionViewCollapseAll", "actionViewColorizePacketList",
    "actionViewColoringRules", "actionViewResizeColumns", "actionViewResetLayout",
    "actionViewShowPacketInNewWindow",
    // Go
    "actionGoGoToPacket", "actionGoNextPacket", "actionGoPreviousPacket",
    "actionGoFirstPacket", "actionGoLastPacket", "actionGoAutoScroll",
    // Capture
    "actionCaptureOptions", "actionCaptureStart", "actionCaptureStop",
    "actionCaptureRestart", "actionCaptureRefreshInterfaces",
    // Analyze
    "actionAnalyzeDisplayFilters", "actionDisplayFilterExpression",
    "actionAnalyzeApplyAsColumn", "actionAnalyzeExpertInfo",
    // Statistics
    "actionStatisticsCaptureFileProperties", "actionStatisticsProtocolHierarchy",
    "actionStatisticsConversations", "actionStatisticsEndpoints",
    "actionStatisticsPacketLengths", "actionStatisticsIOGraph",
    "actionStatisticsFlowGraph", "actionBluetoothATT_Server_Attributes",
    // Help
    "actionHelpAbout", "actionBlehoundQuickStart", "actionBlehoundDocs",
    "actionBlehoundIssue", "actionBlehoundDevicePanel", "actionBlehoundDevicesPanel",
};

QString docsUrl(const char *page)
{
    return QString::fromUtf8(kDocsBase) + (isChinese() ? "zh/" : "") + QString::fromUtf8(page);
}

void pruneMenu(QMenu *menu)
{
    foreach (QAction *action, menu->actions()) {
        if (action->isSeparator()) {
            continue;
        }
        if (QMenu *submenu = action->menu()) {
            action->setVisible(kKeptSubmenus.contains(submenu->objectName()));
        } else {
            action->setVisible(kKeptActions.contains(action->objectName()));
        }
    }
}

void pruneMenuBar(QMenuBar *bar)
{
    foreach (QAction *action, bar->actions()) {
        QMenu *menu = action->menu();
        if (!menu) {
            continue;
        }
        bool keep = kKeptMenus.contains(menu->objectName());
        action->setVisible(keep);
        if (!keep) {
            continue;
        }
        pruneMenu(menu);
        // Dissectors and plugins add items later; prune again before showing.
        if (!menu->property(kPrunedProperty).toBool()) {
            menu->setProperty(kPrunedProperty, true);
            QObject::connect(menu, &QMenu::aboutToShow, menu, [menu]() { pruneMenu(menu); });
        }
    }
}

QAction *linkAction(QMenu *menu, const char *object_name, const QString &text, const QString &url)
{
    QAction *action = menu->findChild<QAction *>(QString::fromUtf8(object_name));
    if (!action) {
        action = new QAction(menu);
        action->setObjectName(QString::fromUtf8(object_name));
        QObject::connect(action, &QAction::triggered, action, [action]() {
            QDesktopServices::openUrl(QUrl(action->data().toString()));
        });
        menu->insertAction(menu->actions().value(0), action);
    }
    action->setText(text);
    action->setData(url);
    return action;
}

void addHelpLinks(Ui::WiresharkMainWindow *ui)
{
    linkAction(ui->menuHelp, "actionBlehoundQuickStart",
               localized("Quick Start", "快速上手"), docsUrl("quickstart/"));
    linkAction(ui->menuHelp, "actionBlehoundDocs",
               localized("BLEhound Documentation", "BLEhound 文档"), docsUrl(""));
    linkAction(ui->menuHelp, "actionBlehoundIssue",
               localized("Report an Issue", "反馈问题"), QString::fromUtf8(kRepoUrl) + "/issues");
}

void rebuildToolbar(Ui::WiresharkMainWindow *ui)
{
    struct Button {
        QAction *action;
        const char *en;
        const char *zh;
    };
    const QList<QList<Button>> groups = {
        {
            { ui->actionCaptureStart, "Start", "开始" },
            { ui->actionCaptureStop, "Stop", "停止" },
            { ui->actionCaptureRestart, "Restart", "重新开始" },
            { ui->actionCaptureOptions, "Options", "捕获设置" },
        },
        {
            { ui->actionFileOpen, "Open", "打开" },
            { ui->actionFileSave, "Save", "保存" },
        },
        {
            { ui->actionEditFindPacket, "Find", "查找" },
            { ui->actionGoAutoScroll, "Auto Scroll", "自动滚动" },
        },
    };

    QToolBar *bar = ui->mainToolBar;
    bar->clear();
    for (int g = 0; g < groups.size(); g++) {
        if (g > 0) {
            bar->addSeparator();
        }
        foreach (const Button &button, groups[g]) {
            button.action->setIconText(localized(button.en, button.zh));
            bar->addAction(button.action);
        }
    }
    // Labels under the icons, so no button has to be guessed.
    bar->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
}

} // namespace

void brandMainWindow(QMainWindow *window, Ui::WiresharkMainWindow *ui)
{
    const QString name = QString::fromUtf8(application_flavor_name_proper());

    // The shark-fin icons are part of the Wireshark trademark.
    ui->actionCaptureStart->setIcon(StockIcon("blehound-capture-start"));
    ui->actionCaptureRestart->setIcon(StockIcon("blehound-capture-restart"));

    ui->actionHelpAbout->setText(QObject::tr("&About %1").arg(name));
    ui->actionFileQuit->setText(QObject::tr("Quit %1").arg(name));

    // Bluetooth ATT attributes are the one useful item of the Wireless menu.
    if (!ui->menuStatistics->actions().contains(ui->actionBluetoothATT_Server_Attributes)) {
        ui->menuStatistics->addSeparator();
        ui->menuStatistics->addAction(ui->actionBluetoothATT_Server_Attributes);
    }
    ui->wirelessToolBar->hide();

    addHelpLinks(ui);
    rebuildToolbar(ui);
    pruneMenuBar(window->menuBar());
    installLayerToolbar(qobject_cast<MainWindow *>(window), ui);
}

} // namespace BLEhound

#endif /* BLEHOUND_BRANDING */
