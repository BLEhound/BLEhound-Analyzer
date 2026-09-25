/* blehound_keys_dialog.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "blehound_keys_dialog.h"

#include "blehound_i18n.h"

#include <algorithm>
#include <functional>

#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

namespace BLEhound {

enum { ColName, ColIdentity, ColIrk, ColLtk, ColCount };

KeysDialog::KeysDialog(QWidget *parent) :
    QDialog(parent)
{
    setWindowTitle(localized("Device Keys", "设备密钥"));
    resize(760, 520);

    QVBoxLayout *layout = new QVBoxLayout(this);
    QLabel *intro = new QLabel(localized(
        "With a device's IRK the sniffer recognises the private addresses it rotates through and keeps "
        "following it. Keys are in wire (LSO-first) order, as a device's own log prints them.",
        "有了设备的 IRK，sniffer 就能认出它轮换的私有地址，换地址也不会跟丢。"
        "密钥按空口顺序（LSO 在前）填写，与设备自己日志里打印的一致。"), this);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    table_ = new QTableWidget(0, ColCount, this);
    table_->setHorizontalHeaderLabels({ localized("Name", "名称"),
                                        localized("Identity address", "身份地址"),
                                        QStringLiteral("IRK"), QStringLiteral("LTK") });
    table_->horizontalHeader()->setSectionResizeMode(ColIrk, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(ColLtk, QHeaderView::Stretch);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->verticalHeader()->hide();
    layout->addWidget(table_, 2);

    QHBoxLayout *row_buttons = new QHBoxLayout();
    QPushButton *add = new QPushButton(localized("Add", "添加"), this);
    QPushButton *remove = new QPushButton(localized("Remove", "删除"), this);
    row_buttons->addWidget(add);
    row_buttons->addWidget(remove);
    row_buttons->addStretch();
    layout->addLayout(row_buttons);

    QLabel *log_label = new QLabel(localized(
        "Or paste the device's console output here (lines like \"IRK wire/LSO-first : …\") and import:",
        "或者把设备的控制台输出粘贴到这里（含 \"IRK wire/LSO-first : …\" 这样的行）后导入："), this);
    log_label->setWordWrap(true);
    layout->addWidget(log_label);
    log_ = new QPlainTextEdit(this);
    log_->setPlaceholderText(QStringLiteral("identity[0] : 02:10:F9:56:78:90 (public)\n"
                                            "    IRK  wire/LSO-first : 2959AE60144E6314AC2D86446CD4344F"));
    layout->addWidget(log_, 1);
    QHBoxLayout *import_row = new QHBoxLayout();
    import_button_ = new QPushButton(localized("Import from log", "从日志导入"), this);
    import_row->addWidget(import_button_);
    import_row->addStretch();
    layout->addLayout(import_row);

    QDialogButtonBox *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    layout->addWidget(buttons);

    connect(add, &QPushButton::clicked, this, &KeysDialog::addRow);
    connect(remove, &QPushButton::clicked, this, &KeysDialog::removeSelected);
    connect(import_button_, &QPushButton::clicked, this, &KeysDialog::importFromLog);
    connect(buttons, &QDialogButtonBox::accepted, this, &KeysDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    foreach (const DeviceKey &key, KeyStore::instance()->keys()) {
        appendKey(key);
    }
}

void KeysDialog::appendKey(const DeviceKey &key)
{
    int row = table_->rowCount();
    table_->insertRow(row);
    table_->setItem(row, ColName, new QTableWidgetItem(key.name));
    table_->setItem(row, ColIdentity, new QTableWidgetItem(key.identity));
    table_->setItem(row, ColIrk, new QTableWidgetItem(KeyStore::hex(key.irk_le)));
    table_->setItem(row, ColLtk, new QTableWidgetItem(KeyStore::hex(key.ltk_le)));
}

void KeysDialog::addRow()
{
    appendKey(DeviceKey());
    table_->editItem(table_->item(table_->rowCount() - 1, ColName));
}

void KeysDialog::removeSelected()
{
    QList<int> rows;
    foreach (const QModelIndex &index, table_->selectionModel()->selectedRows()) {
        rows.append(index.row());
    }
    std::sort(rows.begin(), rows.end(), std::greater<int>());
    foreach (int row, rows) {
        table_->removeRow(row);
    }
}

void KeysDialog::importFromLog()
{
    QList<DeviceKey> found = KeyStore::parseDeviceLog(log_->toPlainText());
    if (found.isEmpty()) {
        QMessageBox::information(this, windowTitle(),
                                 localized("No IRK or LTK lines were found in the pasted text.",
                                           "粘贴的文本里没有找到 IRK / LTK 行。"));
        return;
    }
    foreach (const DeviceKey &key, found) {
        /* Refresh a row that already has this identity instead of duplicating it. */
        int existing = -1;
        for (int row = 0; row < table_->rowCount() && !key.identity.isEmpty(); row++) {
            if (table_->item(row, ColIdentity)->text().compare(key.identity, Qt::CaseInsensitive) == 0) {
                existing = row;
                break;
            }
        }
        if (existing < 0) {
            appendKey(key);
            continue;
        }
        if (key.hasIrk()) {
            table_->item(existing, ColIrk)->setText(KeyStore::hex(key.irk_le));
        }
        if (key.hasLtk()) {
            table_->item(existing, ColLtk)->setText(KeyStore::hex(key.ltk_le));
        }
    }
    log_->clear();
}

bool KeysDialog::collect(QList<DeviceKey> *keys, QString *error) const
{
    for (int row = 0; row < table_->rowCount(); row++) {
        DeviceKey key;
        bool ok_irk, ok_ltk;

        key.name = table_->item(row, ColName)->text().trimmed();
        key.identity = table_->item(row, ColIdentity)->text().trimmed().toUpper();
        key.irk_le = KeyStore::keyFromHex(table_->item(row, ColIrk)->text(), &ok_irk);
        key.ltk_le = KeyStore::keyFromHex(table_->item(row, ColLtk)->text(), &ok_ltk);
        if (!ok_irk || !ok_ltk) {
            *error = localized("Row %1: a key must be 16 bytes (32 hex digits).",
                               "第 %1 行：密钥必须是 16 字节（32 个十六进制字符）。").arg(row + 1);
            return false;
        }
        if (!key.hasIrk() && !key.hasLtk()) {
            continue;                       /* blank row */
        }
        keys->append(key);
    }
    return true;
}

void KeysDialog::accept()
{
    QList<DeviceKey> keys;
    QString error;

    if (!collect(&keys, &error)) {
        QMessageBox::warning(this, windowTitle(), error);
        return;
    }
    KeyStore::instance()->setKeys(keys);
    QDialog::accept();
}

} // namespace BLEhound
