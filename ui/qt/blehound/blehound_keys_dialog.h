/** @file
 *
 * Dialog to enter device keys (IRK / LTK), by hand or pasted from a
 * device's console log.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QDialog>

#include "blehound_key_store.h"

class QPlainTextEdit;
class QPushButton;
class QTableWidget;

namespace BLEhound {

class KeysDialog : public QDialog
{
    Q_OBJECT

public:
    explicit KeysDialog(QWidget *parent = nullptr);

private slots:
    void addRow();
    void removeSelected();
    void importFromLog();
    void accept() override;

private:
    void appendKey(const DeviceKey &key);
    bool collect(QList<DeviceKey> *keys, QString *error) const;

    QTableWidget *table_;
    QPlainTextEdit *log_;
    QPushButton *import_button_;
};

} // namespace BLEhound
