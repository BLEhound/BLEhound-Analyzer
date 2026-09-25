/** @file
 *
 * Capture settings shared by the device panel and the capture streamers.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QMutex>
#include <QObject>

#include "blehound_streamer.h"

namespace BLEhound {

/**
 * Persistent capture configuration. The panel edits it on the main thread;
 * streamers take a copy when a capture starts, so changes apply to the
 * next capture.
 */
class CaptureSettings : public QObject
{
    Q_OBJECT

public:
    static CaptureSettings *instance();

    CaptureConfig config() const;               /**< thread-safe copy */
    QString targetMacText() const;

    /** Main thread. Saves and emits changed(). */
    void setConfig(const CaptureConfig &config, const QString &target_mac_text);

signals:
    void changed();

private:
    explicit CaptureSettings(QObject *parent = nullptr);
    void load();
    void save() const;

    mutable QMutex mutex_;
    CaptureConfig config_;
    QString target_mac_text_;
};

} // namespace BLEhound
