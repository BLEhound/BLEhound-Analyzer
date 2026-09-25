/* blehound_capture_settings.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "blehound_capture_settings.h"

#include <QSettings>

#include <blehound/blehound.h>

namespace BLEhound {

static const char *kOrg = "BLEhound";
static const char *kApp = "Analyzer";

CaptureSettings *CaptureSettings::instance()
{
    static CaptureSettings *settings = new CaptureSettings();
    return settings;
}

CaptureSettings::CaptureSettings(QObject *parent) :
    QObject(parent)
{
    load();
}

CaptureConfig CaptureSettings::config() const
{
    QMutexLocker locker(&mutex_);
    return config_;
}

QString CaptureSettings::targetMacText() const
{
    QMutexLocker locker(&mutex_);
    return target_mac_text_;
}

void CaptureSettings::setConfig(const CaptureConfig &config, const QString &target_mac_text)
{
    {
        QMutexLocker locker(&mutex_);
        config_ = config;
        target_mac_text_ = target_mac_text;
    }
    save();
    emit changed();
}

void CaptureSettings::load()
{
    QSettings settings(QString::fromUtf8(kOrg), QString::fromUtf8(kApp));
    CaptureConfig config;
    uint8_t mac[6];

    config.hopping = settings.value(QStringLiteral("capture/hopping"), true).toBool();
    config.channel = (quint8)settings.value(QStringLiteral("capture/channel"), 37).toUInt();
    if (config.channel < 37 || config.channel > 39) {
        config.channel = 37;
    }
    target_mac_text_ = settings.value(QStringLiteral("capture/targetMac")).toString();
    if (bh_parse_mac(target_mac_text_.toUtf8().constData(), mac)) {
        config.target_mac_le = QByteArray(reinterpret_cast<const char *>(mac), sizeof(mac));
    }
    config.include_crc_errors = settings.value(QStringLiteral("capture/includeCrcErrors"), false).toBool();
    config.single_target = settings.value(QStringLiteral("capture/singleTarget"), true).toBool();
    config.follow_relay = settings.value(QStringLiteral("capture/followRelay"), false).toBool();
    config_ = config;
}

void CaptureSettings::save() const
{
    QSettings settings(QString::fromUtf8(kOrg), QString::fromUtf8(kApp));
    QMutexLocker locker(&mutex_);

    settings.setValue(QStringLiteral("capture/hopping"), config_.hopping);
    settings.setValue(QStringLiteral("capture/channel"), (uint)config_.channel);
    settings.setValue(QStringLiteral("capture/targetMac"), target_mac_text_);
    settings.setValue(QStringLiteral("capture/includeCrcErrors"), config_.include_crc_errors);
    settings.setValue(QStringLiteral("capture/singleTarget"), config_.single_target);
    settings.setValue(QStringLiteral("capture/followRelay"), config_.follow_relay);
}

} // namespace BLEhound
