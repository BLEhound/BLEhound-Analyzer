/** @file
 *
 * Minimal POSIX serial port for the BLEhound dongle.
 *
 * Unlike QSerialPort, a POSIX fd may be written from a thread other than
 * the one reading it, which the follow relay needs: the board that hears a
 * CONNECT_IND hands it to the other boards' ports right away.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QMutex>
#include <QString>

#include <stddef.h>
#include <stdint.h>

namespace BLEhound {

class PosixSerial
{
public:
    PosixSerial() = default;
    ~PosixSerial();
    PosixSerial(const PosixSerial &) = delete;
    PosixSerial &operator=(const PosixSerial &) = delete;

    /** Open raw, assert DTR (the firmware streams only once it sees DTR). */
    bool open(const QString &path, QString *error = nullptr);
    void close();
    bool isOpen() const { return fd_ >= 0; }

    /** @return bytes read, 0 on timeout, -1 on error. Owner thread only. */
    ssize_t read(uint8_t *buf, size_t cap, int timeout_ms);

    /** Write everything; safe from any thread. */
    bool write(const uint8_t *data, size_t len);

    /** Discard unread input after waiting @p settle_ms. Owner thread only. */
    void drainInput(int settle_ms);

private:
    int fd_ = -1;
    QMutex mutex_;      /**< serialises write() against open()/close() */
};

} // namespace BLEhound
