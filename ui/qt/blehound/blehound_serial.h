/** @file
 *
 * Minimal native serial port for the BLEhound dongle: a POSIX fd on
 * macOS/Linux, an overlapped Win32 handle on Windows.
 *
 * Unlike QSerialPort, it may be written from a thread other than the one
 * reading it, which the follow relay needs: the board that hears a
 * CONNECT_IND hands it to the other boards' ports right away.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QMutex>
#include <QString>

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <ws_posix_compat.h>        /* ssize_t */
#endif

namespace BLEhound {

class NativeSerial
{
public:
    NativeSerial() = default;
    ~NativeSerial();
    NativeSerial(const NativeSerial &) = delete;
    NativeSerial &operator=(const NativeSerial &) = delete;

    /** Open raw, assert DTR (the firmware streams only once it sees DTR). */
    bool open(const QString &path, QString *error = nullptr);
    void close();
    bool isOpen() const;

    /** @return bytes read, 0 on timeout, -1 on error. Owner thread only. */
    ssize_t read(uint8_t *buf, size_t cap, int timeout_ms);

    /** Write everything; safe from any thread. */
    bool write(const uint8_t *data, size_t len);

    /** Discard unread input after waiting @p settle_ms. Owner thread only. */
    void drainInput(int settle_ms);

private:
#ifdef _WIN32
    void *handle_ = nullptr;        /**< HANDLE; nullptr when closed */
    void *read_event_ = nullptr;    /**< OVERLAPPED event for the reader thread */
    int read_timeout_ms_ = -1;      /**< COMMTIMEOUTS currently programmed */
#else
    int fd_ = -1;
#endif
    QMutex mutex_;                  /**< serialises write() against open()/close() */
};

} // namespace BLEhound
