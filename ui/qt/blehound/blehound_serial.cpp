/* blehound_serial.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "blehound_serial.h"

#include <QThread>

#ifdef _WIN32

#include <windows.h>

namespace BLEhound {

static QString lastErrorString()
{
    DWORD code = GetLastError();
    wchar_t *msg = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, code, 0, reinterpret_cast<LPWSTR>(&msg), 0, nullptr);
    QString text = n ? QString::fromWCharArray(msg, (int)n).trimmed() : QStringLiteral("error %1").arg(code);
    if (msg) {
        LocalFree(msg);
    }
    return text;
}

NativeSerial::~NativeSerial()
{
    close();
}

bool NativeSerial::isOpen() const
{
    return handle_ != nullptr;
}

bool NativeSerial::open(const QString &path, QString *error)
{
    QMutexLocker locker(&mutex_);
    // QSerialPortInfo::systemLocation() is already "\\.\COMn"; accept a bare "COMn" too.
    QString device = path.startsWith(QStringLiteral("\\\\")) ? path : QStringLiteral("\\\\.\\") + path;
    HANDLE h = CreateFileW(reinterpret_cast<LPCWSTR>(device.utf16()), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr);

    if (h == INVALID_HANDLE_VALUE) {
        if (error) *error = lastErrorString();
        return false;
    }

    DCB dcb;
    memset(&dcb, 0, sizeof(dcb));
    dcb.DCBlength = sizeof(dcb);
    if (!GetCommState(h, &dcb)) {
        if (error) *error = lastErrorString();
        CloseHandle(h);
        return false;
    }
    dcb.BaudRate = CBR_115200;              /* USB CDC ignores it */
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.fBinary = TRUE;
    dcb.fParity = FALSE;
    dcb.fOutxCtsFlow = FALSE;
    dcb.fOutxDsrFlow = FALSE;
    dcb.fDsrSensitivity = FALSE;
    dcb.fTXContinueOnXoff = TRUE;
    dcb.fOutX = FALSE;
    dcb.fInX = FALSE;
    dcb.fErrorChar = FALSE;
    dcb.fNull = FALSE;
    dcb.fAbortOnError = FALSE;
    dcb.fDtrControl = DTR_CONTROL_ENABLE;   /* the firmware streams only once DTR is asserted */
    dcb.fRtsControl = RTS_CONTROL_ENABLE;
    if (!SetCommState(h, &dcb)) {
        if (error) *error = lastErrorString();
        CloseHandle(h);
        return false;
    }
    SetupComm(h, 1 << 16, 1 << 14);
    PurgeComm(h, PURGE_RXCLEAR | PURGE_TXCLEAR | PURGE_RXABORT | PURGE_TXABORT);
    EscapeCommFunction(h, SETDTR);

    read_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    read_timeout_ms_ = -1;
    handle_ = h;
    return true;
}

void NativeSerial::close()
{
    QMutexLocker locker(&mutex_);
    if (handle_) {
        HANDLE h = static_cast<HANDLE>(handle_);
        CancelIoEx(h, nullptr);
        EscapeCommFunction(h, CLRDTR);
        CloseHandle(h);
        handle_ = nullptr;
    }
    if (read_event_) {
        CloseHandle(static_cast<HANDLE>(read_event_));
        read_event_ = nullptr;
    }
}

ssize_t NativeSerial::read(uint8_t *buf, size_t cap, int timeout_ms)
{
    HANDLE h = static_cast<HANDLE>(handle_);
    if (!h) {
        return -1;
    }
    if (timeout_ms != read_timeout_ms_) {
        // Return as soon as any byte is available, otherwise after timeout_ms:
        // ReadIntervalTimeout = ReadTotalTimeoutMultiplier = MAXDWORD is the
        // documented "wait for the first byte" combination.
        COMMTIMEOUTS timeouts;
        memset(&timeouts, 0, sizeof(timeouts));
        timeouts.ReadIntervalTimeout = MAXDWORD;
        timeouts.ReadTotalTimeoutMultiplier = MAXDWORD;
        timeouts.ReadTotalTimeoutConstant = timeout_ms > 0 ? (DWORD)timeout_ms : 1;
        timeouts.WriteTotalTimeoutConstant = 1000;
        if (!SetCommTimeouts(h, &timeouts)) {
            return -1;
        }
        read_timeout_ms_ = timeout_ms;
    }

    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = static_cast<HANDLE>(read_event_);
    ResetEvent(ov.hEvent);
    DWORD got = 0;
    if (!ReadFile(h, buf, (DWORD)cap, &got, &ov)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            return -1;                      /* device gone, port yanked */
        }
        if (!GetOverlappedResult(h, &ov, &got, TRUE)) {
            return -1;
        }
    }
    return (ssize_t)got;                    /* 0 = timeout */
}

bool NativeSerial::write(const uint8_t *data, size_t len)
{
    QMutexLocker locker(&mutex_);
    HANDLE h = static_cast<HANDLE>(handle_);
    if (!h) {
        return false;
    }
    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) {
        return false;
    }
    bool ok = true;
    while (len > 0 && ok) {
        DWORD written = 0;
        if (!WriteFile(h, data, (DWORD)len, &written, &ov)) {
            if (GetLastError() != ERROR_IO_PENDING) {
                ok = false;
                break;
            }
            if (WaitForSingleObject(ov.hEvent, 1000) != WAIT_OBJECT_0) {
                CancelIoEx(h, &ov);
                ok = false;
                break;
            }
            if (!GetOverlappedResult(h, &ov, &written, TRUE)) {
                ok = false;
                break;
            }
        }
        if (written == 0) {
            ok = false;
            break;
        }
        data += written;
        len -= written;
    }
    CloseHandle(ov.hEvent);
    return ok;
}

void NativeSerial::drainInput(int settle_ms)
{
    QThread::msleep(settle_ms);
    if (handle_) {
        PurgeComm(static_cast<HANDLE>(handle_), PURGE_RXCLEAR);
    }
}

} // namespace BLEhound

#else /* POSIX */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

namespace BLEhound {

NativeSerial::~NativeSerial()
{
    close();
}

bool NativeSerial::isOpen() const
{
    return fd_ >= 0;
}

bool NativeSerial::open(const QString &path, QString *error)
{
    QMutexLocker locker(&mutex_);
    QByteArray p = path.toLocal8Bit();
    struct termios tio;
    int fd = ::open(p.constData(), O_RDWR | O_NOCTTY | O_NONBLOCK);

    if (fd < 0) {
        if (error) *error = QString::fromLocal8Bit(strerror(errno));
        return false;
    }
    if (tcgetattr(fd, &tio) != 0) {
        if (error) *error = QString::fromLocal8Bit(strerror(errno));
        ::close(fd);
        return false;
    }
    cfmakeraw(&tio);
    tio.c_cflag |= CLOCAL | CREAD;      /* USB CDC: ignore modem status lines */
    tio.c_cc[VMIN] = 0;
    tio.c_cc[VTIME] = 0;
    if (tcsetattr(fd, TCSANOW, &tio) != 0) {
        if (error) *error = QString::fromLocal8Bit(strerror(errno));
        ::close(fd);
        return false;
    }
    tcflush(fd, TCIOFLUSH);
    ioctl(fd, TIOCEXCL);                /* like QSerialPort: one owner at a time */
    int dtr = TIOCM_DTR;
    ioctl(fd, TIOCMBIS, &dtr);
    fd_ = fd;
    return true;
}

void NativeSerial::close()
{
    QMutexLocker locker(&mutex_);
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

ssize_t NativeSerial::read(uint8_t *buf, size_t cap, int timeout_ms)
{
    struct pollfd pfd = { fd_, POLLIN, 0 };
    int ready = poll(&pfd, 1, timeout_ms);

    if (ready < 0) {
        return errno == EINTR ? 0 : -1;
    }
    if (ready == 0) {
        return 0;
    }
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        return -1;
    }
    ssize_t n = ::read(fd_, buf, cap);
    if (n < 0) {
        return (errno == EAGAIN || errno == EINTR) ? 0 : -1;
    }
    return n == 0 ? -1 : n;            /* 0 bytes on a readable fd: device gone */
}

bool NativeSerial::write(const uint8_t *data, size_t len)
{
    QMutexLocker locker(&mutex_);
    if (fd_ < 0) {
        return false;
    }
    while (len > 0) {
        ssize_t n = ::write(fd_, data, len);
        if (n < 0) {
            if (errno == EAGAIN) {
                struct pollfd pfd = { fd_, POLLOUT, 0 };
                if (poll(&pfd, 1, 200) <= 0) {
                    return false;
                }
                continue;
            }
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        data += n;
        len -= (size_t)n;
    }
    return true;
}

void NativeSerial::drainInput(int settle_ms)
{
    QThread::msleep(settle_ms);
    tcflush(fd_, TCIFLUSH);
}

} // namespace BLEhound

#endif /* _WIN32 */
