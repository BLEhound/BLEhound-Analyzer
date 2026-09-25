/* blehound_serial.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "blehound_serial.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <QThread>

namespace BLEhound {

PosixSerial::~PosixSerial()
{
    close();
}

bool PosixSerial::open(const QString &path, QString *error)
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
    int dtr = TIOCM_DTR;
    ioctl(fd, TIOCMBIS, &dtr);
    fd_ = fd;
    return true;
}

void PosixSerial::close()
{
    QMutexLocker locker(&mutex_);
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

ssize_t PosixSerial::read(uint8_t *buf, size_t cap, int timeout_ms)
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

bool PosixSerial::write(const uint8_t *data, size_t len)
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

void PosixSerial::drainInput(int settle_ms)
{
    QThread::msleep(settle_ms);
    tcflush(fd_, TCIFLUSH);
}

} // namespace BLEhound
