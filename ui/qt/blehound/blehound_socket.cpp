/* blehound_socket.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_CAPTURE

#include "blehound_socket.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <glib.h>

#include <wsutil/wslog.h>

#ifdef MSG_NOSIGNAL
#define BH_SEND_FLAGS MSG_NOSIGNAL
#else
#define BH_SEND_FLAGS 0             /* macOS: SO_NOSIGPIPE is set on the socket instead */
#endif

namespace BLEhound {
namespace Socket {

int listenOn(const QString &path_str)
{
    struct sockaddr_un addr;
    QByteArray path = path_str.toLocal8Bit();

    if ((size_t)path.size() >= sizeof(addr.sun_path)) {
        ws_warning("BLEhound socket path too long: %s", path.constData());
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        ws_warning("BLEhound socket(): %s", g_strerror(errno));
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path.constData(), (size_t)path.size());
    unlink(path.constData());
    if (bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0 || listen(fd, 1) < 0) {
        ws_warning("BLEhound bind/listen %s: %s", path.constData(), g_strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int acceptClient(int listen_fd, int timeout_ms)
{
    struct pollfd pfd = { listen_fd, POLLIN, 0 };

    if (poll(&pfd, 1, timeout_ms) <= 0) {
        return -1;
    }
    int client_fd = accept(listen_fd, nullptr, nullptr);
    if (client_fd < 0) {
        return -1;
    }
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(client_fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    return client_fd;
}

bool sendAll(int fd, const QByteArray &data)
{
    const char *p = data.constData();
    qsizetype left = data.size();

    while (left > 0) {
        ssize_t n = send(fd, p, (size_t)left, BH_SEND_FLAGS);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        p += n;
        left -= n;
    }
    return true;
}

bool clientClosed(int fd)
{
    struct pollfd pfd = { fd, POLLIN, 0 };
    char c;

    if (poll(&pfd, 1, 0) <= 0) {
        return false;
    }
    if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
        return true;
    }
    return recv(fd, &c, 1, MSG_PEEK | MSG_DONTWAIT) == 0;
}

} // namespace Socket
} // namespace BLEhound
