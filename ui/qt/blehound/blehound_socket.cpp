/* blehound_socket.cpp
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_CAPTURE

#include "blehound_socket.h"

#include <string.h>

#include <glib.h>

#include <wsutil/wslog.h>

#ifdef _WIN32

#include <windows.h>

#include <string>

namespace BLEhound {
namespace Socket {

static const DWORD kPipeBufferSize = 1 << 16;

struct Listener {
    std::wstring name;
    HANDLE pipe = INVALID_HANDLE_VALUE;     /**< the instance waiting for the next dumpcap */
    HANDLE event = nullptr;
    OVERLAPPED overlapped;
    bool connect_pending = false;
};

static HANDLE createInstance(const std::wstring &name)
{
    HANDLE h = CreateNamedPipeW(name.c_str(),
                                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                PIPE_UNLIMITED_INSTANCES, kPipeBufferSize, kPipeBufferSize, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        ws_warning("BLEhound CreateNamedPipe(%s): error %lu",
                   qUtf8Printable(QString::fromStdWString(name)), GetLastError());
    }
    return h;
}

/* Start (or continue) waiting for a client on the current instance. */
static bool startConnect(Listener *listener)
{
    if (listener->connect_pending) {
        return true;
    }
    memset(&listener->overlapped, 0, sizeof(listener->overlapped));
    listener->overlapped.hEvent = listener->event;
    ResetEvent(listener->event);
    if (ConnectNamedPipe(listener->pipe, &listener->overlapped)) {
        // Overlapped ConnectNamedPipe never returns TRUE; treat it as connected anyway.
        SetEvent(listener->event);
        listener->connect_pending = true;
        return true;
    }
    switch (GetLastError()) {
    case ERROR_IO_PENDING:
        listener->connect_pending = true;
        return true;
    case ERROR_PIPE_CONNECTED:              /* dumpcap got there first */
        SetEvent(listener->event);
        listener->connect_pending = true;
        return true;
    default:
        ws_warning("BLEhound ConnectNamedPipe: error %lu", GetLastError());
        return false;
    }
}

Listener *listenOn(const QString &path)
{
    Listener *listener = new Listener;
    listener->name = path.toStdWString();
    listener->event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    listener->pipe = createInstance(listener->name);
    if (!listener->event || listener->pipe == INVALID_HANDLE_VALUE) {
        closeListener(listener);
        return nullptr;
    }
    return listener;
}

void closeListener(Listener *listener)
{
    if (!listener) {
        return;
    }
    if (listener->pipe != INVALID_HANDLE_VALUE) {
        if (listener->connect_pending) {
            CancelIoEx(listener->pipe, &listener->overlapped);
        }
        CloseHandle(listener->pipe);
    }
    if (listener->event) {
        CloseHandle(listener->event);
    }
    delete listener;
}

Client acceptClient(Listener *listener, int timeout_ms)
{
    if (!startConnect(listener)) {
        return kNoClient;
    }
    if (WaitForSingleObject(listener->event, timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms) != WAIT_OBJECT_0) {
        return kNoClient;                   /* still waiting; the connect stays pending */
    }
    DWORD ignored;
    if (!GetOverlappedResult(listener->pipe, &listener->overlapped, &ignored, FALSE) &&
            GetLastError() != ERROR_PIPE_CONNECTED) {
        // The connect failed; start over with a fresh instance.
        ws_warning("BLEhound pipe connect: error %lu", GetLastError());
        listener->connect_pending = false;
        CloseHandle(listener->pipe);
        listener->pipe = createInstance(listener->name);
        return kNoClient;
    }
    listener->connect_pending = false;
    HANDLE client = listener->pipe;
    // Keep an instance listening at all times so that dumpcap's CreateFile
    // never finds the pipe missing.
    listener->pipe = createInstance(listener->name);
    return reinterpret_cast<Client>(client);
}

void closeClient(Client client)
{
    HANDLE h = reinterpret_cast<HANDLE>(client);
    if (h && h != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(h);
        DisconnectNamedPipe(h);
        CloseHandle(h);
    }
}

bool sendAll(Client client, const QByteArray &data)
{
    HANDLE h = reinterpret_cast<HANDLE>(client);
    const char *p = data.constData();
    qsizetype left = data.size();
    OVERLAPPED ov;

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) {
        return false;
    }
    bool ok = true;
    while (left > 0) {
        DWORD written = 0;
        ResetEvent(ov.hEvent);
        if (!WriteFile(h, p, (DWORD)left, &written, &ov)) {
            if (GetLastError() != ERROR_IO_PENDING || !GetOverlappedResult(h, &ov, &written, TRUE)) {
                ok = false;                 /* ERROR_BROKEN_PIPE / ERROR_NO_DATA: dumpcap is gone */
                break;
            }
        }
        if (written == 0) {
            ok = false;
            break;
        }
        p += written;
        left -= written;
    }
    CloseHandle(ov.hEvent);
    return ok;
}

bool clientClosed(Client client)
{
    HANDLE h = reinterpret_cast<HANDLE>(client);
    DWORD available = 0;

    if (!PeekNamedPipe(h, nullptr, 0, nullptr, &available, nullptr)) {
        return true;                        /* ERROR_BROKEN_PIPE once dumpcap closes its end */
    }
    return false;
}

} // namespace Socket
} // namespace BLEhound

#else /* POSIX: Unix socket */

#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef MSG_NOSIGNAL
#define BH_SEND_FLAGS MSG_NOSIGNAL
#else
#define BH_SEND_FLAGS 0             /* macOS: SO_NOSIGPIPE is set on the socket instead */
#endif

namespace BLEhound {
namespace Socket {

struct Listener {
    int fd = -1;
    QByteArray path;
};

Listener *listenOn(const QString &path_str)
{
    struct sockaddr_un addr;
    QByteArray path = path_str.toLocal8Bit();

    if ((size_t)path.size() >= sizeof(addr.sun_path)) {
        ws_warning("BLEhound socket path too long: %s", path.constData());
        return nullptr;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        ws_warning("BLEhound socket(): %s", g_strerror(errno));
        return nullptr;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path.constData(), (size_t)path.size());
    unlink(path.constData());
    if (bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0 || listen(fd, 1) < 0) {
        ws_warning("BLEhound bind/listen %s: %s", path.constData(), g_strerror(errno));
        close(fd);
        return nullptr;
    }
    Listener *listener = new Listener;
    listener->fd = fd;
    listener->path = path;
    return listener;
}

void closeListener(Listener *listener)
{
    if (!listener) {
        return;
    }
    close(listener->fd);
    unlink(listener->path.constData());
    delete listener;
}

Client acceptClient(Listener *listener, int timeout_ms)
{
    struct pollfd pfd = { listener->fd, POLLIN, 0 };

    if (poll(&pfd, 1, timeout_ms) <= 0) {
        return kNoClient;
    }
    int client_fd = accept(listener->fd, nullptr, nullptr);
    if (client_fd < 0) {
        return kNoClient;
    }
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(client_fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    return client_fd;
}

void closeClient(Client client)
{
    close((int)client);
}

bool sendAll(Client client, const QByteArray &data)
{
    int fd = (int)client;
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

bool clientClosed(Client client)
{
    int fd = (int)client;
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

#endif /* _WIN32 */
