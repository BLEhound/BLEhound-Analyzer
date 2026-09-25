/** @file
 *
 * Unix socket helpers shared by the BLEhound capture streamers.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QByteArray>
#include <QString>

namespace BLEhound {
namespace Socket {

/** Bind and listen on a Unix socket; @return the fd or -1. */
int listenOn(const QString &path);

/** Accept one client with a poll timeout; @return the fd or -1. */
int acceptClient(int listen_fd, int timeout_ms);

/** Write all of @p data to a client; @return false once the client is gone. */
bool sendAll(int fd, const QByteArray &data);

/** dumpcap never writes to us, so readable or hung up means end of capture. */
bool clientClosed(int fd);

} // namespace Socket
} // namespace BLEhound
