/** @file
 *
 * The local endpoint the BLEhound capture streamers serve dumpcap on: a
 * Unix socket on macOS/Linux, a named pipe ("\\.\pipe\...") on Windows.
 * dumpcap treats both as a pipe interface and reads a pcap stream.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QByteArray>
#include <QString>

#include <stdint.h>

namespace BLEhound {
namespace Socket {

/** A listening endpoint (opaque). */
struct Listener;

/** A connected dumpcap: a socket fd or a pipe HANDLE. */
typedef intptr_t Client;
static const Client kNoClient = -1;

/** Start serving @p path; @return nullptr on failure. */
Listener *listenOn(const QString &path);

/** Stop serving and remove the endpoint. */
void closeListener(Listener *listener);

/** Wait up to @p timeout_ms for one client; @return kNoClient on timeout. */
Client acceptClient(Listener *listener, int timeout_ms);

/** Disconnect a client. */
void closeClient(Client client);

/** Write all of @p data to a client; @return false once the client is gone. */
bool sendAll(Client client, const QByteArray &data);

/** dumpcap never writes to us, so readable or hung up means end of capture. */
bool clientClosed(Client client);

} // namespace Socket
} // namespace BLEhound
