# BLEhound Analyzer

**BLEhound Analyzer** is the desktop application for the
[BLEhound](https://github.com/BLEhound/BLEhound) Bluetooth LE sniffer dongle:
Wireshark 4.6 rebuilt around the sniffer. It talks to the boards directly (no
Python, no extcap) and adds what a BLE sniffer needs — a live device list,
one-click follow with IRK-based address resolution, on-host decryption with the
device's LTK, a connection view with a channel heat map, request/response
transactions, synchronized three-board capture and USB firmware update.
Everything Wireshark can do with a BLE capture still works.

Documentation and screenshots: **https://blehound.github.io/analyzer/**
（中文：https://blehound.github.io/zh/analyzer/ ）

![BLEhound Analyzer](https://blehound.github.io/img/analyzer/07-capturing.png)

## Download

Installers are on the [Releases](https://github.com/BLEhound/BLEhound-Analyzer/releases) page:

- Windows 10/11 (x64): `BLEhound-Analyzer-<version>-x64.exe` — installs side by
  side with a stock Wireshark, no Npcap needed.
- macOS (Apple Silicon): `BLEhound Analyzer.app`.

## Build from source

The code lives on the `blehound/4.6` branch (based on Wireshark v4.6.9). Build
notes for macOS and Windows: [BLEHOUND.md](BLEHOUND.md) /
[BLEHOUND.zh-CN.md](BLEHOUND.zh-CN.md). BLEhound-specific code is kept in its
own directories so the branch stays easy to rebase onto new Wireshark releases:

| Directory | Contents |
|---|---|
| `libblehound/` | Dongle host protocol library: framing, commands, multi-board sync clock, aggregator, follow relay, decryption, SMP/DFU (Apache-2.0) |
| `ui/qt/blehound/` | The Qt panels and dialogs, native capture streamers, key store, firmware update |
| `resources/icons/blehound/` | Icons |
| `packaging/nsis/` | Branded Windows installer (`BLEHOUND_BRANDING`) |

Set `-DBLEHOUND_BRANDING=OFF` to build stock Wireshark from the same tree.

## License and trademarks

This is a fork of [Wireshark](https://www.wireshark.org/); like Wireshark it is
licensed under the GNU General Public License version 2 or later, see
[COPYING](COPYING). The upstream README is kept as
[README.wireshark.md](README.wireshark.md). `libblehound/` is additionally
available under the Apache License 2.0 ([libblehound/LICENSE](libblehound/LICENSE)).

Wireshark and the "fin" logo are registered trademarks of the Wireshark
Foundation. BLEhound Analyzer is an independent project and is not endorsed by
or affiliated with the Wireshark Foundation.
