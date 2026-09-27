# BLEhound Analyzer

BLEhound Analyzer is a Bluetooth LE protocol analyzer for the BLEhound sniffer
dongle, built from the Wireshark source tree (branch `blehound/4.6`, based on
Wireshark v4.6.9). It is licensed GPL-2.0-or-later like Wireshark itself.

中文版见 [BLEHOUND.zh-CN.md](BLEHOUND.zh-CN.md)。

## How the fork is organized

- The GUI runs the upstream Wireshark *packet* flavor unchanged. A thin brand
  layer (`set_application_brand()` in `wsutil/application_flavor.c`) changes only
  the display name and the personal configuration directory
  (`~/.config/blehound-analyzer`, `%APPDATA%\BLEhound Analyzer`).
- Branding is controlled by the CMake option `BLEHOUND_BRANDING` (default `ON`);
  turning it off builds stock Wireshark. On Windows it also brands the NSIS
  installer (`BLEhound-Analyzer-<version>-x64.exe`: own install directory,
  registry keys, shortcuts and file association, no Npcap/USBPcap pages) so it
  installs side by side with a stock Wireshark. The executable stays `Wireshark.exe`.
- Native dongle capture needs Qt SerialPort. The streamers serve dumpcap a pcap
  stream on a Unix socket (macOS/Linux) or a named pipe `\\.\pipe\blehound-<user>-<port>`
  (Windows); `blehound_serial.*` and `blehound_socket.*` hold both implementations.
- With branding on, the generic extcap tools (ciscodump, sshdump, wifidump, ...)
  are not built, the shark-fin toolbar icons are replaced, and the app / dock /
  About icons come from `resources/icons/blehound/` (regenerate with
  `resources/icons/blehound/make-icons.sh` from `mark.svg`).
- BLEhound-specific code lives in its own directories (`ui/qt/blehound/`,
  `resources/icons/blehound/`) so rebasing onto new 4.6.x releases stays cheap.

## Build on macOS (Apple Silicon)

```bash
./tools/macos-setup-brew.sh --install-required --install-optional
brew install ccache
mkdir build && cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
      -DCMAKE_PREFIX_PATH="$(brew --prefix qt);$(brew --prefix libxml2)" ..
ninja
```

The build produces `build/run/Wireshark.app`. For a named, runnable copy:

```bash
ditto build/run/Wireshark.app "dist/BLEhound Analyzer.app"
codesign --force --deep -s - "dist/BLEhound Analyzer.app"   # ad-hoc, local testing only
open "dist/BLEhound Analyzer.app"
```

This development bundle still links against libraries in the build tree; a
self-contained, signed and notarized DMG is produced by the release packaging.

## Build on Windows (x64)

Visual Studio 2022 (MSVC, CMake, Ninja), Windows 10/11 SDK, Python 3, NSIS and
win_flex_bison (`winget install NSIS.NSIS WinFlexBison.win_flex_bison`), plus
Qt 6 with the SerialPort module, e.g. with aqtinstall:

```powershell
pip install aqtinstall
aqt install-qt --outputdir C:\Qt windows desktop 6.10.3 win64_msvc2022_64 --modules qt5compat qtmultimedia qtserialport
```

Then, from a "x64 Native Tools" prompt:

```powershell
$env:WIRESHARK_BASE_DIR = "C:\Development"      # third-party libs are fetched here by CMake
$env:CMAKE_PREFIX_PATH  = "C:\Qt\6.10.3\msvc2022_64"
mkdir build; cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln
msbuild /m /p:Configuration=RelWithDebInfo wireshark_nsis_prep.vcxproj
msbuild    /p:Configuration=RelWithDebInfo wireshark_nsis.vcxproj
```

The installer lands in `build\packaging\nsis\BLEhound-Analyzer-<version>-x64.exe`.
sis\BLEhound-Analyzer-<version>-x64.exe`.
The User's Guide is bundled only when `xsltproc` is on the PATH (DocBook XSL
comes with the fetched asciidoctor bundle); without it the installer is built
without the guide.
