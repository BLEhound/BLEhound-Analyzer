# BLEhound Analyzer

BLEhound Analyzer is a Bluetooth LE protocol analyzer for the BLEhound sniffer
dongle, built from the Wireshark source tree (branch `blehound/4.6`, based on
Wireshark v4.6.9). It is licensed GPL-2.0-or-later like Wireshark itself.

## How the fork is organized

- The GUI runs the upstream Wireshark *packet* flavor unchanged. A thin brand
  layer (`set_application_brand()` in `wsutil/application_flavor.c`) changes only
  the display name and the personal configuration directory
  (`~/.config/blehound-analyzer`, `%APPDATA%\BLEhound Analyzer`).
- Branding is controlled by the CMake option `BLEHOUND_BRANDING` (default `ON`);
  turning it off builds stock Wireshark.
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
