# BLEhound Analyzer

BLEhound Analyzer 是面向 BLEhound 嗅探 dongle 的蓝牙 LE 协议分析器，基于 Wireshark
源码树构建（分支 `blehound/4.6`，基于 Wireshark v4.6.9）。与 Wireshark 一样，采用
GPL-2.0-or-later 许可证。

英文版见 [BLEHOUND.md](BLEHOUND.md)。

## 分支的组织方式

- GUI 直接复用上游 Wireshark 的 *packet* 版本，未做改动。一层很薄的品牌层
  （`wsutil/application_flavor.c` 中的 `set_application_brand()`）只修改显示名称和
  个人配置目录（`~/.config/blehound-analyzer`，`%APPDATA%\BLEhound Analyzer`）。
- 品牌化由 CMake 选项 `BLEHOUND_BRANDING` 控制（默认 `ON`）；关掉即构建原版 Wireshark。
  在 Windows 上它同时品牌化 NSIS 安装包（`BLEhound-Analyzer-<版本>-x64.exe`：独立的
  安装目录、注册表键、快捷方式和文件关联，不再有 Npcap/USBPcap 页面），因此可以与原版
  Wireshark 并存安装。可执行文件仍叫 `Wireshark.exe`。
- 原生 dongle 抓包需要 Qt SerialPort。各 streamer 以 pcap 流的形式把数据喂给 dumpcap，
  在 macOS/Linux 上走 Unix socket，在 Windows 上走命名管道
  `\\.\pipe\blehound-<用户名>-<串口名>`；`blehound_serial.*` 与 `blehound_socket.*`
  里同时包含两种实现。
- 开启品牌化时，通用 extcap 工具（ciscodump、sshdump、wifidump 等）不再构建，鲨鱼鳍
  工具栏图标被替换，应用/Dock/关于图标来自 `resources/icons/blehound/`
  （可用 `resources/icons/blehound/make-icons.sh` 从 `mark.svg` 重新生成）。
- BLEhound 专有代码放在独立目录（`ui/qt/blehound/`、`resources/icons/blehound/`、
  `libblehound/`），这样往后 rebase 到新的 4.6.x 版本代价很小。

## 在 macOS（Apple Silicon）上构建

```bash
./tools/macos-setup-brew.sh --install-required --install-optional
brew install ccache
mkdir build && cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
      -DCMAKE_PREFIX_PATH="$(brew --prefix qt);$(brew --prefix libxml2)" ..
ninja
```

构建产物是 `build/run/Wireshark.app`。若要一个带正式名称、可直接运行的副本：

```bash
ditto build/run/Wireshark.app "dist/BLEhound Analyzer.app"
codesign --force --deep -s - "dist/BLEhound Analyzer.app"   # 临时签名，仅供本机测试
open "dist/BLEhound Analyzer.app"
```

这个开发用 bundle 仍然链接到构建树里的库；自包含、已签名并经公证的 DMG 由发布打包流程生成。

## 在 Windows（x64）上构建

需要 Visual Studio 2022（MSVC、CMake、Ninja）、Windows 10/11 SDK、Python 3、NSIS 和
win_flex_bison（`winget install NSIS.NSIS WinFlexBison.win_flex_bison`），以及带
SerialPort 模块的 Qt 6，例如用 aqtinstall 安装：

```powershell
pip install aqtinstall
aqt install-qt --outputdir C:\Qt windows desktop 6.10.3 win64_msvc2022_64 --modules qt5compat qtmultimedia qtserialport
```

然后在 "x64 Native Tools" 命令提示符里：

```powershell
$env:WIRESHARK_BASE_DIR = "C:\Development"      # CMake 会把第三方库下载到这里
$env:CMAKE_PREFIX_PATH  = "C:\Qt\6.10.3\msvc2022_64"
mkdir build; cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln
msbuild /m /p:Configuration=RelWithDebInfo wireshark_nsis_prep.vcxproj
msbuild    /p:Configuration=RelWithDebInfo wireshark_nsis.vcxproj
```

安装包生成在 `build\packaging\nsis\BLEhound-Analyzer-<版本>-x64.exe`。
只有当 `xsltproc` 在 PATH 中时才会打包用户手册（DocBook XSL 随自动下载的 asciidoctor
bundle 提供）；没有它时安装包照常生成，只是不含手册。
