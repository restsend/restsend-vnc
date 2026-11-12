# restsend-vnc

A single-file, statically linked VNC server for Windows with a tray GUI.
Works with standard VNC viewers and with macOS built-in Screen Sharing.
一个单文件、静态链接的 Windows VNC 服务器（托盘 GUI），支持标准 VNC 客户端与 macOS 内置「屏幕共享」。

**English** | [中文](#中文)

---

## English

### Features

- Windows.Graphics.Capture screen capture, multi-display, automatic resolution changes
- Mouse/keyboard injection (Unicode, modifiers, wheel, extended keys)
- Encodings: Raw / Hextile / ZRLE (zlib-rs + SSSE3 + packed palette)
- Standard clipboard sync, both directions (text)
- File transfer via Tight extensions (upload/download/resume/mkdir, sandboxed to `--share-dir`)
- Tray icon + native settings window: port, colour level, password, title, loopback-only, keep-awake, debug panel
- macOS Screen Sharing: RFB 003.889 + Apple DH (type 30) auth, video/input, lock-screen notice
- Debug overlay (fps, throughput, encode time, CPU, memory, versions) — toggle with `Ctrl + 3 left clicks`
- Single instance; renders a notice while the Windows session is locked

### Download

GitHub Actions builds and publishes on tags `v*`:

| File | Arch |
|---|---|
| `restsend-vnc-win64.exe` | x86_64 |
| `restsend-vnc-win32.exe` | i686 |

The default build is a Windows GUI subsystem binary (no console).
Logs: `%APPDATA%\restsend-vnc\restsend-vnc.log`.

### Quick start

1. Run `restsend-vnc.exe` (tray icon appears)
2. Tray → **Settings**: port, password, title, etc. Save applies immediately
3. Connect: `vnc://<windows-ip>:5900`

Allow the firewall if prompted, or:

```powershell
New-NetFirewallRule -DisplayName restsend-vnc -Direction Inbound -Protocol TCP -LocalPort 5900 -Action Allow
```

Default listen address is `0.0.0.0`. Enable **Only accept loopback connections** (or `--host 127.0.0.1`) to restrict.

### Clients

| Client | Video/Input | Clipboard |
|---|---|---|
| TigerVNC / RealVNC / TightVNC / UltraVNC | ✅ | ✅ (standard text clipboard) |
| macOS built-in Screen Sharing | ✅ | ⏳ requires the ARD encrypted channel (in progress) |

### Configuration

- Config file: `%APPDATA%\restsend-vnc\settings.ini` (written by the tray)
- Command-line flags apply to the current run only, are never written to the config file, and override it
- Common flags: `--port`, `--password`, `--host`, `--color-level 8|16|24`, `--fps`, `--scale`, `--share-dir`, `--debug`

### Build

```bash
# x86_64 Windows (mingw cross build)
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

# console build for debugging
cargo build --release --target x86_64-pc-windows-gnu --no-default-features
```

Artifact: `target/x86_64-pc-windows-gnu/release/restsend-vnc.exe`

### Notes

- Elevated windows (Task Manager, UAC) require running as administrator (Windows UIPI)
- Apple clients only allow shared clipboard on encrypted ARD sessions
- The password is stored in plain text in `settings.ini`

### License

MIT

---

## 中文

### 功能

- Windows.Graphics.Capture 采集，多显示器，分辨率变化自动重建
- 鼠标/键盘注入（Unicode、修饰键、滚轮、扩展键）
- 编码：Raw / Hextile / ZRLE（zlib-rs + SSSE3 + 调色板子编码）
- 标准剪贴板双向同步（文本）
- Tight 扩展文件传输（上传/下载/断点续传/建目录，沙箱在 `--share-dir`）
- 托盘 + 原生设置窗口：端口、颜色档位、密码、标题、仅 loopback、保持唤醒、调试面板
- macOS 屏幕共享：RFB 003.889 + Apple DH（type 30）认证、画面/输入、锁屏提示
- 调试叠加层（帧率/吞吐/编码耗时/CPU/内存/版本），`Ctrl + 左键点 3 下`开关
- 单实例运行；Windows 锁屏时渲染提示而不是冻结画面

### 下载

GitHub Actions 在 tag `v*` 时自动构建并发布：

| 文件 | 架构 |
|---|---|
| `restsend-vnc-win64.exe` | x86_64 |
| `restsend-vnc-win32.exe` | i686 |

默认构建为 Windows GUI 子系统（无控制台）。
日志：`%APPDATA%\restsend-vnc\restsend-vnc.log`。

### 快速开始

1. 运行 `restsend-vnc.exe`（托盘出现）
2. 右键托盘 → **Settings**：设置端口、密码、标题等，Save 后即时生效
3. 客户端连接：`vnc://<Windows-IP>:5900`

首次运行如遇防火墙提示请允许，或：

```powershell
New-NetFirewallRule -DisplayName restsend-vnc -Direction Inbound -Protocol TCP -LocalPort 5900 -Action Allow
```

默认监听 `0.0.0.0`。只想本机访问请勾选 **Only accept loopback connections**（或 `--host 127.0.0.1`）。

### 客户端

| 客户端 | 画面/输入 | 剪贴板 |
|---|---|---|
| TigerVNC / RealVNC / TightVNC / UltraVNC | ✅ | ✅（标准文本剪贴板） |
| macOS 内置「屏幕共享」 | ✅ | ⏳ 需要 ARD 私有加密通道（进行中） |

### 配置

- 配置文件：`%APPDATA%\restsend-vnc\settings.ini`（托盘保存）
- 命令行参数**仅对本次运行生效、不写入配置文件**，且优先于配置文件
- 常用参数：`--port`、`--password`、`--host`、`--color-level 8|16|24`、`--fps`、`--scale`、`--share-dir`、`--debug`

### 构建

```bash
# x86_64 Windows（mingw 交叉编译）
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

# 控制台调试版
cargo build --release --target x86_64-pc-windows-gnu --no-default-features
```

产物：`target/x86_64-pc-windows-gnu/release/restsend-vnc.exe`

### 说明

- 提权窗口（任务管理器/UAC）需要以管理员身份运行才能注入输入（Windows UIPI 限制）
- Apple 客户端只在 ARD 加密会话中允许共享剪贴板
- 密码明文保存在 `settings.ini`，注意文件权限

### License

MIT
