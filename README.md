# restsend-vnc

一个面向 Windows 的无 GUI/托盘式 VNC 服务器，单文件、静态链接，开箱即用。
支持标准 VNC 客户端（TigerVNC / RealVNC / TightVNC / UltraVNC）与 macOS 内置「屏幕共享」。

## 功能

- 屏幕采集（Windows.Graphics.Capture）、多显示器、自适应分辨率
- 鼠标/键盘注入（含 Unicode、修饰键、滚轮、扩展键）
- 编码：Raw / Hextile / ZRLE（zlib-rs + SSSE3 + 调色板子编码）
- **标准剪贴板双向同步**（文本，ClientCutText / ServerCutText）
- **文件传输**（Tight 扩展：上传/下载/断点续传/建目录，沙箱在 `--share-dir`）
- **系统托盘 + 原生设置窗口**：端口、颜色档位、密码、标题、仅 loopback、保持唤醒、调试面板
- macOS 屏幕共享.app：RFB 003.889 + Apple DH（type 30）认证、视频/输入/锁屏提示
- 调试叠加层（时间/链路/帧率/吞吐/编码耗时/CPU/内存/版本），`Ctrl + 左键点 3 下`开关
- 单实例运行；锁屏时渲染提示而非冻结画面

## 下载与构建产物

GitHub Actions 在 **tag `v*`** 时自动构建并发布 Release：

| 文件 | 架构 |
|---|---|
| `restsend-vnc-win64.exe` | x86_64 |
| `restsend-vnc-win32.exe` | i686 |

默认构建为 Windows GUI 子系统（无控制台，日志写 `%APPDATA%\restsend-vnc\restsend-vnc.log`）。

## 快速开始

1. 运行 `restsend-vnc.exe`（托盘出现）
2. 右键托盘 → **Settings**：设置端口、密码、标题等，Save 后即时生效
3. 客户端连接：`vnc://<Windows-IP>:5900`

首次运行如遇防火墙提示请允许；或放行端口：

```powershell
New-NetFirewallRule -DisplayName restsend-vnc -Direction Inbound -Protocol TCP -LocalPort 5900 -Action Allow
```

> 默认监听 `0.0.0.0`（所有网卡）。只想本机访问请勾选 **Only accept loopback connections**，
> 或命令行加 `--host 127.0.0.1`。

## 客户端选择

| 客户端 | 画面/输入 | 剪贴板 |
|---|---|---|
| TigerVNC / RealVNC / TightVNC / UltraVNC | ✅ | ✅（标准文本剪贴板） |
| macOS 内置「屏幕共享」 | ✅ | ⏳ 需要 ARD 私有加密通道（进行中） |

## 配置

- 配置文件：`%APPDATA%\restsend-vnc\settings.ini`（托盘设置保存于此）
- 命令行参数**仅对本次运行生效，不写入配置文件**，且优先于配置文件
- 常用参数：`--port`、`--password`、`--host`、`--color-level 8|16|24`、`--fps`、`--scale`、`--share-dir`、`--debug`

## 本地构建

```bash
# x86_64 Windows（mingw 交叉编译）
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

# 控制台调试版
cargo build --release --target x86_64-pc-windows-gnu --no-default-features
```

产物：`target/x86_64-pc-windows-gnu/release/restsend-vnc.exe`

## 说明

- 提权窗口（任务管理器/UAC）需要以管理员身份运行才能注入输入（Windows UIPI 限制）
- Apple 客户端只在 ARD 加密会话中允许共享剪贴板；标准客户端不受影响
- 密码明文保存在 `settings.ini`，注意文件权限

## License

MIT
