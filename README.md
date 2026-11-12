# rvnc

一个无 GUI 的 Windows VNC 服务器 CLI。指定 host / port / password / view-only 即可启动，
用任意 VNC viewer（TightVNC、UltraVNC、TigerVNC、RealVNC……）连接。

```
rvnc --host 0.0.0.0 --port 5900 --password s3cret --keep-awake
```

## 功能

- **RFB 3.8 协议**（RFC 6143）：从零实现，含 3.3 / 3.7 客户端兼容
- **认证**：VNC DES challenge-response；`--no-auth` 可匿名（警告）
- **屏幕采集**：Windows.Graphics.Capture（`scap`），支持 Retina 式缩放、多显示器（`--display N`）
- **自适应分辨率**：显示器模式变化时自动重建采集流，并向支持 NewFBSize 的客户端推送尺寸变更
- **编码**：Raw / Hextile / ZRLE（zlib），按客户端能力自动选择，tile 级增量 diff + 合并
- **输入注入**：SendInput（键盘/鼠标/滚轮/Unicode 字符），支持修饰键组合
- **剪贴板同步**：双向（ClientCutText / ServerCutText），带回声抑制
- **文件传输**：TightVNC/UltraVNC 兼容扩展（消息类型 130-136 + Tight 安全类型协商），
  上传/下载/断点续传/建目录，路径沙箱锁定在 `--share-dir` 内
- **防休眠**：`--keep-awake`（`SetThreadExecutionState`，默认关闭）
- **测试模式**：`--test-pattern` 合成动画画面，无需任何权限，便于调试 viewer

## 用法

```
rvnc [OPTIONS]

  --host <HOST>          监听地址（默认 0.0.0.0，即所有网卡；勾选「仅 loopback」时强制 127.0.0.1）
  --port <PORT>          监听端口（默认 5900）
  --password <PASSWORD>  VNC 认证密码（协议仅使用前 8 字节）
                         回退顺序：--password > RVNC_PASSWORD 环境变量 > 交互输入
  --no-auth              匿名连接（会打印警告）
  --view-only            忽略所有客户端输入（键盘/鼠标/剪贴板/文件）
  --display <N>          显示器编号（默认 0）
  --fps <N>              最大帧率（默认 30）
  --color-level <N>      颜色深度：8(3-3-2) / 16(5-6-5) / 24(全彩，默认)
  --scale <0.25-1.0>     发送前缩放（0.5 = 四分之一像素，视频/慢链路效果最明显）
  --debug                启动时开启右下角统计叠加层（运行中也可用 Ctrl+左键点 3 下切换）
  --zrle-level <1-9>     ZRLE 的 zlib 级别（默认 3；越高越小越慢）
  --name <NAME>          viewer 显示的会话名（默认 rvnc）
  --share-dir <DIR>      启用文件传输并限定可访问目录
  --keep-awake           运行期间阻止系统休眠（默认关闭）
  --no-clipboard         禁用剪贴板同步
  --test-pattern         合成测试画面（不采集真实屏幕）
  -v / RUST_LOG          日志（默认 info）
```

### 示例

```powershell
# 局域网共享，带密码 + 防休眠 + 文件传输
rvnc --host 0.0.0.0 --password s3cret --share-dir C:\Users\me\Public --keep-awake

# 只读监视
rvnc --password s3cret --view-only

# 调试 viewer（合成画面，不碰真实桌面）
rvnc --test-pattern --port 5901 --no-auth
```

## 与 viewer 的兼容性

| 功能 | 需要 | 说明 |
|---|---|---|
| 画面 + 控制 | 任意 viewer | 至少协商到 Raw 编码 |
| **macOS 系统屏幕共享.app** | — | 完整支持：通告 RFB 003.889 + Apple Remote Desktop DH 认证（type 30）。连接时用户名随便填、密码填 `--password` 的值 |
| 文件传输 | Tight 安全类型 | TightVNC / UltraVNC viewer 会启用 FT 界面 |

Apple 3.889 方言的扩展消息均已按固定帧解析：type 9/10 为会话协商，type 16 为
**AES-128-ECB 加密的 16 字节消息块**（`[0x10][子类型][16B]`，会话密钥来自 DH 认证）。
type 16 中已解出并支持：

* 键盘：`ff | 按下/抬起 | keysym(BE u32)`
* 指针：`... | ff | 按键掩码 | x(u16) | y(u16)`（坐标为帧缓冲绝对坐标，1=左键、2=右键）

服务端还会向 Apple 客户端发送 **消息类型 20（AutoPasteboardInfo）** 明文通知
（`14 00 00 04 00 01 00 <cmd>`，cmd=2 表示「剪贴板可用」）。收到后客户端
「编辑 → Get Clipboard / Send Clipboard」菜单项即可用；宿主机剪贴板变化时会再次推送。

Apple 3.889 的**加密控制通道**（服务端→客户端）也已逆向并实现：

* 会话开始时先发一条明文伪 rect（encoding 1103），携带用 DH 密钥 AES-128-ECB
  包裹的新 key/IV；
* 之后每条控制消息为 `AES-128-CBC(BE16(len) || payload || 0 填充 || SHA1(BE32(seq)||前段))`，
  长度对齐到 16 字节；
* 该路径目前由环境变量 `RVNC_APPLE_EXTINIT` 控制，默认仍走明文。

**为什么默认走明文**：客户端是否启用共享剪贴板由
`-[SSSessionView supportsSharedPasteboard]` 决定，它等价于
`doesServerSupportFeature:5` → `RFBServerCommandSupported(ref, 35) && RFBServerCommandSupported(ref, 25)`。
该位图来自 ARD 扩展 ServerInit（`RFBServerInfo2`，46 字节头 + 机器名）。rvnc 已能构造它，
开启后客户端的 `autoClipboard` 会保持为 1（即特性判定通过），但客户端随后要求
**服务端→客户端整条帧流都走 AES-128-CBC 加密记录**（`EncryptOneMessage`，0x8000 分块），
收到明文帧会立即断开。

rvnc 已实现该加密帧流（`AppleStreamCipher`：CBC 连续链、0x8000 分块、
BE16 长度 + SHA1 尾、明文 encoding 1103 建立伪 rect），并把建立消息改到
客户端首次 SetEncodings 之后发送（与 AppleVNCServer 的发送时机一致）。
实测客户端会正常 SetEncodings，但收到第一份加密帧后仍会重置，说明建立伪 rect
的字段（seq/flags/客户端是否必须声明该 encoding）还需继续校准。
因此 `RVNC_APPLE_EXTINIT` 默认关闭，默认走稳定的明文模式。

客户端把每个连接的状态保存在 `~/Library/Preferences/com.apple.ScreenSharing.plist`
的 `connectionsStore.sessionMetadatas.*.sessionState.restorationAttributes.autoClipboard`，
服务器不支持时会自动清零；这也解释了「Get/Send Clipboard 可点但无数据」。

未识别的消息会被安全忽略，不再导致断线。

注意：VNC 协议在认证之后是明文传输（包括像素与剪贴板）。请只在可信网络内使用，
或通过 SSH 隧道：`ssh -L 5900:127.0.0.1:5900 host`。

## macOS「屏幕共享」连接

系统自带屏幕共享.app 不支持经典 VNC 密码认证（type 2）。rvnc 内置了 Apple 私有的
**Remote Desktop 认证（安全类型 30，DH 密钥交换）**，设置了密码后屏幕共享.app 可以直接带密码连接：
连接时会提示输入「用户名和密码」——**用户名随便填**（服务端忽略），密码填 `--password` 的值。

安全说明：Apple DH 认证只加密凭据交换，认证后的画面流仍是明文（与 neatvnc 行为一致），
仅建议可信网络使用。

## 开发

```
cargo test                    # 协议单元测试（任意平台可跑）
cargo check --target x86_64-pc-windows-msvc   # Windows 目标编译检查
```

代码结构：

```
src/
  main.rs config.rs      CLI 与配置解析
  server.rs session.rs   监听 + 每连接会话（读线程 + 写线程）
  framebuffer.rs diff.rs 共享帧缓冲 / tile 增量 diff
  encode/                Raw / Hextile / ZRLE 编码器
  rfb/                   协议核心：握手、认证、消息、像素格式、文件传输
  screen/                采集（Windows.Graphics.Capture / 测试图案）
  input/                 SendInput 注入 + keysym 映射表
  clipboard.rs awake.rs  剪贴板同步 / 防休眠
```

## 构建 Windows 可执行文件（免安装、无第三方 DLL）

`.cargo/config.toml` 已为两个 Windows target 开启 `+crt-static`（静态 CRT），
产物是**单个 .exe**，只依赖 Windows 系统自带组件，不需要安装
VC Redistributable，也不需要随附任何 .dll：

```
$ llvm-objdump -p rvnc.exe | grep -i "dll name"    # 依赖检查
KERNEL32.dll, user32.dll, ws2_32.dll, advapi32.dll, d3d11.dll,
bcryptprimitives.dll, combase.dll, api-ms-win-crt-*.dll, ...
```

以上全部是 Windows 10 1903+（WGC 系统要求）自带的系统组件。

### 方式一：从任意平台交叉构建（GNU 工具链）

macOS：`brew install mingw-w64`；Ubuntu：`apt install mingw-w64`；Windows 无需交叉。

```
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
# 产物: target/x86_64-pc-windows-gnu/release/rvnc.exe
```

### 方式二：MSVC ABI 交叉构建（cargo-xwin）

需要 llvm（提供 clang-cl / lld-link）：

```
brew install llvm lld          # apt install clang lld
cargo install cargo-xwin
cargo xwin build --release --target x86_64-pc-windows-msvc
# 首次运行会下载 Windows SDK（约几百 MB，之后有缓存）
# 产物: target/x86_64-pc-windows-msvc/release/rvnc.exe
```

### 方式三：GitHub Actions

仓库自带 `.github/workflows/build-windows.yml`：在 windows-latest 上用官方
MSVC 工具链构建（推 tag 或手动触发），同时有一个 Ubuntu 交叉构建任务作为
可移植性验证；产物在 Actions Artifacts 中下载。

### 构建要求说明

- 目标系统：Windows 10 1903+（Windows.Graphics.Capture 的最低要求）
- 依赖全部为纯 Rust 或 Win32 系统绑定：flate2 用 miniz_oxide（无 zlib.dll），
  加密用 RustCrypto（无 OpenSSL），剪贴板走 Win32 API



## Apple ARD 对照探针

`tools/ard_probe.py` 是一个最小 ARD 客户端：连到**真实 macOS 屏幕共享服务**，
完成 Apple DH 认证、解析扩展 ServerInit 与加密建立伪 rect，然后把
服务端→客户端加密流整段 CBC 解密并按记录导出。用于对照真实服务端的行为
（普通抓包无法解密，因为 DH 私钥只存在于两端）。

```bash
# 目标 Mac 需开启「系统设置 → 通用 → 共享 → 屏幕共享」
ARD_PASSWORD='该账号密码' python3 tools/ard_probe.py 192.168.3.221 5900 pi /tmp/ard_probe.out
```

输出会包含 `RFBServerInfo2`、`encryption setup: seq/key/iv`、以及每条解密记录
的前 24 字节；完整数据以 `TAG <hex>` 行写入 `OUTFILE`。

## Windows 上运行（3 步）

1. 把 `rvnc.exe` 拷到 Windows 机器（无需安装、无需任何 DLL，单文件）：

```powershell
# 在 Windows PowerShell / cmd 里
.
vnc.exe --host 0.0.0.0 --port 5900 --password s3cret --keep-awake
```

2. 首次运行如果 Windows 防火墙弹窗，选择「允许访问」；或用管理员 PowerShell 放行端口：

```powershell
New-NetFirewallRule -DisplayName rvnc -Direction Inbound -Protocol TCP -LocalPort 5900 -Action Allow
```

3. 从 Mac 用`屏幕共享.app`或任意 VNC viewer 连接：

```
vnc://<Windows-IP>:5900
```

注意：
- 必须在**已登录的交互式桌面**里运行（Windows 锁屏/无人登录时采集不到画面）；
- 默认监听 `0.0.0.0`（所有网卡）；要只允许本机访问，请在托盘 Settings 勾选
  「Only accept loopback connections」，或命令行加 `--host 127.0.0.1`；
- 想看画面但不想暴露真实桌面时用 `--test-pattern`；
- 文件传输需要 `--share-dir`，并用 TightVNC/UltraVNC（Tight 安全类型）连接。

## 交叉构建（macOS → Windows）

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
# 产物：target/x86_64-pc-windows-gnu/release/rvnc.exe
```

## 已知行为与调优

- **任务管理器/UAC 等提权窗口收不到输入**：这是 Windows UIPI 限制，任何普通权限进程都无法向提权窗口注入键鼠。
  解决：**以管理员身份运行 rvnc**（右键终端 → 以管理员身份运行，再启动 rvnc）。启动时若不是管理员，日志会给出警告。
- **锁屏提示**：Windows 会话锁定（或出现安全桌面）时，采集会停止。rvnc 会检测到并渲染一屏
  `WINDOWS SESSION LOCKED / PLEASE UNLOCK TO CONTINUE` 提示，而不是让 viewer 停在冻结画面；解锁后自动恢复。
  检测带**去抖**（连续两次锁定）并同时要求「采集确实停住」，因此屏保/切换桌面时不会反复闪提示。
- **滚轮**：Apple 客户端的滚轮是 subtype 1 + mask `0x08`/`0x10`（button 4/5），现已正确映射。
- **调试叠加层**：`--debug` 启动时开启；运行中按住 **Ctrl（或 Cmd）+ 左键点 3 下**可随时开关。
  右下角磨砂玻璃面板显示：本地时间、客户端地址、`CAP/PUSH FPS`、`TX KB/S`、`ENC MS`、
  `DROP`（丢帧）、进程 `CPU`/`MEM`，以及 `UP`（服务运行时长）与 `SES`（当前会话时长）。
  可据此判断瓶颈在采集、编码还是网络。
- **Mac 屏幕共享的修饰键**：客户端把 **Command 发成 Alt_L、Option 发成 Meta_L**。rvnc 对 Apple 客户端做了
  映射：**Command → Ctrl，Option → Alt**，所以 Cmd+C = Ctrl+C。真实 Control 键保持 Control。
- **延迟/CPU 调优**：
  - 鼠标跟手优先：`--fps 60`（采集与推送上限一起提高）；
  - CPU 占用高：`--color-level 16`（5-6-5，ZRLE 压缩率更高、编码更省）或
    `--color-level 8`；也可配 `RVNC_ZRLE_LEVEL=2`（1–9，默认 6，越低越快、体积越大）；
  - 网络带宽小：`--color-level 16` + 默认压缩等级或 `--fps 20`；
  - **不动分辨率降低带宽**（test-pattern 实测 10 秒发送量）：
    `--color-level 24` ≈ 13.5 MB，`16` ≈ 4.8 MB，`8` ≈ 0.97 MB；
  - 单次更新上限 1 MB、单矩形原始数据上限 512 KB：拖动窗口/视频这类大区域变化
    会切成多条带分帧编码，避免单次 `ENC` 上百毫秒卡住；
  - 压缩后端改用 **zlib-rs**（纯 Rust，带 SIMD 优化；交叉编译无风险），
    并新增 `--zrle-level`（默认 3，1 最快 / 9 最小）；
  - 客户端/链路落后时（发送队列 >4）直接跳过编码，不再白白消耗 CPU 生成发不出去的帧；
  - 内核发送缓冲提升到 1 MB（Wi-Fi/较高 RTT 下吞吐更好）；
  - 推送已改为「捕获到新帧立即推 + 队列满丢帧 + 静态画面不重复 diff + 不再整帧克隆」，
    不会因为客户端慢而阻塞采集，静止桌面几乎不占 CPU。

## 托盘 / 设置 / 单实例（Windows）

`rvnc.exe` 启动后常驻**系统托盘**（图标为深色圆角底 + 显示器，Heroicons 线性风格），右键菜单：

- **Settings…**：原生 Win32 设置窗口（已启用 **Common Controls v6 视觉样式** +
  Segoe UI 字体 + Per-Monitor V2 DPI，呈现现代 Windows 11 风格，而非 Win2000 外观）
  - 端口（Port）
  - 颜色深度 24 / 16 / 8
  - 仅接受 loopback 连接
  - 保持系统唤醒（默认开）
  - 允许调试面板（关闭后 Ctrl+左键点 3 下不再生效）
  - **密码**（留空 = 无认证；VNC 认证只使用前 8 个字节）
  - 站点 URL（默认 `https://restsend.com`，托盘菜单可直接打开）
- **Disconnect all sessions**：立即断开所有已连接客户端
- **打开站点 URL**
- **About**：版本 + 构建时间
- **Exit**

设置持久化到 `%APPDATA%\rvnc\settings.ini`（密码为明文，注意文件权限）；
**命令行参数/环境变量优先于配置文件**；保存后新连接立即使用新密码。
端口/loopback 修改后监听器会**热重载**，无需重启进程。

**单实例**：进程启动时创建命名互斥量，重复启动会直接退出。

### 单一可执行文件（GUI）

默认构建即 **Windows GUI 子系统** 的 `rvnc.exe`：双击运行、无控制台、常驻托盘，
日志写入 `%APPDATA%\rvnc\rvnc.log`。仍可带命令行参数运行（`--password`、`--port` 等）。

需要控制台版时（调试/服务器场景）：

```bash
cargo build --release --target x86_64-pc-windows-gnu --no-default-features
```

未提供密码时 GUI 版会以**无认证**方式运行并写日志警告
（建议用 `RVNC_PASSWORD` 环境变量、命令行 `--password`，或托盘 Settings 里设置密码）。

### 调试面板版本信息

`--debug` 或 Ctrl+左键点 3 下后，右下角磨砂面板额外显示：

```
SRV 0.1.0 2026-11-12 12:14
CLI RFB 3.889 APPLE-DH
UP 00:12:34  SES 00:03:21
```

（服务端版本/构建时间 + 客户端协议与认证方式 + 运行时长/会话时长）
