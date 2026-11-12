# restsend-vnc

A single-file, statically linked VNC server for Windows with a tray GUI.
Works with standard VNC viewers and with macOS built-in Screen Sharing.

## Features

- Windows.Graphics.Capture screen capture, multi-display, automatic resolution changes
- Mouse/keyboard injection (Unicode, modifiers, wheel, extended keys)
- Encodings: Raw / Hextile / ZRLE (zlib-rs + SSSE3 + packed palette)
- Standard clipboard sync, both directions (text)
- File transfer via Tight extensions (upload/download/resume/mkdir, sandboxed to `--share-dir`)
- Tray icon + native settings window: port, colour level, password, title, loopback-only, keep-awake, debug panel
- macOS Screen Sharing: RFB 003.889 + Apple DH (type 30) auth, video/input, lock-screen notice
- Debug overlay (fps, throughput, encode time, CPU, memory, versions) — toggle with `Ctrl + 3 left clicks`
- Session audit log (client version, connect time, disconnect reason, duration)
- Single instance; renders a notice while the Windows session is locked

## Download

GitHub Actions builds and publishes on tags `v*`:

| File | Arch |
|---|---|
| `restsend-vnc-win64.exe` | x86_64 |
| `restsend-vnc-win32.exe` | i686 |

The default build is a Windows GUI subsystem binary (no console).
Logs: `%APPDATA%\restsend-vnc\restsend-vnc.log`.
Session audit: `%APPDATA%\restsend-vnc\sessions.log`.

## Quick start

1. Run `restsend-vnc.exe` (tray icon appears)
2. Tray → **Settings**: port, password, title, etc. Save applies immediately
3. Connect: `vnc://<windows-ip>:5900`

Allow the firewall if prompted, or:

```powershell
New-NetFirewallRule -DisplayName restsend-vnc -Direction Inbound -Protocol TCP -LocalPort 5900 -Action Allow
```

Default listen address is `0.0.0.0`. Enable **Only accept loopback connections** (or `--host 127.0.0.1`) to restrict.

## Clients

| Client | Video/Input | Clipboard |
|---|---|---|
| TigerVNC / RealVNC / TightVNC / UltraVNC | ✅ | ✅ (standard text clipboard) |
| macOS built-in Screen Sharing | ✅ | ⏳ requires the ARD encrypted channel (in progress) |

## Configuration

- Config file: `%APPDATA%\restsend-vnc\settings.ini` (written by the tray)
- Command-line flags apply to the current run only, are never written to the config file, and override it
- Common flags: `--port`, `--password`, `--host`, `--color-level 8|16|24`, `--fps`, `--scale`, `--share-dir`, `--debug`

## Build

```bash
# x86_64 Windows (mingw cross build)
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

# console build for debugging
cargo build --release --target x86_64-pc-windows-gnu --no-default-features
```

Artifact: `target/x86_64-pc-windows-gnu/release/restsend-vnc.exe`

## Notes

- Elevated windows (Task Manager, UAC) require running as administrator (Windows UIPI)
- Apple clients only allow shared clipboard on encrypted ARD sessions
- The password is stored in plain text in `settings.ini`
- Default log level is `warn` (`-v` or `RUST_LOG` for more)

## License

MIT
