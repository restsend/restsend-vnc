# restsend-vnc

A single-file, statically linked VNC server for Windows with a tray GUI.
Works with standard VNC viewers and with macOS built-in Screen Sharing.

## Features

- Windows.Graphics.Capture screen capture, multi-display, automatic resolution changes
- Mouse/keyboard injection (Unicode, modifiers, wheel, extended keys)
- Encodings: Raw / Hextile / ZRLE (zlib-rs + SSSE3 + packed palette)
- Standard clipboard sync, both directions (text)
- TLS via VeNCrypt (RFB security type 19), self-signed certificate generated on first use; works with TigerVNC and other VeNCrypt viewers
- File transfer via Tight extensions (upload/download/resume/mkdir), off by default and sandboxed to the configured shared folder (defaults to your user directory)
- Tray icon + native settings window: port, colour level, password, title, loopback-only, keep-awake, debug panel, shared folder
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

| Client | Video/Input | Clipboard | TLS |
|---|---|---|---|
| TigerVNC | ✅ | ✅ (standard text clipboard) | ✅ VeNCrypt (accept the self-signed prompt) |
| RealVNC Viewer | ✅ | ✅ (standard text clipboard) | ⚠️ depends on version; use auto mode |
| TightVNC / UltraVNC | ✅ | ✅ (standard text clipboard) | ❌ no VeNCrypt; use `--tls off` or auto mode |
| macOS built-in Screen Sharing | ✅ | ⏳ requires the ARD encrypted channel (in progress) | ❌ not supported; use auto mode |

## Configuration

- Config file: `%APPDATA%\restsend-vnc\settings.ini` (written by the tray)
- Command-line flags apply to the current run only, are never written to the config file, and override it
- File transfer is **off by default**. Enable **Share files** in Settings and choose a shared folder (defaults to your user directory); new connections pick the change up immediately. `--share-dir <DIR>` enables it for the current run only
- Common flags: `--port`, `--password`, `--host`, `--color-level 8|16|24`, `--fps`, `--scale`, `--share-dir`, `--debug`, `--tls`

## TLS / VeNCrypt

Encryption is enabled by default in **auto** mode: viewers that support VeNCrypt
negotiate TLS, while older viewers (TightVNC, UltraVNC, macOS Screen Sharing)
fall back to the legacy plaintext path. Modes:

```bash
restsend-vnc --tls auto        # default: prefer TLS, fall back
restsend-vnc --tls required    # reject clients that do not support VeNCrypt
restsend-vnc --tls off         # plaintext only
```

A self-signed ECDSA certificate is generated on first use and stored in
`%APPDATA%\restsend-vnc\tls\` (`server.crt` / `server.key`). Provide a real
certificate with:

```bash
restsend-vnc --tls required --tls-cert C:\cert\server.pem --tls-key C:\cert\server.key
```

The SHA-256 fingerprint is logged at startup and shown by the viewer's
certificate prompt; verify it once out of band. `--tls required` intentionally
rejects macOS Screen Sharing and clients without VeNCrypt. In `auto` mode an
attacker who can modify the network can strip the VeNCrypt offer and force the
plaintext fallback, so use `required` on untrusted networks. File transfer uses
the TightVNC extension, which is only negotiated with the Tight security type:
in required TLS mode file transfer is unavailable.

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
- The debug overlay's `CLI` line ends in `[TLS]` or `[PLAIN]` so the live link's encryption is visible
- The password is stored in plain text in `settings.ini`
- Default log level is `warn` (`-v` or `RUST_LOG` for more)

## License

MIT
