# restsend-vnc

A single-file, statically linked VNC server for Windows with a tray GUI.
Works with standard VNC viewers and with macOS built-in Screen Sharing.

## Features

- Windows.Graphics.Capture screen capture, multi-display, automatic resolution changes
- Mouse/keyboard injection (Unicode, modifiers, wheel, extended keys)
- Encodings: Raw / Hextile / ZRLE (zlib-rs + SSSE3 + packed palette)
- Standard clipboard sync, both directions (text)
- Rich ARD clipboard for macOS Screen Sharing (text), carried over the encrypted ARD control channel
- TLS via VeNCrypt (RFB security type 19, X509None/X509Vnc subtypes), self-signed certificate generated on first use; works with TigerVNC and other VeNCrypt viewers
- File transfer via Tight extensions (upload/download/resume/mkdir), off by default and sandboxed to the configured shared folder (defaults to your user directory)
- ARD file transfer for macOS Screen Sharing (`0x22`), off by default and sandboxed to the same folder: drag files into the session to upload them. Windows→Mac file paste is experimental (Screen Sharing's file-promise handling varies by version)
- Tray icon + native tabbed settings window (General / Security / Files): port, colour level, password, title, loopback-only, keep-awake, debug panel, shared folder, encryption
- Optional manual connection approval: every authenticated connection can require a local Accept/Reject click; no screen data is sent before approval, and unanswered requests are rejected after 30 seconds
- CIDR allow-list for incoming peers (Security tab or `--allow-cidrs`); empty means allow all, and a malformed list fails closed
- Persisted **View only** mode (General tab or `--view-only`): new sessions can watch but cannot send input, clipboard or file uploads
- macOS Screen Sharing: RFB 003.889 + Apple DH (type 30) auth, video/input, encrypted ARD control channel, shared clipboard and ARD file transfer, lock-screen notice
- Debug overlay (fps, throughput, encode time, CPU, memory, versions) — toggle with `Ctrl + 3 left clicks`
- Session audit log (client version, connect time, disconnect reason, duration, confirmation pending/accept/reject/timeout, ACL rejects)
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

| Client | Video/Input | Clipboard | Files | TLS |
|---|---|---|---|---|
| TigerVNC | ✅ | ✅ (standard text clipboard) | ❌ | ✅ VeNCrypt (accept the self-signed prompt) |
| RealVNC Viewer | ✅ | ✅ (standard text clipboard) | ❌ | ⚠️ depends on version; use auto mode |
| TightVNC / UltraVNC | ✅ | ✅ (standard text clipboard) | ✅ Tight extension | ❌ no VeNCrypt; use `--tls off` or auto mode |
| macOS built-in Screen Sharing | ✅ | ✅ text over the ARD control channel | ✅ drag & drop upload (ARD `0x22`); Windows→Mac paste experimental | ❌ not supported; use auto mode |

File transfer requires **Share files** to be enabled; both the Tight and ARD
paths are sandboxed to the same configured folder.

## Configuration

- Config file: `%APPDATA%\restsend-vnc\settings.ini` (written by the tray)
- Command-line flags apply to the current run only, are never written to the config file, and override it
- File transfer is **off by default**. Enable **Share files** in Settings and choose a shared folder (defaults to your user directory); new connections pick the change up immediately. `--share-dir <DIR>` enables it for the current run only. Tight-compatible viewers use the Tight extension; macOS Screen Sharing uses Apple's `0x22` file-copy channel (drag files into the session to upload them). Windows→Mac file paste is experimental: the host advertises copied files as `public.file-url` pasteboard items and serves them on request, but whether Screen Sharing asks for the bytes depends on the macOS version. Both paths resolve paths inside the same sandbox; ARD uploads ignore the viewer-proposed destination and land in the shared folder
- Connection confirmation is **off by default**. Enable **Ask before accepting incoming connections** on the Security tab (or pass `--confirm`) to require a local Accept click for each new connection. The prompt appears after authentication and before `ServerInit`; rejected, timed-out (30 s) or unattended requests are closed without sending any screen data. At most 4 requests are queued; further connections are refused. Use `--no-confirm` to override the persisted setting for one run
- The **Allowed networks (CIDR)** field on the Security tab restricts incoming peers. Entries are comma or space separated (`192.168.1.0/24, 10.0.0.0/8`); a bare address means a single host. Leave it empty to allow all. Loopback is **not** implicit, so add `127.0.0.1/32` if local viewers must connect. Invalid entries are rejected when saving; a hand-edited invalid list fails closed. The rule applies to new connections immediately (`--allow-cidrs LIST` overrides it for one run)
- **View only** on the General tab makes new sessions display-only: keyboard, mouse, clipboard and file uploads are disabled. `--view-only` forces it for one run and `--no-view-only` overrides a persisted `view_only=1`. Existing sessions keep the mode they were opened with
- Common flags: `--port`, `--password`, `--host`, `--allow-cidrs`, `--color-level 8|16|24`, `--fps`, `--scale`, `--share-dir`, `--debug`, `--tls`, `--confirm`, `--no-confirm`, `--view-only`, `--no-view-only`

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
plaintext fallback, so use `required` on untrusted networks. Tight file transfer
uses the TightVNC extension, which is only negotiated with the Tight security
type: in required TLS mode Tight file transfer is unavailable. The ARD file
channel used by macOS Screen Sharing is independent of VeNCrypt and remains
available in `auto` mode (it is never offered with `required`, because Screen
Sharing does not implement VeNCrypt).

VeNCrypt uses the X.509 sub-types (X509None/X509Vnc), so the viewer verifies
the server certificate and shows the usual self-signed prompt. The legacy
anonymous TLS sub-types (TLSNone/TLSVnc) are not offered because rustls does
not implement anonymous cipher suites.

## Build

```bash
# x86_64 Windows (mingw cross build)
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

# console build for debugging
cargo build --release --target x86_64-pc-windows-gnu --no-default-features
```

Artifact: `target/x86_64-pc-windows-gnu/release/restsend-vnc.exe`

Desktop capture uses `windows-capture 2.x` directly (no `scap` wrapper and no
vendored copy).

The release profile uses fat LTO and one codegen unit; the win64 build is
about 3.8 MB (down from 4.9 MB with thin LTO).

## Notes

- Elevated windows (Task Manager, UAC) require running as administrator (Windows UIPI)
- Punctuation and non-ASCII characters are injected as Unicode text (the exact character, regardless of host keyboard layout and without going through the host IME); letters, digits and space use virtual keys so shortcuts (Ctrl+C, Alt+Tab) keep working, and punctuation pressed together with Ctrl/Alt also keeps its virtual key so editor chords like Ctrl+/ still fire
- The capture session is recreated after lock/unlock and after sleep/hibernate resume, because Windows.Graphics.Capture resumes without its yellow screen-sharing border
- Apple/ARD clients (macOS Screen Sharing) use the server-composited pointer: the server hides the client's local pointer and draws/erases its own, because Screen Sharing's local cursor leaves old cursors behind during full-frame updates. Other viewers use the zero-traffic client-side Rich Cursor; `RESTSEND_VNC_CURSOR_SERVER=1` forces the composited overlay for them, and `RESTSEND_VNC_CURSOR_ALPHA=1` opts Apple clients into CursorAlpha (1104) for protocol testing
- Connection confirmation fails closed: a console build prompts on stdin, and rejects the connection when no terminal/UI is available
- Internal test hooks: `RESTSEND_VNC_APPROVAL=accept|reject|timeout`, `RESTSEND_VNC_APPROVAL_TIMEOUT_MS`, and `RESTSEND_VNC_ALLOW_MULTIPLE=1` (bypass the single-instance mutex) are used by the integration tests. `RESTSEND_VNC_CLIPBOARD_FILE=<path>` substitutes a file for the host clipboard (headless tests), `RESTSEND_VNC_APPLE_NO_EXT=1` disables the extended ARD ServerInit and `RESTSEND_VNC_APPLE_NO_ENC=1` keeps Apple frames plaintext for protocol diagnosis
- macOS Screen Sharing shares its pasteboard only over the encrypted ARD control channel: text works in both directions, and copied files are advertised as `public.file-url` items so the Mac can fetch them through the ARD file channel
- The debug overlay's `CLI` line ends in `[TLS]` or `[PLAIN]` so the live link's encryption is visible
- Windows pointer trails are disabled only while a capture session is active (and restored on stop), because some Windows builds composite the trail ghosts into the captured frame and they appear as dark dots behind fast pointer movement
- The password is stored in plain text in `settings.ini`
- Default log level is `warn` (`-v` or `RUST_LOG` for more)

## License

MIT
