//! Windows input injection via SendInput (keyboard + mouse + wheel).

use crate::rfb::keysym as ks;

use windows::Win32::UI::Input::KeyboardAndMouse::MOUSE_EVENT_FLAGS;

pub struct WinInput {
    last_x: u16,
    last_y: u16,
    last_mask: u8,
    screen_w: i32,
    screen_h: i32,
}

impl WinInput {
    pub fn new() -> Self {
        enable_dpi_awareness();
        use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};
        let (w, h) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
        WinInput {
            last_x: 0,
            last_y: 0,
            last_mask: 0,
            screen_w: w.max(1),
            screen_h: h.max(1),
        }
    }

    pub fn key(&mut self, keysym: u32, down: bool) {
        if keysym == 0 {
            return;
        }

        // Direct Unicode keysyms: inject via KEYEVENTF_UNICODE (layout-safe).
        if let Some(ch) = ks::unicode_codepoint(keysym) {
            send_unicode(ch, down);
            return;
        }

        let Some(vk) = keysym_vk(keysym) else {
            tracing::debug!(keysym = format!("{keysym:#x}"), "no Windows VK mapping");
            return;
        };
        send_vk(vk, down);
    }

    pub fn pointer(&mut self, x: u16, y: u16, mask: u8) {
        let buttons_changed = mask != self.last_mask;
        let position_changed = x != self.last_x || y != self.last_y;

        if position_changed {
            let norm_x = ((x as i64 * 65535) / (self.screen_w.max(2) as i64 - 1)) as i32;
            let norm_y = ((y as i64 * 65535) / (self.screen_h.max(2) as i64 - 1)) as i32;
            send_mouse_move(norm_x, norm_y);
        }

        if buttons_changed {
            use windows::Win32::UI::Input::KeyboardAndMouse::{
                MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
                MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
            };
            // Buttons: left/middle/right press/release on transitions.
            const BUTTONS: [(u8, MOUSE_EVENT_FLAGS, MOUSE_EVENT_FLAGS); 3] = [
                (0x1, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
                (0x2, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
                (0x4, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
            ];
            for (bit, down_flag, up_flag) in BUTTONS {
                let pressed_now = mask & bit != 0;
                let pressed_before = self.last_mask & bit != 0;
                if pressed_now != pressed_before {
                    send_mouse_flag(if pressed_now { down_flag } else { up_flag });
                }
            }
            // Wheel on rising edge.
            const WHEEL_DELTA: i32 = 120;
            const WHEEL: [(u8, i32); 2] = [(0x8, 1), (0x10, -1)];
            for (bit, dir) in WHEEL {
                if (mask & bit) != 0 && (self.last_mask & bit) == 0 {
                    send_wheel(
                        windows::Win32::UI::Input::KeyboardAndMouse::MOUSEEVENTF_WHEEL,
                        dir * WHEEL_DELTA,
                    );
                }
            }
        }

        self.last_x = x;
        self.last_y = y;
        self.last_mask = mask;
    }
}

pub fn enable_dpi_awareness() {
    use windows::Win32::UI::HiDpi::{
        SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
    };
    unsafe {
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
}

// --- keyboard ---------------------------------------------------------------

fn send_vk(vk: u16, down: bool) {
    use windows::Win32::Foundation::LPARAM;
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
        KEYEVENTF_KEYUP,
    };
    // Navigation/right-hand keys must carry the extended-key flag or some
    // apps read them as the numpad equivalents.
    const EXTENDED: &[u16] = &[
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2C, 0x2D, 0x2E, 0x5B, 0x5C, 0x5D, 0x6F,
        0x90, 0xA3, 0xA5,
    ];
    let mut flags = if down {
        Default::default()
    } else {
        KEYEVENTF_KEYUP
    };
    if EXTENDED.contains(&vk) {
        flags |= KEYEVENTF_EXTENDEDKEY;
    }
    let input = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: windows::Win32::UI::Input::KeyboardAndMouse::VIRTUAL_KEY(vk),
                wScan: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: usize::default(),
            },
        },
    };
    unsafe {
        SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
    }
    let _ = LPARAM::default;
}

fn send_unicode(ch: char, down: bool) {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
    };
    let mut units = [0u16; 2];
    let len = ch.len_utf16();
    ch.encode_utf16(&mut units);
    for unit in units.iter().take(len) {
        let flags = KEYEVENTF_UNICODE
            | if down {
                Default::default()
            } else {
                KEYEVENTF_KEYUP
            };
        let input = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: Default::default(),
                    wScan: *unit,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: usize::default(),
                },
            },
        };
        unsafe {
            SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
        }
    }
}

/// keysym -> Windows virtual-key code.
pub fn keysym_vk(keysym: u32) -> Option<u16> {
    use crate::rfb::keysym as ks;
    // Printable ASCII: letters map to their uppercase VK, punctuation to OEM VKs.
    if (0x20..=0x7E).contains(&keysym) {
        let ch = keysym as u8 as char;
        return ascii_vk(ch);
    }
    Some(match keysym {
        ks::BACKSPACE => 0x08,
        ks::TAB => 0x09,
        ks::RETURN => 0x0D,
        ks::ESCAPE => 0x1B,
        ks::PRIOR => 0x21,
        ks::NEXT => 0x22,
        ks::END => 0x23,
        ks::HOME => 0x24,
        ks::LEFT => 0x25,
        ks::UP => 0x26,
        ks::RIGHT => 0x27,
        ks::DOWN => 0x28,
        ks::PRINT => 0x2C,
        ks::INSERT => 0x2D,
        ks::DELETE => 0x2E,
        ks::PAUSE => 0x13,
        ks::SCROLL_LOCK => 0x91,
        ks::NUM_LOCK => 0x90,
        ks::CAPS_LOCK => 0x14,
        ks::MENU => 0x5D, // VK_APPS
        ks::SUPER_L | ks::META_L => 0x5B,
        ks::SUPER_R | ks::META_R => 0x5C,
        ks::SHIFT_L => 0xA0,
        ks::SHIFT_R => 0xA1,
        ks::CONTROL_L => 0xA2,
        ks::CONTROL_R => 0xA3,
        ks::ALT_L => 0xA4,
        ks::ALT_R => 0xA5,
        k if (0xFFBE..=0xFFC9).contains(&k) => 0x70 + (k - 0xFFBE) as u16, // F1..F12
        k if (0xFFCA..=0xFFE0).contains(&k) => 0x70 + 12 + (k - 0xFFCA) as u16, // F13..F24
        // Keypad
        ks::KP_MULTIPLY => 0x6A,
        ks::KP_ADD => 0x6B,
        ks::KP_SUBTRACT => 0x6D,
        ks::KP_DECIMAL => 0x6E,
        ks::KP_DIVIDE => 0x6F,
        ks::KP_ENTER => 0x0D,
        k if (0xFFB0..=0xFFB9).contains(&k) => 0x60 + (k - 0xFFB0) as u16,
        _ => return None,
    })
}

fn ascii_vk(ch: char) -> Option<u16> {
    Some(match ch {
        'a'..='z' | 'A'..='Z' => ch.to_ascii_uppercase() as u16, // VK codes == 'A'..='Z'
        '0'..='9' => ch as u16,                                  // VK codes == '0'..='9'
        ' ' => 0x20,
        ';' => 0xBA,
        '=' => 0xBB,
        ',' => 0xBC,
        '-' => 0xBD,
        '.' => 0xBE,
        '/' => 0xBF,
        '`' => 0xC0,
        '[' => 0xDB,
        '\\' => 0xDC,
        ']' => 0xDD,
        '\'' => 0xDE,
        _ => return None,
    })
}

// --- mouse ------------------------------------------------------------------

fn send_mouse_move(norm_x: i32, norm_y: i32) {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_MOUSE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_MOVE, MOUSEINPUT,
    };
    let input = INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                dx: norm_x,
                dy: norm_y,
                mouseData: 0,
                time: 0,
                dwExtraInfo: usize::default(),
            },
        },
    };
    unsafe {
        SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
    }
}

fn send_mouse_flag(flag: MOUSE_EVENT_FLAGS) {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_MOUSE, MOUSEINPUT,
    };
    let input = INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dwFlags: flag,
                dx: 0,
                dy: 0,
                mouseData: 0,
                time: 0,
                dwExtraInfo: usize::default(),
            },
        },
    };
    unsafe {
        SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
    }
}

fn send_wheel(flag: windows::Win32::UI::Input::KeyboardAndMouse::MOUSE_EVENT_FLAGS, delta: i32) {
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_MOUSE, MOUSEINPUT,
    };
    let input = INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dwFlags: flag,
                dx: 0,
                dy: 0,
                mouseData: delta as u32,
                time: 0,
                dwExtraInfo: usize::default(),
            },
        },
    };
    unsafe {
        SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keysym_vk_basics() {
        assert_eq!(keysym_vk(0x63), Some(0x43)); // 'c' -> VK_C
        assert_eq!(keysym_vk(ks::RETURN), Some(0x0D));
        assert_eq!(keysym_vk(ks::SHIFT_L), Some(0xA0));
        assert_eq!(keysym_vk(ks::F1), Some(0x70));
        assert_eq!(keysym_vk(ks::KP_ADD), Some(0x6B));
        assert_eq!(keysym_vk(ks::SUPER_L), Some(0x5B));
    }
}
