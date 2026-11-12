//! X11 keysym constants used by the RFB KeyEvent message and the
//! platform-specific keysym -> keycode mapping tables.

#![allow(dead_code)]

pub const BACKSPACE: u32 = 0xFF08;
pub const TAB: u32 = 0xFF09;
pub const RETURN: u32 = 0xFF0D;
pub const PAUSE: u32 = 0xFF13;
pub const SCROLL_LOCK: u32 = 0xFF14;
pub const ESCAPE: u32 = 0xFF1B;
pub const HOME: u32 = 0xFF50;
pub const LEFT: u32 = 0xFF51;
pub const UP: u32 = 0xFF52;
pub const RIGHT: u32 = 0xFF53;
pub const DOWN: u32 = 0xFF54;
pub const PRIOR: u32 = 0xFF55; // PageUp
pub const NEXT: u32 = 0xFF56; // PageDown
pub const END: u32 = 0xFF57;
pub const PRINT: u32 = 0xFF61;
pub const INSERT: u32 = 0xFF63;
pub const MENU: u32 = 0xFF67;
pub const BREAK: u32 = 0xFF6B;
pub const NUM_LOCK: u32 = 0xFF7F;
pub const CAPS_LOCK: u32 = 0xFFE5;
pub const SHIFT_L: u32 = 0xFFE1;
pub const SHIFT_R: u32 = 0xFFE2;
pub const CONTROL_L: u32 = 0xFFE3;
pub const CONTROL_R: u32 = 0xFFE4;
pub const META_L: u32 = 0xFFE7;
pub const META_R: u32 = 0xFFE8;
pub const ALT_L: u32 = 0xFFE9;
pub const ALT_R: u32 = 0xFFEA;
pub const SUPER_L: u32 = 0xFFEB;
pub const SUPER_R: u32 = 0xFFEC;
pub const DELETE: u32 = 0xFFFF;

pub const F1: u32 = 0xFFBE; // F1..F35 = 0xFFBE..0xFFE0
pub const F12: u32 = 0xFFC9;

pub const KP_SPACE: u32 = 0xFF80;
pub const KP_TAB: u32 = 0xFF89;
pub const KP_ENTER: u32 = 0xFF8D;
pub const KP_MULTIPLY: u32 = 0xFFAA;
pub const KP_ADD: u32 = 0xFFAB;
pub const KP_SUBTRACT: u32 = 0xFFAD;
pub const KP_DECIMAL: u32 = 0xFFAE;
pub const KP_DIVIDE: u32 = 0xFFAF;
pub const KP_0: u32 = 0xFFB0; // KP_0..KP_9 = 0xFFB0..0xFFB9

/// Keysyms above this value encode Unicode directly: keysym = 0x01000000 + codepoint.
pub const UNICODE_BASE: u32 = 0x0100_0000;

/// Returns the Unicode codepoint if this keysym is a direct Unicode encoding.
pub fn unicode_codepoint(keysym: u32) -> Option<char> {
    if keysym >= UNICODE_BASE {
        char::from_u32(keysym - UNICODE_BASE)
    } else {
        None
    }
}
