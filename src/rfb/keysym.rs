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

/// Returns the exact character a keysym stands for, for keysyms the platform
/// backend should inject as a character (e.g. `KEYEVENTF_UNICODE`) instead of
/// a virtual key:
///
/// * direct Unicode keysyms (`0x01000000 + codepoint`),
/// * Latin-1 keysyms `0xA0..=0xFF` (identity mapping to codepoints),
/// * printable ASCII punctuation — including shifted forms like `* ( { "` —
///   which have no virtual-key of their own (they need Shift on the host
///   layout) and are routed through the host IME if sent as virtual keys.
///
/// Letters, digits and space return `None` so they keep the virtual-key path
/// and modifier chords (Ctrl+C, Alt+1) keep working.
pub fn injection_char(keysym: u32) -> Option<char> {
    if let Some(ch) = unicode_codepoint(keysym) {
        return Some(ch);
    }
    if (0xA0..=0xFF).contains(&keysym) {
        return char::from_u32(keysym);
    }
    if (0x20..=0x7E).contains(&keysym) {
        let ch = keysym as u8 as char;
        if !ch.is_ascii_alphanumeric() && ch != ' ' {
            return Some(ch);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injection_char_covers_punctuation() {
        // Characters reported as untypable over RFB: "/" needs no shift but
        // must not go through the host IME, the rest have no VK at all.
        for ch in ['/', '"', '{', '*', '(', '!', '?', '<', '>', '|', ':', '~', '+', '_'] {
            assert_eq!(injection_char(ch as u32), Some(ch), "failed for {ch:?}");
        }
    }

    #[test]
    fn injection_char_keeps_vks_for_alphanumerics() {
        // Letters, digits and space stay on the virtual-key path so
        // modifier chords (Ctrl+C, Alt+1, Ctrl+Space) keep working.
        assert_eq!(injection_char(b'a' as u32), None);
        assert_eq!(injection_char(b'A' as u32), None);
        assert_eq!(injection_char(b'7' as u32), None);
        assert_eq!(injection_char(b' ' as u32), None);
        // Control keysyms are not characters.
        assert_eq!(injection_char(RETURN), None);
        assert_eq!(injection_char(SHIFT_L), None);
    }

    #[test]
    fn injection_char_covers_latin1_and_direct_unicode() {
        assert_eq!(injection_char(0xE9), Some('é')); // Latin-1 keysym
        assert_eq!(injection_char(0xFC), Some('ü'));
        assert_eq!(injection_char(0x0100_2026), Some('\u{2026}')); // direct Unicode keysym (…)
        assert_eq!(injection_char(0x0101_F600), Some('\u{1F600}')); // 😀
        // Raw codepoints below the 0x01000000 Unicode base are not valid
        // keysym encodings (0x2026 is not "…" on the wire).
        assert_eq!(injection_char(0x2026), None);
        assert_eq!(injection_char(0x3000), None);
    }
}
