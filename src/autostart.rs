//! Per-user "start with Windows" helper (HKCU Run key).

#[cfg(target_os = "windows")]
pub fn set(enabled: bool) {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
        KEY_SET_VALUE, REG_SZ,
    };
    let path = wide("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    let name = wide("restsend-vnc");
    unsafe {
        let mut key = HKEY::default();
        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(path.as_ptr()),
            Some(0),
            KEY_SET_VALUE,
            &mut key,
        )
        .is_err()
        {
            return;
        }
        if enabled {
            let exe = std::env::current_exe().unwrap_or_default();
            let value = wide(&format!("\"{}\"", exe.display()));
            let bytes = std::slice::from_raw_parts(value.as_ptr() as *const u8, value.len() * 2);
            let _ = RegSetValueExW(key, PCWSTR(name.as_ptr()), Some(0), REG_SZ, Some(bytes));
        } else {
            let _ = RegDeleteValueW(key, PCWSTR(name.as_ptr()));
        }
        let _ = RegCloseKey(key);
    }
}

#[cfg(target_os = "windows")]
pub fn enabled() -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE,
    };
    let path = wide("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    let name = wide("restsend-vnc");
    unsafe {
        let mut key = HKEY::default();
        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(path.as_ptr()),
            Some(0),
            KEY_QUERY_VALUE,
            &mut key,
        )
        .is_err()
        {
            return false;
        }
        let mut kind = Default::default();
        let mut size = 0u32;
        let found = RegQueryValueExW(
            key,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        )
        .is_ok();
        let _ = RegCloseKey(key);
        found
    }
}

#[cfg(not(target_os = "windows"))]
pub fn set(_enabled: bool) {}

#[cfg(not(target_os = "windows"))]
pub fn enabled() -> bool {
    false
}

#[cfg(target_os = "windows")]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
