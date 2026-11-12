//! Windows input injection via SendInput (keyboard + mouse + wheel).

#[cfg(target_os = "windows")]
pub mod windows;

/// Backend interface used by the session: keysyms in, platform events out.
pub enum InputBackend {
    /// No injection available (non-Windows host / test-pattern mode): drop everything.
    #[allow(dead_code)]
    Noop,
    #[cfg(target_os = "windows")]
    Win(windows::WinInput),
}

impl InputBackend {
    /// Builds the platform backend. `fb_width/height` is the framebuffer
    /// (capture) resolution used to scale client coordinates.
    pub fn for_platform(fb_width: u32, fb_height: u32) -> InputBackend {
        #[cfg(target_os = "windows")]
        {
            let _ = (fb_width, fb_height);
            InputBackend::Win(windows::WinInput::new())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (fb_width, fb_height);
            InputBackend::Noop
        }
    }

    pub fn key(&mut self, keysym: u32, down: bool) {
        match self {
            InputBackend::Noop => {
                let _ = (keysym, down);
            }
            #[cfg(target_os = "windows")]
            InputBackend::Win(b) => b.key(keysym, down),
        }
    }

    /// Full pointer state update: position + button mask (RFB bit order:
    /// 1=left, 2=middle, 4=right, 8=wheel up, 16=wheel down).
    pub fn pointer(&mut self, x: u16, y: u16, mask: u8) {
        match self {
            InputBackend::Noop => {
                let _ = (x, y, mask);
            }
            #[cfg(target_os = "windows")]
            InputBackend::Win(b) => b.pointer(x, y, mask),
        }
    }
}
