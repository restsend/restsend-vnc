//! Screen capture backends.

pub mod dummy;
pub mod font;
pub mod overlay;

#[cfg(target_os = "windows")]
pub mod desktop;
#[cfg(target_os = "windows")]
pub mod locked;

use std::io;
use std::thread::JoinHandle;

use crate::framebuffer::ScreenState;

/// What to capture.
#[derive(Debug, Clone, Copy)]
pub enum ScreenKind {
    /// Synthetic animated test pattern (no permissions needed).
    Dummy,
    /// The real desktop via Windows.Graphics.Capture.
    Desktop,
}

/// Spawns the capture thread publishing frames into `state`.
pub fn spawn(
    kind: ScreenKind,
    display_index: usize,
    fps: u32,
    state: std::sync::Arc<ScreenState>,
) -> io::Result<JoinHandle<()>> {
    match kind {
        ScreenKind::Dummy => Ok(dummy::spawn(fps.max(1), state)),
        ScreenKind::Desktop => {
            #[cfg(target_os = "windows")]
            {
                // Watchdog: draw a lock notice while the workstation is locked.
                let _ = locked::spawn(std::sync::Arc::clone(&state));
                return desktop::spawn(display_index, fps.max(1), state);
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = (display_index, state);
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "desktop capture requires Windows; use --test-pattern on this host",
                ))
            }
        }
    }
}
