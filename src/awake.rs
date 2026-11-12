//! Keep-awake (`--keep-awake`, disabled by default): prevents Windows from
//! sleeping while rvnc is running via `SetThreadExecutionState`
//! (`ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED`).

#[cfg(target_os = "windows")]
pub fn enable() {
    use windows::Win32::System::Power::{
        SetThreadExecutionState, ES_CONTINUOUS, ES_DISPLAY_REQUIRED, ES_SYSTEM_REQUIRED,
        EXECUTION_STATE,
    };

    let _ = std::thread::Builder::new()
        .name("rvnc-keep-awake".into())
        .spawn(|| {
            // The execution state applies to this thread; it must stay alive.
            unsafe {
                let ret = SetThreadExecutionState(
                    ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED,
                );
                if ret == EXECUTION_STATE(0) {
                    tracing::warn!("SetThreadExecutionState failed; sleep prevention inactive");
                    return;
                }
            }
            tracing::info!("keep-awake enabled (system + display)");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        });
}

#[cfg(not(target_os = "windows"))]
pub fn enable() {
    tracing::warn!("keep-awake is only supported on Windows");
}
