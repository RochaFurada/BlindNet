use crate::ffi::admin_server;
use crate::platform::{esp_result, Result};

pub use crate::ffi::admin_server::{
    AdminServerConfigRaw, AdminServerMode, ADMIN_SERVER_MODE_BOOTSTRAP,
    ADMIN_SERVER_MODE_MAINTENANCE,
};

pub unsafe fn start(config: &AdminServerConfigRaw) -> Result {
    esp_result(unsafe { admin_server::admin_server_start(config) })
}

pub unsafe fn open_window(config: Option<&AdminServerConfigRaw>, timeout_ms: u32) -> Result {
    let ptr = match config {
        Some(config) => config as *const AdminServerConfigRaw,
        None => core::ptr::null(),
    };
    esp_result(unsafe { admin_server::admin_server_open_window(ptr, timeout_ms) })
}

pub fn stop() -> Result {
    esp_result(unsafe { admin_server::admin_server_stop() })
}

pub fn is_running() -> bool {
    unsafe { admin_server::admin_server_is_running() }
}

pub fn is_unlocked() -> bool {
    unsafe { admin_server::admin_server_is_unlocked() }
}

pub fn lock() {
    unsafe { admin_server::admin_server_lock() };
}
