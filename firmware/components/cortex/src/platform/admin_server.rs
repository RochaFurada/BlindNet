use crate::ffi::admin_server;
use crate::platform::{esp_result, Result};

pub use crate::ffi::admin_server::AdminServerConfigRaw;

pub unsafe fn start(config: &AdminServerConfigRaw) -> Result {
    esp_result(unsafe { admin_server::admin_server_start(config) })
}

pub fn stop() -> Result {
    esp_result(unsafe { admin_server::admin_server_stop() })
}

pub fn is_running() -> bool {
    unsafe { admin_server::admin_server_is_running() }
}
