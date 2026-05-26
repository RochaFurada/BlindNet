use core::ffi::{c_char, c_void};

use crate::ffi::EspErr;

pub type AdminServerMode = i32;

pub const ADMIN_SERVER_MODE_BOOTSTRAP: AdminServerMode = 0;
pub const ADMIN_SERVER_MODE_MAINTENANCE: AdminServerMode = 1;

#[repr(C)]
pub struct AdminServerConfigRaw {
    pub setup_ap_ssid: *const c_char,
    pub setup_ap_password: *const c_char,
    pub mode: AdminServerMode,
    pub guardian_id: u32,
    pub zone_id: u32,
    pub on_window_closed: Option<unsafe extern "C" fn(ctx: *mut c_void)>,
    pub ctx: *mut c_void,
}

unsafe extern "C" {
    pub fn admin_server_start(config: *const AdminServerConfigRaw) -> EspErr;
    pub fn admin_server_open_window(config: *const AdminServerConfigRaw, timeout_ms: u32)
        -> EspErr;
    pub fn admin_server_stop() -> EspErr;
    pub fn admin_server_is_running() -> bool;
    pub fn admin_server_is_unlocked() -> bool;
    pub fn admin_server_lock();
}
