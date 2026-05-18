use core::ffi::c_char;

use crate::ffi::EspErr;

#[repr(C)]
pub struct AdminServerConfigRaw {
    pub setup_ap_ssid: *const c_char,
    pub setup_ap_password: *const c_char,
}

unsafe extern "C" {
    pub fn admin_server_start(config: *const AdminServerConfigRaw) -> EspErr;
    pub fn admin_server_stop() -> EspErr;
    pub fn admin_server_is_running() -> bool;
}
