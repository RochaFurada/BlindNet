use core::ffi::c_char;

use crate::ffi::EspErr;

unsafe extern "C" {
    pub fn setup_ap_start(ssid: *const c_char, password: *const c_char) -> EspErr;
}
