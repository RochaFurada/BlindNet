use core::ffi::c_char;

use crate::ffi::setup_ap;
use crate::platform::{esp_result, Result};

pub unsafe fn start(ssid: *const c_char, password: *const c_char) -> Result {
    esp_result(unsafe { setup_ap::setup_ap_start(ssid, password) })
}
