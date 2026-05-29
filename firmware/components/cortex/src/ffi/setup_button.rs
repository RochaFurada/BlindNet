use core::ffi::c_void;

use crate::ffi::EspErr;

pub const SETUP_BUTTON_DEFAULT_GPIO: i32 = 0;
pub const SETUP_BUTTON_DEFAULT_HOLD_MS: u32 = 5000;
pub const SETUP_BUTTON_DEFAULT_POLL_MS: u32 = 50;

pub type SetupButtonCb = Option<unsafe extern "C" fn(ctx: *mut c_void)>;

#[repr(C)]
pub struct SetupButtonConfigRaw {
    pub gpio_num: i32,
    pub active_low: bool,
    pub hold_ms: u32,
    pub poll_ms: u32,
    pub on_hold: SetupButtonCb,
    pub ctx: *mut c_void,
}

unsafe extern "C" {
    pub fn setup_button_start(config: *const SetupButtonConfigRaw) -> EspErr;
    pub fn setup_button_stop() -> EspErr;
    pub fn setup_button_is_running() -> bool;
}
