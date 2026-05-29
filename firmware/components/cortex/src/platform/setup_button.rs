use crate::ffi::setup_button;
use crate::platform::{esp_result, Result};

pub use crate::ffi::setup_button::{
    SetupButtonCb, SetupButtonConfigRaw, SETUP_BUTTON_DEFAULT_GPIO, SETUP_BUTTON_DEFAULT_HOLD_MS,
    SETUP_BUTTON_DEFAULT_POLL_MS,
};

pub unsafe fn start(config: Option<&SetupButtonConfigRaw>) -> Result {
    let ptr = match config {
        Some(config) => config as *const SetupButtonConfigRaw,
        None => core::ptr::null(),
    };
    esp_result(unsafe { setup_button::setup_button_start(ptr) })
}

pub fn stop() -> Result {
    esp_result(unsafe { setup_button::setup_button_stop() })
}

pub fn is_running() -> bool {
    unsafe { setup_button::setup_button_is_running() }
}
