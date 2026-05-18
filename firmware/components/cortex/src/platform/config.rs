use crate::ffi::config_store;
use crate::platform::{esp_result, Result};

pub use config_store::ZoneguardConfigRaw;

pub fn init() -> Result {
    esp_result(unsafe { config_store::config_store_init() })
}

pub fn load(out_config: &mut ZoneguardConfigRaw) -> Result {
    esp_result(unsafe { config_store::config_store_load(out_config) })
}

pub fn save(config: &ZoneguardConfigRaw) -> Result {
    esp_result(unsafe { config_store::config_store_save(config) })
}

pub fn erase() -> Result {
    esp_result(unsafe { config_store::config_store_erase() })
}

pub fn set_defaults(config: &mut ZoneguardConfigRaw) {
    unsafe { config_store::config_store_set_defaults(config) };
}
