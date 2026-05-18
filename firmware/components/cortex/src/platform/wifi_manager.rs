use crate::ffi::wifi_manager;
use crate::platform::{esp_result, Result};

pub use crate::ffi::wifi_manager::{
    EspNetifRaw, WifiManagerConfigRaw, WifiManagerStaState, WifiManagerStatusRaw,
    WIFI_MANAGER_MAX_PASSWORD_LEN, WIFI_MANAGER_MAX_SSID_LEN, WIFI_MANAGER_STA_CONNECTED,
    WIFI_MANAGER_STA_CONNECTING, WIFI_MANAGER_STA_DISCONNECTED, WIFI_MANAGER_STA_GOT_IP,
};

pub fn start(config: &WifiManagerConfigRaw) -> Result {
    esp_result(unsafe { wifi_manager::wifi_manager_start(config) })
}

pub fn stop() -> Result {
    esp_result(unsafe { wifi_manager::wifi_manager_stop() })
}

pub fn is_sta_connected() -> bool {
    unsafe { wifi_manager::wifi_manager_is_sta_connected() }
}

pub fn has_ip() -> bool {
    unsafe { wifi_manager::wifi_manager_has_ip() }
}

pub fn status() -> WifiManagerStatusRaw {
    unsafe { wifi_manager::wifi_manager_get_status() }
}

pub fn sta_netif() -> *mut EspNetifRaw {
    unsafe { wifi_manager::wifi_manager_get_sta_netif() }
}

pub fn ap_netif() -> *mut EspNetifRaw {
    unsafe { wifi_manager::wifi_manager_get_ap_netif() }
}

pub fn ap_ip() -> Result<u32> {
    let mut ip = 0u32;
    let err = unsafe { wifi_manager::wifi_manager_get_ap_ip(&mut ip) };
    if err == crate::ffi::ESP_OK {
        Ok(ip)
    } else {
        Err(err)
    }
}
