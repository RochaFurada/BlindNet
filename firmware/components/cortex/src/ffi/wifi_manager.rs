use core::ffi::{c_char, c_void};

use crate::ffi::EspErr;

pub const WIFI_MANAGER_MAX_SSID_LEN: usize = 32;
pub const WIFI_MANAGER_MAX_PASSWORD_LEN: usize = 64;

pub type WifiManagerStaState = i32;

pub const WIFI_MANAGER_STA_DISCONNECTED: WifiManagerStaState = 0;
pub const WIFI_MANAGER_STA_CONNECTING: WifiManagerStaState = 1;
pub const WIFI_MANAGER_STA_CONNECTED: WifiManagerStaState = 2;
pub const WIFI_MANAGER_STA_GOT_IP: WifiManagerStaState = 3;

#[repr(C)]
pub struct WifiManagerConfigRaw {
    pub sta_ssid: [u8; WIFI_MANAGER_MAX_SSID_LEN],
    pub sta_password: [u8; WIFI_MANAGER_MAX_PASSWORD_LEN],
    pub ap_ssid: [u8; WIFI_MANAGER_MAX_SSID_LEN],
    pub ap_password: [u8; WIFI_MANAGER_MAX_PASSWORD_LEN],
    pub ap_channel: u8,
    pub ap_max_connections: u8,
    pub sta_max_retries: u8,
    pub ap_hidden: bool,
}

#[repr(C)]
pub struct WifiManagerStatusRaw {
    pub sta_state: WifiManagerStaState,
    pub sta_retry_count: u8,
    pub ap_connected_clients: u8,
}

pub type EspNetifRaw = c_void;

unsafe extern "C" {
    pub fn wifi_manager_start(config: *const WifiManagerConfigRaw) -> EspErr;
    pub fn wifi_manager_stop() -> EspErr;
    pub fn wifi_manager_switch_to_ap(
        ssid: *const c_char,
        password: *const c_char,
        max_connections: u8,
    ) -> EspErr;
    pub fn wifi_manager_restore_normal() -> EspErr;
    pub fn wifi_manager_is_sta_connected() -> bool;
    pub fn wifi_manager_has_ip() -> bool;
    pub fn wifi_manager_get_status() -> WifiManagerStatusRaw;
    pub fn wifi_manager_get_sta_netif() -> *mut EspNetifRaw;
    pub fn wifi_manager_get_ap_netif() -> *mut EspNetifRaw;
    pub fn wifi_manager_get_ap_ip(out_ip: *mut u32) -> EspErr;
}
