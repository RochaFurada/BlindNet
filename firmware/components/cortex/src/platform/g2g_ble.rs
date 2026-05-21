use core::ffi::c_void;
use core::ptr;

use crate::ffi::g2g_ble;
use crate::platform::{esp_result, Result};

pub use crate::ffi::g2g_ble::{
    G2gBleConfigRaw, G2gBleFragmentCb, G2gBleStatsRaw, G2G_BLE_FRAGMENT_MAX_LEN, G2G_BLE_MAX_PEERS,
    G2G_BLE_TX_QUEUE_LEN,
};

pub unsafe fn start(config: Option<&G2gBleConfigRaw>) -> Result {
    let ptr = config.map_or(ptr::null(), |config| config);
    esp_result(unsafe { g2g_ble::g2g_ble_start(ptr) })
}

pub fn stop() -> Result {
    esp_result(unsafe { g2g_ble::g2g_ble_stop() })
}

pub fn is_running() -> bool {
    unsafe { g2g_ble::g2g_ble_is_running() }
}

pub fn send_fragment(bytes: &[u8]) -> Result {
    esp_result(unsafe { g2g_ble::g2g_ble_send_fragment(bytes.as_ptr(), bytes.len()) })
}

pub fn stats() -> G2gBleStatsRaw {
    unsafe { g2g_ble::g2g_ble_get_stats() }
}

pub fn null_ctx() -> *mut c_void {
    ptr::null_mut()
}
