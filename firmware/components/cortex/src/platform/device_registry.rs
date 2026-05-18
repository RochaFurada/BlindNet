use core::ffi::{c_char, c_void};
use core::ptr;

use crate::ffi::device_registry;
use crate::platform::{esp_result, Result};

pub use crate::ffi::device_registry::{
    DeviceRecordRaw, DeviceRegistryIterCb, DeviceRegistryStatsRaw, DeviceState,
    DEVICE_REGISTRY_MAX_DEVICES, DEVICE_REGISTRY_NAME_LEN, DEVICE_REGISTRY_PROFILE_LEN,
    DEVICE_STATE_BLOCKED, DEVICE_STATE_QUARANTINED, DEVICE_STATE_SUSPICIOUS, DEVICE_STATE_TRUSTED,
    DEVICE_STATE_UNKNOWN,
};

pub fn init(zone_id: u32) -> Result {
    esp_result(unsafe { device_registry::device_registry_init(zone_id) })
}

pub fn reset() {
    unsafe { device_registry::device_registry_reset() };
}

pub unsafe fn upsert_mac_ip(
    mac: &[u8; 6],
    ip: u32,
    name: *const c_char,
    profile: *const c_char,
    out_record: Option<&mut DeviceRecordRaw>,
) -> Result {
    let out = out_record.map_or(ptr::null_mut(), |record| record);
    esp_result(unsafe {
        device_registry::device_registry_upsert_mac_ip(mac.as_ptr(), ip, name, profile, out)
    })
}

pub fn find_by_ip(ip: u32, out_record: &mut DeviceRecordRaw) -> bool {
    unsafe { device_registry::device_registry_find_by_ip(ip, out_record) }
}

pub fn find_by_mac(mac: &[u8; 6], out_record: &mut DeviceRecordRaw) -> bool {
    unsafe { device_registry::device_registry_find_by_mac(mac.as_ptr(), out_record) }
}

pub fn find_by_id(device_id: u32, out_record: &mut DeviceRecordRaw) -> bool {
    unsafe { device_registry::device_registry_find_by_id(device_id, out_record) }
}

pub fn set_state_by_ip(ip: u32, state: DeviceState, risk_score: u8) -> bool {
    unsafe { device_registry::device_registry_set_state_by_ip(ip, state, risk_score) }
}

pub fn set_state_by_id(device_id: u32, state: DeviceState, risk_score: u8) -> bool {
    unsafe { device_registry::device_registry_set_state_by_id(device_id, state, risk_score) }
}

pub fn remove_by_ip(ip: u32) -> bool {
    unsafe { device_registry::device_registry_remove_by_ip(ip) }
}

pub unsafe fn foreach(cb: DeviceRegistryIterCb, ctx: *mut c_void) {
    unsafe { device_registry::device_registry_foreach(cb, ctx) };
}

pub fn stats() -> DeviceRegistryStatsRaw {
    unsafe { device_registry::device_registry_get_stats() }
}

pub fn make_id_from_mac(mac: &[u8; 6]) -> u32 {
    unsafe { device_registry::device_registry_make_id_from_mac(mac.as_ptr()) }
}

pub fn state_to_string(state: DeviceState) -> *const c_char {
    unsafe { device_registry::device_state_to_string(state) }
}
