use core::ffi::{c_char, c_void};

use crate::ffi::EspErr;

pub const DEVICE_REGISTRY_MAX_DEVICES: usize = 32;
pub const DEVICE_REGISTRY_NAME_LEN: usize = 32;
pub const DEVICE_REGISTRY_PROFILE_LEN: usize = 24;

pub type DeviceState = i32;
pub const DEVICE_STATE_UNKNOWN: DeviceState = 0;
pub const DEVICE_STATE_TRUSTED: DeviceState = 1;
pub const DEVICE_STATE_SUSPICIOUS: DeviceState = 2;
pub const DEVICE_STATE_QUARANTINED: DeviceState = 3;
pub const DEVICE_STATE_BLOCKED: DeviceState = 4;

#[repr(C)]
pub struct DeviceRecordRaw {
    pub device_id: u32,
    pub mac: [u8; 6],
    pub ip: u32,
    pub zone_id: u32,
    pub state: DeviceState,
    pub risk_score: u8,
    pub first_seen_ms: u32,
    pub last_seen_ms: u32,
    pub name: [c_char; DEVICE_REGISTRY_NAME_LEN],
    pub profile: [c_char; DEVICE_REGISTRY_PROFILE_LEN],
}

#[repr(C)]
pub struct DeviceRegistryStatsRaw {
    pub capacity: u32,
    pub active_devices: u32,
    pub added: u64,
    pub updated: u64,
    pub removed: u64,
    pub lookups: u64,
    pub misses: u64,
}

pub type DeviceRegistryIterCb =
    Option<unsafe extern "C" fn(record: *const DeviceRecordRaw, ctx: *mut c_void)>;

unsafe extern "C" {
    pub fn device_registry_init(zone_id: u32) -> EspErr;
    pub fn device_registry_reset();
    pub fn device_registry_upsert_mac_ip(
        mac: *const u8,
        ip: u32,
        name: *const c_char,
        profile: *const c_char,
        out_record: *mut DeviceRecordRaw,
    ) -> EspErr;
    pub fn device_registry_find_by_ip(ip: u32, out_record: *mut DeviceRecordRaw) -> bool;
    pub fn device_registry_find_by_mac(mac: *const u8, out_record: *mut DeviceRecordRaw) -> bool;
    pub fn device_registry_find_by_id(device_id: u32, out_record: *mut DeviceRecordRaw) -> bool;
    pub fn device_registry_set_state_by_ip(ip: u32, state: DeviceState, risk_score: u8) -> bool;
    pub fn device_registry_set_state_by_id(
        device_id: u32,
        state: DeviceState,
        risk_score: u8,
    ) -> bool;
    pub fn device_registry_remove_by_ip(ip: u32) -> bool;
    pub fn device_registry_foreach(cb: DeviceRegistryIterCb, ctx: *mut c_void);
    pub fn device_registry_get_stats() -> DeviceRegistryStatsRaw;
    pub fn device_registry_make_id_from_mac(mac: *const u8) -> u32;
    pub fn device_state_to_string(state: DeviceState) -> *const c_char;
}
