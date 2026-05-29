use core::ffi::{c_char, c_void};
use core::ptr;

use crate::ffi::quarantine_manager;
use crate::platform::flow_table::FlowKeyRaw;
use crate::platform::{esp_result, Result};

pub use crate::ffi::quarantine_manager::{
    QuarantineCheckResultRaw, QuarantineEntryRaw, QuarantineIterCb, QuarantineManagerConfigRaw,
    QuarantineManagerStatsRaw, QuarantineMode, QuarantineSource, QuarantineSubjectRaw,
    QuarantineSubjectType, QUARANTINE_MAX_ENTRIES, QUARANTINE_MODE_BLOCK_ALL,
    QUARANTINE_MODE_LOG_ONLY, QUARANTINE_MODE_RESTRICTED, QUARANTINE_REASON_LEN,
    QUARANTINE_SOURCE_LOCAL_POLICY, QUARANTINE_SOURCE_MANUAL, QUARANTINE_SOURCE_RATE_LIMIT,
    QUARANTINE_SOURCE_SWARM, QUARANTINE_SOURCE_UNKNOWN, QUARANTINE_SUBJECT_DEVICE_ID,
    QUARANTINE_SUBJECT_IP, QUARANTINE_SUBJECT_MAC, QUARANTINE_SUBJECT_NONE,
};

pub fn init(config: Option<&QuarantineManagerConfigRaw>) -> Result {
    let ptr = config.map_or(ptr::null(), |config| config);
    esp_result(unsafe { quarantine_manager::quarantine_manager_init(ptr) })
}

pub fn reset() {
    unsafe { quarantine_manager::quarantine_manager_reset() };
}

pub unsafe fn add(
    subject: &QuarantineSubjectRaw,
    mode: QuarantineMode,
    source: QuarantineSource,
    ttl_ms: u32,
    risk_score: u8,
    reason: *const c_char,
) -> Result {
    esp_result(unsafe {
        quarantine_manager::quarantine_manager_add(
            subject, mode, source, ttl_ms, risk_score, reason,
        )
    })
}

pub unsafe fn add_ip(
    ip: u32,
    mode: QuarantineMode,
    source: QuarantineSource,
    ttl_ms: u32,
    risk_score: u8,
    reason: *const c_char,
) -> Result {
    esp_result(unsafe {
        quarantine_manager::quarantine_manager_add_ip(ip, mode, source, ttl_ms, risk_score, reason)
    })
}

pub unsafe fn add_mac(
    mac: &[u8; 6],
    mode: QuarantineMode,
    source: QuarantineSource,
    ttl_ms: u32,
    risk_score: u8,
    reason: *const c_char,
) -> Result {
    esp_result(unsafe {
        quarantine_manager::quarantine_manager_add_mac(
            mac.as_ptr(),
            mode,
            source,
            ttl_ms,
            risk_score,
            reason,
        )
    })
}

pub unsafe fn add_device_id(
    device_id: u32,
    mode: QuarantineMode,
    source: QuarantineSource,
    ttl_ms: u32,
    risk_score: u8,
    reason: *const c_char,
) -> Result {
    esp_result(unsafe {
        quarantine_manager::quarantine_manager_add_device_id(
            device_id, mode, source, ttl_ms, risk_score, reason,
        )
    })
}

pub fn remove(subject: &QuarantineSubjectRaw) -> bool {
    unsafe { quarantine_manager::quarantine_manager_remove(subject) }
}

pub fn remove_ip(ip: u32) -> bool {
    unsafe { quarantine_manager::quarantine_manager_remove_ip(ip) }
}

pub fn check(subject: &QuarantineSubjectRaw, out_result: &mut QuarantineCheckResultRaw) -> bool {
    unsafe { quarantine_manager::quarantine_manager_check(subject, out_result) }
}

pub fn check_ip(ip: u32, out_result: &mut QuarantineCheckResultRaw) -> bool {
    unsafe { quarantine_manager::quarantine_manager_check_ip(ip, out_result) }
}

pub fn check_flow_src(key: &FlowKeyRaw, out_result: &mut QuarantineCheckResultRaw) -> bool {
    unsafe { quarantine_manager::quarantine_manager_check_flow_src(key, out_result) }
}

pub fn expire_old() -> u32 {
    unsafe { quarantine_manager::quarantine_manager_expire_old() }
}

pub fn stats() -> QuarantineManagerStatsRaw {
    unsafe { quarantine_manager::quarantine_manager_get_stats() }
}

pub unsafe fn foreach(cb: QuarantineIterCb, user_ctx: *mut c_void) {
    unsafe { quarantine_manager::quarantine_manager_foreach(cb, user_ctx) };
}

pub fn subject_from_ip(ip: u32) -> QuarantineSubjectRaw {
    unsafe { quarantine_manager::quarantine_subject_from_ip(ip) }
}

pub fn subject_from_mac(mac: &[u8; 6]) -> QuarantineSubjectRaw {
    unsafe { quarantine_manager::quarantine_subject_from_mac(mac.as_ptr()) }
}

pub fn subject_from_device_id(device_id: u32) -> QuarantineSubjectRaw {
    unsafe { quarantine_manager::quarantine_subject_from_device_id(device_id) }
}

pub fn mode_to_string(mode: QuarantineMode) -> *const c_char {
    unsafe { quarantine_manager::quarantine_mode_to_string(mode) }
}

pub fn source_to_string(source: QuarantineSource) -> *const c_char {
    unsafe { quarantine_manager::quarantine_source_to_string(source) }
}
