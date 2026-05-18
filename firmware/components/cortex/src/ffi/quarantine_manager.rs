use core::ffi::{c_char, c_void};

use crate::ffi::flow_table::FlowKeyRaw;
use crate::ffi::EspErr;

pub const QUARANTINE_MAX_ENTRIES: usize = 64;
pub const QUARANTINE_REASON_LEN: usize = 48;

pub type QuarantineSubjectType = i32;
pub const QUARANTINE_SUBJECT_NONE: QuarantineSubjectType = 0;
pub const QUARANTINE_SUBJECT_IP: QuarantineSubjectType = 1;
pub const QUARANTINE_SUBJECT_MAC: QuarantineSubjectType = 2;
pub const QUARANTINE_SUBJECT_DEVICE_ID: QuarantineSubjectType = 3;

pub type QuarantineMode = i32;
pub const QUARANTINE_MODE_BLOCK_ALL: QuarantineMode = 0;
pub const QUARANTINE_MODE_RESTRICTED: QuarantineMode = 1;
pub const QUARANTINE_MODE_LOG_ONLY: QuarantineMode = 2;

pub type QuarantineSource = i32;
pub const QUARANTINE_SOURCE_LOCAL_POLICY: QuarantineSource = 0;
pub const QUARANTINE_SOURCE_RATE_LIMIT: QuarantineSource = 1;
pub const QUARANTINE_SOURCE_SWARM: QuarantineSource = 2;
pub const QUARANTINE_SOURCE_MANUAL: QuarantineSource = 3;
pub const QUARANTINE_SOURCE_UNKNOWN: QuarantineSource = 4;

#[repr(C)]
#[derive(Copy, Clone)]
pub union QuarantineSubjectIdRaw {
    pub ip: u32,
    pub mac: [u8; 6],
    pub device_id: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct QuarantineSubjectRaw {
    pub subject_type: QuarantineSubjectType,
    pub id: QuarantineSubjectIdRaw,
}

#[repr(C)]
pub struct QuarantineEntryRaw {
    pub subject: QuarantineSubjectRaw,
    pub mode: QuarantineMode,
    pub source: QuarantineSource,
    pub created_at_ms: u32,
    pub expires_at_ms: u32,
    pub last_hit_ms: u32,
    pub hit_count: u32,
    pub risk_score: u8,
    pub reason: [c_char; QUARANTINE_REASON_LEN],
}

#[repr(C)]
pub struct QuarantineManagerConfigRaw {
    pub default_ttl_ms: u32,
    pub evict_lru_when_full: bool,
}

#[repr(C)]
pub struct QuarantineCheckResultRaw {
    pub quarantined: bool,
    pub mode: QuarantineMode,
    pub source: QuarantineSource,
    pub expires_at_ms: u32,
    pub remaining_ms: u32,
    pub hit_count: u32,
    pub risk_score: u8,
    pub reason: [c_char; QUARANTINE_REASON_LEN],
}

#[repr(C)]
pub struct QuarantineManagerStatsRaw {
    pub capacity: u32,
    pub active_entries: u32,
    pub added: u64,
    pub refreshed: u64,
    pub removed: u64,
    pub expired: u64,
    pub hits: u64,
    pub misses: u64,
    pub evicted: u64,
    pub invalid_input: u64,
}

pub type QuarantineIterCb =
    Option<unsafe extern "C" fn(entry: *const QuarantineEntryRaw, user_ctx: *mut c_void)>;

unsafe extern "C" {
    pub fn quarantine_manager_init(config: *const QuarantineManagerConfigRaw) -> EspErr;
    pub fn quarantine_manager_reset();
    pub fn quarantine_manager_add(
        subject: *const QuarantineSubjectRaw,
        mode: QuarantineMode,
        source: QuarantineSource,
        ttl_ms: u32,
        risk_score: u8,
        reason: *const c_char,
    ) -> EspErr;
    pub fn quarantine_manager_add_ip(
        ip: u32,
        mode: QuarantineMode,
        source: QuarantineSource,
        ttl_ms: u32,
        risk_score: u8,
        reason: *const c_char,
    ) -> EspErr;
    pub fn quarantine_manager_add_mac(
        mac: *const u8,
        mode: QuarantineMode,
        source: QuarantineSource,
        ttl_ms: u32,
        risk_score: u8,
        reason: *const c_char,
    ) -> EspErr;
    pub fn quarantine_manager_add_device_id(
        device_id: u32,
        mode: QuarantineMode,
        source: QuarantineSource,
        ttl_ms: u32,
        risk_score: u8,
        reason: *const c_char,
    ) -> EspErr;
    pub fn quarantine_manager_remove(subject: *const QuarantineSubjectRaw) -> bool;
    pub fn quarantine_manager_remove_ip(ip: u32) -> bool;
    pub fn quarantine_manager_check(
        subject: *const QuarantineSubjectRaw,
        out_result: *mut QuarantineCheckResultRaw,
    ) -> bool;
    pub fn quarantine_manager_check_ip(ip: u32, out_result: *mut QuarantineCheckResultRaw) -> bool;
    pub fn quarantine_manager_check_flow_src(
        key: *const FlowKeyRaw,
        out_result: *mut QuarantineCheckResultRaw,
    ) -> bool;
    pub fn quarantine_manager_expire_old() -> u32;
    pub fn quarantine_manager_get_stats() -> QuarantineManagerStatsRaw;
    pub fn quarantine_manager_foreach(cb: QuarantineIterCb, user_ctx: *mut c_void);
    pub fn quarantine_subject_from_ip(ip: u32) -> QuarantineSubjectRaw;
    pub fn quarantine_subject_from_mac(mac: *const u8) -> QuarantineSubjectRaw;
    pub fn quarantine_subject_from_device_id(device_id: u32) -> QuarantineSubjectRaw;
    pub fn quarantine_mode_to_string(mode: QuarantineMode) -> *const c_char;
    pub fn quarantine_source_to_string(source: QuarantineSource) -> *const c_char;
}
