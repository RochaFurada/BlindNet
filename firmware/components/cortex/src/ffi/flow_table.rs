use core::ffi::c_void;

use crate::ffi::EspErr;

pub const FLOW_TABLE_MAX_ENTRIES: usize = 128;

pub type FlowProto = i32;
pub const FLOW_PROTO_UNKNOWN: FlowProto = 0;
pub const FLOW_PROTO_TCP: FlowProto = 6;
pub const FLOW_PROTO_UDP: FlowProto = 17;
pub const FLOW_PROTO_ICMP: FlowProto = 1;

pub type FlowDirection = i32;
pub const FLOW_DIRECTION_UNKNOWN: FlowDirection = 0;
pub const FLOW_DIRECTION_ZONE_TO_UPLINK: FlowDirection = 1;
pub const FLOW_DIRECTION_UPLINK_TO_ZONE: FlowDirection = 2;
pub const FLOW_DIRECTION_ZONE_TO_ZONE: FlowDirection = 3;

pub type FlowState = i32;
pub const FLOW_STATE_EMPTY: FlowState = 0;
pub const FLOW_STATE_ACTIVE: FlowState = 1;
pub const FLOW_STATE_QUARANTINED: FlowState = 2;
pub const FLOW_STATE_BLOCKED: FlowState = 3;
pub const FLOW_STATE_EXPIRED: FlowState = 4;

pub type FlowTouchResult = i32;
pub const FLOW_TOUCH_CREATED: FlowTouchResult = 0;
pub const FLOW_TOUCH_UPDATED: FlowTouchResult = 1;
pub const FLOW_TOUCH_EVICTED_OLD_ENTRY: FlowTouchResult = 2;
pub const FLOW_TOUCH_FAILED_TABLE_DISABLED: FlowTouchResult = 3;
pub const FLOW_TOUCH_FAILED_INVALID_ARG: FlowTouchResult = 4;

#[repr(C)]
pub struct FlowKeyRaw {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

#[repr(C)]
pub struct FlowEntryRaw {
    pub key: FlowKeyRaw,
    pub direction: FlowDirection,
    pub state: FlowState,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen_ms: u32,
    pub last_seen_ms: u32,
    pub last_policy_action: u32,
    pub flags: u32,
    pub risk_score: u8,
    pub reserved: [u8; 3],
}

#[repr(C)]
pub struct FlowTableConfigRaw {
    pub max_idle_ms: u32,
    pub hard_ttl_ms: u32,
    pub evict_lru_when_full: bool,
}

#[repr(C)]
pub struct FlowTableStatsRaw {
    pub capacity: u32,
    pub active_entries: u32,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub created_flows: u64,
    pub updated_flows: u64,
    pub evicted_flows: u64,
    pub expired_flows: u64,
    pub dropped_updates: u64,
}

pub type FlowTableIterCb =
    Option<unsafe extern "C" fn(entry: *const FlowEntryRaw, user_ctx: *mut c_void)>;

unsafe extern "C" {
    pub fn flow_table_init(config: *const FlowTableConfigRaw) -> EspErr;
    pub fn flow_table_reset();
    pub fn flow_table_touch(
        key: *const FlowKeyRaw,
        direction: FlowDirection,
        bytes: u32,
        out_entry: *mut FlowEntryRaw,
    ) -> FlowTouchResult;
    pub fn flow_table_find(key: *const FlowKeyRaw, out_entry: *mut FlowEntryRaw) -> bool;
    pub fn flow_table_set_state(key: *const FlowKeyRaw, state: FlowState) -> bool;
    pub fn flow_table_set_risk(key: *const FlowKeyRaw, risk_score: u8) -> bool;
    pub fn flow_table_set_policy_action(key: *const FlowKeyRaw, action: u32) -> bool;
    pub fn flow_table_expire_old() -> u32;
    pub fn flow_table_get_stats() -> FlowTableStatsRaw;
    pub fn flow_table_foreach(cb: FlowTableIterCb, user_ctx: *mut c_void);
    pub fn flow_table_hash_key(key: *const FlowKeyRaw) -> u32;
    pub fn flow_table_key_equals(a: *const FlowKeyRaw, b: *const FlowKeyRaw) -> bool;
}
