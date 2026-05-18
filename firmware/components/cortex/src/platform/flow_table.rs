use core::ffi::c_void;
use core::ptr;

use crate::ffi::flow_table;
use crate::platform::{esp_result, Result};

pub use crate::ffi::flow_table::{
    FlowDirection, FlowEntryRaw, FlowKeyRaw, FlowProto, FlowState, FlowTableConfigRaw,
    FlowTableIterCb, FlowTableStatsRaw, FlowTouchResult, FLOW_DIRECTION_UNKNOWN,
    FLOW_DIRECTION_UPLINK_TO_ZONE, FLOW_DIRECTION_ZONE_TO_UPLINK, FLOW_DIRECTION_ZONE_TO_ZONE,
    FLOW_PROTO_ICMP, FLOW_PROTO_TCP, FLOW_PROTO_UDP, FLOW_PROTO_UNKNOWN, FLOW_STATE_ACTIVE,
    FLOW_STATE_BLOCKED, FLOW_STATE_EMPTY, FLOW_STATE_EXPIRED, FLOW_STATE_QUARANTINED,
    FLOW_TABLE_MAX_ENTRIES, FLOW_TOUCH_CREATED, FLOW_TOUCH_EVICTED_OLD_ENTRY,
    FLOW_TOUCH_FAILED_INVALID_ARG, FLOW_TOUCH_FAILED_TABLE_DISABLED, FLOW_TOUCH_UPDATED,
};

pub fn init(config: Option<&FlowTableConfigRaw>) -> Result {
    let ptr = config.map_or(ptr::null(), |config| config);
    esp_result(unsafe { flow_table::flow_table_init(ptr) })
}

pub fn reset() {
    unsafe { flow_table::flow_table_reset() };
}

pub fn touch(
    key: &FlowKeyRaw,
    direction: FlowDirection,
    bytes: u32,
    out_entry: Option<&mut FlowEntryRaw>,
) -> FlowTouchResult {
    let out = out_entry.map_or(ptr::null_mut(), |entry| entry);
    unsafe { flow_table::flow_table_touch(key, direction, bytes, out) }
}

pub fn find(key: &FlowKeyRaw, out_entry: &mut FlowEntryRaw) -> bool {
    unsafe { flow_table::flow_table_find(key, out_entry) }
}

pub fn set_state(key: &FlowKeyRaw, state: FlowState) -> bool {
    unsafe { flow_table::flow_table_set_state(key, state) }
}

pub fn set_risk(key: &FlowKeyRaw, risk_score: u8) -> bool {
    unsafe { flow_table::flow_table_set_risk(key, risk_score) }
}

pub fn set_policy_action(key: &FlowKeyRaw, action: u32) -> bool {
    unsafe { flow_table::flow_table_set_policy_action(key, action) }
}

pub fn expire_old() -> u32 {
    unsafe { flow_table::flow_table_expire_old() }
}

pub fn stats() -> FlowTableStatsRaw {
    unsafe { flow_table::flow_table_get_stats() }
}

pub unsafe fn foreach(cb: FlowTableIterCb, user_ctx: *mut c_void) {
    unsafe { flow_table::flow_table_foreach(cb, user_ctx) };
}

pub fn hash_key(key: &FlowKeyRaw) -> u32 {
    unsafe { flow_table::flow_table_hash_key(key) }
}

pub fn key_equals(a: &FlowKeyRaw, b: &FlowKeyRaw) -> bool {
    unsafe { flow_table::flow_table_key_equals(a, b) }
}
