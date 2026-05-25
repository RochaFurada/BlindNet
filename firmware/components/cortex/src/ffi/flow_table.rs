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

