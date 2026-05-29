use core::ffi::{c_char, c_void};

use crate::ffi::EspErr;

pub const EVENT_BUS_QUEUE_LEN: usize = 32;

pub type ZgEventType = i32;

pub const ZG_EVENT_NONE: ZgEventType = 0;
pub const ZG_EVENT_DEVICE_JOINED: ZgEventType = 1;
pub const ZG_EVENT_DEVICE_LEFT: ZgEventType = 2;
pub const ZG_EVENT_DEVICE_QUARANTINED: ZgEventType = 3;
pub const ZG_EVENT_DEVICE_RELEASED: ZgEventType = 4;
pub const ZG_EVENT_FLOW_SEEN: ZgEventType = 5;
pub const ZG_EVENT_POLICY_DENY: ZgEventType = 6;
pub const ZG_EVENT_RATE_EXCEEDED: ZgEventType = 7;
pub const ZG_EVENT_DNS_QUERY: ZgEventType = 8;
pub const ZG_EVENT_DNS_BLOCKED: ZgEventType = 9;
pub const ZG_EVENT_SWARM_QUARANTINE_NOTICE: ZgEventType = 10;
pub const ZG_EVENT_SWARM_FLOW_EVENT: ZgEventType = 11;
pub const ZG_EVENT_GATEWAY_UP: ZgEventType = 12;
pub const ZG_EVENT_GATEWAY_DOWN: ZgEventType = 13;
pub const ZG_EVENT_CONFIG_UPDATED: ZgEventType = 14;
pub const ZG_EVENT_ERROR: ZgEventType = 15;
pub const ZG_EVENT_AP_CLIENT_JOINED: ZgEventType = 16;
pub const ZG_EVENT_AP_CLIENT_LEFT: ZgEventType = 17;

#[repr(C)]
pub struct ZgEventRaw {
    pub event_type: ZgEventType,
    pub ts_ms: u32,
    pub zone_id: u32,
    pub device_id: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub risk_score: u8,
    pub code: u32,
    pub reason: [c_char; 48],
}

pub type EventBusListener =
    Option<unsafe extern "C" fn(event: *const ZgEventRaw, ctx: *mut c_void)>;

unsafe extern "C" {
    pub fn event_bus_init() -> EspErr;
    pub fn event_bus_publish(event: *const ZgEventRaw) -> EspErr;
    pub fn event_bus_subscribe(cb: EventBusListener, ctx: *mut c_void) -> EspErr;
}
