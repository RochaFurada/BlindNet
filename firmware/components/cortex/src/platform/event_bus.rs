use core::ffi::c_void;

use crate::ffi::event_bus;
use crate::platform::{esp_result, Result};

pub use crate::ffi::event_bus::{
    EventBusListener, ZgEventRaw, ZgEventType, EVENT_BUS_QUEUE_LEN, ZG_EVENT_CONFIG_UPDATED,
    ZG_EVENT_DEVICE_JOINED, ZG_EVENT_DEVICE_LEFT, ZG_EVENT_DEVICE_QUARANTINED,
    ZG_EVENT_DEVICE_RELEASED, ZG_EVENT_DNS_BLOCKED, ZG_EVENT_DNS_QUERY, ZG_EVENT_ERROR,
    ZG_EVENT_FLOW_SEEN, ZG_EVENT_GATEWAY_DOWN, ZG_EVENT_GATEWAY_UP, ZG_EVENT_NONE,
    ZG_EVENT_POLICY_DENY, ZG_EVENT_RATE_EXCEEDED, ZG_EVENT_SWARM_FLOW_EVENT,
    ZG_EVENT_SWARM_QUARANTINE_NOTICE,
};

pub fn init() -> Result {
    esp_result(unsafe { event_bus::event_bus_init() })
}

pub fn publish(event: &ZgEventRaw) -> Result {
    esp_result(unsafe { event_bus::event_bus_publish(event) })
}

pub unsafe fn subscribe(cb: EventBusListener, ctx: *mut c_void) -> Result {
    esp_result(unsafe { event_bus::event_bus_subscribe(cb, ctx) })
}
