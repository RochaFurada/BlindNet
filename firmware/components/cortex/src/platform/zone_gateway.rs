use crate::ffi::zone_gateway;
use crate::platform::{esp_result, Result};

pub use crate::ffi::zone_gateway::{
    ZoneGatewayConfigRaw, ZoneGatewayState, ZoneGatewayStatusRaw, ZONE_GATEWAY_STATE_ERROR,
    ZONE_GATEWAY_STATE_RUNNING, ZONE_GATEWAY_STATE_STOPPED, ZONE_GATEWAY_STATE_WAITING_UPLINK,
};

pub fn start(config: &ZoneGatewayConfigRaw) -> Result {
    esp_result(unsafe { zone_gateway::zone_gateway_start(config) })
}

pub fn start_and_wait(config: &ZoneGatewayConfigRaw, timeout_ms: u32, poll_ms: u32) -> Result {
    esp_result(unsafe { zone_gateway::zone_gateway_start_and_wait(config, timeout_ms, poll_ms) })
}

pub fn stop() -> Result {
    esp_result(unsafe { zone_gateway::zone_gateway_stop() })
}

pub fn status() -> ZoneGatewayStatusRaw {
    unsafe { zone_gateway::zone_gateway_get_status() }
}

pub fn is_running() -> bool {
    unsafe { zone_gateway::zone_gateway_is_running() }
}

pub fn is_napt_enabled() -> bool {
    unsafe { zone_gateway::zone_gateway_is_napt_enabled() }
}