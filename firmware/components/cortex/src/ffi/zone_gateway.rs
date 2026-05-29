use crate::ffi::EspErr;

pub type ZoneGatewayState = i32;

pub const ZONE_GATEWAY_STATE_STOPPED: ZoneGatewayState = 0;
pub const ZONE_GATEWAY_STATE_WAITING_UPLINK: ZoneGatewayState = 1;
pub const ZONE_GATEWAY_STATE_RUNNING: ZoneGatewayState = 2;
pub const ZONE_GATEWAY_STATE_ERROR: ZoneGatewayState = 3;

#[repr(C)]
pub struct ZoneGatewayConfigRaw {
    pub wait_for_sta_ip: bool,
    pub wait_interval_ms: u32,
    pub uplink_timeout_ms: u32,
    pub set_sta_as_default: bool,
    pub auto_recover: bool,
}

#[repr(C)]
pub struct ZoneGatewayStatusRaw {
    pub state: ZoneGatewayState,
    pub napt_enabled: bool,
    pub sta_has_ip: bool,
    pub start_attempts: u32,
    pub last_error: u32,
}

unsafe extern "C" {
    pub fn zone_gateway_start(config: *const ZoneGatewayConfigRaw) -> EspErr;
    pub fn zone_gateway_start_and_wait(
        config: *const ZoneGatewayConfigRaw,
        timeout_ms: u32,
        poll_ms: u32,
    ) -> EspErr;
    pub fn zone_gateway_stop() -> EspErr;
    pub fn zone_gateway_get_status() -> ZoneGatewayStatusRaw;
    pub fn zone_gateway_is_running() -> bool;
    pub fn zone_gateway_is_napt_enabled() -> bool;
}
