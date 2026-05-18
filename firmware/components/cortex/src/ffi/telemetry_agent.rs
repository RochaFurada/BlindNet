use core::ffi::c_char;

use crate::ffi::EspErr;

pub type TelemetryOutputFlags = i32;
pub const TELEMETRY_OUTPUT_NONE: TelemetryOutputFlags = 0;
pub const TELEMETRY_OUTPUT_SERIAL: TelemetryOutputFlags = 1 << 0;
pub const TELEMETRY_OUTPUT_UDP: TelemetryOutputFlags = 1 << 1;

#[repr(C)]
pub struct TelemetryAgentConfigRaw {
    pub zone_id: u32,
    pub guardian_id: u32,
    pub interval_ms: u32,
    pub outputs: u32,
    pub udp_host: *const c_char,
    pub udp_port: u16,
    pub send_on_start: bool,
}

#[repr(C)]
pub struct TelemetryAgentStatsRaw {
    pub snapshots_built: u64,
    pub serial_sent: u64,
    pub udp_sent: u64,
    pub udp_errors: u64,
    pub build_errors: u64,
}

unsafe extern "C" {
    pub fn telemetry_agent_start(config: *const TelemetryAgentConfigRaw) -> EspErr;
    pub fn telemetry_agent_stop() -> EspErr;
    pub fn telemetry_agent_is_running() -> bool;
    pub fn telemetry_agent_send_snapshot_now() -> EspErr;
    pub fn telemetry_agent_get_stats() -> TelemetryAgentStatsRaw;
}
