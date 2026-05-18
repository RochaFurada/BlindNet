use core::ptr;

use crate::ffi::telemetry_agent;
use crate::platform::{esp_result, Result};

pub use crate::ffi::telemetry_agent::{
    TelemetryAgentConfigRaw, TelemetryAgentStatsRaw, TelemetryOutputFlags, TELEMETRY_OUTPUT_NONE,
    TELEMETRY_OUTPUT_SERIAL, TELEMETRY_OUTPUT_UDP,
};

pub unsafe fn start(config: Option<&TelemetryAgentConfigRaw>) -> Result {
    let ptr = config.map_or(ptr::null(), |config| config);
    esp_result(unsafe { telemetry_agent::telemetry_agent_start(ptr) })
}

pub fn stop() -> Result {
    esp_result(unsafe { telemetry_agent::telemetry_agent_stop() })
}

pub fn is_running() -> bool {
    unsafe { telemetry_agent::telemetry_agent_is_running() }
}

pub fn send_snapshot_now() -> Result {
    esp_result(unsafe { telemetry_agent::telemetry_agent_send_snapshot_now() })
}

pub fn stats() -> TelemetryAgentStatsRaw {
    unsafe { telemetry_agent::telemetry_agent_get_stats() }
}
