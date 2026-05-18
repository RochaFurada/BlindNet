use core::ffi::{c_char, c_void};
use core::ptr;

use crate::ffi::swarm_agent;
use crate::platform::quarantine_manager::{QuarantineMode, QuarantineSource};
use crate::platform::{esp_result, Result};

pub use crate::ffi::swarm_agent::{
    SwarmAgentConfigRaw, SwarmAgentFrameCb, SwarmAgentStatsRaw, SwarmFrameRaw, SwarmMsgType,
    SwarmPayloadFlowEventRaw, SwarmPayloadHelloRaw, SwarmPayloadQuarantineNoticeRaw,
    SwarmPayloadZoneStateRaw, SwarmVerifyMode, SwarmZoneMode, SWARM_AGENT_BROADCAST_ID,
    SWARM_AGENT_HMAC_LEN, SWARM_AGENT_MAX_PAYLOAD, SWARM_AGENT_REASON_LEN, SWARM_MSG_FLOW_EVENT,
    SWARM_MSG_HEALTH_PING, SWARM_MSG_HELLO, SWARM_MSG_POLICY_UPDATE, SWARM_MSG_QUARANTINE_NOTICE,
    SWARM_MSG_ZONE_STATE, SWARM_VERIFY_DISABLED, SWARM_VERIFY_HMAC_SHA256,
    SWARM_ZONE_MODE_DEGRADED, SWARM_ZONE_MODE_ISOLATED, SWARM_ZONE_MODE_NORMAL,
    SWARM_ZONE_MODE_SUSPECT,
};

pub unsafe fn start(config: Option<&SwarmAgentConfigRaw>) -> Result {
    let ptr = config.map_or(ptr::null(), |config| config);
    esp_result(unsafe { swarm_agent::swarm_agent_start(ptr) })
}

pub fn stop() -> Result {
    esp_result(unsafe { swarm_agent::swarm_agent_stop() })
}

pub fn is_running() -> bool {
    unsafe { swarm_agent::swarm_agent_is_running() }
}

pub unsafe fn set_frame_callback(cb: SwarmAgentFrameCb, user_ctx: *mut c_void) {
    unsafe { swarm_agent::swarm_agent_set_frame_callback(cb, user_ctx) };
}

pub fn send_hello() -> Result {
    esp_result(unsafe { swarm_agent::swarm_agent_send_hello() })
}

pub fn send_zone_state(
    mode: SwarmZoneMode,
    connected_clients: u8,
    quarantined_devices: u8,
    active_flows: u32,
    policy_version: u32,
) -> Result {
    esp_result(unsafe {
        swarm_agent::swarm_agent_send_zone_state(
            mode,
            connected_clients,
            quarantined_devices,
            active_flows,
            policy_version,
        )
    })
}

pub fn send_flow_event(event: &SwarmPayloadFlowEventRaw) -> Result {
    esp_result(unsafe { swarm_agent::swarm_agent_send_flow_event(event) })
}

pub unsafe fn send_quarantine_notice_ip(
    subject_ip: u32,
    mode: QuarantineMode,
    source: QuarantineSource,
    ttl_ms: u32,
    risk_score: u8,
    reason: *const c_char,
) -> Result {
    esp_result(unsafe {
        swarm_agent::swarm_agent_send_quarantine_notice_ip(
            subject_ip, mode, source, ttl_ms, risk_score, reason,
        )
    })
}

pub fn stats() -> SwarmAgentStatsRaw {
    unsafe { swarm_agent::swarm_agent_get_stats() }
}

pub fn msg_type_to_string(message_type: u8) -> *const c_char {
    unsafe { swarm_agent::swarm_msg_type_to_string(message_type) }
}
