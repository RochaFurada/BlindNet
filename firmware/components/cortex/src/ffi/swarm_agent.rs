use core::ffi::{c_char, c_void};

use crate::ffi::flow_table::FlowDirection;
use crate::ffi::quarantine_manager::{QuarantineMode, QuarantineSource};
use crate::ffi::EspErr;

pub const SWARM_AGENT_MAX_PAYLOAD: usize = 192;
pub const SWARM_AGENT_HMAC_LEN: usize = 32;
pub const SWARM_AGENT_REASON_LEN: usize = 48;
pub const SWARM_AGENT_BROADCAST_ID: u32 = 0;

pub type SwarmMsgType = i32;
pub const SWARM_MSG_HELLO: SwarmMsgType = 1;
pub const SWARM_MSG_ZONE_STATE: SwarmMsgType = 2;
pub const SWARM_MSG_FLOW_EVENT: SwarmMsgType = 3;
pub const SWARM_MSG_QUARANTINE_NOTICE: SwarmMsgType = 4;
pub const SWARM_MSG_POLICY_UPDATE: SwarmMsgType = 5;
pub const SWARM_MSG_HEALTH_PING: SwarmMsgType = 6;

pub type SwarmVerifyMode = i32;
pub const SWARM_VERIFY_DISABLED: SwarmVerifyMode = 0;
pub const SWARM_VERIFY_HMAC_SHA256: SwarmVerifyMode = 1;

pub type SwarmZoneMode = i32;
pub const SWARM_ZONE_MODE_NORMAL: SwarmZoneMode = 0;
pub const SWARM_ZONE_MODE_SUSPECT: SwarmZoneMode = 1;
pub const SWARM_ZONE_MODE_DEGRADED: SwarmZoneMode = 2;
pub const SWARM_ZONE_MODE_ISOLATED: SwarmZoneMode = 3;

#[repr(C, packed)]
pub struct SwarmPayloadHelloRaw {
    pub zone_id: u32,
    pub guardian_id: u32,
    pub uptime_ms: u32,
    pub capabilities: u32,
}

#[repr(C, packed)]
pub struct SwarmPayloadZoneStateRaw {
    pub zone_id: u32,
    pub guardian_id: u32,
    pub zone_mode: u8,
    pub connected_clients: u8,
    pub quarantined_devices: u8,
    pub reserved0: u8,
    pub active_flows: u32,
    pub uptime_ms: u32,
    pub policy_version: u32,
}

#[repr(C, packed)]
pub struct SwarmPayloadFlowEventRaw {
    pub zone_id: u32,
    pub guardian_id: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub direction: u8,
    pub risk_score: u8,
    pub reason_code: u8,
    pub packets_window: u32,
    pub bytes_window: u32,
}

#[repr(C, packed)]
pub struct SwarmPayloadQuarantineNoticeRaw {
    pub zone_id: u32,
    pub guardian_id: u32,
    pub subject_type: u8,
    pub mode: u8,
    pub source: u8,
    pub risk_score: u8,
    pub subject_ip: u32,
    pub ttl_ms: u32,
    pub reason: [c_char; SWARM_AGENT_REASON_LEN],
}

#[repr(C, packed)]
pub struct SwarmFrameRaw {
    pub magic: u16,
    pub version: u8,
    pub frame_type: u8,
    pub message_id: u32,
    pub origin_id: u32,
    pub target_id: u32,
    pub hop_count: u8,
    pub reserved0: u8,
    pub payload_len: u16,
    pub issued_ms: u32,
    pub expires_ms: u32,
    pub nonce: u32,
    pub hmac: [u8; SWARM_AGENT_HMAC_LEN],
    pub payload: [u8; SWARM_AGENT_MAX_PAYLOAD],
}

#[repr(C)]
pub struct SwarmAgentConfigRaw {
    pub guardian_id: u32,
    pub zone_id: u32,
    pub udp_port: u16,
    pub broadcast_addr: *const c_char,
    pub hello_interval_ms: u32,
    pub zone_state_interval_ms: u32,
    pub verify_mode: SwarmVerifyMode,
    pub shared_key: *const u8,
    pub shared_key_len: usize,
}

pub type SwarmAgentFrameCb =
    Option<unsafe extern "C" fn(frame: *const SwarmFrameRaw, user_ctx: *mut c_void)>;

#[repr(C)]
pub struct SwarmAgentStatsRaw {
    pub tx_frames: u64,
    pub rx_frames: u64,
    pub rx_invalid_magic: u64,
    pub rx_bad_hmac: u64,
    pub rx_expired: u64,
    pub rx_self_ignored: u64,
    pub tx_errors: u64,
    pub rx_errors: u64,
}

unsafe extern "C" {
    pub fn swarm_agent_start(config: *const SwarmAgentConfigRaw) -> EspErr;
    pub fn swarm_agent_stop() -> EspErr;
    pub fn swarm_agent_is_running() -> bool;
    pub fn swarm_agent_set_frame_callback(cb: SwarmAgentFrameCb, user_ctx: *mut c_void);
    pub fn swarm_agent_send_hello() -> EspErr;
    pub fn swarm_agent_send_zone_state(
        mode: SwarmZoneMode,
        connected_clients: u8,
        quarantined_devices: u8,
        active_flows: u32,
        policy_version: u32,
    ) -> EspErr;
    pub fn swarm_agent_send_flow_event(event: *const SwarmPayloadFlowEventRaw) -> EspErr;
    pub fn swarm_agent_send_quarantine_notice_ip(
        subject_ip: u32,
        mode: QuarantineMode,
        source: QuarantineSource,
        ttl_ms: u32,
        risk_score: u8,
        reason: *const c_char,
    ) -> EspErr;
    pub fn swarm_agent_get_stats() -> SwarmAgentStatsRaw;
    pub fn swarm_msg_type_to_string(message_type: u8) -> *const c_char;
}

pub fn flow_direction_to_swarm(direction: FlowDirection) -> u8 {
    direction as u8
}
