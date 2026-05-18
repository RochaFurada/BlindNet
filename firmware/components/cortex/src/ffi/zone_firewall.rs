use core::ffi::c_char;

use crate::ffi::flow_table::{FlowDirection, FlowKeyRaw};
use crate::ffi::policy_engine::PolicyAction;
use crate::ffi::EspErr;

pub type ZoneFirewallVerdict = i32;
pub const ZONE_FIREWALL_VERDICT_ALLOW: ZoneFirewallVerdict = 0;
pub const ZONE_FIREWALL_VERDICT_DROP: ZoneFirewallVerdict = 1;
pub const ZONE_FIREWALL_VERDICT_REDIRECT: ZoneFirewallVerdict = 2;
pub const ZONE_FIREWALL_VERDICT_LOG_ONLY: ZoneFirewallVerdict = 3;

#[repr(C)]
pub struct ZoneFirewallConfigRaw {
    pub zone_id: u32,
    pub default_allow: bool,
    pub auto_quarantine_on_rate_limit: bool,
    pub quarantine_ttl_ms: u32,
}

#[repr(C)]
pub struct ZoneFirewallDecisionRaw {
    pub verdict: ZoneFirewallVerdict,
    pub policy_action: PolicyAction,
    pub rate_exceeded: bool,
    pub quarantined: bool,
    pub risk_score: u8,
    pub reason: [c_char; 64],
}

#[repr(C)]
pub struct ZoneFirewallStatsRaw {
    pub evaluations: u64,
    pub allowed: u64,
    pub dropped: u64,
    pub redirected: u64,
    pub quarantined_hits: u64,
    pub rate_exceeded: u64,
    pub policy_denied: u64,
}

unsafe extern "C" {
    pub fn zone_firewall_init(config: *const ZoneFirewallConfigRaw) -> EspErr;
    pub fn zone_firewall_evaluate_flow(
        key: *const FlowKeyRaw,
        direction: FlowDirection,
        packet_bytes: u32,
        out_decision: *mut ZoneFirewallDecisionRaw,
    ) -> EspErr;
    pub fn zone_firewall_get_stats() -> ZoneFirewallStatsRaw;
    pub fn zone_firewall_verdict_to_string(verdict: ZoneFirewallVerdict) -> *const c_char;
}
