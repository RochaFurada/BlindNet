use crate::ffi::zone_firewall;
use crate::platform::flow_table::{FlowDirection, FlowKeyRaw};
use crate::platform::{esp_result, Result};

pub use crate::ffi::zone_firewall::{
    ZoneFirewallConfigRaw, ZoneFirewallDecisionRaw, ZoneFirewallStatsRaw, ZoneFirewallVerdict,
    ZONE_FIREWALL_VERDICT_ALLOW, ZONE_FIREWALL_VERDICT_DROP, ZONE_FIREWALL_VERDICT_LOG_ONLY,
    ZONE_FIREWALL_VERDICT_REDIRECT,
};

pub fn init(config: &ZoneFirewallConfigRaw) -> Result {
    esp_result(unsafe { zone_firewall::zone_firewall_init(config) })
}

pub fn evaluate_flow(
    key: &FlowKeyRaw,
    direction: FlowDirection,
    packet_bytes: u32,
    out_decision: &mut ZoneFirewallDecisionRaw,
) -> Result {
    esp_result(unsafe {
        zone_firewall::zone_firewall_evaluate_flow(key, direction, packet_bytes, out_decision)
    })
}

pub fn stats() -> ZoneFirewallStatsRaw {
    unsafe { zone_firewall::zone_firewall_get_stats() }
}

pub fn verdict_to_string(verdict: ZoneFirewallVerdict) -> *const core::ffi::c_char {
    unsafe { zone_firewall::zone_firewall_verdict_to_string(verdict) }
}
