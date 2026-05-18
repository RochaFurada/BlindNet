use core::ffi::{c_char, c_void};

use crate::ffi::flow_table::{FlowDirection, FlowKeyRaw};
use crate::ffi::EspErr;

pub const POLICY_ENGINE_MAX_RULES: usize = 64;

pub const POLICY_ANY_IP: u32 = 0;
pub const POLICY_ANY_MASK: u32 = 0;
pub const POLICY_ANY_PORT: u16 = 0;
pub const POLICY_ANY_PROTO: u8 = 0;

pub type PolicyAction = i32;
pub const POLICY_ACTION_ALLOW: PolicyAction = 0;
pub const POLICY_ACTION_DENY: PolicyAction = 1;
pub const POLICY_ACTION_RATE_LIMIT: PolicyAction = 2;
pub const POLICY_ACTION_QUARANTINE: PolicyAction = 3;
pub const POLICY_ACTION_REDIRECT: PolicyAction = 4;
pub const POLICY_ACTION_LOG_ONLY: PolicyAction = 5;
pub const POLICY_ACTION_ASK_SWARM: PolicyAction = 6;

pub type PolicyReason = i32;
pub const POLICY_REASON_DEFAULT: PolicyReason = 0;
pub const POLICY_REASON_RULE_MATCH: PolicyReason = 1;
pub const POLICY_REASON_NO_RULE: PolicyReason = 2;
pub const POLICY_REASON_RULE_EXPIRED: PolicyReason = 3;
pub const POLICY_REASON_INVALID_INPUT: PolicyReason = 4;

#[repr(C)]
pub struct PolicyRuleRaw {
    pub rule_id: u32,
    pub enabled: bool,
    pub priority: u16,
    pub direction: FlowDirection,
    pub src_ip: u32,
    pub src_mask: u32,
    pub dst_ip: u32,
    pub dst_mask: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub action: PolicyAction,
    pub risk_score: u8,
    pub log_event: bool,
    pub expires_at_ms: u32,
    pub reason: [c_char; 48],
}

#[repr(C)]
pub struct PolicyEngineConfigRaw {
    pub default_action: PolicyAction,
    pub default_log_event: bool,
    pub default_risk_score: u8,
}

#[repr(C)]
pub struct PolicyDecisionRaw {
    pub action: PolicyAction,
    pub reason: PolicyReason,
    pub matched_rule_id: u32,
    pub matched_priority: u16,
    pub risk_score: u8,
    pub log_event: bool,
    pub reason_text: [c_char; 48],
}

#[repr(C)]
pub struct PolicyEngineStatsRaw {
    pub capacity: u32,
    pub active_rules: u32,
    pub evaluations: u64,
    pub allowed: u64,
    pub denied: u64,
    pub rate_limited: u64,
    pub quarantined: u64,
    pub redirected: u64,
    pub log_only: u64,
    pub ask_swarm: u64,
    pub no_match: u64,
    pub invalid_input: u64,
}

pub type PolicyRuleIterCb =
    Option<unsafe extern "C" fn(rule: *const PolicyRuleRaw, user_ctx: *mut c_void)>;

unsafe extern "C" {
    pub fn policy_engine_init(config: *const PolicyEngineConfigRaw) -> EspErr;
    pub fn policy_engine_reset();
    pub fn policy_engine_add_rule(rule: *const PolicyRuleRaw, out_rule_id: *mut u32) -> EspErr;
    pub fn policy_engine_remove_rule(rule_id: u32) -> bool;
    pub fn policy_engine_get_rule(rule_id: u32, out_rule: *mut PolicyRuleRaw) -> bool;
    pub fn policy_engine_evaluate(
        key: *const FlowKeyRaw,
        direction: FlowDirection,
        out_decision: *mut PolicyDecisionRaw,
    ) -> EspErr;
    pub fn policy_engine_set_default_action(action: PolicyAction);
    pub fn policy_engine_expire_rules() -> u32;
    pub fn policy_engine_get_stats() -> PolicyEngineStatsRaw;
    pub fn policy_engine_foreach_rule(cb: PolicyRuleIterCb, user_ctx: *mut c_void);
    pub fn policy_engine_ipv4(a: u8, b: u8, c: u8, d: u8) -> u32;
    pub fn policy_engine_cidr_mask(cidr: u8) -> u32;
    pub fn policy_action_to_string(action: PolicyAction) -> *const c_char;
}
