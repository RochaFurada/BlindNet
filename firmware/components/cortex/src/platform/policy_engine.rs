use core::ffi::{c_char, c_void};
use core::ptr;

use crate::ffi::policy_engine;
use crate::platform::flow_table::{FlowDirection, FlowKeyRaw};
use crate::platform::{esp_result, Result};

pub use crate::ffi::policy_engine::{
    PolicyAction, PolicyDecisionRaw, PolicyEngineConfigRaw, PolicyEngineStatsRaw, PolicyReason,
    PolicyRuleIterCb, PolicyRuleRaw, POLICY_ACTION_ALLOW, POLICY_ACTION_ASK_SWARM,
    POLICY_ACTION_DENY, POLICY_ACTION_LOG_ONLY, POLICY_ACTION_QUARANTINE, POLICY_ACTION_RATE_LIMIT,
    POLICY_ACTION_REDIRECT, POLICY_ANY_IP, POLICY_ANY_MASK, POLICY_ANY_PORT, POLICY_ANY_PROTO,
    POLICY_ENGINE_MAX_RULES, POLICY_REASON_DEFAULT, POLICY_REASON_INVALID_INPUT,
    POLICY_REASON_NO_RULE, POLICY_REASON_RULE_EXPIRED, POLICY_REASON_RULE_MATCH,
};

pub fn init(config: Option<&PolicyEngineConfigRaw>) -> Result {
    let ptr = config.map_or(ptr::null(), |config| config);
    esp_result(unsafe { policy_engine::policy_engine_init(ptr) })
}

pub fn reset() {
    unsafe { policy_engine::policy_engine_reset() };
}

pub fn add_rule(rule: &PolicyRuleRaw, out_rule_id: Option<&mut u32>) -> Result {
    let out = out_rule_id.map_or(ptr::null_mut(), |id| id);
    esp_result(unsafe { policy_engine::policy_engine_add_rule(rule, out) })
}

pub fn remove_rule(rule_id: u32) -> bool {
    unsafe { policy_engine::policy_engine_remove_rule(rule_id) }
}

pub fn get_rule(rule_id: u32, out_rule: &mut PolicyRuleRaw) -> bool {
    unsafe { policy_engine::policy_engine_get_rule(rule_id, out_rule) }
}

pub fn evaluate(
    key: &FlowKeyRaw,
    direction: FlowDirection,
    out_decision: &mut PolicyDecisionRaw,
) -> Result {
    esp_result(unsafe { policy_engine::policy_engine_evaluate(key, direction, out_decision) })
}

pub fn set_default_action(action: PolicyAction) {
    unsafe { policy_engine::policy_engine_set_default_action(action) };
}

pub fn expire_rules() -> u32 {
    unsafe { policy_engine::policy_engine_expire_rules() }
}

pub fn stats() -> PolicyEngineStatsRaw {
    unsafe { policy_engine::policy_engine_get_stats() }
}

pub unsafe fn foreach_rule(cb: PolicyRuleIterCb, user_ctx: *mut c_void) {
    unsafe { policy_engine::policy_engine_foreach_rule(cb, user_ctx) };
}

pub fn ipv4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    unsafe { policy_engine::policy_engine_ipv4(a, b, c, d) }
}

pub fn cidr_mask(cidr: u8) -> u32 {
    unsafe { policy_engine::policy_engine_cidr_mask(cidr) }
}

pub fn action_to_string(action: PolicyAction) -> *const c_char {
    unsafe { policy_engine::policy_action_to_string(action) }
}
