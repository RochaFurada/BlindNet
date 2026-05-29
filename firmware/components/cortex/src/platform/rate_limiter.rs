use core::ffi::{c_char, c_void};
use core::ptr;

use crate::ffi::rate_limiter;
use crate::platform::flow_table::{FlowDirection, FlowKeyRaw};
use crate::platform::{esp_result, Result};

pub use crate::ffi::rate_limiter::{
    RateLimitDecision, RateLimitParamsRaw, RateLimitReason, RateLimitResultRaw,
    RateLimitRuleIterCb, RateLimitRuleRaw, RateLimiterConfigRaw, RateLimiterStatsRaw,
    RATE_LIMITER_MAX_BUCKETS, RATE_LIMITER_MAX_RULES, RATE_LIMIT_ANY_IP, RATE_LIMIT_ANY_MASK,
    RATE_LIMIT_ANY_PORT, RATE_LIMIT_ANY_PROTO, RATE_LIMIT_DECISION_ALLOW,
    RATE_LIMIT_DECISION_ERROR, RATE_LIMIT_DECISION_EXCEEDED, RATE_LIMIT_REASON_DEFAULT,
    RATE_LIMIT_REASON_INVALID_INPUT, RATE_LIMIT_REASON_NO_RULE, RATE_LIMIT_REASON_RULE_MATCH,
    RATE_LIMIT_REASON_TABLE_FULL,
};

pub fn init(config: Option<&RateLimiterConfigRaw>) -> Result {
    let ptr = config.map_or(ptr::null(), |config| config);
    esp_result(unsafe { rate_limiter::rate_limiter_init(ptr) })
}

pub fn reset() {
    unsafe { rate_limiter::rate_limiter_reset() };
}

pub fn add_rule(rule: &RateLimitRuleRaw, out_rule_id: Option<&mut u32>) -> Result {
    let out = out_rule_id.map_or(ptr::null_mut(), |id| id);
    esp_result(unsafe { rate_limiter::rate_limiter_add_rule(rule, out) })
}

pub fn remove_rule(rule_id: u32) -> bool {
    unsafe { rate_limiter::rate_limiter_remove_rule(rule_id) }
}

pub fn get_rule(rule_id: u32, out_rule: &mut RateLimitRuleRaw) -> bool {
    unsafe { rate_limiter::rate_limiter_get_rule(rule_id, out_rule) }
}

pub fn check(
    key: &FlowKeyRaw,
    direction: FlowDirection,
    packet_bytes: u32,
    out_result: &mut RateLimitResultRaw,
) -> Result {
    esp_result(unsafe {
        rate_limiter::rate_limiter_check(key, direction, packet_bytes, out_result)
    })
}

pub fn expire_old() -> u32 {
    unsafe { rate_limiter::rate_limiter_expire_old() }
}

pub fn stats() -> RateLimiterStatsRaw {
    unsafe { rate_limiter::rate_limiter_get_stats() }
}

pub unsafe fn foreach_rule(cb: RateLimitRuleIterCb, user_ctx: *mut c_void) {
    unsafe { rate_limiter::rate_limiter_foreach_rule(cb, user_ctx) };
}

pub fn ipv4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    unsafe { rate_limiter::rate_limiter_ipv4(a, b, c, d) }
}

pub fn cidr_mask(cidr: u8) -> u32 {
    unsafe { rate_limiter::rate_limiter_cidr_mask(cidr) }
}

pub fn decision_to_string(decision: RateLimitDecision) -> *const c_char {
    unsafe { rate_limiter::rate_limit_decision_to_string(decision) }
}
