use core::ffi::{c_char, c_void};

use crate::ffi::flow_table::{FlowDirection, FlowKeyRaw};
use crate::ffi::EspErr;

pub const RATE_LIMITER_MAX_BUCKETS: usize = 128;
pub const RATE_LIMITER_MAX_RULES: usize = 32;

pub const RATE_LIMIT_ANY_IP: u32 = 0;
pub const RATE_LIMIT_ANY_MASK: u32 = 0;
pub const RATE_LIMIT_ANY_PORT: u16 = 0;
pub const RATE_LIMIT_ANY_PROTO: u8 = 0;

pub type RateLimitDecision = i32;
pub const RATE_LIMIT_DECISION_ALLOW: RateLimitDecision = 0;
pub const RATE_LIMIT_DECISION_EXCEEDED: RateLimitDecision = 1;
pub const RATE_LIMIT_DECISION_ERROR: RateLimitDecision = 2;

pub type RateLimitReason = i32;
pub const RATE_LIMIT_REASON_DEFAULT: RateLimitReason = 0;
pub const RATE_LIMIT_REASON_RULE_MATCH: RateLimitReason = 1;
pub const RATE_LIMIT_REASON_NO_RULE: RateLimitReason = 2;
pub const RATE_LIMIT_REASON_INVALID_INPUT: RateLimitReason = 3;
pub const RATE_LIMIT_REASON_TABLE_FULL: RateLimitReason = 4;

#[repr(C)]
pub struct RateLimitParamsRaw {
    pub window_ms: u32,
    pub max_packets: u32,
    pub max_bytes: u32,
}

#[repr(C)]
pub struct RateLimitRuleRaw {
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
    pub params: RateLimitParamsRaw,
    pub log_event: bool,
    pub suggest_quarantine: bool,
    pub reason: [c_char; 48],
}

#[repr(C)]
pub struct RateLimiterConfigRaw {
    pub default_params: RateLimitParamsRaw,
    pub max_idle_ms: u32,
    pub evict_lru_when_full: bool,
}

#[repr(C)]
pub struct RateLimitResultRaw {
    pub decision: RateLimitDecision,
    pub reason: RateLimitReason,
    pub matched_rule_id: u32,
    pub matched_priority: u16,
    pub window_ms: u32,
    pub packets_in_window: u32,
    pub bytes_in_window: u32,
    pub max_packets: u32,
    pub max_bytes: u32,
    pub log_event: bool,
    pub suggest_quarantine: bool,
    pub reason_text: [c_char; 48],
}

#[repr(C)]
pub struct RateLimiterStatsRaw {
    pub capacity_buckets: u32,
    pub capacity_rules: u32,
    pub active_buckets: u32,
    pub active_rules: u32,
    pub checks: u64,
    pub allowed: u64,
    pub exceeded: u64,
    pub created_buckets: u64,
    pub evicted_buckets: u64,
    pub expired_buckets: u64,
    pub invalid_input: u64,
}

pub type RateLimitRuleIterCb =
    Option<unsafe extern "C" fn(rule: *const RateLimitRuleRaw, user_ctx: *mut c_void)>;

unsafe extern "C" {
    pub fn rate_limiter_init(config: *const RateLimiterConfigRaw) -> EspErr;
    pub fn rate_limiter_reset();
    pub fn rate_limiter_add_rule(rule: *const RateLimitRuleRaw, out_rule_id: *mut u32) -> EspErr;
    pub fn rate_limiter_remove_rule(rule_id: u32) -> bool;
    pub fn rate_limiter_get_rule(rule_id: u32, out_rule: *mut RateLimitRuleRaw) -> bool;
    pub fn rate_limiter_check(
        key: *const FlowKeyRaw,
        direction: FlowDirection,
        packet_bytes: u32,
        out_result: *mut RateLimitResultRaw,
    ) -> EspErr;
    pub fn rate_limiter_expire_old() -> u32;
    pub fn rate_limiter_get_stats() -> RateLimiterStatsRaw;
    pub fn rate_limiter_foreach_rule(cb: RateLimitRuleIterCb, user_ctx: *mut c_void);
    pub fn rate_limiter_ipv4(a: u8, b: u8, c: u8, d: u8) -> u32;
    pub fn rate_limiter_cidr_mask(cidr: u8) -> u32;
    pub fn rate_limit_decision_to_string(decision: RateLimitDecision) -> *const c_char;
}
