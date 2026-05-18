use core::ffi::c_char;

use crate::ffi::EspErr;

pub const DNS_FILTER_MAX_RULES: usize = 32;
pub const DNS_FILTER_DOMAIN_LEN: usize = 128;

pub type DnsFilterAction = i32;
pub const DNS_FILTER_ALLOW: DnsFilterAction = 0;
pub const DNS_FILTER_BLOCK: DnsFilterAction = 1;
pub const DNS_FILTER_REDIRECT: DnsFilterAction = 2;
pub const DNS_FILTER_LOG_ONLY: DnsFilterAction = 3;

#[repr(C)]
pub struct DnsFilterRuleRaw {
    pub rule_id: u32,
    pub enabled: bool,
    pub priority: u16,
    pub pattern: [c_char; DNS_FILTER_DOMAIN_LEN],
    pub action: DnsFilterAction,
    pub redirect_ip: u32,
    pub risk_score: u8,
    pub reason: [c_char; 48],
}

#[repr(C)]
pub struct DnsFilterConfigRaw {
    pub listen_port: u16,
    pub upstream_dns_ip: u32,
    pub default_allow: bool,
}

#[repr(C)]
pub struct DnsFilterStatsRaw {
    pub queries: u64,
    pub allowed: u64,
    pub blocked: u64,
    pub redirected: u64,
    pub errors: u64,
    pub active_rules: u32,
}

unsafe extern "C" {
    pub fn dns_filter_init(config: *const DnsFilterConfigRaw) -> EspErr;
    pub fn dns_filter_start() -> EspErr;
    pub fn dns_filter_stop() -> EspErr;
    pub fn dns_filter_add_rule(rule: *const DnsFilterRuleRaw, out_rule_id: *mut u32) -> EspErr;
    pub fn dns_filter_remove_rule(rule_id: u32) -> bool;
    pub fn dns_filter_evaluate_domain(
        domain: *const c_char,
        out_redirect_ip: *mut u32,
        out_risk_score: *mut u8,
        out_reason: *mut c_char,
        reason_len: usize,
    ) -> DnsFilterAction;
    pub fn dns_filter_get_stats() -> DnsFilterStatsRaw;
    pub fn dns_filter_ipv4(a: u8, b: u8, c: u8, d: u8) -> u32;
}
