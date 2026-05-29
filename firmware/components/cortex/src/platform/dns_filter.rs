use core::ffi::c_char;
use core::ptr;

use crate::ffi::dns_filter;
use crate::platform::{esp_result, Result};

pub use crate::ffi::dns_filter::{
    DnsFilterAction, DnsFilterConfigRaw, DnsFilterRuleRaw, DnsFilterStatsRaw, DNS_FILTER_ALLOW,
    DNS_FILTER_BLOCK, DNS_FILTER_DOMAIN_LEN, DNS_FILTER_LOG_ONLY, DNS_FILTER_MAX_RULES,
    DNS_FILTER_REDIRECT,
};

pub fn init(config: Option<&DnsFilterConfigRaw>) -> Result {
    let ptr = config.map_or(ptr::null(), |config| config);
    esp_result(unsafe { dns_filter::dns_filter_init(ptr) })
}

pub fn start() -> Result {
    esp_result(unsafe { dns_filter::dns_filter_start() })
}

pub fn stop() -> Result {
    esp_result(unsafe { dns_filter::dns_filter_stop() })
}

pub fn add_rule(rule: &DnsFilterRuleRaw, out_rule_id: Option<&mut u32>) -> Result {
    let out = out_rule_id.map_or(ptr::null_mut(), |id| id);
    esp_result(unsafe { dns_filter::dns_filter_add_rule(rule, out) })
}

pub fn remove_rule(rule_id: u32) -> bool {
    unsafe { dns_filter::dns_filter_remove_rule(rule_id) }
}

pub unsafe fn evaluate_domain(
    domain: *const c_char,
    out_redirect_ip: Option<&mut u32>,
    out_risk_score: Option<&mut u8>,
    out_reason: *mut c_char,
    reason_len: usize,
) -> DnsFilterAction {
    let redirect = out_redirect_ip.map_or(ptr::null_mut(), |ip| ip);
    let risk = out_risk_score.map_or(ptr::null_mut(), |score| score);
    unsafe {
        dns_filter::dns_filter_evaluate_domain(domain, redirect, risk, out_reason, reason_len)
    }
}

pub fn stats() -> DnsFilterStatsRaw {
    unsafe { dns_filter::dns_filter_get_stats() }
}

pub fn ipv4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    unsafe { dns_filter::dns_filter_ipv4(a, b, c, d) }
}
