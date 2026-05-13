#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DNS_FILTER_MAX_RULES
#define DNS_FILTER_MAX_RULES 32
#endif

#define DNS_FILTER_DOMAIN_LEN 128

typedef enum {
    DNS_FILTER_ALLOW = 0,
    DNS_FILTER_BLOCK,
    DNS_FILTER_REDIRECT,
    DNS_FILTER_LOG_ONLY
} dns_filter_action_t;

typedef struct {
    uint32_t rule_id;
    bool enabled;
    uint16_t priority;
    char pattern[DNS_FILTER_DOMAIN_LEN];
    dns_filter_action_t action;
    uint32_t redirect_ip;
    uint8_t risk_score;
    char reason[48];
} dns_filter_rule_t;

typedef struct {
    uint16_t listen_port;
    uint32_t upstream_dns_ip;
    bool default_allow;
} dns_filter_config_t;

typedef struct {
    uint64_t queries;
    uint64_t allowed;
    uint64_t blocked;
    uint64_t redirected;
    uint64_t errors;
    uint32_t active_rules;
} dns_filter_stats_t;

esp_err_t dns_filter_init(const dns_filter_config_t *config);
esp_err_t dns_filter_start(void);
esp_err_t dns_filter_stop(void);

esp_err_t dns_filter_add_rule(const dns_filter_rule_t *rule, uint32_t *out_rule_id);
bool dns_filter_remove_rule(uint32_t rule_id);

dns_filter_action_t dns_filter_evaluate_domain(
    const char *domain,
    uint32_t *out_redirect_ip,
    uint8_t *out_risk_score,
    char *out_reason,
    size_t reason_len
);

dns_filter_stats_t dns_filter_get_stats(void);
uint32_t dns_filter_ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d);

#ifdef __cplusplus
}
#endif
