#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "flow_table.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef RATE_LIMITER_MAX_BUCKETS
#define RATE_LIMITER_MAX_BUCKETS 128
#endif

#ifndef RATE_LIMITER_MAX_RULES
#define RATE_LIMITER_MAX_RULES 32
#endif

#define RATE_LIMIT_ANY_IP      0u
#define RATE_LIMIT_ANY_MASK    0u
#define RATE_LIMIT_ANY_PORT    0u
#define RATE_LIMIT_ANY_PROTO   0u

typedef enum {
    RATE_LIMIT_DECISION_ALLOW = 0,
    RATE_LIMIT_DECISION_EXCEEDED,
    RATE_LIMIT_DECISION_ERROR
} rate_limit_decision_t;

typedef enum {
    RATE_LIMIT_REASON_DEFAULT = 0,
    RATE_LIMIT_REASON_RULE_MATCH,
    RATE_LIMIT_REASON_NO_RULE,
    RATE_LIMIT_REASON_INVALID_INPUT,
    RATE_LIMIT_REASON_TABLE_FULL
} rate_limit_reason_t;

typedef struct {
    uint32_t window_ms;
    uint32_t max_packets;
    uint32_t max_bytes;
} rate_limit_params_t;

typedef struct {
    uint32_t rule_id;
    bool enabled;
    uint16_t priority;
    flow_direction_t direction;
    uint32_t src_ip;
    uint32_t src_mask;
    uint32_t dst_ip;
    uint32_t dst_mask;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    rate_limit_params_t params;
    bool log_event;
    bool suggest_quarantine;
    char reason[48];
} rate_limit_rule_t;

typedef struct {
    rate_limit_params_t default_params;
    uint32_t max_idle_ms;
    bool evict_lru_when_full;
} rate_limiter_config_t;

typedef struct {
    rate_limit_decision_t decision;
    rate_limit_reason_t reason;
    uint32_t matched_rule_id;
    uint16_t matched_priority;
    uint32_t window_ms;
    uint32_t packets_in_window;
    uint32_t bytes_in_window;
    uint32_t max_packets;
    uint32_t max_bytes;
    bool log_event;
    bool suggest_quarantine;
    char reason_text[48];
} rate_limit_result_t;

typedef struct {
    uint32_t capacity_buckets;
    uint32_t capacity_rules;
    uint32_t active_buckets;
    uint32_t active_rules;
    uint64_t checks;
    uint64_t allowed;
    uint64_t exceeded;
    uint64_t created_buckets;
    uint64_t evicted_buckets;
    uint64_t expired_buckets;
    uint64_t invalid_input;
} rate_limiter_stats_t;

typedef void (*rate_limit_rule_iter_cb_t)(const rate_limit_rule_t *rule, void *user_ctx);

esp_err_t rate_limiter_init(const rate_limiter_config_t *config);
void rate_limiter_reset(void);

esp_err_t rate_limiter_add_rule(const rate_limit_rule_t *rule, uint32_t *out_rule_id);
bool rate_limiter_remove_rule(uint32_t rule_id);
bool rate_limiter_get_rule(uint32_t rule_id, rate_limit_rule_t *out_rule);

esp_err_t rate_limiter_check(
    const flow_key_t *key,
    flow_direction_t direction,
    uint32_t packet_bytes,
    rate_limit_result_t *out_result
);

uint32_t rate_limiter_expire_old(void);
rate_limiter_stats_t rate_limiter_get_stats(void);
void rate_limiter_foreach_rule(rate_limit_rule_iter_cb_t cb, void *user_ctx);

uint32_t rate_limiter_ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
uint32_t rate_limiter_cidr_mask(uint8_t cidr);

const char *rate_limit_decision_to_string(rate_limit_decision_t decision);

#ifdef __cplusplus
}
#endif
