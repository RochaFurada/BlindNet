#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "esp_err.h"
#include "flow_table.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef POLICY_ENGINE_MAX_RULES
#define POLICY_ENGINE_MAX_RULES 64
#endif

#define POLICY_ANY_IP      0u
#define POLICY_ANY_MASK    0u
#define POLICY_ANY_PORT    0u
#define POLICY_ANY_PROTO   0u

typedef enum {
    POLICY_ACTION_ALLOW = 0,
    POLICY_ACTION_DENY,
    POLICY_ACTION_RATE_LIMIT,
    POLICY_ACTION_QUARANTINE,
    POLICY_ACTION_REDIRECT,
    POLICY_ACTION_LOG_ONLY,
    POLICY_ACTION_ASK_SWARM
} policy_action_t;

typedef enum {
    POLICY_REASON_DEFAULT = 0,
    POLICY_REASON_RULE_MATCH,
    POLICY_REASON_NO_RULE,
    POLICY_REASON_RULE_EXPIRED,
    POLICY_REASON_INVALID_INPUT
} policy_reason_t;

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
    policy_action_t action;
    uint8_t risk_score;
    bool log_event;
    uint32_t expires_at_ms;
    char reason[48];
} policy_rule_t;

typedef struct {
    policy_action_t default_action;
    bool default_log_event;
    uint8_t default_risk_score;
} policy_engine_config_t;

typedef struct {
    policy_action_t action;
    policy_reason_t reason;
    uint32_t matched_rule_id;
    uint16_t matched_priority;
    uint8_t risk_score;
    bool log_event;
    char reason_text[48];
} policy_decision_t;

typedef struct {
    uint32_t capacity;
    uint32_t active_rules;
    uint64_t evaluations;
    uint64_t allowed;
    uint64_t denied;
    uint64_t rate_limited;
    uint64_t quarantined;
    uint64_t redirected;
    uint64_t log_only;
    uint64_t ask_swarm;
    uint64_t no_match;
    uint64_t invalid_input;
} policy_engine_stats_t;

typedef void (*policy_rule_iter_cb_t)(const policy_rule_t *rule, void *user_ctx);

esp_err_t policy_engine_init(const policy_engine_config_t *config);
void policy_engine_reset(void);

esp_err_t policy_engine_add_rule(const policy_rule_t *rule, uint32_t *out_rule_id);
bool policy_engine_remove_rule(uint32_t rule_id);
bool policy_engine_get_rule(uint32_t rule_id, policy_rule_t *out_rule);

esp_err_t policy_engine_evaluate(
    const flow_key_t *key,
    flow_direction_t direction,
    policy_decision_t *out_decision
);

void policy_engine_set_default_action(policy_action_t action);
uint32_t policy_engine_expire_rules(void);
policy_engine_stats_t policy_engine_get_stats(void);
void policy_engine_foreach_rule(policy_rule_iter_cb_t cb, void *user_ctx);

uint32_t policy_engine_ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
uint32_t policy_engine_cidr_mask(uint8_t cidr);

const char *policy_action_to_string(policy_action_t action);

#ifdef __cplusplus
}
#endif
