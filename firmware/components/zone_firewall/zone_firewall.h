#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "flow_table.h"
#include "policy_engine.h"
#include "rate_limiter.h"
#include "quarantine_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ZONE_FIREWALL_VERDICT_ALLOW = 0,
    ZONE_FIREWALL_VERDICT_DROP,
    ZONE_FIREWALL_VERDICT_REDIRECT,
    ZONE_FIREWALL_VERDICT_LOG_ONLY
} zone_firewall_verdict_t;

typedef struct {
    uint32_t zone_id;
    bool default_allow;
    bool auto_quarantine_on_rate_limit;
    uint32_t quarantine_ttl_ms;
} zone_firewall_config_t;

typedef struct {
    zone_firewall_verdict_t verdict;
    policy_action_t policy_action;
    bool rate_exceeded;
    bool quarantined;
    uint8_t risk_score;
    char reason[64];
} zone_firewall_decision_t;

typedef struct {
    uint64_t evaluations;
    uint64_t allowed;
    uint64_t dropped;
    uint64_t redirected;
    uint64_t quarantined_hits;
    uint64_t rate_exceeded;
    uint64_t policy_denied;
} zone_firewall_stats_t;

esp_err_t zone_firewall_init(const zone_firewall_config_t *config);

esp_err_t zone_firewall_evaluate_flow(
    const flow_key_t *key,
    flow_direction_t direction,
    uint32_t packet_bytes,
    zone_firewall_decision_t *out_decision
);

zone_firewall_stats_t zone_firewall_get_stats(void);
const char *zone_firewall_verdict_to_string(zone_firewall_verdict_t verdict);

#ifdef __cplusplus
}
#endif
