#include "policy_engine.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"

static const char *TAG = "policy_engine";

typedef struct {
    bool in_use;
    policy_rule_t rule;
} policy_slot_t;

static policy_slot_t s_rules[POLICY_ENGINE_MAX_RULES];
static policy_engine_config_t s_config;
static policy_engine_stats_t s_stats;
static bool s_initialized = false;
static uint32_t s_next_rule_id = 1;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000ULL);
}

static void safe_copy_reason(char *dst, size_t dst_size, const char *src)
{
    if (!dst || dst_size == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

uint32_t policy_engine_ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
}

uint32_t policy_engine_cidr_mask(uint8_t cidr)
{
    if (cidr == 0) return 0;
    if (cidr >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - cidr);
}

const char *policy_action_to_string(policy_action_t action)
{
    switch (action) {
        case POLICY_ACTION_ALLOW: return "ALLOW";
        case POLICY_ACTION_DENY: return "DENY";
        case POLICY_ACTION_RATE_LIMIT: return "RATE_LIMIT";
        case POLICY_ACTION_QUARANTINE: return "QUARANTINE";
        case POLICY_ACTION_REDIRECT: return "REDIRECT";
        case POLICY_ACTION_LOG_ONLY: return "LOG_ONLY";
        case POLICY_ACTION_ASK_SWARM: return "ASK_SWARM";
        default: return "UNKNOWN";
    }
}

static void load_default_config(policy_engine_config_t *config)
{
    memset(config, 0, sizeof(*config));
    config->default_action = POLICY_ACTION_ALLOW;
    config->default_log_event = false;
    config->default_risk_score = 0;
}

static bool ip_matches(uint32_t rule_ip, uint32_t rule_mask, uint32_t ip)
{
    if (rule_mask == POLICY_ANY_MASK) return true;
    return (ip & rule_mask) == (rule_ip & rule_mask);
}

static bool port_matches(uint16_t rule_port, uint16_t port)
{
    if (rule_port == POLICY_ANY_PORT) return true;
    return rule_port == port;
}

static bool proto_matches(uint8_t rule_proto, uint8_t proto)
{
    if (rule_proto == POLICY_ANY_PROTO) return true;
    return rule_proto == proto;
}

static bool direction_matches(flow_direction_t rule_direction, flow_direction_t direction)
{
    if (rule_direction == FLOW_DIRECTION_UNKNOWN) return true;
    return rule_direction == direction;
}

static bool rule_is_expired(const policy_rule_t *rule, uint32_t ts)
{
    if (!rule) return true;
    if (rule->expires_at_ms == 0) return false;
    return ts >= rule->expires_at_ms;
}

static bool rule_matches(const policy_rule_t *rule, const flow_key_t *key, flow_direction_t direction, uint32_t ts)
{
    if (!rule || !key) return false;
    if (!rule->enabled) return false;
    if (rule_is_expired(rule, ts)) return false;
    if (!direction_matches(rule->direction, direction)) return false;
    if (!ip_matches(rule->src_ip, rule->src_mask, key->src_ip)) return false;
    if (!ip_matches(rule->dst_ip, rule->dst_mask, key->dst_ip)) return false;
    if (!port_matches(rule->src_port, key->src_port)) return false;
    if (!port_matches(rule->dst_port, key->dst_port)) return false;
    if (!proto_matches(rule->proto, key->proto)) return false;
    return true;
}

static void fill_default_decision(policy_decision_t *decision)
{
    memset(decision, 0, sizeof(*decision));
    decision->action = s_config.default_action;
    decision->reason = POLICY_REASON_NO_RULE;
    decision->risk_score = s_config.default_risk_score;
    decision->log_event = s_config.default_log_event;
    safe_copy_reason(decision->reason_text, sizeof(decision->reason_text), "default_policy");
}

static void fill_rule_decision(policy_decision_t *decision, const policy_rule_t *rule)
{
    memset(decision, 0, sizeof(*decision));
    decision->action = rule->action;
    decision->reason = POLICY_REASON_RULE_MATCH;
    decision->matched_rule_id = rule->rule_id;
    decision->matched_priority = rule->priority;
    decision->risk_score = rule->risk_score;
    decision->log_event = rule->log_event;
    safe_copy_reason(decision->reason_text, sizeof(decision->reason_text), rule->reason);
}

static void update_stats_for_action(policy_action_t action)
{
    s_stats.evaluations++;

    switch (action) {
        case POLICY_ACTION_ALLOW: s_stats.allowed++; break;
        case POLICY_ACTION_DENY: s_stats.denied++; break;
        case POLICY_ACTION_RATE_LIMIT: s_stats.rate_limited++; break;
        case POLICY_ACTION_QUARANTINE: s_stats.quarantined++; break;
        case POLICY_ACTION_REDIRECT: s_stats.redirected++; break;
        case POLICY_ACTION_LOG_ONLY: s_stats.log_only++; break;
        case POLICY_ACTION_ASK_SWARM: s_stats.ask_swarm++; break;
        default: break;
    }
}

static int find_empty_slot_locked(void)
{
    for (int i = 0; i < POLICY_ENGINE_MAX_RULES; ++i) {
        if (!s_rules[i].in_use) return i;
    }
    return -1;
}

static int find_rule_slot_locked(uint32_t rule_id)
{
    for (int i = 0; i < POLICY_ENGINE_MAX_RULES; ++i) {
        if (s_rules[i].in_use && s_rules[i].rule.rule_id == rule_id) return i;
    }
    return -1;
}

esp_err_t policy_engine_init(const policy_engine_config_t *config)
{
    portENTER_CRITICAL(&s_lock);

    memset(s_rules, 0, sizeof(s_rules));
    memset(&s_stats, 0, sizeof(s_stats));

    load_default_config(&s_config);
    if (config) s_config = *config;

    s_stats.capacity = POLICY_ENGINE_MAX_RULES;
    s_next_rule_id = 1;
    s_initialized = true;

    portEXIT_CRITICAL(&s_lock);

    ESP_LOGI(TAG, "policy_engine init capacity=%u default=%s",
             POLICY_ENGINE_MAX_RULES, policy_action_to_string(s_config.default_action));

    return ESP_OK;
}

void policy_engine_reset(void)
{
    portENTER_CRITICAL(&s_lock);
    memset(s_rules, 0, sizeof(s_rules));
    memset(&s_stats, 0, sizeof(s_stats));
    s_stats.capacity = POLICY_ENGINE_MAX_RULES;
    s_next_rule_id = 1;
    portEXIT_CRITICAL(&s_lock);
}

esp_err_t policy_engine_add_rule(const policy_rule_t *rule, uint32_t *out_rule_id)
{
    if (!rule || !s_initialized) return ESP_ERR_INVALID_ARG;

    esp_err_t result = ESP_OK;
    uint32_t created_id = 0;

    portENTER_CRITICAL(&s_lock);

    int slot = find_empty_slot_locked();
    if (slot < 0) {
        result = ESP_ERR_NO_MEM;
    } else {
        policy_rule_t copy = *rule;

        if (copy.rule_id == 0) copy.rule_id = s_next_rule_id++;
        copy.enabled = true;

        s_rules[slot].in_use = true;
        s_rules[slot].rule = copy;
        s_stats.active_rules++;

        created_id = copy.rule_id;
        if (out_rule_id) *out_rule_id = created_id;
    }

    portEXIT_CRITICAL(&s_lock);

    if (result == ESP_OK) {
        ESP_LOGI(TAG, "regra adicionada id=%lu action=%s priority=%u reason=%s",
                 (unsigned long)created_id,
                 policy_action_to_string(rule->action),
                 rule->priority,
                 rule->reason);
    }

    return result;
}

bool policy_engine_remove_rule(uint32_t rule_id)
{
    if (!s_initialized || rule_id == 0) return false;

    bool removed = false;

    portENTER_CRITICAL(&s_lock);

    int slot = find_rule_slot_locked(rule_id);
    if (slot >= 0) {
        memset(&s_rules[slot], 0, sizeof(s_rules[slot]));
        if (s_stats.active_rules > 0) s_stats.active_rules--;
        removed = true;
    }

    portEXIT_CRITICAL(&s_lock);

    return removed;
}

bool policy_engine_get_rule(uint32_t rule_id, policy_rule_t *out_rule)
{
    if (!s_initialized || rule_id == 0 || !out_rule) return false;

    bool found = false;

    portENTER_CRITICAL(&s_lock);
    int slot = find_rule_slot_locked(rule_id);
    if (slot >= 0) {
        *out_rule = s_rules[slot].rule;
        found = true;
    }
    portEXIT_CRITICAL(&s_lock);

    return found;
}

esp_err_t policy_engine_evaluate(const flow_key_t *key, flow_direction_t direction, policy_decision_t *out_decision)
{
    if (!out_decision) return ESP_ERR_INVALID_ARG;

    if (!s_initialized || !key) {
        memset(out_decision, 0, sizeof(*out_decision));
        out_decision->action = POLICY_ACTION_DENY;
        out_decision->reason = POLICY_REASON_INVALID_INPUT;
        safe_copy_reason(out_decision->reason_text, sizeof(out_decision->reason_text), "invalid_input");

        portENTER_CRITICAL(&s_lock);
        s_stats.invalid_input++;
        portEXIT_CRITICAL(&s_lock);

        return ESP_ERR_INVALID_ARG;
    }

    const uint32_t ts = now_ms();
    policy_rule_t best_rule;
    bool has_match = false;
    uint16_t best_priority = 0;

    memset(&best_rule, 0, sizeof(best_rule));

    portENTER_CRITICAL(&s_lock);

    for (int i = 0; i < POLICY_ENGINE_MAX_RULES; ++i) {
        if (!s_rules[i].in_use) continue;

        policy_rule_t *rule = &s_rules[i].rule;
        if (!rule_matches(rule, key, direction, ts)) continue;

        if (!has_match || rule->priority >= best_priority) {
            best_rule = *rule;
            best_priority = rule->priority;
            has_match = true;
        }
    }

    if (has_match) {
        fill_rule_decision(out_decision, &best_rule);
        update_stats_for_action(out_decision->action);
    } else {
        fill_default_decision(out_decision);
        s_stats.no_match++;
        update_stats_for_action(out_decision->action);
    }

    portEXIT_CRITICAL(&s_lock);

    return ESP_OK;
}

void policy_engine_set_default_action(policy_action_t action)
{
    portENTER_CRITICAL(&s_lock);
    s_config.default_action = action;
    portEXIT_CRITICAL(&s_lock);
}

uint32_t policy_engine_expire_rules(void)
{
    if (!s_initialized) return 0;

    const uint32_t ts = now_ms();
    uint32_t expired = 0;

    portENTER_CRITICAL(&s_lock);

    for (int i = 0; i < POLICY_ENGINE_MAX_RULES; ++i) {
        if (!s_rules[i].in_use) continue;

        if (rule_is_expired(&s_rules[i].rule, ts)) {
            memset(&s_rules[i], 0, sizeof(s_rules[i]));
            if (s_stats.active_rules > 0) s_stats.active_rules--;
            expired++;
        }
    }

    portEXIT_CRITICAL(&s_lock);

    return expired;
}

policy_engine_stats_t policy_engine_get_stats(void)
{
    policy_engine_stats_t copy;
    portENTER_CRITICAL(&s_lock);
    copy = s_stats;
    portEXIT_CRITICAL(&s_lock);
    return copy;
}

void policy_engine_foreach_rule(policy_rule_iter_cb_t cb, void *user_ctx)
{
    if (!cb || !s_initialized) return;

    for (int i = 0; i < POLICY_ENGINE_MAX_RULES; ++i) {
        policy_rule_t copy;
        bool has = false;

        portENTER_CRITICAL(&s_lock);
        if (s_rules[i].in_use) {
            copy = s_rules[i].rule;
            has = true;
        }
        portEXIT_CRITICAL(&s_lock);

        if (has) cb(&copy, user_ctx);
    }
}
