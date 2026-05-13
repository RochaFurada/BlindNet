#include "rate_limiter.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"

static const char *TAG = "rate_limiter";

typedef struct {
    flow_key_t key;
    flow_direction_t direction;
} bucket_key_t;

typedef struct {
    bool in_use;
    bucket_key_t bucket_key;
    uint32_t window_start_ms;
    uint32_t last_seen_ms;
    uint32_t packets_in_window;
    uint32_t bytes_in_window;
    uint32_t exceeded_count;
} rate_bucket_t;

typedef struct {
    bool in_use;
    rate_limit_rule_t rule;
} rate_rule_slot_t;

static rate_bucket_t s_buckets[RATE_LIMITER_MAX_BUCKETS];
static rate_rule_slot_t s_rules[RATE_LIMITER_MAX_RULES];

static rate_limiter_config_t s_config;
static rate_limiter_stats_t s_stats;

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

uint32_t rate_limiter_ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
}

uint32_t rate_limiter_cidr_mask(uint8_t cidr)
{
    if (cidr == 0) return 0;
    if (cidr >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - cidr);
}

const char *rate_limit_decision_to_string(rate_limit_decision_t decision)
{
    switch (decision) {
        case RATE_LIMIT_DECISION_ALLOW: return "ALLOW";
        case RATE_LIMIT_DECISION_EXCEEDED: return "EXCEEDED";
        case RATE_LIMIT_DECISION_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

static void load_default_config(rate_limiter_config_t *config)
{
    memset(config, 0, sizeof(*config));
    config->default_params.window_ms = 1000;
    config->default_params.max_packets = 60;
    config->default_params.max_bytes = 0;
    config->max_idle_ms = 60000;
    config->evict_lru_when_full = true;
}

static bool bucket_key_equals(const bucket_key_t *a, const bucket_key_t *b)
{
    if (!a || !b) return false;
    return a->direction == b->direction && flow_table_key_equals(&a->key, &b->key);
}

static bool ip_matches(uint32_t rule_ip, uint32_t rule_mask, uint32_t ip)
{
    if (rule_mask == RATE_LIMIT_ANY_MASK) return true;
    return (ip & rule_mask) == (rule_ip & rule_mask);
}

static bool port_matches(uint16_t rule_port, uint16_t port)
{
    if (rule_port == RATE_LIMIT_ANY_PORT) return true;
    return rule_port == port;
}

static bool proto_matches(uint8_t rule_proto, uint8_t proto)
{
    if (rule_proto == RATE_LIMIT_ANY_PROTO) return true;
    return rule_proto == proto;
}

static bool direction_matches(flow_direction_t rule_direction, flow_direction_t direction)
{
    if (rule_direction == FLOW_DIRECTION_UNKNOWN) return true;
    return rule_direction == direction;
}

static bool rule_matches(const rate_limit_rule_t *rule, const flow_key_t *key, flow_direction_t direction)
{
    if (!rule || !key || !rule->enabled) return false;
    if (!direction_matches(rule->direction, direction)) return false;
    if (!ip_matches(rule->src_ip, rule->src_mask, key->src_ip)) return false;
    if (!ip_matches(rule->dst_ip, rule->dst_mask, key->dst_ip)) return false;
    if (!port_matches(rule->src_port, key->src_port)) return false;
    if (!port_matches(rule->dst_port, key->dst_port)) return false;
    if (!proto_matches(rule->proto, key->proto)) return false;
    return true;
}

static bool find_best_rule_locked(const flow_key_t *key, flow_direction_t direction, rate_limit_rule_t *out_rule)
{
    bool found = false;
    uint16_t best_priority = 0;
    rate_limit_rule_t best;
    memset(&best, 0, sizeof(best));

    for (int i = 0; i < RATE_LIMITER_MAX_RULES; ++i) {
        if (!s_rules[i].in_use) continue;

        rate_limit_rule_t *rule = &s_rules[i].rule;
        if (!rule_matches(rule, key, direction)) continue;

        if (!found || rule->priority >= best_priority) {
            best = *rule;
            best_priority = rule->priority;
            found = true;
        }
    }

    if (found && out_rule) *out_rule = best;
    return found;
}

static int find_bucket_locked(const bucket_key_t *bucket_key)
{
    for (int i = 0; i < RATE_LIMITER_MAX_BUCKETS; ++i) {
        if (s_buckets[i].in_use && bucket_key_equals(&s_buckets[i].bucket_key, bucket_key)) return i;
    }
    return -1;
}

static int find_empty_bucket_locked(void)
{
    for (int i = 0; i < RATE_LIMITER_MAX_BUCKETS; ++i) {
        if (!s_buckets[i].in_use) return i;
    }
    return -1;
}

static int find_lru_bucket_locked(void)
{
    int lru = -1;
    uint32_t oldest = UINT32_MAX;

    for (int i = 0; i < RATE_LIMITER_MAX_BUCKETS; ++i) {
        if (!s_buckets[i].in_use) continue;

        if (s_buckets[i].last_seen_ms < oldest) {
            oldest = s_buckets[i].last_seen_ms;
            lru = i;
        }
    }

    return lru;
}

static int find_empty_rule_locked(void)
{
    for (int i = 0; i < RATE_LIMITER_MAX_RULES; ++i) {
        if (!s_rules[i].in_use) return i;
    }
    return -1;
}

static int find_rule_slot_locked(uint32_t rule_id)
{
    for (int i = 0; i < RATE_LIMITER_MAX_RULES; ++i) {
        if (s_rules[i].in_use && s_rules[i].rule.rule_id == rule_id) return i;
    }
    return -1;
}

static void clear_bucket_locked(int index)
{
    if (index < 0 || index >= RATE_LIMITER_MAX_BUCKETS) return;

    if (s_buckets[index].in_use && s_stats.active_buckets > 0) {
        s_stats.active_buckets--;
    }

    memset(&s_buckets[index], 0, sizeof(s_buckets[index]));
}

static int create_bucket_locked(const bucket_key_t *bucket_key, uint32_t ts)
{
    int index = find_empty_bucket_locked();

    if (index < 0) {
        if (!s_config.evict_lru_when_full) return -1;

        index = find_lru_bucket_locked();
        if (index < 0) return -1;

        clear_bucket_locked(index);
        s_stats.evicted_buckets++;
    }

    memset(&s_buckets[index], 0, sizeof(s_buckets[index]));

    s_buckets[index].in_use = true;
    s_buckets[index].bucket_key = *bucket_key;
    s_buckets[index].window_start_ms = ts;
    s_buckets[index].last_seen_ms = ts;

    s_stats.active_buckets++;
    s_stats.created_buckets++;

    return index;
}

static bool params_exceeded(const rate_limit_params_t *params, const rate_bucket_t *bucket)
{
    if (!params || !bucket) return false;

    if (params->max_packets > 0 && bucket->packets_in_window > params->max_packets) return true;
    if (params->max_bytes > 0 && bucket->bytes_in_window > params->max_bytes) return true;

    return false;
}

static void fill_result(rate_limit_result_t *result, rate_limit_decision_t decision,
                        rate_limit_reason_t reason, const rate_limit_rule_t *rule,
                        const rate_limit_params_t *params, const rate_bucket_t *bucket)
{
    memset(result, 0, sizeof(*result));
    result->decision = decision;
    result->reason = reason;

    if (rule) {
        result->matched_rule_id = rule->rule_id;
        result->matched_priority = rule->priority;
        result->log_event = rule->log_event;
        result->suggest_quarantine = rule->suggest_quarantine;
        safe_copy_reason(result->reason_text, sizeof(result->reason_text), rule->reason);
    } else {
        safe_copy_reason(result->reason_text, sizeof(result->reason_text), "default_rate_limit");
    }

    if (params) {
        result->window_ms = params->window_ms;
        result->max_packets = params->max_packets;
        result->max_bytes = params->max_bytes;
    }

    if (bucket) {
        result->packets_in_window = bucket->packets_in_window;
        result->bytes_in_window = bucket->bytes_in_window;
    }
}

esp_err_t rate_limiter_init(const rate_limiter_config_t *config)
{
    portENTER_CRITICAL(&s_lock);

    memset(s_buckets, 0, sizeof(s_buckets));
    memset(s_rules, 0, sizeof(s_rules));
    memset(&s_stats, 0, sizeof(s_stats));

    load_default_config(&s_config);

    if (config) {
        s_config = *config;
        if (s_config.default_params.window_ms == 0) s_config.default_params.window_ms = 1000;
        if (s_config.max_idle_ms == 0) s_config.max_idle_ms = 60000;
    }

    s_stats.capacity_buckets = RATE_LIMITER_MAX_BUCKETS;
    s_stats.capacity_rules = RATE_LIMITER_MAX_RULES;

    s_next_rule_id = 1;
    s_initialized = true;

    portEXIT_CRITICAL(&s_lock);

    ESP_LOGI(TAG, "rate_limiter init buckets=%u rules=%u",
             RATE_LIMITER_MAX_BUCKETS, RATE_LIMITER_MAX_RULES);

    return ESP_OK;
}

void rate_limiter_reset(void)
{
    portENTER_CRITICAL(&s_lock);
    memset(s_buckets, 0, sizeof(s_buckets));
    memset(s_rules, 0, sizeof(s_rules));
    memset(&s_stats, 0, sizeof(s_stats));
    s_stats.capacity_buckets = RATE_LIMITER_MAX_BUCKETS;
    s_stats.capacity_rules = RATE_LIMITER_MAX_RULES;
    s_next_rule_id = 1;
    portEXIT_CRITICAL(&s_lock);
}

esp_err_t rate_limiter_add_rule(const rate_limit_rule_t *rule, uint32_t *out_rule_id)
{
    if (!rule || !s_initialized) return ESP_ERR_INVALID_ARG;

    esp_err_t result = ESP_OK;
    uint32_t created_id = 0;

    portENTER_CRITICAL(&s_lock);

    int slot = find_empty_rule_locked();
    if (slot < 0) {
        result = ESP_ERR_NO_MEM;
    } else {
        rate_limit_rule_t copy = *rule;

        if (copy.rule_id == 0) copy.rule_id = s_next_rule_id++;
        copy.enabled = true;
        if (copy.params.window_ms == 0) copy.params.window_ms = s_config.default_params.window_ms;

        s_rules[slot].in_use = true;
        s_rules[slot].rule = copy;

        s_stats.active_rules++;
        created_id = copy.rule_id;
        if (out_rule_id) *out_rule_id = created_id;
    }

    portEXIT_CRITICAL(&s_lock);

    return result;
}

bool rate_limiter_remove_rule(uint32_t rule_id)
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

bool rate_limiter_get_rule(uint32_t rule_id, rate_limit_rule_t *out_rule)
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

esp_err_t rate_limiter_check(const flow_key_t *key, flow_direction_t direction,
                             uint32_t packet_bytes, rate_limit_result_t *out_result)
{
    if (!out_result) return ESP_ERR_INVALID_ARG;

    if (!s_initialized || !key) {
        memset(out_result, 0, sizeof(*out_result));
        out_result->decision = RATE_LIMIT_DECISION_ERROR;
        out_result->reason = RATE_LIMIT_REASON_INVALID_INPUT;

        portENTER_CRITICAL(&s_lock);
        s_stats.invalid_input++;
        portEXIT_CRITICAL(&s_lock);

        return ESP_ERR_INVALID_ARG;
    }

    const uint32_t ts = now_ms();
    bucket_key_t bucket_key = { .key = *key, .direction = direction };

    portENTER_CRITICAL(&s_lock);

    s_stats.checks++;

    rate_limit_rule_t matched_rule;
    bool has_rule = find_best_rule_locked(key, direction, &matched_rule);

    rate_limit_params_t params = has_rule ? matched_rule.params : s_config.default_params;
    if (params.window_ms == 0) params.window_ms = 1000;

    int bucket_index = find_bucket_locked(&bucket_key);
    if (bucket_index < 0) bucket_index = create_bucket_locked(&bucket_key, ts);

    if (bucket_index < 0) {
        s_stats.invalid_input++;
        fill_result(out_result, RATE_LIMIT_DECISION_ERROR, RATE_LIMIT_REASON_TABLE_FULL,
                    has_rule ? &matched_rule : NULL, &params, NULL);
        portEXIT_CRITICAL(&s_lock);
        return ESP_ERR_NO_MEM;
    }

    rate_bucket_t *bucket = &s_buckets[bucket_index];

    uint32_t elapsed = ts - bucket->window_start_ms;
    if (elapsed >= params.window_ms) {
        bucket->window_start_ms = ts;
        bucket->packets_in_window = 0;
        bucket->bytes_in_window = 0;
    }

    bucket->packets_in_window++;
    bucket->bytes_in_window += packet_bytes;
    bucket->last_seen_ms = ts;

    bool exceeded = params_exceeded(&params, bucket);

    if (exceeded) {
        bucket->exceeded_count++;
        s_stats.exceeded++;
        fill_result(out_result, RATE_LIMIT_DECISION_EXCEEDED,
                    has_rule ? RATE_LIMIT_REASON_RULE_MATCH : RATE_LIMIT_REASON_NO_RULE,
                    has_rule ? &matched_rule : NULL, &params, bucket);
    } else {
        s_stats.allowed++;
        fill_result(out_result, RATE_LIMIT_DECISION_ALLOW,
                    has_rule ? RATE_LIMIT_REASON_RULE_MATCH : RATE_LIMIT_REASON_DEFAULT,
                    has_rule ? &matched_rule : NULL, &params, bucket);
    }

    portEXIT_CRITICAL(&s_lock);

    return ESP_OK;
}

uint32_t rate_limiter_expire_old(void)
{
    if (!s_initialized) return 0;

    const uint32_t ts = now_ms();
    uint32_t expired = 0;

    portENTER_CRITICAL(&s_lock);

    for (int i = 0; i < RATE_LIMITER_MAX_BUCKETS; ++i) {
        if (!s_buckets[i].in_use) continue;

        uint32_t idle = ts - s_buckets[i].last_seen_ms;
        if (idle > s_config.max_idle_ms) {
            clear_bucket_locked(i);
            expired++;
        }
    }

    s_stats.expired_buckets += expired;

    portEXIT_CRITICAL(&s_lock);

    return expired;
}

rate_limiter_stats_t rate_limiter_get_stats(void)
{
    rate_limiter_stats_t copy;
    portENTER_CRITICAL(&s_lock);
    copy = s_stats;
    portEXIT_CRITICAL(&s_lock);
    return copy;
}

void rate_limiter_foreach_rule(rate_limit_rule_iter_cb_t cb, void *user_ctx)
{
    if (!cb || !s_initialized) return;

    for (int i = 0; i < RATE_LIMITER_MAX_RULES; ++i) {
        rate_limit_rule_t copy;
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
