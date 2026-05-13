#include "zone_firewall.h"
#include "event_bus.h"
#include "device_registry.h"

#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"

static const char *TAG = "zone_firewall";

static zone_firewall_config_t s_config;
static zone_firewall_stats_t s_stats;
static bool s_initialized = false;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

const char *zone_firewall_verdict_to_string(zone_firewall_verdict_t verdict)
{
    switch (verdict) {
        case ZONE_FIREWALL_VERDICT_ALLOW: return "ALLOW";
        case ZONE_FIREWALL_VERDICT_DROP: return "DROP";
        case ZONE_FIREWALL_VERDICT_REDIRECT: return "REDIRECT";
        case ZONE_FIREWALL_VERDICT_LOG_ONLY: return "LOG_ONLY";
        default: return "UNKNOWN";
    }
}

static void set_reason(char *dst, size_t size, const char *reason)
{
    if (!dst || size == 0) return;
    if (!reason) { dst[0] = '\0'; return; }
    strncpy(dst, reason, size - 1);
    dst[size - 1] = '\0';
}

static void publish_event(zg_event_type_t type, const flow_key_t *key, uint8_t risk, const char *reason)
{
    zg_event_t ev = {0};

    ev.type = type;
    ev.zone_id = s_config.zone_id;
    ev.src_ip = key ? key->src_ip : 0;
    ev.dst_ip = key ? key->dst_ip : 0;
    ev.src_port = key ? key->src_port : 0;
    ev.dst_port = key ? key->dst_port : 0;
    ev.proto = key ? key->proto : 0;
    ev.risk_score = risk;

    snprintf(ev.reason, sizeof(ev.reason), "%s", reason ? reason : "");
    event_bus_publish(&ev);
}

esp_err_t zone_firewall_init(const zone_firewall_config_t *config)
{
    memset(&s_config, 0, sizeof(s_config));

    if (config) s_config = *config;

    if (s_config.quarantine_ttl_ms == 0) s_config.quarantine_ttl_ms = 60000;

    memset(&s_stats, 0, sizeof(s_stats));

    s_initialized = true;

    ESP_LOGI(TAG, "zone_firewall iniciado zone=%lu", (unsigned long)s_config.zone_id);

    return ESP_OK;
}

esp_err_t zone_firewall_evaluate_flow(
    const flow_key_t *key,
    flow_direction_t direction,
    uint32_t packet_bytes,
    zone_firewall_decision_t *out_decision
)
{
    if (!s_initialized || !key || !out_decision) return ESP_ERR_INVALID_ARG;

    memset(out_decision, 0, sizeof(*out_decision));
    out_decision->verdict = ZONE_FIREWALL_VERDICT_ALLOW;
    out_decision->policy_action = POLICY_ACTION_ALLOW;

    portENTER_CRITICAL(&s_lock);
    s_stats.evaluations++;
    portEXIT_CRITICAL(&s_lock);

    flow_entry_t entry;
    flow_table_touch(key, direction, packet_bytes, &entry);

    quarantine_check_result_t q;

    if (quarantine_manager_check_flow_src(key, &q)) {
        out_decision->quarantined = true;
        out_decision->risk_score = q.risk_score;
        set_reason(out_decision->reason, sizeof(out_decision->reason), q.reason);

        if (q.mode == QUARANTINE_MODE_BLOCK_ALL) {
            out_decision->verdict = ZONE_FIREWALL_VERDICT_DROP;

            portENTER_CRITICAL(&s_lock);
            s_stats.dropped++;
            s_stats.quarantined_hits++;
            portEXIT_CRITICAL(&s_lock);

            publish_event(ZG_EVENT_POLICY_DENY, key, q.risk_score, "quarantine_block");

            return ESP_OK;
        }
    }

    policy_decision_t p;

    if (policy_engine_evaluate(key, direction, &p) != ESP_OK) {
        out_decision->verdict = s_config.default_allow ?
            ZONE_FIREWALL_VERDICT_ALLOW :
            ZONE_FIREWALL_VERDICT_DROP;
    } else {
        out_decision->policy_action = p.action;
        out_decision->risk_score = p.risk_score;
        set_reason(out_decision->reason, sizeof(out_decision->reason), p.reason_text);

        if (p.action == POLICY_ACTION_DENY) {
            out_decision->verdict = ZONE_FIREWALL_VERDICT_DROP;

            portENTER_CRITICAL(&s_lock);
            s_stats.dropped++;
            s_stats.policy_denied++;
            portEXIT_CRITICAL(&s_lock);

            publish_event(ZG_EVENT_POLICY_DENY, key, p.risk_score, p.reason_text);

            return ESP_OK;
        }

        if (p.action == POLICY_ACTION_QUARANTINE) {
            quarantine_manager_add_ip(
                key->src_ip,
                QUARANTINE_MODE_BLOCK_ALL,
                QUARANTINE_SOURCE_LOCAL_POLICY,
                s_config.quarantine_ttl_ms,
                p.risk_score,
                p.reason_text
            );

            device_registry_set_state_by_ip(key->src_ip, DEVICE_STATE_QUARANTINED, p.risk_score);

            out_decision->verdict = ZONE_FIREWALL_VERDICT_DROP;

            portENTER_CRITICAL(&s_lock);
            s_stats.dropped++;
            s_stats.policy_denied++;
            portEXIT_CRITICAL(&s_lock);

            publish_event(ZG_EVENT_DEVICE_QUARANTINED, key, p.risk_score, p.reason_text);

            return ESP_OK;
        }

        if (p.action == POLICY_ACTION_REDIRECT) {
            out_decision->verdict = ZONE_FIREWALL_VERDICT_REDIRECT;

            portENTER_CRITICAL(&s_lock);
            s_stats.redirected++;
            portEXIT_CRITICAL(&s_lock);

            return ESP_OK;
        }
    }

    rate_limit_result_t r;

    if (rate_limiter_check(key, direction, packet_bytes, &r) == ESP_OK &&
        r.decision == RATE_LIMIT_DECISION_EXCEEDED) {

        out_decision->rate_exceeded = true;
        if (out_decision->risk_score < 80) out_decision->risk_score = 80;
        set_reason(out_decision->reason, sizeof(out_decision->reason), r.reason_text);

        portENTER_CRITICAL(&s_lock);
        s_stats.rate_exceeded++;
        portEXIT_CRITICAL(&s_lock);

        publish_event(ZG_EVENT_RATE_EXCEEDED, key, out_decision->risk_score, r.reason_text);

        if (s_config.auto_quarantine_on_rate_limit && r.suggest_quarantine) {
            quarantine_manager_add_ip(
                key->src_ip,
                QUARANTINE_MODE_BLOCK_ALL,
                QUARANTINE_SOURCE_RATE_LIMIT,
                s_config.quarantine_ttl_ms,
                out_decision->risk_score,
                r.reason_text
            );

            device_registry_set_state_by_ip(
                key->src_ip,
                DEVICE_STATE_QUARANTINED,
                out_decision->risk_score
            );
        }

        out_decision->verdict = ZONE_FIREWALL_VERDICT_DROP;

        portENTER_CRITICAL(&s_lock);
        s_stats.dropped++;
        portEXIT_CRITICAL(&s_lock);

        return ESP_OK;
    }

    if (out_decision->policy_action == POLICY_ACTION_LOG_ONLY) {
        out_decision->verdict = ZONE_FIREWALL_VERDICT_LOG_ONLY;
        publish_event(ZG_EVENT_FLOW_SEEN, key, out_decision->risk_score, out_decision->reason);
    } else {
        out_decision->verdict = ZONE_FIREWALL_VERDICT_ALLOW;
    }

    portENTER_CRITICAL(&s_lock);
    s_stats.allowed++;
    portEXIT_CRITICAL(&s_lock);

    return ESP_OK;
}

zone_firewall_stats_t zone_firewall_get_stats(void)
{
    zone_firewall_stats_t copy;

    portENTER_CRITICAL(&s_lock);
    copy = s_stats;
    portEXIT_CRITICAL(&s_lock);

    return copy;
}
