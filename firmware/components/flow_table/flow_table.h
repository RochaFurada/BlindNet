#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef FLOW_TABLE_MAX_ENTRIES
#define FLOW_TABLE_MAX_ENTRIES 128
#endif

typedef enum {
    FLOW_PROTO_UNKNOWN = 0,
    FLOW_PROTO_TCP     = 6,
    FLOW_PROTO_UDP     = 17,
    FLOW_PROTO_ICMP    = 1
} flow_proto_t;

typedef enum {
    FLOW_DIRECTION_UNKNOWN = 0,
    FLOW_DIRECTION_ZONE_TO_UPLINK,
    FLOW_DIRECTION_UPLINK_TO_ZONE,
    FLOW_DIRECTION_ZONE_TO_ZONE
} flow_direction_t;

typedef enum {
    FLOW_STATE_EMPTY = 0,
    FLOW_STATE_ACTIVE,
    FLOW_STATE_QUARANTINED,
    FLOW_STATE_BLOCKED,
    FLOW_STATE_EXPIRED
} flow_state_t;

typedef enum {
    FLOW_TOUCH_CREATED = 0,
    FLOW_TOUCH_UPDATED,
    FLOW_TOUCH_EVICTED_OLD_ENTRY,
    FLOW_TOUCH_FAILED_TABLE_DISABLED,
    FLOW_TOUCH_FAILED_INVALID_ARG
} flow_touch_result_t;

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
} flow_key_t;

typedef struct {
    flow_key_t key;
    flow_direction_t direction;
    flow_state_t state;
    uint64_t packets;
    uint64_t bytes;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
    uint32_t last_policy_action;
    uint32_t flags;
    uint8_t risk_score;
    uint8_t reserved[3];
} flow_entry_t;

typedef struct {
    uint32_t max_idle_ms;
    uint32_t hard_ttl_ms;
    bool evict_lru_when_full;
} flow_table_config_t;

typedef struct {
    uint32_t capacity;
    uint32_t active_entries;
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t created_flows;
    uint64_t updated_flows;
    uint64_t evicted_flows;
    uint64_t expired_flows;
    uint64_t dropped_updates;
} flow_table_stats_t;

typedef void (*flow_table_iter_cb_t)(const flow_entry_t *entry, void *user_ctx);

esp_err_t flow_table_init(const flow_table_config_t *config);
void flow_table_reset(void);

flow_touch_result_t flow_table_touch(
    const flow_key_t *key,
    flow_direction_t direction,
    uint32_t bytes,
    flow_entry_t *out_entry
);

bool flow_table_find(const flow_key_t *key, flow_entry_t *out_entry);

bool flow_table_set_state(const flow_key_t *key, flow_state_t state);
bool flow_table_set_risk(const flow_key_t *key, uint8_t risk_score);
bool flow_table_set_policy_action(const flow_key_t *key, uint32_t action);

uint32_t flow_table_expire_old(void);

flow_table_stats_t flow_table_get_stats(void);

void flow_table_foreach(flow_table_iter_cb_t cb, void *user_ctx);

uint32_t flow_table_hash_key(const flow_key_t *key);
bool flow_table_key_equals(const flow_key_t *a, const flow_key_t *b);

#ifdef __cplusplus
}
#endif
