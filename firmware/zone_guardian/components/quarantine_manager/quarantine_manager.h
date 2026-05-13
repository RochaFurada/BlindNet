#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "esp_err.h"
#include "flow_table.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef QUARANTINE_MAX_ENTRIES
#define QUARANTINE_MAX_ENTRIES 64
#endif

#define QUARANTINE_REASON_LEN 48

typedef enum {
    QUARANTINE_SUBJECT_NONE = 0,
    QUARANTINE_SUBJECT_IP,
    QUARANTINE_SUBJECT_MAC,
    QUARANTINE_SUBJECT_DEVICE_ID
} quarantine_subject_type_t;

typedef enum {
    QUARANTINE_MODE_BLOCK_ALL = 0,
    QUARANTINE_MODE_RESTRICTED,
    QUARANTINE_MODE_LOG_ONLY
} quarantine_mode_t;

typedef enum {
    QUARANTINE_SOURCE_LOCAL_POLICY = 0,
    QUARANTINE_SOURCE_RATE_LIMIT,
    QUARANTINE_SOURCE_SWARM,
    QUARANTINE_SOURCE_MANUAL,
    QUARANTINE_SOURCE_UNKNOWN
} quarantine_source_t;

typedef struct {
    quarantine_subject_type_t type;
    union {
        uint32_t ip;
        uint8_t mac[6];
        uint32_t device_id;
    } id;
} quarantine_subject_t;

typedef struct {
    quarantine_subject_t subject;
    quarantine_mode_t mode;
    quarantine_source_t source;
    uint32_t created_at_ms;
    uint32_t expires_at_ms;
    uint32_t last_hit_ms;
    uint32_t hit_count;
    uint8_t risk_score;
    char reason[QUARANTINE_REASON_LEN];
} quarantine_entry_t;

typedef struct {
    uint32_t default_ttl_ms;
    bool evict_lru_when_full;
} quarantine_manager_config_t;

typedef struct {
    bool quarantined;
    quarantine_mode_t mode;
    quarantine_source_t source;
    uint32_t expires_at_ms;
    uint32_t remaining_ms;
    uint32_t hit_count;
    uint8_t risk_score;
    char reason[QUARANTINE_REASON_LEN];
} quarantine_check_result_t;

typedef struct {
    uint32_t capacity;
    uint32_t active_entries;
    uint64_t added;
    uint64_t refreshed;
    uint64_t removed;
    uint64_t expired;
    uint64_t hits;
    uint64_t misses;
    uint64_t evicted;
    uint64_t invalid_input;
} quarantine_manager_stats_t;

typedef void (*quarantine_iter_cb_t)(const quarantine_entry_t *entry, void *user_ctx);

esp_err_t quarantine_manager_init(const quarantine_manager_config_t *config);
void quarantine_manager_reset(void);

esp_err_t quarantine_manager_add(
    const quarantine_subject_t *subject,
    quarantine_mode_t mode,
    quarantine_source_t source,
    uint32_t ttl_ms,
    uint8_t risk_score,
    const char *reason
);

esp_err_t quarantine_manager_add_ip(
    uint32_t ip,
    quarantine_mode_t mode,
    quarantine_source_t source,
    uint32_t ttl_ms,
    uint8_t risk_score,
    const char *reason
);

esp_err_t quarantine_manager_add_mac(
    const uint8_t mac[6],
    quarantine_mode_t mode,
    quarantine_source_t source,
    uint32_t ttl_ms,
    uint8_t risk_score,
    const char *reason
);

esp_err_t quarantine_manager_add_device_id(
    uint32_t device_id,
    quarantine_mode_t mode,
    quarantine_source_t source,
    uint32_t ttl_ms,
    uint8_t risk_score,
    const char *reason
);

bool quarantine_manager_remove(const quarantine_subject_t *subject);
bool quarantine_manager_remove_ip(uint32_t ip);

bool quarantine_manager_check(
    const quarantine_subject_t *subject,
    quarantine_check_result_t *out_result
);

bool quarantine_manager_check_ip(uint32_t ip, quarantine_check_result_t *out_result);
bool quarantine_manager_check_flow_src(const flow_key_t *key, quarantine_check_result_t *out_result);

uint32_t quarantine_manager_expire_old(void);

quarantine_manager_stats_t quarantine_manager_get_stats(void);
void quarantine_manager_foreach(quarantine_iter_cb_t cb, void *user_ctx);

quarantine_subject_t quarantine_subject_from_ip(uint32_t ip);
quarantine_subject_t quarantine_subject_from_mac(const uint8_t mac[6]);
quarantine_subject_t quarantine_subject_from_device_id(uint32_t device_id);

const char *quarantine_mode_to_string(quarantine_mode_t mode);
const char *quarantine_source_to_string(quarantine_source_t source);

#ifdef __cplusplus
}
#endif
