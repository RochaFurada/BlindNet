#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DEVICE_REGISTRY_MAX_DEVICES
#define DEVICE_REGISTRY_MAX_DEVICES 32
#endif

#define DEVICE_REGISTRY_NAME_LEN 32
#define DEVICE_REGISTRY_PROFILE_LEN 24

typedef enum {
    DEVICE_STATE_UNKNOWN = 0,
    DEVICE_STATE_TRUSTED,
    DEVICE_STATE_SUSPICIOUS,
    DEVICE_STATE_QUARANTINED,
    DEVICE_STATE_BLOCKED
} device_state_t;

typedef struct {
    uint32_t device_id;
    uint8_t mac[6];
    uint32_t ip;
    uint32_t zone_id;
    device_state_t state;
    uint8_t risk_score;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
    char name[DEVICE_REGISTRY_NAME_LEN];
    char profile[DEVICE_REGISTRY_PROFILE_LEN];
} device_record_t;

typedef struct {
    uint32_t capacity;
    uint32_t active_devices;
    uint64_t added;
    uint64_t updated;
    uint64_t removed;
    uint64_t lookups;
    uint64_t misses;
} device_registry_stats_t;

typedef void (*device_registry_iter_cb_t)(const device_record_t *record, void *ctx);

esp_err_t device_registry_init(uint32_t zone_id);
void device_registry_reset(void);

esp_err_t device_registry_upsert_mac_ip(
    const uint8_t mac[6],
    uint32_t ip,
    const char *name,
    const char *profile,
    device_record_t *out_record
);

bool device_registry_find_by_ip(uint32_t ip, device_record_t *out_record);
bool device_registry_find_by_mac(const uint8_t mac[6], device_record_t *out_record);
bool device_registry_find_by_id(uint32_t device_id, device_record_t *out_record);

bool device_registry_set_state_by_ip(uint32_t ip, device_state_t state, uint8_t risk_score);
bool device_registry_set_state_by_id(uint32_t device_id, device_state_t state, uint8_t risk_score);

bool device_registry_remove_by_ip(uint32_t ip);

void device_registry_foreach(device_registry_iter_cb_t cb, void *ctx);
device_registry_stats_t device_registry_get_stats(void);

uint32_t device_registry_make_id_from_mac(const uint8_t mac[6]);
const char *device_state_to_string(device_state_t state);

#ifdef __cplusplus
}
#endif
