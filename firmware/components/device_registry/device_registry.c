#include "device_registry.h"
#include "event_bus.h"

#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"

static const char *TAG = "device_registry";

typedef struct {
    bool in_use;
    device_record_t record;
} device_slot_t;

static device_slot_t s_devices[DEVICE_REGISTRY_MAX_DEVICES];
static device_registry_stats_t s_stats;
static uint32_t s_zone_id = 1;
static bool s_initialized = false;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000ULL);
}

static void safe_copy(char *dst, size_t size, const char *src)
{
    if (!dst || size == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    strncpy(dst, src, size - 1);
    dst[size - 1] = '\0';
}

static bool mac_valid(const uint8_t mac[6])
{
    if (!mac) return false;
    const uint8_t zero[6] = {0};
    return memcmp(mac, zero, 6) != 0;
}

static bool mac_equal(const uint8_t a[6], const uint8_t b[6])
{
    return memcmp(a, b, 6) == 0;
}

uint32_t device_registry_make_id_from_mac(const uint8_t mac[6])
{
    if (!mac) return 0;
    uint32_t h = 2166136261u;
    for (int i = 0; i < 6; ++i) {
        h ^= mac[i];
        h *= 16777619u;
    }
    return h == 0 ? 1 : h;
}

const char *device_state_to_string(device_state_t state)
{
    switch (state) {
        case DEVICE_STATE_UNKNOWN: return "UNKNOWN";
        case DEVICE_STATE_TRUSTED: return "TRUSTED";
        case DEVICE_STATE_SUSPICIOUS: return "SUSPICIOUS";
        case DEVICE_STATE_QUARANTINED: return "QUARANTINED";
        case DEVICE_STATE_BLOCKED: return "BLOCKED";
        default: return "INVALID";
    }
}

static int find_by_ip_locked(uint32_t ip)
{
    for (int i = 0; i < DEVICE_REGISTRY_MAX_DEVICES; ++i) {
        if (s_devices[i].in_use && s_devices[i].record.ip == ip) return i;
    }
    return -1;
}

static int find_by_mac_locked(const uint8_t mac[6])
{
    for (int i = 0; i < DEVICE_REGISTRY_MAX_DEVICES; ++i) {
        if (s_devices[i].in_use && mac_equal(s_devices[i].record.mac, mac)) return i;
    }
    return -1;
}

static int find_by_id_locked(uint32_t device_id)
{
    for (int i = 0; i < DEVICE_REGISTRY_MAX_DEVICES; ++i) {
        if (s_devices[i].in_use && s_devices[i].record.device_id == device_id) return i;
    }
    return -1;
}

static int find_empty_locked(void)
{
    for (int i = 0; i < DEVICE_REGISTRY_MAX_DEVICES; ++i) {
        if (!s_devices[i].in_use) return i;
    }
    return -1;
}

esp_err_t device_registry_init(uint32_t zone_id)
{
    portENTER_CRITICAL(&s_lock);
    memset(s_devices, 0, sizeof(s_devices));
    memset(&s_stats, 0, sizeof(s_stats));
    s_stats.capacity = DEVICE_REGISTRY_MAX_DEVICES;
    s_zone_id = zone_id;
    s_initialized = true;
    portEXIT_CRITICAL(&s_lock);

    ESP_LOGI(TAG, "device_registry iniciado zone=%lu", (unsigned long)zone_id);
    return ESP_OK;
}

void device_registry_reset(void)
{
    portENTER_CRITICAL(&s_lock);
    memset(s_devices, 0, sizeof(s_devices));
    memset(&s_stats, 0, sizeof(s_stats));
    s_stats.capacity = DEVICE_REGISTRY_MAX_DEVICES;
    portEXIT_CRITICAL(&s_lock);
}

esp_err_t device_registry_upsert_mac_ip(
    const uint8_t mac[6],
    uint32_t ip,
    const char *name,
    const char *profile,
    device_record_t *out_record
)
{
    if (!s_initialized || !mac_valid(mac) || ip == 0) return ESP_ERR_INVALID_ARG;

    const uint32_t ts = now_ms();
    bool created = false;
    device_record_t copy;

    portENTER_CRITICAL(&s_lock);

    int idx = find_by_mac_locked(mac);
    if (idx < 0) idx = find_by_ip_locked(ip);

    if (idx < 0) {
        idx = find_empty_locked();
        if (idx < 0) {
            portEXIT_CRITICAL(&s_lock);
            return ESP_ERR_NO_MEM;
        }

        memset(&s_devices[idx], 0, sizeof(s_devices[idx]));
        s_devices[idx].in_use = true;
        s_devices[idx].record.device_id = device_registry_make_id_from_mac(mac);
        memcpy(s_devices[idx].record.mac, mac, 6);
        s_devices[idx].record.zone_id = s_zone_id;
        s_devices[idx].record.state = DEVICE_STATE_UNKNOWN;
        s_devices[idx].record.first_seen_ms = ts;
        s_stats.active_devices++;
        s_stats.added++;
        created = true;
    } else {
        s_stats.updated++;
    }

    s_devices[idx].record.ip = ip;
    s_devices[idx].record.last_seen_ms = ts;

    if (name) safe_copy(s_devices[idx].record.name, sizeof(s_devices[idx].record.name), name);
    if (profile) safe_copy(s_devices[idx].record.profile, sizeof(s_devices[idx].record.profile), profile);

    copy = s_devices[idx].record;
    if (out_record) *out_record = copy;

    portEXIT_CRITICAL(&s_lock);

    if (created) {
        zg_event_t ev = {0};
        ev.type = ZG_EVENT_DEVICE_JOINED;
        ev.zone_id = s_zone_id;
        ev.device_id = copy.device_id;
        ev.src_ip = copy.ip;
        snprintf(ev.reason, sizeof(ev.reason), "device_joined");
        event_bus_publish(&ev);
    }

    return ESP_OK;
}

bool device_registry_find_by_ip(uint32_t ip, device_record_t *out_record)
{
    if (!s_initialized || !out_record || ip == 0) return false;

    bool ok = false;
    portENTER_CRITICAL(&s_lock);
    s_stats.lookups++;
    int idx = find_by_ip_locked(ip);
    if (idx >= 0) { *out_record = s_devices[idx].record; ok = true; }
    else s_stats.misses++;
    portEXIT_CRITICAL(&s_lock);
    return ok;
}

bool device_registry_find_by_mac(const uint8_t mac[6], device_record_t *out_record)
{
    if (!s_initialized || !out_record || !mac_valid(mac)) return false;

    bool ok = false;
    portENTER_CRITICAL(&s_lock);
    s_stats.lookups++;
    int idx = find_by_mac_locked(mac);
    if (idx >= 0) { *out_record = s_devices[idx].record; ok = true; }
    else s_stats.misses++;
    portEXIT_CRITICAL(&s_lock);
    return ok;
}

bool device_registry_find_by_id(uint32_t device_id, device_record_t *out_record)
{
    if (!s_initialized || !out_record || device_id == 0) return false;

    bool ok = false;
    portENTER_CRITICAL(&s_lock);
    s_stats.lookups++;
    int idx = find_by_id_locked(device_id);
    if (idx >= 0) { *out_record = s_devices[idx].record; ok = true; }
    else s_stats.misses++;
    portEXIT_CRITICAL(&s_lock);
    return ok;
}

bool device_registry_set_state_by_ip(uint32_t ip, device_state_t state, uint8_t risk_score)
{
    if (!s_initialized || ip == 0) return false;

    bool ok = false;
    uint32_t device_id = 0;

    portENTER_CRITICAL(&s_lock);
    int idx = find_by_ip_locked(ip);
    if (idx >= 0) {
        s_devices[idx].record.state = state;
        s_devices[idx].record.risk_score = risk_score > 100 ? 100 : risk_score;
        device_id = s_devices[idx].record.device_id;
        ok = true;
    }
    portEXIT_CRITICAL(&s_lock);

    if (ok && state == DEVICE_STATE_QUARANTINED) {
        zg_event_t ev = {0};
        ev.type = ZG_EVENT_DEVICE_QUARANTINED;
        ev.zone_id = s_zone_id;
        ev.device_id = device_id;
        ev.src_ip = ip;
        ev.risk_score = risk_score;
        snprintf(ev.reason, sizeof(ev.reason), "registry_state_quarantined");
        event_bus_publish(&ev);
    }

    return ok;
}

bool device_registry_set_state_by_id(uint32_t device_id, device_state_t state, uint8_t risk_score)
{
    if (!s_initialized || device_id == 0) return false;

    bool ok = false;
    uint32_t ip = 0;

    portENTER_CRITICAL(&s_lock);
    int idx = find_by_id_locked(device_id);
    if (idx >= 0) {
        s_devices[idx].record.state = state;
        s_devices[idx].record.risk_score = risk_score > 100 ? 100 : risk_score;
        ip = s_devices[idx].record.ip;
        ok = true;
    }
    portEXIT_CRITICAL(&s_lock);

    if (ok && state == DEVICE_STATE_QUARANTINED) {
        zg_event_t ev = {0};
        ev.type = ZG_EVENT_DEVICE_QUARANTINED;
        ev.zone_id = s_zone_id;
        ev.device_id = device_id;
        ev.src_ip = ip;
        ev.risk_score = risk_score;
        snprintf(ev.reason, sizeof(ev.reason), "registry_state_quarantined");
        event_bus_publish(&ev);
    }

    return ok;
}

bool device_registry_remove_by_ip(uint32_t ip)
{
    if (!s_initialized || ip == 0) return false;

    bool ok = false;
    portENTER_CRITICAL(&s_lock);
    int idx = find_by_ip_locked(ip);
    if (idx >= 0) {
        memset(&s_devices[idx], 0, sizeof(s_devices[idx]));
        if (s_stats.active_devices > 0) s_stats.active_devices--;
        s_stats.removed++;
        ok = true;
    }
    portEXIT_CRITICAL(&s_lock);
    return ok;
}

void device_registry_foreach(device_registry_iter_cb_t cb, void *ctx)
{
    if (!cb || !s_initialized) return;

    for (int i = 0; i < DEVICE_REGISTRY_MAX_DEVICES; ++i) {
        device_record_t copy;
        bool has = false;

        portENTER_CRITICAL(&s_lock);
        if (s_devices[i].in_use) {
            copy = s_devices[i].record;
            has = true;
        }
        portEXIT_CRITICAL(&s_lock);

        if (has) cb(&copy, ctx);
    }
}

device_registry_stats_t device_registry_get_stats(void)
{
    device_registry_stats_t copy;
    portENTER_CRITICAL(&s_lock);
    copy = s_stats;
    portEXIT_CRITICAL(&s_lock);
    return copy;
}
