#include "quarantine_manager.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"

static const char *TAG = "quarantine_manager";

typedef struct {
    bool in_use;
    quarantine_entry_t entry;
} quarantine_slot_t;

static quarantine_slot_t s_slots[QUARANTINE_MAX_ENTRIES];
static quarantine_manager_config_t s_config;
static quarantine_manager_stats_t s_stats;
static bool s_initialized = false;
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

const char *quarantine_mode_to_string(quarantine_mode_t mode)
{
    switch (mode) {
        case QUARANTINE_MODE_BLOCK_ALL: return "BLOCK_ALL";
        case QUARANTINE_MODE_RESTRICTED: return "RESTRICTED";
        case QUARANTINE_MODE_LOG_ONLY: return "LOG_ONLY";
        default: return "UNKNOWN";
    }
}

const char *quarantine_source_to_string(quarantine_source_t source)
{
    switch (source) {
        case QUARANTINE_SOURCE_LOCAL_POLICY: return "LOCAL_POLICY";
        case QUARANTINE_SOURCE_RATE_LIMIT: return "RATE_LIMIT";
        case QUARANTINE_SOURCE_SWARM: return "SWARM";
        case QUARANTINE_SOURCE_MANUAL: return "MANUAL";
        case QUARANTINE_SOURCE_UNKNOWN: return "UNKNOWN";
        default: return "UNKNOWN";
    }
}

static void load_default_config(quarantine_manager_config_t *config)
{
    memset(config, 0, sizeof(*config));
    config->default_ttl_ms = 60000;
    config->evict_lru_when_full = true;
}

quarantine_subject_t quarantine_subject_from_ip(uint32_t ip)
{
    quarantine_subject_t subject;
    memset(&subject, 0, sizeof(subject));
    subject.type = QUARANTINE_SUBJECT_IP;
    subject.id.ip = ip;
    return subject;
}

quarantine_subject_t quarantine_subject_from_mac(const uint8_t mac[6])
{
    quarantine_subject_t subject;
    memset(&subject, 0, sizeof(subject));
    subject.type = QUARANTINE_SUBJECT_MAC;
    if (mac) memcpy(subject.id.mac, mac, 6);
    return subject;
}

quarantine_subject_t quarantine_subject_from_device_id(uint32_t device_id)
{
    quarantine_subject_t subject;
    memset(&subject, 0, sizeof(subject));
    subject.type = QUARANTINE_SUBJECT_DEVICE_ID;
    subject.id.device_id = device_id;
    return subject;
}

static bool subject_is_valid(const quarantine_subject_t *subject)
{
    if (!subject) return false;

    switch (subject->type) {
        case QUARANTINE_SUBJECT_IP:
            return subject->id.ip != 0;

        case QUARANTINE_SUBJECT_MAC: {
            const uint8_t zero[6] = {0};
            return memcmp(subject->id.mac, zero, 6) != 0;
        }

        case QUARANTINE_SUBJECT_DEVICE_ID:
            return subject->id.device_id != 0;

        default:
            return false;
    }
}

static bool subject_equals(const quarantine_subject_t *a, const quarantine_subject_t *b)
{
    if (!a || !b) return false;
    if (a->type != b->type) return false;

    switch (a->type) {
        case QUARANTINE_SUBJECT_IP:
            return a->id.ip == b->id.ip;
        case QUARANTINE_SUBJECT_MAC:
            return memcmp(a->id.mac, b->id.mac, 6) == 0;
        case QUARANTINE_SUBJECT_DEVICE_ID:
            return a->id.device_id == b->id.device_id;
        default:
            return false;
    }
}

static bool entry_is_expired(const quarantine_entry_t *entry, uint32_t ts)
{
    if (!entry) return true;
    if (entry->expires_at_ms == 0) return false;
    return ts >= entry->expires_at_ms;
}

static int find_slot_locked(const quarantine_subject_t *subject)
{
    for (int i = 0; i < QUARANTINE_MAX_ENTRIES; ++i) {
        if (!s_slots[i].in_use) continue;
        if (subject_equals(&s_slots[i].entry.subject, subject)) return i;
    }
    return -1;
}

static int find_empty_slot_locked(void)
{
    for (int i = 0; i < QUARANTINE_MAX_ENTRIES; ++i) {
        if (!s_slots[i].in_use) return i;
    }
    return -1;
}

static int find_lru_slot_locked(void)
{
    int lru_index = -1;
    uint32_t oldest = UINT32_MAX;

    for (int i = 0; i < QUARANTINE_MAX_ENTRIES; ++i) {
        if (!s_slots[i].in_use) continue;

        uint32_t candidate = s_slots[i].entry.last_hit_ms;
        if (candidate == 0) candidate = s_slots[i].entry.created_at_ms;

        if (candidate < oldest) {
            oldest = candidate;
            lru_index = i;
        }
    }

    return lru_index;
}

static void clear_slot_locked(int index)
{
    if (index < 0 || index >= QUARANTINE_MAX_ENTRIES) return;

    if (s_slots[index].in_use && s_stats.active_entries > 0) {
        s_stats.active_entries--;
    }

    memset(&s_slots[index], 0, sizeof(s_slots[index]));
}

static void fill_check_result(quarantine_check_result_t *result, const quarantine_entry_t *entry, uint32_t ts)
{
    memset(result, 0, sizeof(*result));

    if (!entry) {
        result->quarantined = false;
        return;
    }

    result->quarantined = true;
    result->mode = entry->mode;
    result->source = entry->source;
    result->expires_at_ms = entry->expires_at_ms;
    result->hit_count = entry->hit_count;
    result->risk_score = entry->risk_score;

    if (entry->expires_at_ms == 0 || entry->expires_at_ms <= ts) result->remaining_ms = 0;
    else result->remaining_ms = entry->expires_at_ms - ts;

    safe_copy_reason(result->reason, sizeof(result->reason), entry->reason);
}

esp_err_t quarantine_manager_init(const quarantine_manager_config_t *config)
{
    portENTER_CRITICAL(&s_lock);

    memset(s_slots, 0, sizeof(s_slots));
    memset(&s_stats, 0, sizeof(s_stats));

    load_default_config(&s_config);

    if (config) {
        s_config = *config;
        if (s_config.default_ttl_ms == 0) s_config.default_ttl_ms = 60000;
    }

    s_stats.capacity = QUARANTINE_MAX_ENTRIES;
    s_initialized = true;

    portEXIT_CRITICAL(&s_lock);

    ESP_LOGI(TAG, "quarantine_manager init capacity=%u", QUARANTINE_MAX_ENTRIES);

    return ESP_OK;
}

void quarantine_manager_reset(void)
{
    portENTER_CRITICAL(&s_lock);
    memset(s_slots, 0, sizeof(s_slots));
    memset(&s_stats, 0, sizeof(s_stats));
    s_stats.capacity = QUARANTINE_MAX_ENTRIES;
    portEXIT_CRITICAL(&s_lock);
}

esp_err_t quarantine_manager_add(const quarantine_subject_t *subject, quarantine_mode_t mode,
                                 quarantine_source_t source, uint32_t ttl_ms,
                                 uint8_t risk_score, const char *reason)
{
    if (!s_initialized || !subject_is_valid(subject)) {
        portENTER_CRITICAL(&s_lock);
        s_stats.invalid_input++;
        portEXIT_CRITICAL(&s_lock);
        return ESP_ERR_INVALID_ARG;
    }

    if (ttl_ms == 0) ttl_ms = s_config.default_ttl_ms;
    if (risk_score > 100) risk_score = 100;

    const uint32_t ts = now_ms();

    esp_err_t result = ESP_OK;
    bool refreshed = false;

    portENTER_CRITICAL(&s_lock);

    int slot = find_slot_locked(subject);

    if (slot >= 0) {
        quarantine_entry_t *entry = &s_slots[slot].entry;
        entry->mode = mode;
        entry->source = source;
        entry->expires_at_ms = ts + ttl_ms;
        entry->risk_score = risk_score;
        safe_copy_reason(entry->reason, sizeof(entry->reason), reason);
        s_stats.refreshed++;
        refreshed = true;
    } else {
        slot = find_empty_slot_locked();

        if (slot < 0) {
            if (!s_config.evict_lru_when_full) {
                result = ESP_ERR_NO_MEM;
            } else {
                slot = find_lru_slot_locked();
                if (slot < 0) result = ESP_ERR_NO_MEM;
                else {
                    clear_slot_locked(slot);
                    s_stats.evicted++;
                }
            }
        }

        if (result == ESP_OK) {
            quarantine_entry_t *entry = &s_slots[slot].entry;
            memset(entry, 0, sizeof(*entry));

            entry->subject = *subject;
            entry->mode = mode;
            entry->source = source;
            entry->created_at_ms = ts;
            entry->expires_at_ms = ts + ttl_ms;
            entry->risk_score = risk_score;
            safe_copy_reason(entry->reason, sizeof(entry->reason), reason);

            s_slots[slot].in_use = true;
            s_stats.active_entries++;
            s_stats.added++;
        }
    }

    portEXIT_CRITICAL(&s_lock);

    if (result == ESP_OK) {
        ESP_LOGW(TAG, "%s quarentena: mode=%s source=%s ttl=%lums risk=%u reason=%s",
                 refreshed ? "Atualizada" : "Adicionada",
                 quarantine_mode_to_string(mode),
                 quarantine_source_to_string(source),
                 (unsigned long)ttl_ms,
                 risk_score,
                 reason ? reason : "");
    }

    return result;
}

esp_err_t quarantine_manager_add_ip(uint32_t ip, quarantine_mode_t mode, quarantine_source_t source,
                                    uint32_t ttl_ms, uint8_t risk_score, const char *reason)
{
    quarantine_subject_t subject = quarantine_subject_from_ip(ip);
    return quarantine_manager_add(&subject, mode, source, ttl_ms, risk_score, reason);
}

esp_err_t quarantine_manager_add_mac(const uint8_t mac[6], quarantine_mode_t mode,
                                     quarantine_source_t source, uint32_t ttl_ms,
                                     uint8_t risk_score, const char *reason)
{
    quarantine_subject_t subject = quarantine_subject_from_mac(mac);
    return quarantine_manager_add(&subject, mode, source, ttl_ms, risk_score, reason);
}

esp_err_t quarantine_manager_add_device_id(uint32_t device_id, quarantine_mode_t mode,
                                           quarantine_source_t source, uint32_t ttl_ms,
                                           uint8_t risk_score, const char *reason)
{
    quarantine_subject_t subject = quarantine_subject_from_device_id(device_id);
    return quarantine_manager_add(&subject, mode, source, ttl_ms, risk_score, reason);
}

bool quarantine_manager_remove(const quarantine_subject_t *subject)
{
    if (!s_initialized || !subject_is_valid(subject)) return false;

    bool removed = false;

    portENTER_CRITICAL(&s_lock);
    int slot = find_slot_locked(subject);
    if (slot >= 0) {
        clear_slot_locked(slot);
        s_stats.removed++;
        removed = true;
    }
    portEXIT_CRITICAL(&s_lock);

    return removed;
}

bool quarantine_manager_remove_ip(uint32_t ip)
{
    quarantine_subject_t subject = quarantine_subject_from_ip(ip);
    return quarantine_manager_remove(&subject);
}

bool quarantine_manager_check(const quarantine_subject_t *subject, quarantine_check_result_t *out_result)
{
    if (!out_result) return false;
    memset(out_result, 0, sizeof(*out_result));

    if (!s_initialized || !subject_is_valid(subject)) {
        portENTER_CRITICAL(&s_lock);
        s_stats.invalid_input++;
        portEXIT_CRITICAL(&s_lock);
        return false;
    }

    const uint32_t ts = now_ms();
    bool found = false;

    portENTER_CRITICAL(&s_lock);

    int slot = find_slot_locked(subject);

    if (slot >= 0) {
        quarantine_entry_t *entry = &s_slots[slot].entry;

        if (entry_is_expired(entry, ts)) {
            clear_slot_locked(slot);
            s_stats.expired++;
            s_stats.misses++;
            found = false;
        } else {
            entry->hit_count++;
            entry->last_hit_ms = ts;
            fill_check_result(out_result, entry, ts);
            s_stats.hits++;
            found = true;
        }
    } else {
        s_stats.misses++;
    }

    portEXIT_CRITICAL(&s_lock);

    return found;
}

bool quarantine_manager_check_ip(uint32_t ip, quarantine_check_result_t *out_result)
{
    quarantine_subject_t subject = quarantine_subject_from_ip(ip);
    return quarantine_manager_check(&subject, out_result);
}

bool quarantine_manager_check_flow_src(const flow_key_t *key, quarantine_check_result_t *out_result)
{
    if (!key) {
        if (out_result) memset(out_result, 0, sizeof(*out_result));
        return false;
    }
    return quarantine_manager_check_ip(key->src_ip, out_result);
}

uint32_t quarantine_manager_expire_old(void)
{
    if (!s_initialized) return 0;

    const uint32_t ts = now_ms();
    uint32_t expired = 0;

    portENTER_CRITICAL(&s_lock);

    for (int i = 0; i < QUARANTINE_MAX_ENTRIES; ++i) {
        if (!s_slots[i].in_use) continue;

        if (entry_is_expired(&s_slots[i].entry, ts)) {
            clear_slot_locked(i);
            expired++;
        }
    }

    s_stats.expired += expired;

    portEXIT_CRITICAL(&s_lock);

    return expired;
}

quarantine_manager_stats_t quarantine_manager_get_stats(void)
{
    quarantine_manager_stats_t copy;
    portENTER_CRITICAL(&s_lock);
    copy = s_stats;
    portEXIT_CRITICAL(&s_lock);
    return copy;
}

void quarantine_manager_foreach(quarantine_iter_cb_t cb, void *user_ctx)
{
    if (!cb || !s_initialized) return;

    for (int i = 0; i < QUARANTINE_MAX_ENTRIES; ++i) {
        quarantine_entry_t copy;
        bool has = false;

        portENTER_CRITICAL(&s_lock);
        if (s_slots[i].in_use) {
            copy = s_slots[i].entry;
            has = true;
        }
        portEXIT_CRITICAL(&s_lock);

        if (has) cb(&copy, user_ctx);
    }
}
