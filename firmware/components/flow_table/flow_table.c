#include "flow_table.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"

static const char *TAG = "flow_table";

typedef struct {
    bool in_use;
    flow_entry_t entry;
} flow_slot_t;

static flow_slot_t s_slots[FLOW_TABLE_MAX_ENTRIES];
static flow_table_config_t s_config;
static flow_table_stats_t s_stats;
static bool s_initialized = false;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000ULL);
}

static void load_default_config(flow_table_config_t *config)
{
    memset(config, 0, sizeof(*config));
    config->max_idle_ms = 60000;
    config->hard_ttl_ms = 10 * 60000;
    config->evict_lru_when_full = true;
}

bool flow_table_key_equals(const flow_key_t *a, const flow_key_t *b)
{
    if (!a || !b) return false;
    return a->src_ip == b->src_ip &&
           a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

uint32_t flow_table_hash_key(const flow_key_t *key)
{
    if (!key) return 0;

    const uint8_t *data = (const uint8_t *)key;
    uint32_t hash = 2166136261u;

    for (size_t i = 0; i < sizeof(flow_key_t); ++i) {
        hash ^= data[i];
        hash *= 16777619u;
    }

    return hash;
}

static int find_existing_slot_locked(const flow_key_t *key)
{
    for (int i = 0; i < FLOW_TABLE_MAX_ENTRIES; ++i) {
        if (s_slots[i].in_use && flow_table_key_equals(&s_slots[i].entry.key, key)) return i;
    }
    return -1;
}

static int find_empty_slot_locked(void)
{
    for (int i = 0; i < FLOW_TABLE_MAX_ENTRIES; ++i) {
        if (!s_slots[i].in_use) return i;
    }
    return -1;
}

static int find_lru_slot_locked(void)
{
    int lru_index = -1;
    uint32_t oldest = UINT32_MAX;

    for (int i = 0; i < FLOW_TABLE_MAX_ENTRIES; ++i) {
        if (!s_slots[i].in_use) continue;
        if (s_slots[i].entry.last_seen_ms < oldest) {
            oldest = s_slots[i].entry.last_seen_ms;
            lru_index = i;
        }
    }

    return lru_index;
}

static void clear_slot_locked(int index)
{
    if (index < 0 || index >= FLOW_TABLE_MAX_ENTRIES) return;

    if (s_slots[index].in_use && s_stats.active_entries > 0) {
        s_stats.active_entries--;
    }

    memset(&s_slots[index], 0, sizeof(s_slots[index]));
}

static void create_entry_locked(int index, const flow_key_t *key, flow_direction_t direction, uint32_t bytes, uint32_t ts)
{
    flow_entry_t *entry = &s_slots[index].entry;

    memset(entry, 0, sizeof(*entry));

    entry->key = *key;
    entry->direction = direction;
    entry->state = FLOW_STATE_ACTIVE;
    entry->packets = 1;
    entry->bytes = bytes;
    entry->first_seen_ms = ts;
    entry->last_seen_ms = ts;

    s_slots[index].in_use = true;

    s_stats.active_entries++;
    s_stats.total_packets++;
    s_stats.total_bytes += bytes;
    s_stats.created_flows++;
}

static void update_entry_locked(int index, flow_direction_t direction, uint32_t bytes, uint32_t ts)
{
    flow_entry_t *entry = &s_slots[index].entry;

    entry->direction = direction;
    entry->packets++;
    entry->bytes += bytes;
    entry->last_seen_ms = ts;

    if (entry->state == FLOW_STATE_EMPTY || entry->state == FLOW_STATE_EXPIRED) {
        entry->state = FLOW_STATE_ACTIVE;
    }

    s_stats.total_packets++;
    s_stats.total_bytes += bytes;
    s_stats.updated_flows++;
}

esp_err_t flow_table_init(const flow_table_config_t *config)
{
    portENTER_CRITICAL(&s_lock);

    memset(s_slots, 0, sizeof(s_slots));
    memset(&s_stats, 0, sizeof(s_stats));

    load_default_config(&s_config);

    if (config) {
        s_config = *config;
        if (s_config.max_idle_ms == 0) s_config.max_idle_ms = 60000;
        if (s_config.hard_ttl_ms == 0) s_config.hard_ttl_ms = 10 * 60000;
    }

    s_stats.capacity = FLOW_TABLE_MAX_ENTRIES;
    s_initialized = true;

    portEXIT_CRITICAL(&s_lock);

    ESP_LOGI(TAG, "flow_table init capacity=%u", FLOW_TABLE_MAX_ENTRIES);

    return ESP_OK;
}

void flow_table_reset(void)
{
    portENTER_CRITICAL(&s_lock);
    memset(s_slots, 0, sizeof(s_slots));
    memset(&s_stats, 0, sizeof(s_stats));
    s_stats.capacity = FLOW_TABLE_MAX_ENTRIES;
    portEXIT_CRITICAL(&s_lock);
}

flow_touch_result_t flow_table_touch(const flow_key_t *key, flow_direction_t direction, uint32_t bytes, flow_entry_t *out_entry)
{
    if (!key) return FLOW_TOUCH_FAILED_INVALID_ARG;
    if (!s_initialized) return FLOW_TOUCH_FAILED_TABLE_DISABLED;

    const uint32_t ts = now_ms();

    portENTER_CRITICAL(&s_lock);

    int index = find_existing_slot_locked(key);
    if (index >= 0) {
        update_entry_locked(index, direction, bytes, ts);
        if (out_entry) *out_entry = s_slots[index].entry;
        portEXIT_CRITICAL(&s_lock);
        return FLOW_TOUCH_UPDATED;
    }

    index = find_empty_slot_locked();

    if (index >= 0) {
        create_entry_locked(index, key, direction, bytes, ts);
        if (out_entry) *out_entry = s_slots[index].entry;
        portEXIT_CRITICAL(&s_lock);
        return FLOW_TOUCH_CREATED;
    }

    if (!s_config.evict_lru_when_full) {
        s_stats.dropped_updates++;
        portEXIT_CRITICAL(&s_lock);
        return FLOW_TOUCH_FAILED_TABLE_DISABLED;
    }

    index = find_lru_slot_locked();
    if (index < 0) {
        s_stats.dropped_updates++;
        portEXIT_CRITICAL(&s_lock);
        return FLOW_TOUCH_FAILED_TABLE_DISABLED;
    }

    clear_slot_locked(index);
    s_stats.evicted_flows++;

    create_entry_locked(index, key, direction, bytes, ts);
    if (out_entry) *out_entry = s_slots[index].entry;

    portEXIT_CRITICAL(&s_lock);

    return FLOW_TOUCH_EVICTED_OLD_ENTRY;
}

bool flow_table_find(const flow_key_t *key, flow_entry_t *out_entry)
{
    if (!key || !out_entry || !s_initialized) return false;

    bool found = false;

    portENTER_CRITICAL(&s_lock);
    int index = find_existing_slot_locked(key);
    if (index >= 0) {
        *out_entry = s_slots[index].entry;
        found = true;
    }
    portEXIT_CRITICAL(&s_lock);

    return found;
}

bool flow_table_set_state(const flow_key_t *key, flow_state_t state)
{
    if (!key || !s_initialized) return false;

    bool ok = false;
    portENTER_CRITICAL(&s_lock);
    int index = find_existing_slot_locked(key);
    if (index >= 0) {
        s_slots[index].entry.state = state;
        ok = true;
    }
    portEXIT_CRITICAL(&s_lock);
    return ok;
}

bool flow_table_set_risk(const flow_key_t *key, uint8_t risk_score)
{
    if (!key || !s_initialized) return false;
    if (risk_score > 100) risk_score = 100;

    bool ok = false;
    portENTER_CRITICAL(&s_lock);
    int index = find_existing_slot_locked(key);
    if (index >= 0) {
        s_slots[index].entry.risk_score = risk_score;
        ok = true;
    }
    portEXIT_CRITICAL(&s_lock);
    return ok;
}

bool flow_table_set_policy_action(const flow_key_t *key, uint32_t action)
{
    if (!key || !s_initialized) return false;

    bool ok = false;
    portENTER_CRITICAL(&s_lock);
    int index = find_existing_slot_locked(key);
    if (index >= 0) {
        s_slots[index].entry.last_policy_action = action;
        ok = true;
    }
    portEXIT_CRITICAL(&s_lock);
    return ok;
}

uint32_t flow_table_expire_old(void)
{
    if (!s_initialized) return 0;

    const uint32_t ts = now_ms();
    uint32_t expired = 0;

    portENTER_CRITICAL(&s_lock);

    for (int i = 0; i < FLOW_TABLE_MAX_ENTRIES; ++i) {
        if (!s_slots[i].in_use) continue;

        flow_entry_t *entry = &s_slots[i].entry;
        uint32_t idle_ms = ts - entry->last_seen_ms;
        uint32_t age_ms = ts - entry->first_seen_ms;

        if (idle_ms > s_config.max_idle_ms || age_ms > s_config.hard_ttl_ms) {
            clear_slot_locked(i);
            expired++;
        }
    }

    s_stats.expired_flows += expired;
    portEXIT_CRITICAL(&s_lock);

    return expired;
}

flow_table_stats_t flow_table_get_stats(void)
{
    flow_table_stats_t copy;
    portENTER_CRITICAL(&s_lock);
    copy = s_stats;
    portEXIT_CRITICAL(&s_lock);
    return copy;
}

void flow_table_foreach(flow_table_iter_cb_t cb, void *user_ctx)
{
    if (!cb || !s_initialized) return;

    for (int i = 0; i < FLOW_TABLE_MAX_ENTRIES; ++i) {
        flow_entry_t copy;
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
