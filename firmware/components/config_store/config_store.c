#include "config_store.h"
#include "event_bus.h"

#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_random.h"

static const char *TAG = "config_store";
static const char *NVS_NS = "zoneguard";
static const char *NVS_KEY = "config_blob";

#define ZG_CONFIG_MAGIC 0x5A474346u
#define ZG_CONFIG_VERSION 2u

static bool s_initialized = false;

static void cfg_copy(char *dst, size_t size, const char *src)
{
    if (!dst || size == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    strncpy(dst, src, size - 1);
    dst[size - 1] = '\0';
}

void config_store_set_defaults(zoneguard_config_t *config)
{
    if (!config) return;

    memset(config, 0, sizeof(*config));

    config->magic = ZG_CONFIG_MAGIC;
    config->version = ZG_CONFIG_VERSION;

    config->zone_id = 1;
    config->guardian_id = esp_random();

    cfg_copy(config->sta_ssid, sizeof(config->sta_ssid), "TATIANE");
    cfg_copy(config->sta_password, sizeof(config->sta_password), "88090133");
    cfg_copy(config->ap_ssid, sizeof(config->ap_ssid), "ZG_SALA");
    cfg_copy(config->ap_password, sizeof(config->ap_password), "zoneguard123");

    config->ap_channel = 6;
    config->ap_max_connections = 4;

    config->swarm_port = 4747;
    cfg_copy(config->swarm_broadcast, sizeof(config->swarm_broadcast), "255.255.255.255");

    cfg_copy(config->telemetry_host, sizeof(config->telemetry_host), "");
    config->telemetry_port = 5757;

    config->swarm_key_len = 16;
    for (int i = 0; i < config->swarm_key_len; ++i) {
        config->swarm_key[i] = (uint8_t)esp_random();
    }

    config->policy_version = 1;
}

esp_err_t config_store_init(void)
{
    esp_err_t ret = nvs_flash_init();

    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }

    if (ret == ESP_OK) s_initialized = true;
    return ret;
}

esp_err_t config_store_load(zoneguard_config_t *out_config)
{
    if (!s_initialized || !out_config) return ESP_ERR_INVALID_ARG;

    nvs_handle_t h;
    esp_err_t ret = nvs_open(NVS_NS, NVS_READONLY, &h);

    if (ret != ESP_OK) {
        config_store_set_defaults(out_config);
        return ESP_ERR_NOT_FOUND;
    }

    size_t size = sizeof(*out_config);
    ret = nvs_get_blob(h, NVS_KEY, out_config, &size);
    nvs_close(h);

    if (ret != ESP_OK || size != sizeof(*out_config) ||
        out_config->magic != ZG_CONFIG_MAGIC ||
        out_config->version != ZG_CONFIG_VERSION) {
        config_store_set_defaults(out_config);
        return ESP_ERR_NOT_FOUND;
    }

    ESP_LOGI(TAG, "config carregada zone=%lu guardian=%lu",
             (unsigned long)out_config->zone_id,
             (unsigned long)out_config->guardian_id);

    return ESP_OK;
}

esp_err_t config_store_save(const zoneguard_config_t *config)
{
    if (!s_initialized || !config) return ESP_ERR_INVALID_ARG;

    nvs_handle_t h;
    esp_err_t ret = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (ret != ESP_OK) return ret;

    ret = nvs_set_blob(h, NVS_KEY, config, sizeof(*config));
    if (ret == ESP_OK) ret = nvs_commit(h);

    nvs_close(h);

    if (ret == ESP_OK) {
        zg_event_t ev = {0};
        ev.type = ZG_EVENT_CONFIG_UPDATED;
        ev.zone_id = config->zone_id;
        ev.code = config->policy_version;
        snprintf(ev.reason, sizeof(ev.reason), "config_saved");
        event_bus_publish(&ev);
    }

    return ret;
}

esp_err_t config_store_erase(void)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    nvs_handle_t h;
    esp_err_t ret = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (ret != ESP_OK) return ret;

    ret = nvs_erase_key(h, NVS_KEY);
    if (ret == ESP_OK || ret == ESP_ERR_NVS_NOT_FOUND) ret = nvs_commit(h);

    nvs_close(h);
    return ret;
}
