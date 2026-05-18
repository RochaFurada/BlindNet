#include "zone_gateway.h"

#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "wifi_manager.h"

static const char *TAG = "zone_gateway";

#define ZONE_GATEWAY_TASK_STACK_SIZE  4096
#define ZONE_GATEWAY_TASK_PRIORITY    5

static TaskHandle_t s_task = NULL;

static zone_gateway_config_t s_config;

static volatile zone_gateway_state_t s_state = ZONE_GATEWAY_STATE_STOPPED;
static volatile bool s_napt_enabled = false;
static volatile bool s_stop_requested = false;
static volatile uint32_t s_start_attempts = 0;
static volatile uint32_t s_last_error = ESP_OK;

static void load_default_config(zone_gateway_config_t *config)
{
    memset(config, 0, sizeof(*config));
    config->wait_for_sta_ip = true;
    config->wait_interval_ms = 500;
    config->uplink_timeout_ms = 30000;
    config->set_sta_as_default = true;
    config->auto_recover = false;
}

static esp_err_t enable_gateway_napt(void)
{
    esp_netif_t *sta_netif = wifi_manager_get_sta_netif();
    esp_netif_t *ap_netif = wifi_manager_get_ap_netif();

    if (!sta_netif || !ap_netif) {
        ESP_LOGE(TAG, "netif STA/AP inválida");
        return ESP_ERR_INVALID_STATE;
    }

    if (s_config.set_sta_as_default) {
        esp_err_t err = esp_netif_set_default_netif(sta_netif);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Falha ao definir STA como default: %s", esp_err_to_name(err));
            return err;
        }
    }

    esp_err_t err = esp_netif_napt_enable(ap_netif);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Falha ao habilitar NAPT: %s", esp_err_to_name(err));
        return err;
    }

    s_napt_enabled = true;
    ESP_LOGI(TAG, "NAPT habilitado no AP");
    return ESP_OK;
}

static esp_err_t disable_gateway_napt(void)
{
    esp_netif_t *ap_netif = wifi_manager_get_ap_netif();
    if (!ap_netif) return ESP_ERR_INVALID_STATE;

    esp_err_t err = esp_netif_napt_disable(ap_netif);
    if (err == ESP_OK) {
        s_napt_enabled = false;
        ESP_LOGI(TAG, "NAPT desabilitado");
    }
    return err;
}

static bool wait_for_uplink_ip(void)
{
    const uint32_t interval = s_config.wait_interval_ms ? s_config.wait_interval_ms : 500;
    uint32_t waited = 0;

    ESP_LOGI(TAG, "Aguardando IP do STA...");

    while (!s_stop_requested) {
        if (wifi_manager_has_ip()) return true;

        if (s_config.uplink_timeout_ms > 0 && waited >= s_config.uplink_timeout_ms) {
            ESP_LOGE(TAG, "Timeout aguardando uplink");
            return false;
        }

        vTaskDelay(pdMS_TO_TICKS(interval));
        waited += interval;
    }

    return false;
}

static void gateway_task(void *arg)
{
    (void)arg;

    s_state = ZONE_GATEWAY_STATE_WAITING_UPLINK;
    s_napt_enabled = false;
    s_last_error = ESP_OK;

    if (s_config.wait_for_sta_ip) {
        if (!wait_for_uplink_ip()) {
            s_state = ZONE_GATEWAY_STATE_ERROR;
            s_last_error = ESP_ERR_TIMEOUT;
            s_task = NULL;
            vTaskDelete(NULL);
            return;
        }
    }

    s_start_attempts++;

    esp_err_t err = enable_gateway_napt();
    if (err != ESP_OK) {
        s_state = ZONE_GATEWAY_STATE_ERROR;
        s_last_error = err;
        s_task = NULL;
        vTaskDelete(NULL);
        return;
    }

    s_state = ZONE_GATEWAY_STATE_RUNNING;

    while (!s_stop_requested) {
        if (s_config.auto_recover) {
            if (!wifi_manager_has_ip()) {
                s_state = ZONE_GATEWAY_STATE_WAITING_UPLINK;
            } else if (s_state == ZONE_GATEWAY_STATE_WAITING_UPLINK) {
                s_state = ZONE_GATEWAY_STATE_RUNNING;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    disable_gateway_napt();

    s_state = ZONE_GATEWAY_STATE_STOPPED;
    s_task = NULL;

    vTaskDelete(NULL);
}

esp_err_t zone_gateway_start(const zone_gateway_config_t *config)
{
    if (s_task) return ESP_OK;

    load_default_config(&s_config);
    if (config) {
        s_config = *config;
        if (s_config.wait_interval_ms == 0) s_config.wait_interval_ms = 500;
    }

    s_stop_requested = false;
    s_state = ZONE_GATEWAY_STATE_WAITING_UPLINK;
    s_napt_enabled = false;
    s_last_error = ESP_OK;

    if (xTaskCreate(gateway_task, "zone_gateway", ZONE_GATEWAY_TASK_STACK_SIZE, NULL,
                    ZONE_GATEWAY_TASK_PRIORITY, &s_task) != pdPASS) {
        s_state = ZONE_GATEWAY_STATE_ERROR;
        s_last_error = ESP_ERR_NO_MEM;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "ZoneGateway task criada");
    return ESP_OK;
}

esp_err_t zone_gateway_start_and_wait(
    const zone_gateway_config_t *config,
    uint32_t timeout_ms,
    uint32_t poll_ms
)
{
    esp_err_t err = zone_gateway_start(config);
    if (err != ESP_OK) {
        return err;
    }

    if (poll_ms == 0) {
        poll_ms = 250;
    }

    uint32_t waited = 0;
    while (waited < timeout_ms) {
        if (zone_gateway_is_running() && zone_gateway_is_napt_enabled()) {
            return ESP_OK;
        }

        vTaskDelay(pdMS_TO_TICKS(poll_ms));
        waited += poll_ms;
    }

    return ESP_ERR_TIMEOUT;
}

esp_err_t zone_gateway_stop(void)
{
    if (!s_task) return ESP_OK;
    s_stop_requested = true;
    return ESP_OK;
}

zone_gateway_status_t zone_gateway_get_status(void)
{
    zone_gateway_status_t status = {
        .state = s_state,
        .napt_enabled = s_napt_enabled,
        .sta_has_ip = wifi_manager_has_ip(),
        .start_attempts = s_start_attempts,
        .last_error = s_last_error
    };
    return status;
}

bool zone_gateway_is_running(void)
{
    return s_state == ZONE_GATEWAY_STATE_RUNNING;
}

bool zone_gateway_is_napt_enabled(void)
{
    return s_napt_enabled;
}
