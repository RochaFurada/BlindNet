#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_netif.h"
#include "esp_wifi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WIFI_MANAGER_MAX_SSID_LEN      32
#define WIFI_MANAGER_MAX_PASSWORD_LEN  64

typedef struct {
    char sta_ssid[WIFI_MANAGER_MAX_SSID_LEN];
    char sta_password[WIFI_MANAGER_MAX_PASSWORD_LEN];

    char ap_ssid[WIFI_MANAGER_MAX_SSID_LEN];
    char ap_password[WIFI_MANAGER_MAX_PASSWORD_LEN];

    uint8_t ap_channel;
    uint8_t ap_max_connections;
    uint8_t sta_max_retries;

    bool ap_hidden;
} wifi_manager_config_t;

typedef enum {
    WIFI_MANAGER_STA_DISCONNECTED = 0,
    WIFI_MANAGER_STA_CONNECTING,
    WIFI_MANAGER_STA_CONNECTED,
    WIFI_MANAGER_STA_GOT_IP
} wifi_manager_sta_state_t;

typedef struct {
    wifi_manager_sta_state_t sta_state;
    uint8_t sta_retry_count;
    uint8_t ap_connected_clients;
} wifi_manager_status_t;

esp_err_t wifi_manager_start(const wifi_manager_config_t *config);
esp_err_t wifi_manager_stop(void);

bool wifi_manager_is_sta_connected(void);
bool wifi_manager_has_ip(void);

wifi_manager_status_t wifi_manager_get_status(void);

esp_netif_t *wifi_manager_get_sta_netif(void);
esp_netif_t *wifi_manager_get_ap_netif(void);
esp_err_t wifi_manager_get_ap_ip(uint32_t *out_ip);

#ifdef __cplusplus
}
#endif
