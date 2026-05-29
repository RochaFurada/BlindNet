#include "setup_ap.h"

#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "mbedtls/platform_util.h"

static const char *TAG = "setup_ap";
static esp_netif_t *s_setup_ap_netif = NULL;

static void copy_str(char *dst, size_t dst_size, const char *src)
{
    if (!dst || dst_size == 0) {
        return;
    }

    if (!src) {
        dst[0] = '\0';
        return;
    }

    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

esp_err_t setup_ap_start(const char *ssid, const char *password)
{
    if (!ssid || ssid[0] == '\0') {
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGW(TAG, "Iniciando AP temporario de setup");

    esp_err_t ret = esp_netif_init();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        return ret;
    }

    ret = esp_event_loop_create_default();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        return ret;
    }

    s_setup_ap_netif = esp_netif_create_default_wifi_ap();
    if (!s_setup_ap_netif) {
        ESP_LOGE(TAG, "Falha ao criar netif AP de setup");
        return ESP_FAIL;
    }

    wifi_init_config_t wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();
    ret = esp_wifi_init(&wifi_init_config);
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        return ret;
    }

    ret = esp_wifi_set_mode(WIFI_MODE_AP);
    if (ret != ESP_OK) {
        return ret;
    }

    wifi_config_t ap_config;
    mbedtls_platform_zeroize(&ap_config, sizeof(ap_config));

    copy_str((char *)ap_config.ap.ssid, sizeof(ap_config.ap.ssid), ssid);
    copy_str((char *)ap_config.ap.password, sizeof(ap_config.ap.password), password);

    ap_config.ap.ssid_len = strlen(ssid);
    ap_config.ap.channel = 6;
    ap_config.ap.max_connection = 2;
    ap_config.ap.ssid_hidden = 0;

    if (password && strlen(password) >= 8) {
        ap_config.ap.authmode = WIFI_AUTH_WPA_WPA2_PSK;
    } else {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
        ap_config.ap.password[0] = '\0';
    }

    ret = esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    mbedtls_platform_zeroize(&ap_config, sizeof(ap_config));
    if (ret != ESP_OK) {
        return ret;
    }

    ret = esp_wifi_start();
    if (ret != ESP_OK) {
        return ret;
    }

    ESP_LOGW(TAG, "AP de setup iniciado");
    return ESP_OK;
}
