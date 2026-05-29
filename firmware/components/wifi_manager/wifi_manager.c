#include "wifi_manager.h"

#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "event_bus.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "mbedtls/platform_util.h"
#include "nvs_flash.h"

static const char *TAG = "wifi_manager";

#define WIFI_MANAGER_BIT_STA_CONNECTED  BIT0
#define WIFI_MANAGER_BIT_STA_GOT_IP     BIT1

static EventGroupHandle_t s_event_group = NULL;
static esp_netif_t *s_sta_netif = NULL;
static esp_netif_t *s_ap_netif = NULL;
static wifi_manager_config_t s_config;
static wifi_manager_config_t s_normal_config;

static volatile wifi_manager_sta_state_t s_sta_state = WIFI_MANAGER_STA_DISCONNECTED;
static volatile uint8_t s_sta_retry_count = 0;
static volatile uint8_t s_ap_connected_clients = 0;

static bool s_started = false;
static bool s_normal_config_valid = false;
static bool s_ap_only_active = false;

static void safe_copy(char *dst, size_t dst_size, const char *src)
{
    if (!dst || dst_size == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

static esp_err_t init_nvs_if_needed(void)
{
    esp_err_t ret = nvs_flash_init();

    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS precisa ser apagada/reinicializada");
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }

    return ret;
}

static esp_err_t init_netif_and_event_loop(void)
{
    esp_err_t ret = esp_netif_init();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) return ret;

    ret = esp_event_loop_create_default();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) return ret;

    return ESP_OK;
}

static wifi_auth_mode_t get_ap_auth_mode(const char *password)
{
    if (password == NULL || password[0] == '\0') return WIFI_AUTH_OPEN;
    return WIFI_AUTH_WPA_WPA2_PSK;
}

static void log_mac_address(const char *label, wifi_interface_t interface)
{
    uint8_t mac[6] = {0};

    if (esp_wifi_get_mac(interface, mac) == ESP_OK) {
        ESP_LOGI(TAG, "%s MAC: %02X:%02X:%02X:%02X:%02X:%02X",
                 label, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

static void publish_ap_client_event(zg_event_type_t type, const char *reason, uint8_t aid)
{
    zg_event_t event = {0};
    event.type = type;
    event.device_id = aid;
    safe_copy(event.reason, sizeof(event.reason), reason);
    (void)event_bus_publish(&event);
}

static void handle_wifi_event(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    (void)arg;
    (void)event_base;

    switch (event_id) {
        case WIFI_EVENT_STA_START:
            ESP_LOGI(TAG, "STA iniciado, conectando ao roteador...");
            s_sta_state = WIFI_MANAGER_STA_CONNECTING;
            esp_wifi_connect();
            break;

        case WIFI_EVENT_STA_CONNECTED:
            ESP_LOGI(TAG, "STA conectado ao AP principal");
            s_sta_state = WIFI_MANAGER_STA_CONNECTED;
            s_sta_retry_count = 0;
            if (s_event_group) xEventGroupSetBits(s_event_group, WIFI_MANAGER_BIT_STA_CONNECTED);
            break;

        case WIFI_EVENT_STA_DISCONNECTED:
            ESP_LOGW(TAG, "STA desconectado");
            if (s_event_group) {
                xEventGroupClearBits(s_event_group, WIFI_MANAGER_BIT_STA_CONNECTED | WIFI_MANAGER_BIT_STA_GOT_IP);
            }
            s_sta_state = WIFI_MANAGER_STA_DISCONNECTED;

            if (s_ap_only_active) {
                break;
            }

            if (s_sta_retry_count < s_config.sta_max_retries) {
                s_sta_retry_count++;
                ESP_LOGI(TAG, "Tentando reconectar STA (%u/%u)", s_sta_retry_count, s_config.sta_max_retries);
                s_sta_state = WIFI_MANAGER_STA_CONNECTING;
                esp_wifi_connect();
            } else {
                ESP_LOGE(TAG, "Limite de reconexões STA atingido");
            }
            break;

        case WIFI_EVENT_AP_START:
            ESP_LOGI(TAG, "SoftAP da zona iniciado");
            break;

        case WIFI_EVENT_AP_STOP:
            ESP_LOGW(TAG, "SoftAP da zona parado");
            break;

        case WIFI_EVENT_AP_STACONNECTED: {
            wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)event_data;
            s_ap_connected_clients++;
            ESP_LOGI(TAG, "Cliente entrou. MAC=%02X:%02X:%02X:%02X:%02X:%02X AID=%d clientes=%u",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     event->aid, s_ap_connected_clients);
            publish_ap_client_event(ZG_EVENT_AP_CLIENT_JOINED, "ap_client_joined", event->aid);
            break;
        }

        case WIFI_EVENT_AP_STADISCONNECTED: {
            wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *)event_data;
            if (s_ap_connected_clients > 0) s_ap_connected_clients--;
            ESP_LOGW(TAG, "Cliente saiu. MAC=%02X:%02X:%02X:%02X:%02X:%02X AID=%d clientes=%u",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     event->aid, s_ap_connected_clients);
            publish_ap_client_event(ZG_EVENT_AP_CLIENT_LEFT, "ap_client_left", event->aid);
            break;
        }

        default:
            break;
    }
}

static void handle_ip_event(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    (void)arg;
    (void)event_base;

    if (event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "STA recebeu IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_sta_state = WIFI_MANAGER_STA_GOT_IP;
        if (s_event_group) xEventGroupSetBits(s_event_group, WIFI_MANAGER_BIT_STA_GOT_IP);
    }
}

static esp_err_t configure_sta_from(const wifi_manager_config_t *config)
{
    if (!config) return ESP_ERR_INVALID_ARG;

    wifi_config_t sta_config;
    mbedtls_platform_zeroize(&sta_config, sizeof(sta_config));

    safe_copy((char *)sta_config.sta.ssid, sizeof(sta_config.sta.ssid), config->sta_ssid);
    safe_copy((char *)sta_config.sta.password, sizeof(sta_config.sta.password), config->sta_password);

    sta_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    sta_config.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;

    ESP_LOGI(TAG, "Configurando STA: %s", config->sta_ssid);

    esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    mbedtls_platform_zeroize(&sta_config, sizeof(sta_config));
    return err;
}

static esp_err_t configure_ap_from(const wifi_manager_config_t *config)
{
    if (!config) return ESP_ERR_INVALID_ARG;

    wifi_config_t ap_config;
    mbedtls_platform_zeroize(&ap_config, sizeof(ap_config));

    safe_copy((char *)ap_config.ap.ssid, sizeof(ap_config.ap.ssid), config->ap_ssid);
    safe_copy((char *)ap_config.ap.password, sizeof(ap_config.ap.password), config->ap_password);

    ap_config.ap.ssid_len = strlen(config->ap_ssid);
    ap_config.ap.channel = config->ap_channel ? config->ap_channel : 6;
    ap_config.ap.max_connection = config->ap_max_connections ? config->ap_max_connections : 4;
    ap_config.ap.authmode = get_ap_auth_mode(config->ap_password);
    ap_config.ap.ssid_hidden = config->ap_hidden ? 1 : 0;

    ESP_LOGI(TAG, "Configurando SoftAP: ssid=%s canal=%u max=%u",
             config->ap_ssid, ap_config.ap.channel, ap_config.ap.max_connection);

    esp_err_t err = esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    mbedtls_platform_zeroize(&ap_config, sizeof(ap_config));
    return err;
}

esp_err_t wifi_manager_start(const wifi_manager_config_t *config)
{
    if (!config) return ESP_ERR_INVALID_ARG;
    if (s_started) return ESP_OK;

    mbedtls_platform_zeroize(&s_config, sizeof(s_config));
    memcpy(&s_config, config, sizeof(wifi_manager_config_t));

    if (s_config.ap_channel == 0) s_config.ap_channel = 6;
    if (s_config.ap_max_connections == 0) s_config.ap_max_connections = 4;
    if (s_config.sta_max_retries == 0) s_config.sta_max_retries = 10;
    memcpy(&s_normal_config, &s_config, sizeof(s_normal_config));
    s_normal_config_valid = true;
    s_ap_only_active = false;

    ESP_ERROR_CHECK(init_nvs_if_needed());
    ESP_ERROR_CHECK(init_netif_and_event_loop());

    s_event_group = xEventGroupCreate();
    if (!s_event_group) {
        mbedtls_platform_zeroize(&s_config, sizeof(s_config));
        return ESP_ERR_NO_MEM;
    }

    s_sta_netif = esp_netif_create_default_wifi_sta();
    if (!s_sta_netif) {
        mbedtls_platform_zeroize(&s_config, sizeof(s_config));
        return ESP_FAIL;
    }

    s_ap_netif = esp_netif_create_default_wifi_ap();
    if (!s_ap_netif) {
        mbedtls_platform_zeroize(&s_config, sizeof(s_config));
        return ESP_FAIL;
    }

    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init_cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &handle_wifi_event, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &handle_ip_event, NULL, NULL));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(configure_sta_from(&s_config));
    ESP_ERROR_CHECK(configure_ap_from(&s_config));
    mbedtls_platform_zeroize(s_config.sta_password, sizeof(s_config.sta_password));
    mbedtls_platform_zeroize(s_config.ap_password, sizeof(s_config.ap_password));
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_start());

    log_mac_address("STA", WIFI_IF_STA);
    log_mac_address("AP", WIFI_IF_AP);

    s_started = true;
    ESP_LOGI(TAG, "wifi_manager iniciado em APSTA");

    return ESP_OK;
}

esp_err_t wifi_manager_stop(void)
{
    if (!s_started) return ESP_OK;

    esp_err_t ret = esp_wifi_stop();
    if (ret != ESP_OK) return ret;

    ret = esp_wifi_deinit();
    if (ret != ESP_OK) return ret;

    if (s_event_group) {
        vEventGroupDelete(s_event_group);
        s_event_group = NULL;
    }

    s_sta_netif = NULL;
    s_ap_netif = NULL;
    s_sta_state = WIFI_MANAGER_STA_DISCONNECTED;
    s_sta_retry_count = 0;
    s_ap_connected_clients = 0;
    mbedtls_platform_zeroize(&s_config, sizeof(s_config));
    s_started = false;
    s_normal_config_valid = false;
    s_ap_only_active = false;
    mbedtls_platform_zeroize(&s_normal_config, sizeof(s_normal_config));

    return ESP_OK;
}

esp_err_t wifi_manager_switch_to_ap(
    const char *ssid,
    const char *password,
    uint8_t max_connections
)
{
    if (!s_started || !ssid || ssid[0] == '\0') {
        return ESP_ERR_INVALID_ARG;
    }

    wifi_manager_config_t ap_config;
    mbedtls_platform_zeroize(&ap_config, sizeof(ap_config));
    safe_copy(ap_config.ap_ssid, sizeof(ap_config.ap_ssid), ssid);
    safe_copy(ap_config.ap_password, sizeof(ap_config.ap_password), password);
    ap_config.ap_channel = s_normal_config_valid ? s_normal_config.ap_channel : 6;
    ap_config.ap_max_connections = max_connections ? max_connections : 1;
    ap_config.ap_hidden = false;

    if (s_event_group) {
        xEventGroupClearBits(
            s_event_group,
            WIFI_MANAGER_BIT_STA_CONNECTED | WIFI_MANAGER_BIT_STA_GOT_IP
        );
    }
    s_sta_state = WIFI_MANAGER_STA_DISCONNECTED;
    s_sta_retry_count = 0;
    s_ap_connected_clients = 0;
    s_ap_only_active = true;

    (void)esp_wifi_disconnect();

    esp_err_t err = esp_wifi_set_mode(WIFI_MODE_AP);
    if (err == ESP_OK) {
        err = configure_ap_from(&ap_config);
    }

    mbedtls_platform_zeroize(&ap_config, sizeof(ap_config));

    if (err != ESP_OK) {
        s_ap_only_active = false;
        ESP_LOGE(TAG, "Falha ao alternar WiFi para AP: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGW(TAG, "WiFi alternado para modo AP");
    return ESP_OK;
}

esp_err_t wifi_manager_restore_normal(void)
{
    if (!s_started) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!s_normal_config_valid) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!s_ap_only_active) {
        return ESP_OK;
    }

    ESP_LOGW(TAG, "Restaurando WiFi normal APSTA");

    s_ap_only_active = false;
    s_ap_connected_clients = 0;

    esp_err_t err = esp_wifi_stop();
    if (err == ESP_ERR_WIFI_NOT_STARTED) {
        err = ESP_OK;
    }
    if (err == ESP_OK) {
        err = esp_wifi_set_mode(WIFI_MODE_APSTA);
    }
    if (err == ESP_OK) {
        err = configure_sta_from(&s_normal_config);
    }
    if (err == ESP_OK) {
        err = configure_ap_from(&s_normal_config);
    }
    if (err == ESP_OK) {
        err = esp_wifi_start();
    }
    if (err == ESP_OK) {
        err = esp_wifi_connect();
    }

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Falha ao restaurar WiFi normal: %s", esp_err_to_name(err));
        return err;
    }

    s_sta_state = WIFI_MANAGER_STA_CONNECTING;
    s_sta_retry_count = 0;
    return ESP_OK;
}

bool wifi_manager_is_sta_connected(void)
{
    if (!s_event_group) return false;
    return (xEventGroupGetBits(s_event_group) & WIFI_MANAGER_BIT_STA_CONNECTED) != 0;
}

bool wifi_manager_has_ip(void)
{
    if (!s_event_group) return false;
    return (xEventGroupGetBits(s_event_group) & WIFI_MANAGER_BIT_STA_GOT_IP) != 0;
}

wifi_manager_status_t wifi_manager_get_status(void)
{
    wifi_manager_status_t status = {
        .sta_state = s_sta_state,
        .sta_retry_count = s_sta_retry_count,
        .ap_connected_clients = s_ap_connected_clients
    };
    return status;
}

esp_netif_t *wifi_manager_get_sta_netif(void)
{
    return s_sta_netif;
}

esp_netif_t *wifi_manager_get_ap_netif(void)
{
    return s_ap_netif;
}

esp_err_t wifi_manager_get_ap_ip(uint32_t *out_ip)
{
    if (!out_ip) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_ap_netif) {
        return ESP_ERR_INVALID_STATE;
    }

    esp_netif_ip_info_t ip_info;
    esp_err_t err = esp_netif_get_ip_info(s_ap_netif, &ip_info);
    if (err != ESP_OK) {
        return err;
    }

    *out_ip = ip_info.ip.addr;
    return ESP_OK;
}
