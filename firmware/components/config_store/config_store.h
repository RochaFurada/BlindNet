#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CONFIG_STORE_SSID_LEN 32
#define CONFIG_STORE_PASS_LEN 64
#define CONFIG_STORE_HOST_LEN 64
#define CONFIG_STORE_PUBLIC_KEY_MAX_LEN 512
#define CONFIG_STORE_KEY_ID_LEN 16

typedef struct {
    uint32_t magic;
    uint32_t version;

    uint32_t zone_id;
    uint32_t guardian_id;

    char issuer_public_key_pem[CONFIG_STORE_PUBLIC_KEY_MAX_LEN];
    uint8_t issuer_key_id[CONFIG_STORE_KEY_ID_LEN];

    char sta_ssid[CONFIG_STORE_SSID_LEN];
    char sta_password[CONFIG_STORE_PASS_LEN];
    char ap_ssid[CONFIG_STORE_SSID_LEN];
    char ap_password[CONFIG_STORE_PASS_LEN];

    uint8_t ap_channel;
    uint8_t ap_max_connections;

    uint16_t swarm_port;
    char swarm_broadcast[CONFIG_STORE_HOST_LEN];

    char telemetry_host[CONFIG_STORE_HOST_LEN];
    uint16_t telemetry_port;

    uint8_t swarm_key[32];
    uint8_t swarm_key_len;

    uint32_t policy_version;
} zoneguard_config_t;

esp_err_t config_store_init(void);
esp_err_t config_store_load(zoneguard_config_t *out_config);
esp_err_t config_store_save(const zoneguard_config_t *config);
esp_err_t config_store_erase(void);
void config_store_set_defaults(zoneguard_config_t *config);

#ifdef __cplusplus
}
#endif
