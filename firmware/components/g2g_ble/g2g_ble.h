#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define G2G_BLE_FRAGMENT_MAX_LEN 220
#define G2G_BLE_MAX_PEERS 8
#define G2G_BLE_TX_QUEUE_LEN 16

typedef void (*g2g_ble_fragment_cb_t)(
    const uint8_t *bytes,
    size_t len,
    void *ctx
);

typedef struct {
    uint32_t guardian_id;
    uint32_t zone_id;
    g2g_ble_fragment_cb_t on_fragment;
    void *ctx;
} g2g_ble_config_t;

typedef struct {
    uint64_t discovered_peers;
    uint64_t queued_fragments;
    uint64_t tx_fragments;
    uint64_t tx_errors;
    uint64_t rx_fragments;
    uint64_t rx_errors;
} g2g_ble_stats_t;

esp_err_t g2g_ble_start(const g2g_ble_config_t *config);
esp_err_t g2g_ble_stop(void);
bool g2g_ble_is_running(void);

esp_err_t g2g_ble_send_fragment(const uint8_t *bytes, size_t len);

g2g_ble_stats_t g2g_ble_get_stats(void);

#ifdef __cplusplus
}
#endif
