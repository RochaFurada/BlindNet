#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_netif.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ZONE_GATEWAY_STATE_STOPPED = 0,
    ZONE_GATEWAY_STATE_WAITING_UPLINK,
    ZONE_GATEWAY_STATE_RUNNING,
    ZONE_GATEWAY_STATE_ERROR
} zone_gateway_state_t;

typedef struct {
    bool wait_for_sta_ip;
    uint32_t wait_interval_ms;
    uint32_t uplink_timeout_ms;
    bool set_sta_as_default;
    bool auto_recover;
} zone_gateway_config_t;

typedef struct {
    zone_gateway_state_t state;
    bool napt_enabled;
    bool sta_has_ip;
    uint32_t start_attempts;
    uint32_t last_error;
} zone_gateway_status_t;

esp_err_t zone_gateway_start(const zone_gateway_config_t *config);
esp_err_t zone_gateway_stop(void);

zone_gateway_status_t zone_gateway_get_status(void);

bool zone_gateway_is_running(void);
bool zone_gateway_is_napt_enabled(void);

#ifdef __cplusplus
}
#endif
