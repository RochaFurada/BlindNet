#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ADMIN_SERVER_MODE_BOOTSTRAP = 0,
    ADMIN_SERVER_MODE_MAINTENANCE = 1
} admin_server_mode_t;

typedef struct {
    const char *setup_ap_ssid;
    const char *setup_ap_password;
    admin_server_mode_t mode;
    uint32_t guardian_id;
    uint32_t zone_id;
    void (*on_window_closed)(void *ctx);
    void *ctx;
} admin_server_config_t;

esp_err_t admin_server_start(const admin_server_config_t *config);
esp_err_t admin_server_open_window(const admin_server_config_t *config, uint32_t timeout_ms);
esp_err_t admin_server_stop(void);
bool admin_server_is_running(void);
bool admin_server_is_unlocked(void);
void admin_server_lock(void);
void admin_server_note_mqtt_client(const char *client_id);

#ifdef __cplusplus
}
#endif
