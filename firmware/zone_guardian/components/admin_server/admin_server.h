#pragma once

#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *setup_ap_ssid;
    const char *setup_ap_password;
} admin_server_config_t;

esp_err_t admin_server_start(const admin_server_config_t *config);
esp_err_t admin_server_stop(void);
bool admin_server_is_running(void);

#ifdef __cplusplus
}
#endif