#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t setup_ap_start(const char *ssid, const char *password);

#ifdef __cplusplus
}
#endif
