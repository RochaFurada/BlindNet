#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SETUP_BUTTON_DEFAULT_GPIO 0
#define SETUP_BUTTON_DEFAULT_HOLD_MS 5000
#define SETUP_BUTTON_DEFAULT_POLL_MS 50

typedef void (*setup_button_cb_t)(void *ctx);

typedef struct {
    int gpio_num;
    bool active_low;
    uint32_t hold_ms;
    uint32_t poll_ms;
    setup_button_cb_t on_hold;
    void *ctx;
} setup_button_config_t;

esp_err_t setup_button_start(const setup_button_config_t *config);
esp_err_t setup_button_stop(void);
bool setup_button_is_running(void);

#ifdef __cplusplus
}
#endif
