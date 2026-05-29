#include "setup_button.h"

#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "setup_button";

static setup_button_config_t s_config;
static TaskHandle_t s_task = NULL;
static volatile bool s_running = false;

static bool button_pressed(void)
{
    int level = gpio_get_level((gpio_num_t)s_config.gpio_num);
    return s_config.active_low ? level == 0 : level != 0;
}

static void setup_button_task(void *arg)
{
    (void)arg;

    const TickType_t poll_ticks = pdMS_TO_TICKS(s_config.poll_ms);
    uint32_t pressed_ms = 0;
    bool armed = true;

    while (s_running) {
        if (button_pressed()) {
            if (pressed_ms < s_config.hold_ms) {
                pressed_ms += s_config.poll_ms;
            }

            if (armed && pressed_ms >= s_config.hold_ms) {
                armed = false;
                ESP_LOGW(TAG, "botao de setup segurado por %lu ms",
                         (unsigned long)s_config.hold_ms);
                if (s_config.on_hold) {
                    s_config.on_hold(s_config.ctx);
                }
            }
        } else {
            pressed_ms = 0;
            armed = true;
        }

        vTaskDelay(poll_ticks);
    }

    s_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t setup_button_start(const setup_button_config_t *config)
{
    if (s_running) {
        return ESP_OK;
    }

    if (!config || !config->on_hold) {
        return ESP_ERR_INVALID_ARG;
    }

    s_config = *config;
    if (s_config.gpio_num < 0) {
        s_config.gpio_num = SETUP_BUTTON_DEFAULT_GPIO;
    }
    if (s_config.gpio_num >= GPIO_NUM_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_config.hold_ms == 0) {
        s_config.hold_ms = SETUP_BUTTON_DEFAULT_HOLD_MS;
    }
    if (s_config.poll_ms == 0) {
        s_config.poll_ms = SETUP_BUTTON_DEFAULT_POLL_MS;
    }

    gpio_config_t io_config = {
        .pin_bit_mask = 1ULL << (uint32_t)s_config.gpio_num,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = s_config.active_low ? GPIO_PULLUP_ENABLE : GPIO_PULLUP_DISABLE,
        .pull_down_en = s_config.active_low ? GPIO_PULLDOWN_DISABLE : GPIO_PULLDOWN_ENABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };

    esp_err_t err = gpio_config(&io_config);
    if (err != ESP_OK) {
        return err;
    }

    s_running = true;
    BaseType_t created = xTaskCreate(
        setup_button_task,
        "setup_button",
        2048,
        NULL,
        5,
        &s_task
    );

    if (created != pdPASS) {
        s_running = false;
        s_task = NULL;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "setup_button ativo gpio=%d hold=%lu ms",
             s_config.gpio_num, (unsigned long)s_config.hold_ms);
    return ESP_OK;
}

esp_err_t setup_button_stop(void)
{
    if (!s_running) {
        return ESP_OK;
    }

    s_running = false;
    return ESP_OK;
}

bool setup_button_is_running(void)
{
    return s_running;
}
