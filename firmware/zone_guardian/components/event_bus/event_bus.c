#include "event_bus.h"

#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "freertos/portmacro.h"

static const char *TAG = "event_bus";

#ifndef EVENT_BUS_MAX_LISTENERS
#define EVENT_BUS_MAX_LISTENERS 8
#endif

typedef struct {
    event_bus_listener_t cb;
    void *ctx;
} listener_slot_t;

static QueueHandle_t s_queue = NULL;
static TaskHandle_t s_task = NULL;
static listener_slot_t s_listeners[EVENT_BUS_MAX_LISTENERS];
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static bool s_initialized = false;

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000ULL);
}

static void dispatch_task(void *arg)
{
    (void)arg;
    zg_event_t event;

    while (true) {
        if (xQueueReceive(s_queue, &event, portMAX_DELAY) == pdTRUE) {
            listener_slot_t local[EVENT_BUS_MAX_LISTENERS];

            portENTER_CRITICAL(&s_lock);
            memcpy(local, s_listeners, sizeof(local));
            portEXIT_CRITICAL(&s_lock);

            for (int i = 0; i < EVENT_BUS_MAX_LISTENERS; ++i) {
                if (local[i].cb) {
                    local[i].cb(&event, local[i].ctx);
                }
            }
        }
    }
}

esp_err_t event_bus_init(void)
{
    if (s_initialized) return ESP_OK;

    memset(s_listeners, 0, sizeof(s_listeners));

    s_queue = xQueueCreate(EVENT_BUS_QUEUE_LEN, sizeof(zg_event_t));
    if (!s_queue) return ESP_ERR_NO_MEM;

    if (xTaskCreate(dispatch_task, "event_bus", 4096, NULL, 5, &s_task) != pdPASS) {
        vQueueDelete(s_queue);
        s_queue = NULL;
        return ESP_ERR_NO_MEM;
    }

    s_initialized = true;
    ESP_LOGI(TAG, "event_bus iniciado");
    return ESP_OK;
}

esp_err_t event_bus_publish(const zg_event_t *event)
{
    if (!s_initialized || !event) return ESP_ERR_INVALID_ARG;

    zg_event_t copy = *event;
    if (copy.ts_ms == 0) copy.ts_ms = now_ms();

    if (xQueueSend(s_queue, &copy, 0) != pdTRUE) {
        ESP_LOGW(TAG, "fila cheia, evento descartado type=%d", copy.type);
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

esp_err_t event_bus_subscribe(event_bus_listener_t cb, void *ctx)
{
    if (!s_initialized || !cb) return ESP_ERR_INVALID_ARG;

    esp_err_t ret = ESP_ERR_NO_MEM;

    portENTER_CRITICAL(&s_lock);
    for (int i = 0; i < EVENT_BUS_MAX_LISTENERS; ++i) {
        if (!s_listeners[i].cb) {
            s_listeners[i].cb = cb;
            s_listeners[i].ctx = ctx;
            ret = ESP_OK;
            break;
        }
    }
    portEXIT_CRITICAL(&s_lock);

    return ret;
}
