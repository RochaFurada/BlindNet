#include "MQTT_broker.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "mosq_broker.h"

#ifdef __has_include
#if __has_include("mosquitto_broker.h")
#include "mosquitto.h"
#include "mosquitto_broker.h"
#define MQTT_BROKER_HAS_INTERNAL_PUBLISH 1
#endif
#endif

#ifndef MQTT_BROKER_HAS_INTERNAL_PUBLISH
#define MQTT_BROKER_HAS_INTERNAL_PUBLISH 0
#endif

static const char *TAG = "mqtt_broker";

#define MQTT_BROKER_TASK_STACK 8192
#define MQTT_BROKER_TASK_PRIO 5

static mqtt_broker_config_t s_config;
static mqtt_broker_stats_t s_stats;
static struct mosq_broker_config s_mosq_config;
static SemaphoreHandle_t s_lock;
static TaskHandle_t s_task;
static bool s_running;
static char s_host[16];

static void lock_state(void)
{
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
}

static void unlock_state(void)
{
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }
}

static void stats_inc(uint64_t *field)
{
    lock_state();
    if (field) {
        (*field)++;
    }
    unlock_state();
}

static void bind_ip_to_host(uint32_t bind_ip, char out[16])
{
    if (!out) {
        return;
    }

    if (bind_ip == 0) {
        snprintf(out, 16, "0.0.0.0");
        return;
    }

    uint32_t host_ip = ntohl(bind_ip);
    snprintf(
        out,
        16,
        "%u.%u.%u.%u",
        (unsigned)((host_ip >> 24) & 0xFFu),
        (unsigned)((host_ip >> 16) & 0xFFu),
        (unsigned)((host_ip >> 8) & 0xFFu),
        (unsigned)(host_ip & 0xFFu)
    );
}

static int handle_mosq_connect(
    const char *client_id,
    const char *username,
    const char *password,
    int password_len
)
{
    mqtt_broker_connect_cb_t cb = NULL;
    void *ctx = NULL;

    lock_state();
    cb = s_config.connect_cb;
    ctx = s_config.connect_ctx;
    unlock_state();

    bool accepted = true;

    if (!s_config.allow_anonymous && (!username || username[0] == '\0')) {
        accepted = false;
    }

    if (accepted && cb) {
        mqtt_broker_connect_t event = {
            .client_id = client_id,
            .username = username,
            .password = (const uint8_t *)password,
            .password_len = password_len > 0 ? (size_t)password_len : 0
        };
        accepted = cb(&event, ctx);
    }

    if (accepted) {
        lock_state();
        s_stats.accepted_clients++;
        s_stats.connected_clients++;
        unlock_state();

        ESP_LOGI(TAG, "cliente MQTT aceito: %s", client_id ? client_id : "");
        return 0;
    }

    stats_inc(&s_stats.rejected_clients);
    ESP_LOGW(TAG, "cliente MQTT rejeitado: %s", client_id ? client_id : "");
    return 1;
}

static void handle_mosq_message(
    char *client,
    char *topic,
    char *data,
    int len,
    int qos,
    int retain
)
{
    mqtt_broker_message_cb_t cb = NULL;
    void *ctx = NULL;

    lock_state();
    cb = s_config.message_cb;
    ctx = s_config.message_ctx;
    unlock_state();

    stats_inc(&s_stats.rx_packets);
    stats_inc(&s_stats.rx_publishes);

    if (!cb) {
        return;
    }

    mqtt_broker_message_t message = {
        .client_id = client,
        .topic = topic,
        .payload = (const uint8_t *)data,
        .payload_len = len > 0 ? (size_t)len : 0,
        .qos = qos >= 0 ? (uint8_t)qos : 0,
        .retained = retain != 0,
        .remote_ip = 0
    };

    cb(&message, ctx);
}

static void broker_task(void *arg)
{
    (void)arg;

    ESP_LOGI(TAG, "Mosquitto iniciando em %s:%d", s_mosq_config.host, s_mosq_config.port);

    int rc = mosq_broker_run(&s_mosq_config);

    lock_state();
    s_running = false;
    s_task = NULL;
    s_stats.last_exit_code = rc;
    unlock_state();

    ESP_LOGI(TAG, "Mosquitto finalizado rc=%d", rc);
    vTaskDelete(NULL);
}

void mqtt_broker_config_defaults(mqtt_broker_config_t *config)
{
    if (!config) {
        return;
    }

    memset(config, 0, sizeof(*config));
    config->listen_port = MQTT_BROKER_DEFAULT_PORT;
    config->max_payload_len = MQTT_BROKER_PAYLOAD_MAX_LEN;
    config->allow_anonymous = true;
    config->zone_id = 1;
}

esp_err_t mqtt_broker_start(const mqtt_broker_config_t *config)
{
    if (s_running) {
        return ESP_OK;
    }

    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
        if (!s_lock) {
            return ESP_ERR_NO_MEM;
        }
    }

    mqtt_broker_config_defaults(&s_config);
    if (config) {
        s_config = *config;
        if (s_config.listen_port == 0) {
            s_config.listen_port = MQTT_BROKER_DEFAULT_PORT;
        }
        if (s_config.max_payload_len == 0 ||
            s_config.max_payload_len > MQTT_BROKER_PAYLOAD_MAX_LEN) {
            s_config.max_payload_len = MQTT_BROKER_PAYLOAD_MAX_LEN;
        }
        if (s_config.zone_id == 0) {
            s_config.zone_id = 1;
        }
    }

    memset(&s_stats, 0, sizeof(s_stats));
    s_stats.listen_port = s_config.listen_port;
    s_stats.bind_ip = s_config.bind_ip;

    bind_ip_to_host(s_config.bind_ip, s_host);

    memset(&s_mosq_config, 0, sizeof(s_mosq_config));
    s_mosq_config.host = s_host;
    s_mosq_config.port = s_config.listen_port;
    s_mosq_config.handle_connect_cb = handle_mosq_connect;
    s_mosq_config.handle_message_cb = handle_mosq_message;
    s_mosq_config.tls_cfg = NULL;

    s_running = true;

    if (xTaskCreate(
            broker_task,
            "mosquitto",
            MQTT_BROKER_TASK_STACK,
            NULL,
            MQTT_BROKER_TASK_PRIO,
            &s_task
        ) != pdPASS) {
        s_running = false;
        s_task = NULL;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "MQTT broker Mosquitto armado host=%s porta=%u zone=%lu",
             s_host,
             (unsigned)s_config.listen_port,
             (unsigned long)s_config.zone_id);

    return ESP_OK;
}

esp_err_t mqtt_broker_stop(void)
{
    if (!s_running) {
        return ESP_OK;
    }

    mosq_broker_stop();
    return ESP_OK;
}

bool mqtt_broker_is_running(void)
{
    return s_running;
}

static esp_err_t broker_publish_internal(
    const char *client_id,
    const char *topic,
    const void *payload,
    size_t payload_len,
    uint8_t qos,
    bool retain
)
{
    if (client_id && client_id[0] == '\0') {
        return ESP_ERR_INVALID_ARG;
    }
    if (!topic || topic[0] == '\0') {
        return ESP_ERR_INVALID_ARG;
    }
    if (payload_len > 0 && !payload) {
        return ESP_ERR_INVALID_ARG;
    }
    if (payload_len > s_config.max_payload_len || payload_len > (size_t)INT_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }
    if (qos > 2) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_running) {
        return ESP_ERR_INVALID_STATE;
    }

#if MQTT_BROKER_HAS_INTERNAL_PUBLISH
    int rc = mosquitto_broker_publish_copy(
        client_id,
        topic,
        (int)payload_len,
        payload_len > 0 ? payload : NULL,
        qos,
        retain,
        NULL
    );

    switch (rc) {
        case MOSQ_ERR_SUCCESS:
            return ESP_OK;
        case MOSQ_ERR_INVAL:
            return ESP_ERR_INVALID_ARG;
        case MOSQ_ERR_NOMEM:
            return ESP_ERR_NO_MEM;
        default:
            ESP_LOGW(TAG, "falha ao publicar no broker rc=%d topic=%s", rc, topic);
            return ESP_FAIL;
    }
#else
    (void)client_id;
    (void)payload;
    (void)qos;
    (void)retain;

    ESP_LOGW(TAG, "publicacao interna do Mosquitto indisponivel topic=%s", topic);
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

esp_err_t mqtt_broker_publish(
    const char *topic,
    const void *payload,
    size_t payload_len,
    uint8_t qos,
    bool retain
)
{
    return broker_publish_internal(NULL, topic, payload, payload_len, qos, retain);
}

esp_err_t mqtt_broker_publish_to_client(
    const char *client_id,
    const char *topic,
    const void *payload,
    size_t payload_len,
    uint8_t qos,
    bool retain
)
{
    if (!client_id) {
        return ESP_ERR_INVALID_ARG;
    }

    return broker_publish_internal(client_id, topic, payload, payload_len, qos, retain);
}

mqtt_broker_stats_t mqtt_broker_get_stats(void)
{
    mqtt_broker_stats_t copy;

    lock_state();
    copy = s_stats;
    unlock_state();

    return copy;
}
