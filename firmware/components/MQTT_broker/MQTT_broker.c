#include "MQTT_broker.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/time.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "mosq_broker.h"

#ifdef __has_include
#if __has_include("mosquitto_broker.h")
#include "mosquitto.h"
#include "mosquitto_broker.h"
#define MQTT_BROKER_HAS_INTERNAL_PUBLISH 0
#endif
#endif

#ifndef MQTT_BROKER_HAS_INTERNAL_PUBLISH
#define MQTT_BROKER_HAS_INTERNAL_PUBLISH 0
#endif

static const char *TAG = "mqtt_broker";

#define MQTT_BROKER_TASK_STACK 8192
#define MQTT_BROKER_TASK_PRIO 5
#define MQTT_LOCAL_PUBLISH_CLIENT_ID "zoneguard-local"

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

static esp_err_t socket_errno_to_esp(int err)
{
    switch (err) {
        case ENOMEM:
            return ESP_ERR_NO_MEM;
        case EINVAL:
            return ESP_ERR_INVALID_ARG;
        case ETIMEDOUT:
            return ESP_ERR_TIMEOUT;
        default:
            return ESP_FAIL;
    }
}

static esp_err_t send_all(int sock, const uint8_t *data, size_t len)
{
    size_t sent = 0;

    while (sent < len) {
        int rc = send(sock, data + sent, len - sent, 0);
        if (rc < 0) {
            return socket_errno_to_esp(errno);
        }
        if (rc == 0) {
            return ESP_ERR_INVALID_STATE;
        }
        sent += (size_t)rc;
    }

    return ESP_OK;
}

static size_t mqtt_encode_remaining_len(uint8_t *out, size_t value)
{
    size_t len = 0;

    do {
        uint8_t byte = (uint8_t)(value % 128);
        value /= 128;
        if (value > 0) {
            byte |= 0x80;
        }
        out[len++] = byte;
    } while (value > 0 && len < 4);

    return len;
}

static esp_err_t mqtt_append_u16(uint8_t *packet, size_t packet_size, size_t *offset, uint16_t value)
{
    if (!packet || !offset || *offset + 2 > packet_size) {
        return ESP_ERR_INVALID_SIZE;
    }

    packet[(*offset)++] = (uint8_t)((value >> 8) & 0xFFu);
    packet[(*offset)++] = (uint8_t)(value & 0xFFu);
    return ESP_OK;
}

static esp_err_t mqtt_append_bytes(
    uint8_t *packet,
    size_t packet_size,
    size_t *offset,
    const void *data,
    size_t len
)
{
    if (!packet || !offset || (len > 0 && !data) || *offset + len > packet_size) {
        return ESP_ERR_INVALID_SIZE;
    }

    if (len > 0) {
        memcpy(packet + *offset, data, len);
        *offset += len;
    }

    return ESP_OK;
}

static esp_err_t mqtt_append_string(
    uint8_t *packet,
    size_t packet_size,
    size_t *offset,
    const char *text
)
{
    size_t len = text ? strlen(text) : 0;
    if (len > UINT16_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }

    esp_err_t err = mqtt_append_u16(packet, packet_size, offset, (uint16_t)len);
    if (err != ESP_OK) {
        return err;
    }

    return mqtt_append_bytes(packet, packet_size, offset, text, len);
}

static esp_err_t local_mqtt_send_connect(int sock)
{
    uint8_t packet[128];
    size_t offset = 0;
    uint8_t remaining[4];
    const char *client_id = MQTT_LOCAL_PUBLISH_CLIENT_ID;
    size_t remaining_len = 10 + 2 + strlen(client_id);
    size_t remaining_field_len = mqtt_encode_remaining_len(remaining, remaining_len);
    esp_err_t err = ESP_OK;

    packet[offset++] = 0x10;
    err = mqtt_append_bytes(packet, sizeof(packet), &offset, remaining, remaining_field_len);
    if (err == ESP_OK) err = mqtt_append_string(packet, sizeof(packet), &offset, "MQTT");
    if (err == ESP_OK) err = mqtt_append_bytes(packet, sizeof(packet), &offset, (const uint8_t[]){4, 2}, 2);
    if (err == ESP_OK) err = mqtt_append_u16(packet, sizeof(packet), &offset, 15);
    if (err == ESP_OK) err = mqtt_append_string(packet, sizeof(packet), &offset, client_id);
    if (err != ESP_OK) {
        return err;
    }

    err = send_all(sock, packet, offset);
    if (err != ESP_OK) {
        return err;
    }

    uint8_t connack[4] = {0};
    int rc = recv(sock, connack, sizeof(connack), 0);
    if (rc < 0) {
        return socket_errno_to_esp(errno);
    }
    if (rc != 4 || connack[0] != 0x20 || connack[1] != 0x02 || connack[3] != 0x00) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    return ESP_OK;
}

static esp_err_t local_mqtt_publish(
    const char *topic,
    const void *payload,
    size_t payload_len,
    uint8_t qos,
    bool retain
)
{
    if (qos != 0) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    size_t topic_len = strlen(topic);
    if (topic_len > UINT16_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t packet[MQTT_BROKER_TOPIC_LEN + MQTT_BROKER_PAYLOAD_MAX_LEN + 8];
    uint8_t remaining[4];
    size_t remaining_len = 2 + topic_len + payload_len;
    size_t remaining_field_len = mqtt_encode_remaining_len(remaining, remaining_len);
    size_t offset = 0;

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        return socket_errno_to_esp(errno);
    }

    struct timeval timeout = {
        .tv_sec = 2,
        .tv_usec = 0,
    };
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(s_config.listen_port);
    addr.sin_addr.s_addr = s_config.bind_ip != 0 ? s_config.bind_ip : inet_addr("127.0.0.1");

    esp_err_t err = ESP_OK;
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        err = socket_errno_to_esp(errno);
        goto cleanup;
    }

    err = local_mqtt_send_connect(sock);
    if (err != ESP_OK) {
        goto cleanup;
    }

    packet[offset++] = (uint8_t)(0x30u | (retain ? 0x01u : 0x00u));
    err = mqtt_append_bytes(packet, sizeof(packet), &offset, remaining, remaining_field_len);
    if (err == ESP_OK) err = mqtt_append_u16(packet, sizeof(packet), &offset, (uint16_t)topic_len);
    if (err == ESP_OK) err = mqtt_append_bytes(packet, sizeof(packet), &offset, topic, topic_len);
    if (err == ESP_OK) err = mqtt_append_bytes(packet, sizeof(packet), &offset, payload, payload_len);
    if (err != ESP_OK) {
        goto cleanup;
    }

    err = send_all(sock, packet, offset);
    if (err == ESP_OK) {
        const uint8_t disconnect_packet[2] = {0xE0, 0x00};
        (void)send_all(sock, disconnect_packet, sizeof(disconnect_packet));
    }

cleanup:
    closesocket(sock);
    return err;
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

    esp_err_t err = local_mqtt_publish(topic, payload, payload_len, qos, retain);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "falha ao publicar via cliente local topic=%s err=%s", topic, esp_err_to_name(err));
        return err;
    }
    return ESP_OK;
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
