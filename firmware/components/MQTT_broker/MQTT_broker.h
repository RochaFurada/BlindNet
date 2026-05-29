#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MQTT_BROKER_DEFAULT_PORT 1883

#define MQTT_BROKER_CLIENT_ID_LEN 32
#define MQTT_BROKER_TOPIC_LEN 96
#define MQTT_BROKER_PAYLOAD_MAX_LEN 256

typedef struct {
    const char *client_id;
    const char *username;
    const uint8_t *password;
    size_t password_len;
} mqtt_broker_connect_t;

typedef bool (*mqtt_broker_connect_cb_t)(const mqtt_broker_connect_t *event, void *ctx);

typedef struct {
    const char *client_id;
    const char *topic;
    const uint8_t *payload;
    size_t payload_len;
    uint8_t qos;
    bool retained;
    uint32_t remote_ip;
} mqtt_broker_message_t;

typedef void (*mqtt_broker_message_cb_t)(const mqtt_broker_message_t *message, void *ctx);

typedef struct {
    uint16_t listen_port;
    /* IPv4 in network byte order. Zero means INADDR_ANY. */
    uint32_t bind_ip;
    uint16_t max_payload_len;
    bool allow_anonymous;
    uint32_t zone_id;
    mqtt_broker_connect_cb_t connect_cb;
    void *connect_ctx;
    mqtt_broker_message_cb_t message_cb;
    void *message_ctx;
} mqtt_broker_config_t;

typedef struct {
    uint32_t listen_port;
    uint32_t bind_ip;
    uint64_t accepted_clients;
    uint64_t rejected_clients;
    uint64_t connected_clients;
    uint64_t rx_packets;
    uint64_t rx_publishes;
    int last_exit_code;
} mqtt_broker_stats_t;

void mqtt_broker_config_defaults(mqtt_broker_config_t *config);

esp_err_t mqtt_broker_start(const mqtt_broker_config_t *config);
esp_err_t mqtt_broker_stop(void);
bool mqtt_broker_is_running(void);

esp_err_t mqtt_broker_publish(
    const char *topic,
    const void *payload,
    size_t payload_len,
    uint8_t qos,
    bool retain
);

esp_err_t mqtt_broker_publish_to_client(
    const char *client_id,
    const char *topic,
    const void *payload,
    size_t payload_len,
    uint8_t qos,
    bool retain
);

mqtt_broker_stats_t mqtt_broker_get_stats(void);

#ifdef __cplusplus
}
#endif
