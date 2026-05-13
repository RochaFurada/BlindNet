#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ACTIVE_SUBSTANCE_TOPIC_MAX_LEN
#define ACTIVE_SUBSTANCE_TOPIC_MAX_LEN 128
#endif

#ifndef ACTIVE_SUBSTANCE_PAYLOAD_MAX_LEN
#define ACTIVE_SUBSTANCE_PAYLOAD_MAX_LEN 256
#endif

#define ACTIVE_SUBSTANCE_VERSION 1
#define ACTIVE_SUBSTANCE_HASH_LEN 32

/*
 * Active Substance = composto ativo.
 *
 * Esta é a parte que efetivamente vira comando para o dispositivo IoT.
 * No MVP, ela descreve apenas um MQTT PUBLISH: topic + payload.
 */
typedef enum {
    ACTIVE_SUBSTANCE_TRANSPORT_UNKNOWN = 0,
    ACTIVE_SUBSTANCE_TRANSPORT_MQTT_PUBLISH = 1
} active_substance_transport_t;

/*
 * Comando MQTT bruto que o Guardian poderá publicar se a cápsula permitir.
 * Para manter o broker mínimo previsível no MVP, use QoS 0 e retain=false.
 */
typedef struct {
    char topic[ACTIVE_SUBSTANCE_TOPIC_MAX_LEN];
    uint16_t topic_len;
    uint16_t payload_len;
    uint8_t payload[ACTIVE_SUBSTANCE_PAYLOAD_MAX_LEN];
    uint8_t qos;
    bool retain;
} active_substance_mqtt_t;

/*
 * Estrutura principal do composto ativo.
 * Novos transportes podem entrar aqui depois sem mudar o conceito da cápsula.
 */
typedef struct {
    uint8_t version;
    active_substance_transport_t transport;
    active_substance_mqtt_t mqtt;
} active_substance_t;

void active_substance_init(active_substance_t *substance);

esp_err_t active_substance_set_mqtt(
    active_substance_t *substance,
    const char *topic,
    const void *payload,
    size_t payload_len,
    uint8_t qos,
    bool retain
);

esp_err_t active_substance_validate(const active_substance_t *substance);

esp_err_t active_substance_hash(
    const active_substance_t *substance,
    uint8_t out_hash[ACTIVE_SUBSTANCE_HASH_LEN]
);

const char *active_substance_transport_to_string(active_substance_transport_t transport);

#ifdef __cplusplus
}
#endif
