#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef EVENT_BUS_QUEUE_LEN
#define EVENT_BUS_QUEUE_LEN 32
#endif

typedef enum {
    ZG_EVENT_NONE = 0,
    ZG_EVENT_DEVICE_JOINED,
    ZG_EVENT_DEVICE_LEFT,
    ZG_EVENT_DEVICE_QUARANTINED,
    ZG_EVENT_DEVICE_RELEASED,
    ZG_EVENT_FLOW_SEEN,
    ZG_EVENT_POLICY_DENY,
    ZG_EVENT_RATE_EXCEEDED,
    ZG_EVENT_DNS_QUERY,
    ZG_EVENT_DNS_BLOCKED,
    ZG_EVENT_SWARM_QUARANTINE_NOTICE,
    ZG_EVENT_SWARM_FLOW_EVENT,
    ZG_EVENT_GATEWAY_UP,
    ZG_EVENT_GATEWAY_DOWN,
    ZG_EVENT_CONFIG_UPDATED,
    ZG_EVENT_ERROR
} zg_event_type_t;

typedef struct {
    zg_event_type_t type;
    uint32_t ts_ms;
    uint32_t zone_id;
    uint32_t device_id;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t risk_score;
    uint32_t code;
    char reason[48];
} zg_event_t;

typedef void (*event_bus_listener_t)(const zg_event_t *event, void *ctx);

esp_err_t event_bus_init(void);
esp_err_t event_bus_publish(const zg_event_t *event);
esp_err_t event_bus_subscribe(event_bus_listener_t cb, void *ctx);

#ifdef __cplusplus
}
#endif
