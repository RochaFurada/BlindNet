#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "esp_err.h"
#include "flow_table.h"
#include "quarantine_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SWARM_AGENT_MAX_PAYLOAD       192
#define SWARM_AGENT_HMAC_LEN          32
#define SWARM_AGENT_REASON_LEN        48
#define SWARM_AGENT_BROADCAST_ID      0u

typedef enum {
    SWARM_MSG_HELLO = 1,
    SWARM_MSG_ZONE_STATE,
    SWARM_MSG_FLOW_EVENT,
    SWARM_MSG_QUARANTINE_NOTICE,
    SWARM_MSG_POLICY_UPDATE,
    SWARM_MSG_HEALTH_PING
} swarm_msg_type_t;

typedef enum {
    SWARM_VERIFY_DISABLED = 0,
    SWARM_VERIFY_HMAC_SHA256
} swarm_verify_mode_t;

typedef enum {
    SWARM_ZONE_MODE_NORMAL = 0,
    SWARM_ZONE_MODE_SUSPECT,
    SWARM_ZONE_MODE_DEGRADED,
    SWARM_ZONE_MODE_ISOLATED
} swarm_zone_mode_t;

typedef struct __attribute__((packed)) {
    uint32_t zone_id;
    uint32_t guardian_id;
    uint32_t uptime_ms;
    uint32_t capabilities;
} swarm_payload_hello_t;

typedef struct __attribute__((packed)) {
    uint32_t zone_id;
    uint32_t guardian_id;
    uint8_t zone_mode;
    uint8_t connected_clients;
    uint8_t quarantined_devices;
    uint8_t reserved0;
    uint32_t active_flows;
    uint32_t uptime_ms;
    uint32_t policy_version;
} swarm_payload_zone_state_t;

typedef struct __attribute__((packed)) {
    uint32_t zone_id;
    uint32_t guardian_id;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t direction;
    uint8_t risk_score;
    uint8_t reason_code;
    uint32_t packets_window;
    uint32_t bytes_window;
} swarm_payload_flow_event_t;

typedef struct __attribute__((packed)) {
    uint32_t zone_id;
    uint32_t guardian_id;
    uint8_t subject_type;
    uint8_t mode;
    uint8_t source;
    uint8_t risk_score;
    uint32_t subject_ip;
    uint32_t ttl_ms;
    char reason[SWARM_AGENT_REASON_LEN];
} swarm_payload_quarantine_notice_t;

typedef struct __attribute__((packed)) {
    uint16_t magic;
    uint8_t version;
    uint8_t type;
    uint32_t message_id;
    uint32_t origin_id;
    uint32_t target_id;
    uint8_t hop_count;
    uint8_t max_hops;
    uint16_t payload_len;
    uint32_t issued_ms;
    uint32_t expires_ms;
    uint32_t nonce;
    uint8_t hmac[SWARM_AGENT_HMAC_LEN];
    uint8_t payload[SWARM_AGENT_MAX_PAYLOAD];
} swarm_frame_t;

typedef struct {
    uint32_t guardian_id;
    uint32_t zone_id;
    uint16_t udp_port;
    const char *broadcast_addr;
    uint8_t max_hops;
    uint32_t hello_interval_ms;
    uint32_t zone_state_interval_ms;
    swarm_verify_mode_t verify_mode;
    const uint8_t *shared_key;
    size_t shared_key_len;
} swarm_agent_config_t;

typedef void (*swarm_agent_frame_cb_t)(const swarm_frame_t *frame, void *user_ctx);

typedef struct {
    uint64_t tx_frames;
    uint64_t rx_frames;
    uint64_t rx_invalid_magic;
    uint64_t rx_bad_hmac;
    uint64_t rx_expired;
    uint64_t rx_self_ignored;
    uint64_t tx_errors;
    uint64_t rx_errors;
} swarm_agent_stats_t;

esp_err_t swarm_agent_start(const swarm_agent_config_t *config);
esp_err_t swarm_agent_stop(void);
bool swarm_agent_is_running(void);

void swarm_agent_set_frame_callback(swarm_agent_frame_cb_t cb, void *user_ctx);

esp_err_t swarm_agent_send_hello(void);
esp_err_t swarm_agent_send_zone_state(
    swarm_zone_mode_t mode,
    uint8_t connected_clients,
    uint8_t quarantined_devices,
    uint32_t active_flows,
    uint32_t policy_version
);

esp_err_t swarm_agent_send_flow_event(const swarm_payload_flow_event_t *event);

esp_err_t swarm_agent_send_quarantine_notice_ip(
    uint32_t subject_ip,
    quarantine_mode_t mode,
    quarantine_source_t source,
    uint32_t ttl_ms,
    uint8_t risk_score,
    const char *reason
);

swarm_agent_stats_t swarm_agent_get_stats(void);
const char *swarm_msg_type_to_string(uint8_t type);

#ifdef __cplusplus
}
#endif
