#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    TELEMETRY_OUTPUT_NONE   = 0,
    TELEMETRY_OUTPUT_SERIAL = 1 << 0,
    TELEMETRY_OUTPUT_UDP    = 1 << 1
} telemetry_output_flags_t;

typedef struct {
    uint32_t zone_id;
    uint32_t guardian_id;
    uint32_t interval_ms;
    uint32_t outputs;
    const char *udp_host;
    uint16_t udp_port;
    bool send_on_start;
} telemetry_agent_config_t;

typedef struct {
    uint64_t snapshots_built;
    uint64_t serial_sent;
    uint64_t udp_sent;
    uint64_t udp_errors;
    uint64_t build_errors;
} telemetry_agent_stats_t;

esp_err_t telemetry_agent_start(const telemetry_agent_config_t *config);
esp_err_t telemetry_agent_stop(void);

bool telemetry_agent_is_running(void);
esp_err_t telemetry_agent_send_snapshot_now(void);
telemetry_agent_stats_t telemetry_agent_get_stats(void);

#ifdef __cplusplus
}
#endif
