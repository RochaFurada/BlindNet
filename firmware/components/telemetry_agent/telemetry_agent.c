#include "telemetry_agent.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/portmacro.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"

#include "wifi_manager.h"
#include "zone_gateway.h"
#include "flow_table.h"
#include "policy_engine.h"
#include "rate_limiter.h"
#include "quarantine_manager.h"

#include "swarm_agent.h"

static const char *TAG = "telemetry_agent";

#define TELEMETRY_TASK_STACK_SIZE  6144
#define TELEMETRY_TASK_PRIORITY    4
#define TELEMETRY_BUFFER_SIZE      1400

static telemetry_agent_config_t s_config;
static TaskHandle_t s_task = NULL;
static volatile bool s_running = false;
static volatile bool s_stop_requested = false;
static int s_udp_sock = -1;
static telemetry_agent_stats_t s_stats;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000ULL);
}

static void stats_inc(uint64_t *field)
{
    portENTER_CRITICAL(&s_lock);
    (*field)++;
    portEXIT_CRITICAL(&s_lock);
}

static void load_default_config(telemetry_agent_config_t *config)
{
    memset(config, 0, sizeof(*config));
    config->zone_id = 1;
    config->guardian_id = 0xAABB0001;
    config->interval_ms = 10000;
    config->outputs = TELEMETRY_OUTPUT_SERIAL;
    config->udp_host = NULL;
    config->udp_port = 5757;
    config->send_on_start = true;
}

static const char *wifi_state_to_string(wifi_manager_sta_state_t state)
{
    switch (state) {
        case WIFI_MANAGER_STA_DISCONNECTED: return "DISCONNECTED";
        case WIFI_MANAGER_STA_CONNECTING: return "CONNECTING";
        case WIFI_MANAGER_STA_CONNECTED: return "CONNECTED";
        case WIFI_MANAGER_STA_GOT_IP: return "GOT_IP";
        default: return "UNKNOWN";
    }
}

static const char *gateway_state_to_string(zone_gateway_state_t state)
{
    switch (state) {
        case ZONE_GATEWAY_STATE_STOPPED: return "STOPPED";
        case ZONE_GATEWAY_STATE_WAITING_UPLINK: return "WAITING_UPLINK";
        case ZONE_GATEWAY_STATE_RUNNING: return "RUNNING";
        case ZONE_GATEWAY_STATE_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

static esp_err_t open_udp_if_needed(void)
{
    if ((s_config.outputs & TELEMETRY_OUTPUT_UDP) == 0) return ESP_OK;

    if (s_config.udp_host == NULL || s_config.udp_port == 0) return ESP_ERR_INVALID_ARG;
    if (s_udp_sock >= 0) return ESP_OK;

    s_udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (s_udp_sock < 0) return ESP_FAIL;

    return ESP_OK;
}

static void close_udp(void)
{
    if (s_udp_sock >= 0) {
        close(s_udp_sock);
        s_udp_sock = -1;
    }
}

static int append(char *buffer, size_t size, int offset, const char *fmt, ...)
{
    if (!buffer || size == 0 || offset < 0 || (size_t)offset >= size) return -1;

    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(buffer + offset, size - offset, fmt, args);
    va_end(args);

    if (written < 0) return -1;
    if ((size_t)(offset + written) >= size) return -1;

    return offset + written;
}

static esp_err_t build_snapshot(char *buffer, size_t size)
{
    if (!buffer || size == 0) return ESP_ERR_INVALID_ARG;
    memset(buffer, 0, size);

    wifi_manager_status_t wifi = wifi_manager_get_status();
    zone_gateway_status_t gw = zone_gateway_get_status();
    flow_table_stats_t flow = flow_table_get_stats();
    policy_engine_stats_t policy = policy_engine_get_stats();
    rate_limiter_stats_t rate = rate_limiter_get_stats();
    quarantine_manager_stats_t quarantine = quarantine_manager_get_stats();
    swarm_agent_stats_t swarm = swarm_agent_get_stats();

    int off = 0;

    off = append(buffer, size, off, "{");
    off = append(buffer, size, off,
                 "\"type\":\"zoneguard_snapshot\","
                 "\"ts_ms\":%lu,"
                 "\"zone_id\":%lu,"
                 "\"guardian_id\":%lu,",
                 (unsigned long)now_ms(),
                 (unsigned long)s_config.zone_id,
                 (unsigned long)s_config.guardian_id);

    off = append(buffer, size, off,
                 "\"wifi\":{\"sta_state\":\"%s\",\"sta_retries\":%u,\"ap_clients\":%u,\"has_ip\":%s},",
                 wifi_state_to_string(wifi.sta_state),
                 wifi.sta_retry_count,
                 wifi.ap_connected_clients,
                 wifi_manager_has_ip() ? "true" : "false");

    off = append(buffer, size, off,
                 "\"gateway\":{\"state\":\"%s\",\"napt\":%s,\"sta_has_ip\":%s,\"attempts\":%lu,\"last_error\":%lu},",
                 gateway_state_to_string(gw.state),
                 gw.napt_enabled ? "true" : "false",
                 gw.sta_has_ip ? "true" : "false",
                 (unsigned long)gw.start_attempts,
                 (unsigned long)gw.last_error);

    off = append(buffer, size, off,
                 "\"flow\":{\"active\":%lu,\"packets\":%" PRIu64 ",\"bytes\":%" PRIu64 ",\"created\":%" PRIu64 ",\"expired\":%" PRIu64 ",\"evicted\":%" PRIu64 "},",
                 (unsigned long)flow.active_entries,
                 flow.total_packets,
                 flow.total_bytes,
                 flow.created_flows,
                 flow.expired_flows,
                 flow.evicted_flows);

    off = append(buffer, size, off,
                 "\"policy\":{\"rules\":%lu,\"eval\":%" PRIu64 ",\"allow\":%" PRIu64 ",\"deny\":%" PRIu64 ",\"rate\":%" PRIu64 ",\"quarantine\":%" PRIu64 ",\"ask_swarm\":%" PRIu64 "},",
                 (unsigned long)policy.active_rules,
                 policy.evaluations,
                 policy.allowed,
                 policy.denied,
                 policy.rate_limited,
                 policy.quarantined,
                 policy.ask_swarm);

    off = append(buffer, size, off,
                 "\"rate\":{\"buckets\":%lu,\"rules\":%lu,\"checks\":%" PRIu64 ",\"allowed\":%" PRIu64 ",\"exceeded\":%" PRIu64 ",\"expired\":%" PRIu64 "},",
                 (unsigned long)rate.active_buckets,
                 (unsigned long)rate.active_rules,
                 rate.checks,
                 rate.allowed,
                 rate.exceeded,
                 rate.expired_buckets);

    off = append(buffer, size, off,
                 "\"quarantine\":{\"active\":%lu,\"added\":%" PRIu64 ",\"refreshed\":%" PRIu64 ",\"hits\":%" PRIu64 ",\"misses\":%" PRIu64 ",\"expired\":%" PRIu64 "},",
                 (unsigned long)quarantine.active_entries,
                 quarantine.added,
                 quarantine.refreshed,
                 quarantine.hits,
                 quarantine.misses,
                 quarantine.expired);

    off = append(buffer, size, off,
                 "\"swarm\":{\"tx\":%" PRIu64 ",\"rx\":%" PRIu64 ",\"bad_hmac\":%" PRIu64 ",\"expired\":%" PRIu64 ",\"self_ignored\":%" PRIu64 ",\"tx_errors\":%" PRIu64 ",\"rx_errors\":%" PRIu64 "}",
                 swarm.tx_frames,
                 swarm.rx_frames,
                 swarm.rx_bad_hmac,
                 swarm.rx_expired,
                 swarm.rx_self_ignored,
                 swarm.tx_errors,
                 swarm.rx_errors);

    off = append(buffer, size, off, "}");

    if (off < 0) {
        stats_inc(&s_stats.build_errors);
        return ESP_ERR_NO_MEM;
    }

    stats_inc(&s_stats.snapshots_built);
    return ESP_OK;
}

static esp_err_t send_serial(const char *snapshot)
{
    if (!snapshot) return ESP_ERR_INVALID_ARG;
    ESP_LOGI(TAG, "%s", snapshot);
    stats_inc(&s_stats.serial_sent);
    return ESP_OK;
}

static esp_err_t send_udp(const char *snapshot)
{
    if (!snapshot) return ESP_ERR_INVALID_ARG;

    if ((s_config.outputs & TELEMETRY_OUTPUT_UDP) == 0) return ESP_OK;

    esp_err_t err = open_udp_if_needed();
    if (err != ESP_OK) {
        stats_inc(&s_stats.udp_errors);
        return err;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));

    dest.sin_family = AF_INET;
    dest.sin_port = htons(s_config.udp_port);
    dest.sin_addr.s_addr = inet_addr(s_config.udp_host);

    int sent = sendto(s_udp_sock, snapshot, strlen(snapshot), 0,
                      (struct sockaddr *)&dest, sizeof(dest));

    if (sent < 0) {
        stats_inc(&s_stats.udp_errors);
        return ESP_FAIL;
    }

    stats_inc(&s_stats.udp_sent);
    return ESP_OK;
}

esp_err_t telemetry_agent_send_snapshot_now(void)
{
    char buffer[TELEMETRY_BUFFER_SIZE];

    esp_err_t err = build_snapshot(buffer, sizeof(buffer));
    if (err != ESP_OK) return err;

    if (s_config.outputs & TELEMETRY_OUTPUT_SERIAL) send_serial(buffer);
    if (s_config.outputs & TELEMETRY_OUTPUT_UDP) send_udp(buffer);

    return ESP_OK;
}

static void telemetry_task(void *arg)
{
    (void)arg;

    if (s_config.send_on_start) telemetry_agent_send_snapshot_now();

    const uint32_t interval = s_config.interval_ms == 0 ? 10000 : s_config.interval_ms;

    while (!s_stop_requested) {
        telemetry_agent_send_snapshot_now();

        flow_table_expire_old();
        rate_limiter_expire_old();
        quarantine_manager_expire_old();
        policy_engine_expire_rules();

        vTaskDelay(pdMS_TO_TICKS(interval));
    }

    s_task = NULL;
    vTaskDelete(NULL);
}

esp_err_t telemetry_agent_start(const telemetry_agent_config_t *config)
{
    if (s_running) return ESP_OK;

    load_default_config(&s_config);
    if (config) {
        s_config = *config;
        if (s_config.interval_ms == 0) s_config.interval_ms = 10000;
        if (s_config.outputs == TELEMETRY_OUTPUT_NONE) s_config.outputs = TELEMETRY_OUTPUT_SERIAL;
    }

    memset(&s_stats, 0, sizeof(s_stats));

    open_udp_if_needed();

    s_stop_requested = false;

    if (xTaskCreate(telemetry_task, "telemetry_agent", TELEMETRY_TASK_STACK_SIZE, NULL,
                    TELEMETRY_TASK_PRIORITY, &s_task) != pdPASS) {
        close_udp();
        return ESP_ERR_NO_MEM;
    }

    s_running = true;

    ESP_LOGI(TAG, "telemetry_agent iniciado interval=%lums outputs=0x%lx",
             (unsigned long)s_config.interval_ms,
             (unsigned long)s_config.outputs);

    return ESP_OK;
}

esp_err_t telemetry_agent_stop(void)
{
    if (!s_running) return ESP_OK;

    s_stop_requested = true;
    close_udp();
    s_running = false;
    return ESP_OK;
}

bool telemetry_agent_is_running(void)
{
    return s_running;
}

telemetry_agent_stats_t telemetry_agent_get_stats(void)
{
    telemetry_agent_stats_t copy;
    portENTER_CRITICAL(&s_lock);
    copy = s_stats;
    portEXIT_CRITICAL(&s_lock);
    return copy;
}
