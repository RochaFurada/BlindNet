#include "swarm_agent.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/portmacro.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "psa/crypto.h"

static const char *TAG = "swarm_agent";

#define SWARM_MAGIC       0x5A47
#define SWARM_VERSION     2
#define SWARM_RX_STACK    4096
#define SWARM_TX_STACK    4096
#define SWARM_TASK_PRIO   5

static swarm_agent_config_t s_config;
static TaskHandle_t s_rx_task = NULL;
static TaskHandle_t s_periodic_task = NULL;
static int s_sock = -1;
static volatile bool s_running = false;
static volatile bool s_stop_requested = false;
static swarm_agent_frame_cb_t s_frame_cb = NULL;
static void *s_frame_cb_ctx = NULL;
static swarm_agent_stats_t s_stats;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

static uint32_t now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000ULL);
}

static uint32_t next_message_id(void)
{
    static uint32_t s_counter = 1;
    return __atomic_fetch_add(&s_counter, 1, __ATOMIC_RELAXED);
}

const char *swarm_msg_type_to_string(uint8_t type)
{
    switch (type) {
        case SWARM_MSG_HELLO: return "HELLO";
        case SWARM_MSG_ZONE_STATE: return "ZONE_STATE";
        case SWARM_MSG_FLOW_EVENT: return "FLOW_EVENT";
        case SWARM_MSG_QUARANTINE_NOTICE: return "QUARANTINE_NOTICE";
        case SWARM_MSG_POLICY_UPDATE: return "POLICY_UPDATE";
        case SWARM_MSG_HEALTH_PING: return "HEALTH_PING";
        default: return "UNKNOWN";
    }
}

static void stats_inc(uint64_t *field)
{
    portENTER_CRITICAL(&s_lock);
    (*field)++;
    portEXIT_CRITICAL(&s_lock);
}

static void load_default_config(swarm_agent_config_t *config)
{
    memset(config, 0, sizeof(*config));
    config->guardian_id = esp_random();
    config->zone_id = 1;
    config->udp_port = 4747;
    config->broadcast_addr = "255.255.255.255";
    config->hello_interval_ms = 5000;
    config->zone_state_interval_ms = 7000;
    config->verify_mode = SWARM_VERIFY_DISABLED;
}

static bool hmac_enabled(void)
{
    return s_config.verify_mode == SWARM_VERIFY_HMAC_SHA256 &&
           s_config.shared_key != NULL &&
           s_config.shared_key_len > 0;
}

static esp_err_t compute_hmac_sha256(const uint8_t *data, size_t data_len, uint8_t out_hmac[SWARM_AGENT_HMAC_LEN])
{
    if (!data || !out_hmac) return ESP_ERR_INVALID_ARG;

    if (!hmac_enabled()) {
        memset(out_hmac, 0, SWARM_AGENT_HMAC_LEN);
        return ESP_OK;
    }

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) return ESP_FAIL;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_bits(&attributes, s_config.shared_key_len * 8);

    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    status = psa_import_key(&attributes, s_config.shared_key, s_config.shared_key_len, &key);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) return ESP_FAIL;

    size_t hmac_len = 0;
    status = psa_mac_compute(key, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                             data, data_len,
                             out_hmac, SWARM_AGENT_HMAC_LEN, &hmac_len);

    psa_status_t destroy_status = psa_destroy_key(key);
    if (status != PSA_SUCCESS || destroy_status != PSA_SUCCESS || hmac_len != SWARM_AGENT_HMAC_LEN) {
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t sign_frame(swarm_frame_t *frame)
{
    if (!frame) return ESP_ERR_INVALID_ARG;

    memset(frame->hmac, 0, SWARM_AGENT_HMAC_LEN);

    const size_t len_to_sign =
        sizeof(swarm_frame_t) - SWARM_AGENT_MAX_PAYLOAD + frame->payload_len;

    return compute_hmac_sha256((const uint8_t *)frame, len_to_sign, frame->hmac);
}

static bool verify_frame_hmac(const swarm_frame_t *frame)
{
    if (!frame) return false;
    if (!hmac_enabled()) return true;

    swarm_frame_t copy;
    memcpy(&copy, frame, sizeof(copy));

    uint8_t received[SWARM_AGENT_HMAC_LEN];
    memcpy(received, copy.hmac, SWARM_AGENT_HMAC_LEN);
    memset(copy.hmac, 0, SWARM_AGENT_HMAC_LEN);

    uint8_t expected[SWARM_AGENT_HMAC_LEN];

    const size_t len_to_sign =
        sizeof(swarm_frame_t) - SWARM_AGENT_MAX_PAYLOAD + copy.payload_len;

    esp_err_t err = compute_hmac_sha256((const uint8_t *)&copy,
                                        len_to_sign, expected);
    if (err != ESP_OK) return false;

    return memcmp(received, expected, SWARM_AGENT_HMAC_LEN) == 0;
}

static esp_err_t make_frame(swarm_msg_type_t type, uint32_t target_id,
                            const void *payload, uint16_t payload_len,
                            swarm_frame_t *out_frame)
{
    if (!out_frame) return ESP_ERR_INVALID_ARG;
    if (payload_len > SWARM_AGENT_MAX_PAYLOAD) return ESP_ERR_INVALID_SIZE;

    memset(out_frame, 0, sizeof(*out_frame));

    const uint32_t ts = now_ms();

    out_frame->magic = SWARM_MAGIC;
    out_frame->version = SWARM_VERSION;
    out_frame->type = (uint8_t)type;
    out_frame->message_id = next_message_id();
    out_frame->origin_id = s_config.guardian_id;
    out_frame->target_id = target_id;
    out_frame->hop_count = 0;
    out_frame->reserved0 = 0;
    out_frame->payload_len = payload_len;
    out_frame->issued_ms = ts;
    out_frame->expires_ms = ts + 10000;
    out_frame->nonce = esp_random();

    if (payload && payload_len > 0) memcpy(out_frame->payload, payload, payload_len);

    return sign_frame(out_frame);
}

static esp_err_t send_frame(const swarm_frame_t *frame)
{
    if (!frame || s_sock < 0) return ESP_ERR_INVALID_STATE;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));

    dest.sin_family = AF_INET;
    dest.sin_port = htons(s_config.udp_port);
    dest.sin_addr.s_addr = inet_addr(s_config.broadcast_addr ? s_config.broadcast_addr : "255.255.255.255");

    const size_t frame_len = sizeof(swarm_frame_t) - SWARM_AGENT_MAX_PAYLOAD + frame->payload_len;

    int sent = sendto(s_sock, frame, frame_len, 0,
                      (struct sockaddr *)&dest, sizeof(dest));

    if (sent < 0) {
        stats_inc(&s_stats.tx_errors);
        return ESP_FAIL;
    }

    stats_inc(&s_stats.tx_frames);
    return ESP_OK;
}

static bool frame_basic_valid(const swarm_frame_t *frame, int len)
{
    if (!frame) return false;
    if (len < (int)(sizeof(swarm_frame_t) - SWARM_AGENT_MAX_PAYLOAD)) return false;

    if (frame->magic != SWARM_MAGIC) {
        stats_inc(&s_stats.rx_invalid_magic);
        return false;
    }

    if (frame->version != SWARM_VERSION) return false;
    if (frame->reserved0 != 0) return false;
    if (frame->payload_len > SWARM_AGENT_MAX_PAYLOAD) return false;

    int expected = (int)(sizeof(swarm_frame_t) - SWARM_AGENT_MAX_PAYLOAD + frame->payload_len);
    if (len < expected) return false;

    uint32_t ts = now_ms();

    if (frame->expires_ms != 0 && ts > frame->expires_ms) {
        stats_inc(&s_stats.rx_expired);
        return false;
    }

    if (frame->origin_id == s_config.guardian_id) {
        stats_inc(&s_stats.rx_self_ignored);
        return false;
    }

    if (frame->target_id != SWARM_AGENT_BROADCAST_ID && frame->target_id != s_config.guardian_id) {
        return false;
    }

    if (!verify_frame_hmac(frame)) {
        stats_inc(&s_stats.rx_bad_hmac);
        return false;
    }

    return true;
}

static void rx_task(void *arg)
{
    (void)arg;

    while (!s_stop_requested) {
        swarm_frame_t frame;
        memset(&frame, 0, sizeof(frame));

        struct sockaddr_in source;
        socklen_t source_len = sizeof(source);

        int len = recvfrom(s_sock, &frame, sizeof(frame), 0,
                           (struct sockaddr *)&source, &source_len);

        if (len < 0) {
            if (!s_stop_requested) stats_inc(&s_stats.rx_errors);
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }

        if (!frame_basic_valid(&frame, len)) continue;

        stats_inc(&s_stats.rx_frames);

        ESP_LOGI(TAG, "RX %s origin=%lu msg=%lu payload=%u",
                 swarm_msg_type_to_string(frame.type),
                 (unsigned long)frame.origin_id,
                 (unsigned long)frame.message_id,
                 frame.payload_len);

        if (s_frame_cb) s_frame_cb(&frame, s_frame_cb_ctx);
    }

    s_rx_task = NULL;
    vTaskDelete(NULL);
}

static void periodic_task(void *arg)
{
    (void)arg;

    uint32_t last_hello = 0;
    uint32_t last_state = 0;

    while (!s_stop_requested) {
        uint32_t ts = now_ms();

        if (s_config.hello_interval_ms > 0 && ts - last_hello >= s_config.hello_interval_ms) {
            swarm_agent_send_hello();
            last_hello = ts;
        }

        if (s_config.zone_state_interval_ms > 0 && ts - last_state >= s_config.zone_state_interval_ms) {
            swarm_agent_send_zone_state(SWARM_ZONE_MODE_NORMAL, 0, 0, 0, 1);
            last_state = ts;
        }

        vTaskDelay(pdMS_TO_TICKS(250));
    }

    s_periodic_task = NULL;
    vTaskDelete(NULL);
}

static esp_err_t open_udp_socket(void)
{
    s_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (s_sock < 0) return ESP_FAIL;

    int broadcast_enable = 1;
    setsockopt(s_sock, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable));

    int reuse = 1;
    setsockopt(s_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));

    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(s_config.udp_port);
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        close(s_sock);
        s_sock = -1;
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t swarm_agent_start(const swarm_agent_config_t *config)
{
    if (s_running) return ESP_OK;

    load_default_config(&s_config);
    if (config) {
        s_config = *config;
        if (s_config.udp_port == 0) s_config.udp_port = 4747;
        if (!s_config.broadcast_addr) s_config.broadcast_addr = "255.255.255.255";
        if (s_config.hello_interval_ms == 0) s_config.hello_interval_ms = 5000;
        if (s_config.zone_state_interval_ms == 0) s_config.zone_state_interval_ms = 7000;
    }

    memset(&s_stats, 0, sizeof(s_stats));
    s_stop_requested = false;

    esp_err_t err = open_udp_socket();
    if (err != ESP_OK) return err;

    if (xTaskCreate(rx_task, "swarm_rx", SWARM_RX_STACK, NULL,
                    SWARM_TASK_PRIO, &s_rx_task) != pdPASS) {
        close(s_sock);
        s_sock = -1;
        return ESP_ERR_NO_MEM;
    }

    if (xTaskCreate(periodic_task, "swarm_periodic", SWARM_TX_STACK, NULL,
                    SWARM_TASK_PRIO, &s_periodic_task) != pdPASS) {
        s_stop_requested = true;
        close(s_sock);
        s_sock = -1;
        return ESP_ERR_NO_MEM;
    }

    s_running = true;

    ESP_LOGI(TAG, "swarm_agent iniciado guardian=%lu zone=%lu verify=%s",
             (unsigned long)s_config.guardian_id,
             (unsigned long)s_config.zone_id,
             hmac_enabled() ? "HMAC_SHA256" : "DISABLED");

    return ESP_OK;
}

esp_err_t swarm_agent_stop(void)
{
    if (!s_running) return ESP_OK;

    s_stop_requested = true;

    if (s_sock >= 0) {
        shutdown(s_sock, 0);
        close(s_sock);
        s_sock = -1;
    }

    s_running = false;
    return ESP_OK;
}

bool swarm_agent_is_running(void)
{
    return s_running;
}

void swarm_agent_set_frame_callback(swarm_agent_frame_cb_t cb, void *user_ctx)
{
    s_frame_cb = cb;
    s_frame_cb_ctx = user_ctx;
}

esp_err_t swarm_agent_send_hello(void)
{
    swarm_payload_hello_t payload;
    memset(&payload, 0, sizeof(payload));

    payload.zone_id = s_config.zone_id;
    payload.guardian_id = s_config.guardian_id;
    payload.uptime_ms = now_ms();
    payload.capabilities = 0x00000001;

    swarm_frame_t frame;
    esp_err_t err = make_frame(SWARM_MSG_HELLO, SWARM_AGENT_BROADCAST_ID, &payload, sizeof(payload), &frame);
    if (err != ESP_OK) return err;
    return send_frame(&frame);
}

esp_err_t swarm_agent_send_zone_state(swarm_zone_mode_t mode, uint8_t connected_clients,
                                       uint8_t quarantined_devices, uint32_t active_flows,
                                       uint32_t policy_version)
{
    swarm_payload_zone_state_t payload;
    memset(&payload, 0, sizeof(payload));

    payload.zone_id = s_config.zone_id;
    payload.guardian_id = s_config.guardian_id;
    payload.zone_mode = (uint8_t)mode;
    payload.connected_clients = connected_clients;
    payload.quarantined_devices = quarantined_devices;
    payload.active_flows = active_flows;
    payload.uptime_ms = now_ms();
    payload.policy_version = policy_version;

    swarm_frame_t frame;
    esp_err_t err = make_frame(SWARM_MSG_ZONE_STATE, SWARM_AGENT_BROADCAST_ID, &payload, sizeof(payload), &frame);
    if (err != ESP_OK) return err;
    return send_frame(&frame);
}

esp_err_t swarm_agent_send_flow_event(const swarm_payload_flow_event_t *event)
{
    if (!event) return ESP_ERR_INVALID_ARG;

    swarm_payload_flow_event_t payload = *event;
    payload.zone_id = s_config.zone_id;
    payload.guardian_id = s_config.guardian_id;

    swarm_frame_t frame;
    esp_err_t err = make_frame(SWARM_MSG_FLOW_EVENT, SWARM_AGENT_BROADCAST_ID, &payload, sizeof(payload), &frame);
    if (err != ESP_OK) return err;
    return send_frame(&frame);
}

esp_err_t swarm_agent_send_quarantine_notice_ip(uint32_t subject_ip, quarantine_mode_t mode,
                                                quarantine_source_t source, uint32_t ttl_ms,
                                                uint8_t risk_score, const char *reason)
{
    swarm_payload_quarantine_notice_t payload;
    memset(&payload, 0, sizeof(payload));

    payload.zone_id = s_config.zone_id;
    payload.guardian_id = s_config.guardian_id;
    payload.subject_type = (uint8_t)QUARANTINE_SUBJECT_IP;
    payload.mode = (uint8_t)mode;
    payload.source = (uint8_t)source;
    payload.risk_score = risk_score;
    payload.subject_ip = subject_ip;
    payload.ttl_ms = ttl_ms;

    if (reason) {
        strncpy(payload.reason, reason, sizeof(payload.reason) - 1);
        payload.reason[sizeof(payload.reason) - 1] = '\0';
    }

    swarm_frame_t frame;
    esp_err_t err = make_frame(SWARM_MSG_QUARANTINE_NOTICE, SWARM_AGENT_BROADCAST_ID,
                               &payload, sizeof(payload), &frame);
    if (err != ESP_OK) return err;
    return send_frame(&frame);
}

swarm_agent_stats_t swarm_agent_get_stats(void)
{
    swarm_agent_stats_t copy;
    portENTER_CRITICAL(&s_lock);
    copy = s_stats;
    portEXIT_CRITICAL(&s_lock);
    return copy;
}
