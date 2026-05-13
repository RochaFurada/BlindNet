#include <cstdio>
#include <cstring>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_system.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"

extern "C" {
#include "event_bus.h"
#include "config_store.h"
#include "admin_server.h"

#include "wifi_manager.h"
#include "zone_gateway.h"

#include "flow_table.h"
#include "policy_engine.h"
#include "rate_limiter.h"
#include "quarantine_manager.h"

#include "device_registry.h"
#include "dns_filter.h"
#include "zone_firewall.h"
}

#include "swarm_agent.hpp"
#include "telemetry_agent.hpp"

static const char *TAG = "zoneguard_main";

static esp_netif_t *s_setup_ap_netif = nullptr;

// ============================================================
// Forward declarations
// ============================================================

static void add_initial_policies();
static void add_initial_rate_limits();
static void add_initial_dns_rules();
static void test_zone_firewall_fake_flow();

// ============================================================
// Utilidades
// ============================================================

static void copy_str(char *dst, size_t dst_size, const char *src)
{
    if (!dst || dst_size == 0) {
        return;
    }

    if (!src) {
        dst[0] = '\0';
        return;
    }

    std::strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

// ============================================================
// BootAwait: helpers tipo "await" para boot assíncrono
// ============================================================

class BootAwait {
public:
    static bool start_gateway_and_wait(
        const zone_gateway_config_t *gateway_config,
        uint32_t timeout_ms,
        uint32_t poll_ms = 250
    ) {
        if (!gateway_config) {
            ESP_LOGE(TAG, "gateway_config inválido");
            return false;
        }

        if (poll_ms == 0) {
            poll_ms = 250;
        }

        ESP_LOGI(TAG, "Iniciando zone_gateway...");

        esp_err_t err = zone_gateway_start(gateway_config);

        if (err != ESP_OK) {
            ESP_LOGE(TAG, "zone_gateway_start falhou: %s", esp_err_to_name(err));
            return false;
        }

        ESP_LOGI(TAG, "Aguardando gateway/NAPT ficar pronto...");

        uint32_t waited = 0;

        while (waited < timeout_ms) {
            if (zone_gateway_is_running() && zone_gateway_is_napt_enabled()) {
                ESP_LOGI(
                    TAG,
                    "Gateway/NAPT pronto após %lu ms",
                    (unsigned long)waited
                );
                return true;
            }

            vTaskDelay(pdMS_TO_TICKS(poll_ms));
            waited += poll_ms;
        }

        ESP_LOGE(
            TAG,
            "Timeout aguardando gateway/NAPT após %lu ms",
            (unsigned long)timeout_ms
        );

        return false;
    }

    static bool init_and_start_dns(
        const dns_filter_config_t *dns_config
    ) {
        if (!dns_config) {
            ESP_LOGE(TAG, "dns_config inválido");
            return false;
        }

        ESP_LOGI(TAG, "Inicializando dns_filter...");

        esp_err_t err = dns_filter_init(dns_config);

        if (err != ESP_OK) {
            ESP_LOGE(TAG, "dns_filter_init falhou: %s", esp_err_to_name(err));
            return false;
        }

        add_initial_dns_rules();

        ESP_LOGI(TAG, "Iniciando dns_filter...");

        err = dns_filter_start();

        if (err != ESP_OK) {
            ESP_LOGE(TAG, "dns_filter_start falhou: %s", esp_err_to_name(err));
            return false;
        }

        ESP_LOGI(TAG, "DNS filter iniciado");
        return true;
    }

private:
    BootAwait() = delete;
};

// ============================================================
// Setup AP temporário
// ============================================================

static esp_err_t setup_ap_start(const char *ssid, const char *password)
{
    ESP_LOGW(TAG, "Iniciando AP temporário de setup");

    esp_err_t ret;

    ret = esp_netif_init();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        return ret;
    }

    ret = esp_event_loop_create_default();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        return ret;
    }

    s_setup_ap_netif = esp_netif_create_default_wifi_ap();

    if (!s_setup_ap_netif) {
        ESP_LOGE(TAG, "Falha ao criar netif AP de setup");
        return ESP_FAIL;
    }

    wifi_init_config_t wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_init_config));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));

    wifi_config_t ap_config = {};
    copy_str((char *)ap_config.ap.ssid, sizeof(ap_config.ap.ssid), ssid);
    copy_str((char *)ap_config.ap.password, sizeof(ap_config.ap.password), password);

    ap_config.ap.ssid_len = std::strlen(ssid);
    ap_config.ap.channel = 6;
    ap_config.ap.max_connection = 2;
    ap_config.ap.ssid_hidden = 0;

    if (password && std::strlen(password) >= 8) {
        ap_config.ap.authmode = WIFI_AUTH_WPA_WPA2_PSK;
    } else {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
        ap_config.ap.password[0] = '\0';
    }

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGW(TAG, "AP de setup iniciado");
    ESP_LOGW(TAG, "Rede: %s", ssid);
    ESP_LOGW(TAG, "Acesse: http://192.168.4.1/");

    return ESP_OK;
}

// ============================================================
// Event bus callback
// ============================================================

static void on_event(const zg_event_t *event, void *ctx)
{
    (void)ctx;

    if (!event) {
        return;
    }

    ESP_LOGI(
        "ZG_EVENT",
        "type=%d zone=%lu device=%lu src=%lu dst=%lu sport=%u dport=%u proto=%u risk=%u reason=%s",
        event->type,
        (unsigned long)event->zone_id,
        (unsigned long)event->device_id,
        (unsigned long)event->src_ip,
        (unsigned long)event->dst_ip,
        event->src_port,
        event->dst_port,
        event->proto,
        event->risk_score,
        event->reason
    );
}

// ============================================================
// Swarm callback
// ============================================================

static void on_swarm_frame(const swarm_frame_t *frame, void *ctx)
{
    (void)ctx;

    if (!frame) {
        return;
    }

    ESP_LOGI(
        "SWARM_CB",
        "frame type=%s origin=%lu payload=%u",
        swarm_msg_type_to_string(frame->type),
        (unsigned long)frame->origin_id,
        frame->payload_len
    );

    if (frame->type == SWARM_MSG_QUARANTINE_NOTICE &&
        frame->payload_len >= sizeof(swarm_payload_quarantine_notice_t)) {

        swarm_payload_quarantine_notice_t q;
        std::memcpy(&q, frame->payload, sizeof(q));

        ESP_LOGW(
            "SWARM_CB",
            "QUARANTINE_NOTICE ip=%lu ttl=%lums risk=%u reason=%s",
            (unsigned long)q.subject_ip,
            (unsigned long)q.ttl_ms,
            q.risk_score,
            q.reason
        );

        quarantine_manager_add_ip(
            q.subject_ip,
            (quarantine_mode_t)q.mode,
            QUARANTINE_SOURCE_SWARM,
            q.ttl_ms,
            q.risk_score,
            q.reason
        );

        device_registry_set_state_by_ip(
            q.subject_ip,
            DEVICE_STATE_QUARANTINED,
            q.risk_score
        );
    }
}

// ============================================================
// Políticas iniciais
// ============================================================

static void add_initial_policies()
{
    policy_rule_t block_lan = {};
    block_lan.priority = 800;
    block_lan.direction = FLOW_DIRECTION_ZONE_TO_UPLINK;

    block_lan.src_ip = POLICY_ANY_IP;
    block_lan.src_mask = POLICY_ANY_MASK;

    block_lan.dst_ip = policy_engine_ipv4(192, 168, 1, 0);
    block_lan.dst_mask = policy_engine_cidr_mask(24);

    block_lan.src_port = POLICY_ANY_PORT;
    block_lan.dst_port = POLICY_ANY_PORT;
    block_lan.proto = POLICY_ANY_PROTO;

    block_lan.action = POLICY_ACTION_DENY;
    block_lan.risk_score = 80;
    block_lan.log_event = true;

    std::snprintf(
        block_lan.reason,
        sizeof(block_lan.reason),
        "block_lateral_lan"
    );

    ESP_ERROR_CHECK(policy_engine_add_rule(&block_lan, nullptr));

    policy_rule_t allow_dns = {};
    allow_dns.priority = 700;
    allow_dns.direction = FLOW_DIRECTION_ZONE_TO_UPLINK;

    allow_dns.src_ip = POLICY_ANY_IP;
    allow_dns.src_mask = POLICY_ANY_MASK;

    allow_dns.dst_ip = POLICY_ANY_IP;
    allow_dns.dst_mask = POLICY_ANY_MASK;

    allow_dns.src_port = POLICY_ANY_PORT;
    allow_dns.dst_port = 53;
    allow_dns.proto = FLOW_PROTO_UDP;

    allow_dns.action = POLICY_ACTION_ALLOW;
    allow_dns.risk_score = 5;
    allow_dns.log_event = false;

    std::snprintf(
        allow_dns.reason,
        sizeof(allow_dns.reason),
        "allow_dns"
    );

    ESP_ERROR_CHECK(policy_engine_add_rule(&allow_dns, nullptr));

    policy_rule_t allow_http = {};
    allow_http.priority = 100;
    allow_http.direction = FLOW_DIRECTION_ZONE_TO_UPLINK;

    allow_http.src_ip = POLICY_ANY_IP;
    allow_http.src_mask = POLICY_ANY_MASK;

    allow_http.dst_ip = POLICY_ANY_IP;
    allow_http.dst_mask = POLICY_ANY_MASK;

    allow_http.src_port = POLICY_ANY_PORT;
    allow_http.dst_port = 80;
    allow_http.proto = FLOW_PROTO_TCP;

    allow_http.action = POLICY_ACTION_ALLOW;
    allow_http.risk_score = 10;
    allow_http.log_event = false;

    std::snprintf(
        allow_http.reason,
        sizeof(allow_http.reason),
        "allow_http"
    );

    ESP_ERROR_CHECK(policy_engine_add_rule(&allow_http, nullptr));

    policy_rule_t allow_https = {};
    allow_https.priority = 100;
    allow_https.direction = FLOW_DIRECTION_ZONE_TO_UPLINK;

    allow_https.src_ip = POLICY_ANY_IP;
    allow_https.src_mask = POLICY_ANY_MASK;

    allow_https.dst_ip = POLICY_ANY_IP;
    allow_https.dst_mask = POLICY_ANY_MASK;

    allow_https.src_port = POLICY_ANY_PORT;
    allow_https.dst_port = 443;
    allow_https.proto = FLOW_PROTO_TCP;

    allow_https.action = POLICY_ACTION_ALLOW;
    allow_https.risk_score = 10;
    allow_https.log_event = false;

    std::snprintf(
        allow_https.reason,
        sizeof(allow_https.reason),
        "allow_https"
    );

    ESP_ERROR_CHECK(policy_engine_add_rule(&allow_https, nullptr));
}

// ============================================================
// Rate limits iniciais
// ============================================================

static void add_initial_rate_limits()
{
    rate_limit_rule_t general = {};
    general.priority = 100;
    general.direction = FLOW_DIRECTION_ZONE_TO_UPLINK;

    general.src_ip = RATE_LIMIT_ANY_IP;
    general.src_mask = RATE_LIMIT_ANY_MASK;

    general.dst_ip = RATE_LIMIT_ANY_IP;
    general.dst_mask = RATE_LIMIT_ANY_MASK;

    general.src_port = RATE_LIMIT_ANY_PORT;
    general.dst_port = RATE_LIMIT_ANY_PORT;
    general.proto = RATE_LIMIT_ANY_PROTO;

    general.params.window_ms = 1000;
    general.params.max_packets = 100;
    general.params.max_bytes = 0;

    general.log_event = true;
    general.suggest_quarantine = false;

    std::snprintf(
        general.reason,
        sizeof(general.reason),
        "general_zone_rate_limit"
    );

    ESP_ERROR_CHECK(rate_limiter_add_rule(&general, nullptr));

    rate_limit_rule_t dns = {};
    dns.priority = 500;
    dns.direction = FLOW_DIRECTION_ZONE_TO_UPLINK;

    dns.src_ip = RATE_LIMIT_ANY_IP;
    dns.src_mask = RATE_LIMIT_ANY_MASK;

    dns.dst_ip = RATE_LIMIT_ANY_IP;
    dns.dst_mask = RATE_LIMIT_ANY_MASK;

    dns.src_port = RATE_LIMIT_ANY_PORT;
    dns.dst_port = 53;
    dns.proto = FLOW_PROTO_UDP;

    dns.params.window_ms = 10000;
    dns.params.max_packets = 30;
    dns.params.max_bytes = 0;

    dns.log_event = true;
    dns.suggest_quarantine = true;

    std::snprintf(
        dns.reason,
        sizeof(dns.reason),
        "dns_flood_protection"
    );

    ESP_ERROR_CHECK(rate_limiter_add_rule(&dns, nullptr));
}

// ============================================================
// DNS filter inicial
// ============================================================

static void add_initial_dns_rules()
{
    dns_filter_rule_t block_bad = {};

    block_bad.priority = 1000;
    copy_str(block_bad.pattern, sizeof(block_bad.pattern), "*.bad-domain.com");

    block_bad.action = DNS_FILTER_BLOCK;
    block_bad.redirect_ip = 0;
    block_bad.risk_score = 90;

    std::snprintf(
        block_bad.reason,
        sizeof(block_bad.reason),
        "blocked_domain"
    );

    ESP_ERROR_CHECK(dns_filter_add_rule(&block_bad, nullptr));
}

// ============================================================
// Teste fake do firewall
// ============================================================

static void test_zone_firewall_fake_flow()
{
    flow_key_t key = {};
    key.src_ip = policy_engine_ipv4(192, 168, 4, 2);
    key.dst_ip = policy_engine_ipv4(8, 8, 8, 8);
    key.src_port = 50000;
    key.dst_port = 53;
    key.proto = FLOW_PROTO_UDP;

    zone_firewall_decision_t decision = {};

    ESP_ERROR_CHECK(zone_firewall_evaluate_flow(
        &key,
        FLOW_DIRECTION_ZONE_TO_UPLINK,
        80,
        &decision
    ));

    ESP_LOGI(
        "FW_TEST",
        "verdict=%s policy=%s risk=%u reason=%s",
        zone_firewall_verdict_to_string(decision.verdict),
        policy_action_to_string(decision.policy_action),
        decision.risk_score,
        decision.reason
    );
}

// ============================================================
// Modo setup
// ============================================================

static void enter_setup_mode()
{
    ESP_LOGW(TAG, "================================================");
    ESP_LOGW(TAG, "SEM CONFIG SALVA. ENTRANDO EM MODO SETUP.");
    ESP_LOGW(TAG, "================================================");

    const char *setup_ssid = "ZoneGuard_Setup";
    const char *setup_password = "setup1234";

    ESP_ERROR_CHECK(setup_ap_start(setup_ssid, setup_password));

    admin_server_config_t admin_config = {};
    admin_config.setup_ap_ssid = setup_ssid;
    admin_config.setup_ap_password = setup_password;

    ESP_ERROR_CHECK(admin_server_start(&admin_config));

    ESP_LOGW(TAG, "Conecte no Wi-Fi: %s", setup_ssid);
    ESP_LOGW(TAG, "Senha: %s", setup_password);
    ESP_LOGW(TAG, "Abra: http://192.168.4.1/");
    ESP_LOGW(TAG, "Após salvar, o ESP reinicia em modo normal.");
}

// ============================================================
// Modo normal
// ============================================================

static void enter_normal_mode(const zoneguard_config_t *cfg)
{
    ESP_LOGI(TAG, "================================================");
    ESP_LOGI(TAG, "CONFIG ENCONTRADA. ENTRANDO EM MODO NORMAL.");
    ESP_LOGI(TAG, "================================================");

    ESP_LOGI(
        TAG,
        "Config: zone_id=%lu guardian_id=%lu ap_ssid=%s sta_ssid=%s",
        (unsigned long)cfg->zone_id,
        (unsigned long)cfg->guardian_id,
        cfg->ap_ssid,
        cfg->sta_ssid
    );

    ESP_ERROR_CHECK(device_registry_init(cfg->zone_id));

    // --------------------------------------------------------
    // Wi-Fi AP + STA
    // --------------------------------------------------------

    wifi_manager_config_t wifi_config = {};

    copy_str(
        wifi_config.sta_ssid,
        sizeof(wifi_config.sta_ssid),
        cfg->sta_ssid
    );

    copy_str(
        wifi_config.sta_password,
        sizeof(wifi_config.sta_password),
        cfg->sta_password
    );

    copy_str(
        wifi_config.ap_ssid,
        sizeof(wifi_config.ap_ssid),
        cfg->ap_ssid
    );

    copy_str(
        wifi_config.ap_password,
        sizeof(wifi_config.ap_password),
        cfg->ap_password
    );

    wifi_config.ap_channel = cfg->ap_channel ? cfg->ap_channel : 6;
    wifi_config.ap_max_connections = cfg->ap_max_connections ? cfg->ap_max_connections : 4;
    wifi_config.sta_max_retries = 10;
    wifi_config.ap_hidden = false;

    ESP_ERROR_CHECK(wifi_manager_start(&wifi_config));

    // --------------------------------------------------------
    // Flow table
    // --------------------------------------------------------

    flow_table_config_t flow_config = {};
    flow_config.max_idle_ms = 60000;
    flow_config.hard_ttl_ms = 10 * 60000;
    flow_config.evict_lru_when_full = true;

    ESP_ERROR_CHECK(flow_table_init(&flow_config));

    // --------------------------------------------------------
    // Policy engine
    // --------------------------------------------------------

    policy_engine_config_t policy_config = {};
    policy_config.default_action = POLICY_ACTION_ALLOW;
    policy_config.default_log_event = false;
    policy_config.default_risk_score = 0;

    ESP_ERROR_CHECK(policy_engine_init(&policy_config));
    add_initial_policies();

    // --------------------------------------------------------
    // Rate limiter
    // --------------------------------------------------------

    rate_limiter_config_t rate_config = {};
    rate_config.default_params.window_ms = 1000;
    rate_config.default_params.max_packets = 100;
    rate_config.default_params.max_bytes = 0;
    rate_config.max_idle_ms = 60000;
    rate_config.evict_lru_when_full = true;

    ESP_ERROR_CHECK(rate_limiter_init(&rate_config));
    add_initial_rate_limits();

    // --------------------------------------------------------
    // Quarantine manager
    // --------------------------------------------------------

    quarantine_manager_config_t quarantine_config = {};
    quarantine_config.default_ttl_ms = 60000;
    quarantine_config.evict_lru_when_full = true;

    ESP_ERROR_CHECK(quarantine_manager_init(&quarantine_config));

    // --------------------------------------------------------
    // Zone firewall
    // --------------------------------------------------------

    zone_firewall_config_t fw_config = {};
    fw_config.zone_id = cfg->zone_id;
    fw_config.default_allow = true;
    fw_config.auto_quarantine_on_rate_limit = true;
    fw_config.quarantine_ttl_ms = 60000;

    ESP_ERROR_CHECK(zone_firewall_init(&fw_config));

    // --------------------------------------------------------
    // Gateway / NAPT
    // --------------------------------------------------------

    zone_gateway_config_t gateway_config = {};
    gateway_config.wait_for_sta_ip = true;
    gateway_config.wait_interval_ms = 500;
    gateway_config.uplink_timeout_ms = 30000;
    gateway_config.set_sta_as_default = true;
    gateway_config.auto_recover = true;

    if (!BootAwait::start_gateway_and_wait(&gateway_config, 30000, 250)) {
        ESP_LOGE(TAG, "Gateway não ficou pronto. Abortando boot normal.");
        return;
    }

    // --------------------------------------------------------
    // DNS filter: somente depois do gateway/NAPT pronto
    // --------------------------------------------------------

    dns_filter_config_t dns_config = {};
    dns_config.listen_port = 53;
    dns_config.upstream_dns_ip = dns_filter_ipv4(8, 8, 8, 8);
    dns_config.default_allow = true;

    if (!BootAwait::init_and_start_dns(&dns_config)) {
        ESP_LOGE(TAG, "DNS filter não iniciou. Continuando sem DNS local.");
        /*
         * Aqui você decide:
         * - return; para abortar completamente
         * - ou continuar sem DNS local
         *
         * Para debug, eu prefiro continuar.
         */
    }

    // --------------------------------------------------------
    // Swarm
    // --------------------------------------------------------

    swarm_agent_config_t swarm_config = {};
    swarm_config.guardian_id = cfg->guardian_id;
    swarm_config.zone_id = cfg->zone_id;
    swarm_config.udp_port = cfg->swarm_port ? cfg->swarm_port : 4747;
    swarm_config.broadcast_addr =
        cfg->swarm_broadcast[0] ? cfg->swarm_broadcast : "255.255.255.255";
    swarm_config.max_hops = 3;
    swarm_config.hello_interval_ms = 5000;
    swarm_config.zone_state_interval_ms = 7000;
    swarm_config.verify_mode = SWARM_VERIFY_HMAC_SHA256;
    swarm_config.shared_key = cfg->swarm_key;
    swarm_config.shared_key_len = cfg->swarm_key_len;

    swarm_agent_set_frame_callback(on_swarm_frame, nullptr);

    esp_err_t swarm_ret = swarm_agent_start(&swarm_config);

    if (swarm_ret != ESP_OK) {
        ESP_LOGW(TAG, "swarm_agent não iniciou: %s", esp_err_to_name(swarm_ret));
    }

    // --------------------------------------------------------
    // Telemetria
    // --------------------------------------------------------

    telemetry_agent_config_t telemetry_config = {};
    telemetry_config.zone_id = cfg->zone_id;
    telemetry_config.guardian_id = cfg->guardian_id;
    telemetry_config.interval_ms = 5000;
    telemetry_config.outputs = TELEMETRY_OUTPUT_SERIAL;
    telemetry_config.udp_host = nullptr;
    telemetry_config.udp_port = cfg->telemetry_port ? cfg->telemetry_port : 5757;
    telemetry_config.send_on_start = true;

    ESP_ERROR_CHECK(telemetry_agent_start(&telemetry_config));

    // --------------------------------------------------------
    // Teste fake
    // --------------------------------------------------------

    test_zone_firewall_fake_flow();

    ESP_LOGI(TAG, "ZoneGuard inicializado em modo normal");
}

// ============================================================
// app_main
// ============================================================

extern "C" void app_main(void)
{
    ESP_LOGI(TAG, "Boot ZoneGuard");

    /*
     * Event bus deve existir nos dois modos:
     * setup e normal.
     */
    ESP_ERROR_CHECK(event_bus_init());
    ESP_ERROR_CHECK(event_bus_subscribe(on_event, nullptr));

    /*
     * Config store decide o modo do boot.
     */
    ESP_ERROR_CHECK(config_store_init());

    zoneguard_config_t cfg = {};

    esp_err_t cfg_ret = config_store_load(&cfg);

    if (cfg_ret != ESP_OK) {
        enter_setup_mode();
        return;
    }

    /*
     * Se config existe, admin_server NÃO é iniciado.
     */
    enter_normal_mode(&cfg);
}