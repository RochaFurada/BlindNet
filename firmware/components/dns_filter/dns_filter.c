#include "dns_filter.h"
#include "event_bus.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/portmacro.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include <sys/time.h>

static const char *TAG = "dns_filter";

#define DNS_BUF_SIZE 512
#define DNS_TASK_STACK 4096
#define DNS_TASK_PRIO 5

#define DNS_JOB_QUEUE_LEN 8

// Estrutura para representar uma regra de filtro de DNS
typedef struct {
    uint8_t query[DNS_BUF_SIZE];
    int query_len;

    struct sockaddr_in client_addr;
    socklen_t client_addr_len;

    char domain[DNS_FILTER_DOMAIN_LEN];
    uint8_t risk;
} dns_job_t;

static QueueHandle_t s_dns_queue = NULL;
static TaskHandle_t s_dns_worker_task = NULL;


typedef struct {
    bool in_use;
    dns_filter_rule_t rule;
} dns_rule_slot_t;

static int s_upstream_sock = -1;
static dns_rule_slot_t s_rules[DNS_FILTER_MAX_RULES];
static dns_filter_config_t s_config;
static dns_filter_stats_t s_stats;
static uint32_t s_next_rule_id = 1;

static int s_sock = -1;
static TaskHandle_t s_task = NULL;
static volatile bool s_running = false;
static volatile bool s_stop = false;

static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

uint32_t dns_filter_ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
}

static void safe_copy(char *dst, size_t size, const char *src)
{
    if (!dst || size == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    strncpy(dst, src, size - 1);
    dst[size - 1] = '\0';
}

static void str_lower(char *s)
{
    if (!s) return;
    while (*s) {
        *s = (char)tolower((unsigned char)*s);
        ++s;
    }
}

static bool domain_match(const char *pattern, const char *domain)
{
    if (!pattern || !domain || pattern[0] == '\0') return false;
    if (strcmp(pattern, "*") == 0) return true;
    
    size_t d = strlen(domain);

    if (pattern[0] == '*') {
        const char *suffix = pattern + 1;
        size_t s = strlen(suffix);
        return d >= s && strcmp(domain + d - s, suffix) == 0;
    }

    return strcmp(pattern, domain) == 0;
}

static bool parse_dns_qname(const uint8_t *buf, int len, char *out, size_t out_len)
{
    if (!buf || len < 12 || !out || out_len == 0) return false;

    int pos = 12;
    size_t off = 0;

    while (pos < len) {
        uint8_t label_len = buf[pos++];
        if (label_len == 0) break;
        if ((label_len & 0xC0) != 0) return false;
        if (pos + label_len > len) return false;

        if (off && off < out_len - 1) out[off++] = '.';

        for (int i = 0; i < label_len && off < out_len - 1; ++i) {
            out[off++] = (char)buf[pos++];
        }
    }

    out[off] = '\0';
    str_lower(out);
    return off > 0;
}

static int find_qname_end(const uint8_t *buf, int len)
{
    int pos = 12;
    while (pos < len) {
        uint8_t l = buf[pos++];
        if (l == 0) return pos;
        if ((l & 0xC0) != 0) return -1;
        pos += l;
    }
    return -1;
}

static int build_a_response(const uint8_t *query, int qlen, uint8_t *resp, int rsize, uint32_t ip_host_order)
{
    if (!query || !resp || qlen < 12 || rsize < qlen + 16) return -1;

    int qname_end = find_qname_end(query, qlen);
    if (qname_end < 0 || qname_end + 4 > qlen) return -1;

    int question_len = qname_end + 4;

    memcpy(resp, query, question_len);

    resp[2] = 0x81;
    resp[3] = 0x80;
    resp[6] = 0x00;
    resp[7] = 0x01;

    int pos = question_len;
    resp[pos++] = 0xC0;
    resp[pos++] = 0x0C;
    resp[pos++] = 0x00;
    resp[pos++] = 0x01;
    resp[pos++] = 0x00;
    resp[pos++] = 0x01;
    resp[pos++] = 0x00;
    resp[pos++] = 0x00;
    resp[pos++] = 0x00;
    resp[pos++] = 0x3C;
    resp[pos++] = 0x00;
    resp[pos++] = 0x04;

    uint32_t ip_be = htonl(ip_host_order);
    memcpy(&resp[pos], &ip_be, 4);
    pos += 4;

    return pos;
}

esp_err_t dns_filter_init(const dns_filter_config_t *config)
{
    memset(s_rules, 0, sizeof(s_rules));
    memset(&s_stats, 0, sizeof(s_stats));
    memset(&s_config, 0, sizeof(s_config));

    s_config.listen_port = 53;
    s_config.upstream_dns_ip = dns_filter_ipv4(8, 8, 8, 8);
    s_config.default_allow = true;

    if (config) s_config = *config;
    if (s_config.listen_port == 0) s_config.listen_port = 53;

    s_next_rule_id = 1;

    ESP_LOGI(TAG, "dns_filter init port=%u", s_config.listen_port);
    return ESP_OK;
}

esp_err_t dns_filter_add_rule(const dns_filter_rule_t *rule, uint32_t *out_rule_id)
{
    if (!rule) return ESP_ERR_INVALID_ARG;

    esp_err_t ret = ESP_ERR_NO_MEM;

    portENTER_CRITICAL(&s_lock);
    for (int i = 0; i < DNS_FILTER_MAX_RULES; ++i) {
        if (!s_rules[i].in_use) {
            s_rules[i].in_use = true;
            s_rules[i].rule = *rule;

            if (s_rules[i].rule.rule_id == 0) {
                s_rules[i].rule.rule_id = s_next_rule_id++;
            }

            s_rules[i].rule.enabled = true;
            str_lower(s_rules[i].rule.pattern);

            s_stats.active_rules++;

            if (out_rule_id) *out_rule_id = s_rules[i].rule.rule_id;
            ret = ESP_OK;
            break;
        }
    }
    portEXIT_CRITICAL(&s_lock);

    return ret;
}

bool dns_filter_remove_rule(uint32_t rule_id)
{
    bool ok = false;

    portENTER_CRITICAL(&s_lock);
    for (int i = 0; i < DNS_FILTER_MAX_RULES; ++i) {
        if (s_rules[i].in_use && s_rules[i].rule.rule_id == rule_id) {
            memset(&s_rules[i], 0, sizeof(s_rules[i]));
            if (s_stats.active_rules > 0) s_stats.active_rules--;
            ok = true;
            break;
        }
    }
    portEXIT_CRITICAL(&s_lock);

    return ok;
}

dns_filter_action_t dns_filter_evaluate_domain(
    const char *domain,
    uint32_t *out_redirect_ip,
    uint8_t *out_risk_score,
    char *out_reason,
    size_t reason_len
)
{
    dns_filter_rule_t best;
    bool found = false;
    uint16_t best_prio = 0;

    memset(&best, 0, sizeof(best));

    portENTER_CRITICAL(&s_lock);
    for (int i = 0; i < DNS_FILTER_MAX_RULES; ++i) {
        if (!s_rules[i].in_use || !s_rules[i].rule.enabled) continue;
        if (!domain_match(s_rules[i].rule.pattern, domain)) continue;

        if (!found || s_rules[i].rule.priority >= best_prio) {
            best = s_rules[i].rule;
            best_prio = best.priority;
            found = true;
        }
    }
    portEXIT_CRITICAL(&s_lock);

    if (!found) {
        if (out_redirect_ip) *out_redirect_ip = 0;
        if (out_risk_score) *out_risk_score = 0;
        if (out_reason && reason_len) safe_copy(out_reason, reason_len, "dns_default");
        return s_config.default_allow ? DNS_FILTER_ALLOW : DNS_FILTER_BLOCK;
    }

    if (out_redirect_ip) *out_redirect_ip = best.redirect_ip;
    if (out_risk_score) *out_risk_score = best.risk_score;
    if (out_reason && reason_len) safe_copy(out_reason, reason_len, best.reason);

    return best.action;
}

static esp_err_t open_upstream_dns_socket(void)
{
    if (s_upstream_sock >= 0) {
        return ESP_OK;
    }

    s_upstream_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (s_upstream_sock < 0) {
        ESP_LOGW(TAG, "falha ao criar socket upstream DNS errno=%d", errno);
        return ESP_FAIL;
    }

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    setsockopt(
        s_upstream_sock,
        SOL_SOCKET,
        SO_RCVTIMEO,
        &timeout,
        sizeof(timeout)
    );

    setsockopt(
        s_upstream_sock,
        SOL_SOCKET,
        SO_SNDTIMEO,
        &timeout,
        sizeof(timeout)
    );

    return ESP_OK;
}


static int forward_dns_to_upstream(
    const uint8_t *query,
    int query_len,
    uint8_t *response,
    int response_size
)
{
    if (!query || query_len <= 0 || !response || response_size <= 0) {
        return -1;
    }

    if (open_upstream_dns_socket() != ESP_OK) {
        return -1;
    }

    struct sockaddr_in upstream;
    memset(&upstream, 0, sizeof(upstream));

    upstream.sin_family = AF_INET;
    upstream.sin_port = htons(53);
    upstream.sin_addr.s_addr = htonl(s_config.upstream_dns_ip);

    int sent = -1;

    for (int attempt = 0; attempt < 3; ++attempt) {
        sent = sendto(
            s_upstream_sock,
            query,
            query_len,
            0,
            (struct sockaddr *)&upstream,
            sizeof(upstream)
        );

        if (sent >= 0) {
            break;
        }

        if (errno == 12) {
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        break;
    }

    if (sent < 0) {
        ESP_LOGW(TAG, "sendto upstream DNS falhou errno=%d", errno);

        close(s_upstream_sock);
        s_upstream_sock = -1;

        return -1;
    }
    

    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    int received = recvfrom(
        s_upstream_sock,
        response,
        response_size,
        0,
        (struct sockaddr *)&from,
        &from_len
    );

    if (received < 0) {
        ESP_LOGW(TAG, "recvfrom upstream DNS falhou errno=%d", errno);
        return -1;
    }

    return received;
}


static void dns_worker_task(void *arg)
{
    (void)arg;

    dns_job_t job;
    uint8_t resp[DNS_BUF_SIZE];

    while (!s_stop) {
        if (xQueueReceive(s_dns_queue, &job, pdMS_TO_TICKS(100)) != pdTRUE) {
            continue;
        }

        int rlen = forward_dns_to_upstream(
            job.query,
            job.query_len,
            resp,
            sizeof(resp)
        );

        if (rlen > 0) {
            sendto(
                s_sock,
                resp,
                rlen,
                0,
                (struct sockaddr *)&job.client_addr,
                job.client_addr_len
            );

            s_stats.allowed++;
        } else {
            s_stats.errors++;
            ESP_LOGW(
                TAG,
                "DNS upstream falhou para %s; sem fallback",
                job.domain
            );
        }
    }

    s_dns_worker_task = NULL;
    vTaskDelete(NULL);
}



static void dns_task(void *arg)
{
    (void)arg;

    uint8_t buf[DNS_BUF_SIZE];
    uint8_t resp[DNS_BUF_SIZE];

    while (!s_stop) {
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);

        int len = recvfrom(
            s_sock,
            buf,
            sizeof(buf),
            0,
            (struct sockaddr *)&src,
            &slen
        );

        if (len <= 0) {
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        char domain[DNS_FILTER_DOMAIN_LEN];

        if (!parse_dns_qname(buf, len, domain, sizeof(domain))) {
            s_stats.errors++;
            continue;
        }

        s_stats.queries++;

        uint32_t redirect_ip = 0;
        uint8_t risk = 0;
        char reason[48];

        dns_filter_action_t action =
            dns_filter_evaluate_domain(
                domain,
                &redirect_ip,
                &risk,
                reason,
                sizeof(reason)
            );

        if (action == DNS_FILTER_BLOCK || action == DNS_FILTER_REDIRECT) {
            zg_event_t ev = {0};

            ev.type = (action == DNS_FILTER_BLOCK)
                ? ZG_EVENT_DNS_BLOCKED
                : ZG_EVENT_DNS_QUERY;

            ev.src_ip = ntohl(src.sin_addr.s_addr);
            ev.risk_score = risk;

            snprintf(
                ev.reason,
                sizeof(ev.reason),
                "%.15s:%.31s",
                reason,
                domain
            );

            event_bus_publish(&ev);
        }

        if (action == DNS_FILTER_BLOCK) {
            int rlen = build_a_response(
                buf,
                len,
                resp,
                sizeof(resp),
                0
            );

            if (rlen > 0) {
                sendto(
                    s_sock,
                    resp,
                    rlen,
                    0,
                    (struct sockaddr *)&src,
                    slen
                );
            }

            s_stats.blocked++;
        }
        else if (action == DNS_FILTER_REDIRECT) {
            int rlen = build_a_response(
                buf,
                len,
                resp,
                sizeof(resp),
                redirect_ip
            );

            if (rlen > 0) {
                sendto(
                    s_sock,
                    resp,
                    rlen,
                    0,
                    (struct sockaddr *)&src,
                    slen
                );
            }

            s_stats.redirected++;
        }
        else {
            dns_job_t job = {0};

            memcpy(job.query, buf, len);
            job.query_len = len;
            job.client_addr = src;
            job.client_addr_len = slen;
            strncpy(job.domain, domain, sizeof(job.domain) - 1);
            job.domain[sizeof(job.domain) - 1] = '\0';
            job.risk = risk;

            if (xQueueSend(s_dns_queue, &job, 0) != pdTRUE) {
                s_stats.errors++;
                ESP_LOGW(
                    TAG,
                    "fila DNS cheia, descartando consulta para %s",
                    domain
                );
            }
        }
    }

    s_task = NULL;
    vTaskDelete(NULL);
}


esp_err_t dns_filter_start(void)
{
    if (s_running) return ESP_OK;

    s_stop = false;

    s_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (s_sock < 0) {
        ESP_LOGE(TAG, "falha ao criar socket DNS errno=%d", errno);
        return ESP_FAIL;
    }

    int reuse = 1;
    setsockopt(s_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));

    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(s_config.listen_port);
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(
            s_sock,
            (struct sockaddr *)&listen_addr,
            sizeof(listen_addr)
        ) < 0) {

        ESP_LOGE(TAG, "bind DNS falhou errno=%d", errno);
        close(s_sock);
        s_sock = -1;
        return ESP_FAIL;
    }

    s_dns_queue = xQueueCreate(DNS_JOB_QUEUE_LEN, sizeof(dns_job_t));

    if (!s_dns_queue) {
        ESP_LOGE(TAG, "falha ao criar fila DNS");
        close(s_sock);
        s_sock = -1;
        return ESP_ERR_NO_MEM;
    }

    if (xTaskCreate(
            dns_worker_task,
            "dns_worker",
            4096,
            NULL,
            5,
            &s_dns_worker_task
        ) != pdPASS) {

        ESP_LOGE(TAG, "falha ao criar dns_worker_task");

        vQueueDelete(s_dns_queue);
        s_dns_queue = NULL;

        close(s_sock);
        s_sock = -1;

        return ESP_ERR_NO_MEM;
    }

    if (xTaskCreate(
            dns_task,
            "dns_filter",
            DNS_TASK_STACK,
            NULL,
            DNS_TASK_PRIO,
            &s_task
        ) != pdPASS) {

        ESP_LOGE(TAG, "falha ao criar dns_task");

        s_stop = true;

        vQueueDelete(s_dns_queue);
        s_dns_queue = NULL;

        close(s_sock);
        s_sock = -1;

        return ESP_ERR_NO_MEM;
    }

    s_running = true;

    ESP_LOGI(TAG, "dns_filter rodando porta=%u", s_config.listen_port);

    return ESP_OK;
}


esp_err_t dns_filter_stop(void)
{
    if (!s_running) return ESP_OK;

    s_stop = true;

    if (s_upstream_sock >= 0) {
        close(s_upstream_sock);
        s_upstream_sock = -1;
    }

    if (s_sock >= 0) {
        close(s_sock);
        s_sock = -1;
    }

    if (s_dns_queue) {
        vQueueDelete(s_dns_queue);
        s_dns_queue = NULL;
    }

    s_running = false;

    return ESP_OK;
}

dns_filter_stats_t dns_filter_get_stats(void)
{
    return s_stats;
}
