#include "admin_server.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_system.h"

#include "mbedtls/md.h"
#include "mbedtls/pk.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "config_store.h"

static const char *TAG = "admin_server";

static httpd_handle_t s_server = NULL;
static bool s_running = false;

#define ADMIN_POST_BUF_SIZE 2048

static const char HTML_PAGE[] =
"<!doctype html>"
"<html>"
"<head>"
"<meta charset='utf-8'>"
"<meta name='viewport' content='width=device-width, initial-scale=1'>"
"<title>ZoneGuard Setup</title>"
"<style>"
"body{font-family:Arial,sans-serif;background:#101418;color:#f2f2f2;margin:0;padding:24px;}"
".box{max-width:420px;margin:auto;background:#181f26;padding:20px;border-radius:14px;box-shadow:0 0 20px #0008;}"
"h1{font-size:22px;margin-top:0;}"
"label{display:block;margin-top:14px;font-size:14px;color:#cbd5df;}"
"input{width:100%;box-sizing:border-box;padding:10px;margin-top:6px;border-radius:8px;border:1px solid #334;background:#0c1117;color:#fff;}"
"button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:8px;background:#2d7dff;color:#fff;font-weight:bold;}"
".hint{font-size:12px;color:#9aa4ad;margin-top:12px;line-height:1.4;}"
"</style>"
"</head>"
"<body>"
"<div class='box'>"
"<h1>ZoneGuard Setup</h1>"
"<form method='POST' action='/save'>"
"<label>Nome do roteador principal</label>"
"<input name='sta_ssid' maxlength='31' required>"
"<label>Senha do roteador principal</label>"
"<input name='sta_password' type='password' maxlength='63'>"
"<label>Nome do AP do ESP</label>"
"<input name='ap_ssid' maxlength='31' value='ZoneGuard_Sala' required>"
"<label>Senha do AP do ESP</label>"
"<input name='ap_password' type='password' maxlength='63' value='zoneguard123' required>"
"<label>Chave pública do usuário</label>"
"<input id='pub_key_user' type='file' accept='.pem,.pub,.txt' required>"
"<textarea id='issuer_public_key_pem' name='issuer_public_key_pem' hidden></textarea>"
"<button type='submit'>Salvar e reiniciar</button>"
"</form>"
"<div class='hint'>Depois de salvar, este servidor de configuração não será iniciado no modo normal.</div>"
"</div>"
"<script>"
"document.getElementById('pub_key_user').addEventListener('change',async function(ev){"
"var file=ev.target.files[0];"
"if(!file){return;}"
"document.getElementById('issuer_public_key_pem').value=await file.text();"
"});"
"</script>"
"</body>"
"</html>";

static void safe_copy(char *dst, size_t dst_size, const char *src)
{
    if (!dst || dst_size == 0) {
        return;
    }

    if (!src) {
        dst[0] = '\0';
        return;
    }

    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

static void url_decode_n(char *dst, size_t dst_size, const char *src, size_t src_len)
{
    if (!dst || dst_size == 0) return;

    size_t di = 0;

    for (size_t si = 0; src && si < src_len && di + 1 < dst_size; ++si) {
        if (src[si] == '+') {
            dst[di++] = ' ';
        } else if (src[si] == '%' && si + 2 < src_len) {
            int hi = hex_value(src[si + 1]);
            int lo = hex_value(src[si + 2]);

            if (hi >= 0 && lo >= 0) {
                dst[di++] = (char)((hi << 4) | lo);
                si += 2;
            } else {
                dst[di++] = src[si];
            }
        } else {
            dst[di++] = src[si];
        }
    }

    dst[di] = '\0';
}

static bool form_get_value(
    const char *body,
    const char *key,
    char *out,
    size_t out_size
)
{
    if (!body || !key || !out || out_size == 0) {
        return false;
    }

    out[0] = '\0';

    size_t key_len = strlen(key);
    const char *p = body;

    while (p && *p) {
        const char *eq = strchr(p, '=');
        if (!eq) break;

        const char *amp = strchr(eq + 1, '&');
        size_t name_len = (size_t)(eq - p);

        if (name_len == key_len && strncmp(p, key, key_len) == 0) {
            size_t value_len = amp ? (size_t)(amp - (eq + 1)) : strlen(eq + 1);

            url_decode_n(out, out_size, eq + 1, value_len);
            return true;
        }

        p = amp ? amp + 1 : NULL;
    }

    return false;
}

static esp_err_t validate_issuer_public_key_pem(const char *pem)
{
    if (!pem || pem[0] == '\0') {
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    int rc = mbedtls_pk_parse_public_key(
        &pk,
        (const unsigned char *)pem,
        strlen(pem) + 1
    );

    if (rc == 0 && !mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA)) {
        rc = -1;
    }

    mbedtls_pk_free(&pk);
    return rc == 0 ? ESP_OK : ESP_ERR_INVALID_ARG;
}

static esp_err_t compute_issuer_key_id(
    const char *pem,
    uint8_t out_key_id[CONFIG_STORE_KEY_ID_LEN]
)
{
    if (!pem || !out_key_id) {
        return ESP_ERR_INVALID_ARG;
    }

    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) {
        return ESP_FAIL;
    }

    uint8_t digest[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    int rc = mbedtls_md_setup(&ctx, info, 0);
    if (rc == 0) rc = mbedtls_md_starts(&ctx);
    if (rc == 0) {
        rc = mbedtls_md_update(
            &ctx,
            (const unsigned char *)pem,
            strlen(pem)
        );
    }
    if (rc == 0) rc = mbedtls_md_finish(&ctx, digest);

    mbedtls_md_free(&ctx);

    if (rc != 0) {
        return ESP_FAIL;
    }

    memcpy(out_key_id, digest, CONFIG_STORE_KEY_ID_LEN);
    return ESP_OK;
}

static esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, HTML_PAGE, HTTPD_RESP_USE_STRLEN);
}

static void restart_later_task(void *arg)
{
    (void)arg;

    /*
     * Dá tempo do navegador receber a resposta.
     */
    vTaskDelay(pdMS_TO_TICKS(1200));

    /*
     * Não é estritamente necessário parar antes de reiniciar,
     * mas isso mostra a intenção correta: liberar recursos.
     */
    admin_server_stop();

    esp_restart();
}

static esp_err_t save_post_handler(httpd_req_t *req)
{
    char body[ADMIN_POST_BUF_SIZE];
    char issuer_public_key_pem[512];

    int total = req->content_len;

    if (total <= 0 || total >= ADMIN_POST_BUF_SIZE) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid body");
        return ESP_FAIL;
    }

    int received = 0;

    while (received < total) {
        int ret = httpd_req_recv(req, body + received, total - received);

        if (ret <= 0) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "recv failed");
            return ESP_FAIL;
        }

        received += ret;
    }

    body[received] = '\0';

    char sta_ssid[32];
    char sta_password[64];
    char ap_ssid[32];
    char ap_password[64];

    if (!form_get_value(body, "sta_ssid", sta_ssid, sizeof(sta_ssid)) ||
        !form_get_value(body, "sta_password", sta_password, sizeof(sta_password)) ||
        !form_get_value(body, "ap_ssid", ap_ssid, sizeof(ap_ssid)) ||
        !form_get_value(body, "ap_password", ap_password, sizeof(ap_password)) ||
        !form_get_value(
            body,
            "issuer_public_key_pem",
            issuer_public_key_pem,
            sizeof(issuer_public_key_pem)
        )) {

        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing fields");
        return ESP_FAIL;
    }

    if (strlen(sta_ssid) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "sta_ssid empty");
        return ESP_FAIL;
    }

    if (strlen(ap_ssid) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ap_ssid empty");
        return ESP_FAIL;
    }

    /*
     * WPA/WPA2 exige senha com pelo menos 8 caracteres.
     */
    if (strlen(ap_password) < 8) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ap_password too short");
        return ESP_FAIL;
    }

    if (validate_issuer_public_key_pem(issuer_public_key_pem) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid issuer public key");
        return ESP_FAIL;
    }

    zoneguard_config_t cfg;
    config_store_set_defaults(&cfg);

    safe_copy(cfg.sta_ssid, sizeof(cfg.sta_ssid), sta_ssid);
    safe_copy(cfg.sta_password, sizeof(cfg.sta_password), sta_password);
    safe_copy(cfg.ap_ssid, sizeof(cfg.ap_ssid), ap_ssid);
    safe_copy(cfg.ap_password, sizeof(cfg.ap_password), ap_password);
    safe_copy(
        cfg.issuer_public_key_pem,
        sizeof(cfg.issuer_public_key_pem),
        issuer_public_key_pem
    );

    esp_err_t key_id_err = compute_issuer_key_id(
        issuer_public_key_pem,
        cfg.issuer_key_id
    );
    if (key_id_err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "key id failed");
        return ESP_FAIL;
    }

    cfg.ap_channel = 6;
    cfg.ap_max_connections = 4;

    esp_err_t err = config_store_save(&cfg);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "falha ao salvar config: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "save failed");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "config salva. Reiniciando para modo normal.");

    const char *resp =
        "<!doctype html><html><body>"
        "<h2>Config salva.</h2>"
        "<p>O ZoneGuard vai reiniciar em modo normal.</p>"
        "</body></html>";

    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);

    /*
     * Não chame httpd_stop() diretamente dentro do handler.
     * Criamos uma task para responder primeiro e parar/reiniciar depois.
     */
    xTaskCreate(
        restart_later_task,
        "admin_restart",
        3072,
        NULL,
        5,
        NULL
    );

    return ESP_OK;
}

esp_err_t admin_server_start(const admin_server_config_t *config)
{
    (void)config;

    if (s_running) {
        return ESP_OK;
    }

    httpd_config_t http_config = HTTPD_DEFAULT_CONFIG();

    /*
     * Mantém o servidor pequeno.
     */
    http_config.server_port = 80;
    http_config.max_uri_handlers = 4;
    http_config.max_open_sockets = 2;
    http_config.stack_size = 8192;
    http_config.lru_purge_enable = true;

    esp_err_t err = httpd_start(&s_server, &http_config);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start falhou: %s", esp_err_to_name(err));
        return err;
    }

    httpd_uri_t root_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = root_get_handler,
        .user_ctx = NULL
    };

    httpd_uri_t save_uri = {
        .uri = "/save",
        .method = HTTP_POST,
        .handler = save_post_handler,
        .user_ctx = NULL
    };

    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &root_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &save_uri));

    s_running = true;

    ESP_LOGI(TAG, "admin_server iniciado em http://192.168.4.1/");

    return ESP_OK;
}

esp_err_t admin_server_stop(void)
{
    if (!s_running || !s_server) {
        return ESP_OK;
    }

    httpd_handle_t server = s_server;

    s_server = NULL;
    s_running = false;

    ESP_LOGW(TAG, "parando admin_server e liberando recursos");

    return httpd_stop(server);
}

bool admin_server_is_running(void)
{
    return s_running;
}
