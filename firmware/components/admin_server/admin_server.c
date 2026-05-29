#include "admin_server.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"

#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "psa/crypto.h"

#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "freertos/task.h"

#include "config_store.h"
#include "amino_acids.h"
#include "ribosome_store.h"
#include "ribosome_table.h"
#include "rna_membrane.h"

static const char *TAG = "admin_server";

static httpd_handle_t s_server = NULL;
static bool s_running = false;
static bool s_unlocked = false;
static admin_server_mode_t s_mode = ADMIN_SERVER_MODE_BOOTSTRAP;
static esp_timer_handle_t s_window_timer = NULL;
static void (*s_on_window_closed)(void *ctx) = NULL;
static void *s_window_ctx = NULL;
static uint8_t s_challenge[32] = {0};
static bool s_challenge_valid = false;

#define ADMIN_POST_BUF_SIZE 2048
#define ADMIN_SIGNATURE_MAX_LEN 96
#define ADMIN_DEVICE_SECRET_HEX_LEN (RIBOSOME_DEVICE_SECRET_LEN * 2)
#define ADMIN_UNLOCKED_WINDOW_MS 180000
#define ADMIN_SEEN_CLIENTS_MAX 16
#define ADMIN_HTTPD_START_RETRIES 6
#define ADMIN_HTTPD_START_RETRY_DELAY_MS 250
#define ADMIN_HTTPD_FORCE_STOP_DELAY_MS 500
#define ADMIN_HTTPD_STACK_SIZE 8192
#define ADMIN_HTTPD_BOOTSTRAP_STACK_SIZE 8192

typedef struct {
    bool in_use;
    char client_id[RIBOSOME_MQTT_CLIENT_ID_LEN];
    uint32_t seen_count;
    int64_t last_seen_us;
} admin_seen_client_t;

static admin_seen_client_t s_seen_clients[ADMIN_SEEN_CLIENTS_MAX];
static portMUX_TYPE s_seen_lock = portMUX_INITIALIZER_UNLOCKED;

static void safe_copy(char *dst, size_t dst_size, const char *src);

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

static const char MAINTENANCE_LOCKED_PAGE[] =
"<!doctype html>"
"<html>"
"<head>"
"<meta charset='utf-8'>"
"<meta name='viewport' content='width=device-width, initial-scale=1'>"
"<title>BlindNet Setup</title>"
"<style>"
"body{font-family:Arial,sans-serif;background:#101418;color:#f2f2f2;margin:0;padding:24px;}"
".box{max-width:520px;margin:auto;background:#181f26;padding:20px;border-radius:14px;box-shadow:0 0 20px #0008;}"
"h1{font-size:22px;margin-top:0;}"
"label{display:block;margin-top:12px;font-size:14px;color:#cbd5df;}"
"input{width:100%;box-sizing:border-box;padding:10px;margin-top:6px;border-radius:8px;border:1px solid #334;background:#0c1117;color:#fff;}"
"button{width:100%;margin-top:18px;padding:12px;border:0;border-radius:8px;background:#2d7dff;color:#fff;font-weight:bold;}"
".hint{font-size:12px;color:#9aa4ad;margin-top:12px;line-height:1.4;}"
"code{word-break:break-all;color:#b8d7ff;}"
"</style>"
"</head>"
"<body>"
"<div class='box'>"
"<h1>BlindNet Admin</h1>"
"<p class='hint'>Assine o desafio retornado em <code>/challenge</code> com sua chave privada e envie a assinatura DER em hexadecimal.</p>"
"<form method='POST' action='/unlock'>"
"<label>Assinatura DER em hex</label>"
"<input name='signature_hex' maxlength='192' required>"
"<button type='submit'>Desbloquear</button>"
"</form>"
"<p class='hint'>Sem assinatura válida, a configuração principal permanece fechada.</p>"
"</div>"
"</body>"
"</html>";

static const char MAINTENANCE_PAGE[] __attribute__((unused)) =
"<!doctype html>"
"<html>"
"<head>"
"<meta charset='utf-8'>"
"<meta name='viewport' content='width=device-width, initial-scale=1'>"
"<title>BlindNet Setup</title>"
"<style>"
"body{font-family:Arial,sans-serif;background:#101418;color:#f2f2f2;margin:0;padding:24px;}"
".box{max-width:520px;margin:auto;background:#181f26;padding:20px;border-radius:14px;box-shadow:0 0 20px #0008;}"
"h1{font-size:22px;margin-top:0;}h2{font-size:16px;margin-top:22px;}"
"label{display:block;margin-top:12px;font-size:14px;color:#cbd5df;}"
"input{width:100%;box-sizing:border-box;padding:10px;margin-top:6px;border-radius:8px;border:1px solid #334;background:#0c1117;color:#fff;}"
"button{width:100%;margin-top:18px;padding:12px;border:0;border-radius:8px;background:#2d7dff;color:#fff;font-weight:bold;}"
".hint{font-size:12px;color:#9aa4ad;margin-top:12px;line-height:1.4;}"
"</style>"
"</head>"
"<body>"
"<div class='box'>"
"<h1>BlindNet Setup</h1>"
"<p class='hint'>Janela administrativa desbloqueada temporariamente.</p>"
"<h2>Configurar membrane</h2>"
"<form method='POST' action='/membrane/template/set'>"
"<label>Template id</label>"
"<input name='template_id' type='number' min='1' value='100' required>"
"<label>Nome do template</label>"
"<input name='template_name' maxlength='31' value='DEVICE_CUSTOM' required>"
"<label>Amino acids permitidos</label>"
"<input name='amino_ids' maxlength='48' value='1,2,7,8' required>"
"<button type='submit'>Salvar template</button>"
"</form>"
"<p class='hint'>Amino ids: 1 ON, 2 OFF, 3 OPEN, 4 CLOSE, 5 SET_SPEED, 6 SET_LEVEL, 7 READ_STATE, 8 TOGGLE, 9 LOCK, 10 UNLOCK, 11 SET_TEMPERATURE, 12 SET_MODE.</p>"
"<h2>Configurar membrane do dispositivo</h2>"
"<form method='POST' action='/device/membrane/set'>"
"<label>MQTT client id</label>"
"<input name='mqtt_client_id' maxlength='32' required>"
"<label>Template id</label>"
"<input name='template_id' type='number' min='1' value='100' required>"
"<label>Nome do template</label>"
"<input name='template_name' maxlength='31' value='DEVICE_CUSTOM' required>"
"<label>Amino acids permitidos</label>"
"<input name='amino_ids' maxlength='48' value='1,2,7,8' required>"
"<button type='submit'>Aplicar no dispositivo</button>"
"</form>"
"<h2>Cadastrar dispositivo</h2>"
"<form method='POST' action='/ribosome/add'>"
"<label>MQTT client id</label>"
"<input name='mqtt_client_id' maxlength='32' required>"
"<label>Template id</label>"
"<input name='template_id' type='number' min='1' value='1' required>"
"<label>Epoch</label>"
"<input name='epoch' type='number' min='0' value='1' required>"
"<label>Device secret hex (32 bytes)</label>"
"<input name='device_secret_hex' maxlength='64' required>"
"<button type='submit'>Cadastrar ribosome</button>"
"</form>"
"<h2>Remover dispositivo</h2>"
"<form method='POST' action='/ribosome/remove'>"
"<label>MQTT client id</label>"
"<input name='mqtt_client_id' maxlength='32' required>"
"<button type='submit'>Remover dispositivo</button>"
"</form>"
"<p class='hint'>A janela fecha automaticamente.</p>"
"</div>"
"</body>"
"</html>";

void admin_server_note_mqtt_client(const char *client_id)
{
    if (!client_id || client_id[0] == '\0') {
        return;
    }

    char clean_id[RIBOSOME_MQTT_CLIENT_ID_LEN] = {0};
    safe_copy(clean_id, sizeof(clean_id), client_id);
    int64_t now_us = esp_timer_get_time();
    int empty_slot = -1;
    int oldest_slot = 0;
    int64_t oldest_seen = INT64_MAX;

    portENTER_CRITICAL(&s_seen_lock);
    for (int i = 0; i < ADMIN_SEEN_CLIENTS_MAX; ++i) {
        if (s_seen_clients[i].in_use &&
            strncmp(s_seen_clients[i].client_id, clean_id, RIBOSOME_MQTT_CLIENT_ID_LEN) == 0) {
            s_seen_clients[i].seen_count++;
            s_seen_clients[i].last_seen_us = now_us;
            portEXIT_CRITICAL(&s_seen_lock);
            return;
        }

        if (!s_seen_clients[i].in_use && empty_slot < 0) {
            empty_slot = i;
        }
        if (s_seen_clients[i].last_seen_us < oldest_seen) {
            oldest_seen = s_seen_clients[i].last_seen_us;
            oldest_slot = i;
        }
    }

    int slot = empty_slot >= 0 ? empty_slot : oldest_slot;
    memset(&s_seen_clients[slot], 0, sizeof(s_seen_clients[slot]));
    s_seen_clients[slot].in_use = true;
    strncpy(s_seen_clients[slot].client_id, clean_id, sizeof(s_seen_clients[slot].client_id) - 1);
    s_seen_clients[slot].seen_count = 1;
    s_seen_clients[slot].last_seen_us = now_us;
    portEXIT_CRITICAL(&s_seen_lock);
}

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

static esp_err_t parse_hex(
    const char *hex,
    uint8_t *out,
    size_t out_size,
    size_t *out_len
)
{
    if (out_len) {
        *out_len = 0;
    }
    if (!hex || !out || out_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t hex_len = strlen(hex);
    if ((hex_len % 2) != 0 || (hex_len / 2) > out_size) {
        return ESP_ERR_INVALID_SIZE;
    }

    size_t len = hex_len / 2;
    for (size_t i = 0; i < len; ++i) {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            mbedtls_platform_zeroize(out, out_size);
            return ESP_ERR_INVALID_ARG;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    if (out_len) {
        *out_len = len;
    }
    return ESP_OK;
}

static esp_err_t parse_exact_hex(const char *hex, uint8_t *out, size_t out_size)
{
    size_t len = 0;
    esp_err_t err = parse_hex(hex, out, out_size, &len);
    if (err != ESP_OK) {
        return err;
    }
    return len == out_size ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

static bool parse_u32_field(const char *text, uint32_t *out)
{
    if (!text || !out || text[0] == '\0') {
        return false;
    }

    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (!end || *end != '\0' || value > UINT32_MAX) {
        return false;
    }

    *out = (uint32_t)value;
    return true;
}

static bool parse_amino_ids(
    const char *text,
    amino_acid_id_t *out_ids,
    uint8_t *out_count
)
{
    if (!text || !out_ids || !out_count) {
        return false;
    }

    *out_count = 0;
    const char *p = text;

    while (*p) {
        while (*p == ' ' || *p == ',' || *p == ';' || *p == '\t') {
            ++p;
        }
        if (*p == '\0') {
            break;
        }

        char *end = NULL;
        unsigned long value = strtoul(p, &end, 10);
        if (!end || end == p || value > UINT16_MAX) {
            return false;
        }

        amino_acid_id_t id = (amino_acid_id_t)value;
        if (!amino_acid_id_valid(id)) {
            return false;
        }

        if (*out_count >= RNA_TEMPLATE_MAX_AMINOS) {
            return false;
        }

        for (uint8_t i = 0; i < *out_count; ++i) {
            if (out_ids[i] == id) {
                return false;
            }
        }

        out_ids[*out_count] = id;
        *out_count = (uint8_t)(*out_count + 1);
        p = end;

        if (*p != '\0' && *p != ' ' && *p != ',' && *p != ';' && *p != '\t') {
            return false;
        }
    }

    return *out_count > 0;
}

static void copy_template_sanitized(
    rna_template_t *dst,
    const rna_template_t *src
)
{
    if (!dst || !src) {
        return;
    }

    rna_template_clear(dst);
    dst->id = src->id;
    safe_copy(dst->name, sizeof(dst->name), src->name);
    dst->amino_count = src->amino_count;
    memcpy(dst->aminos, src->aminos, sizeof(dst->aminos));
    dst->flags = src->flags;
}

static esp_err_t rna_template_table_upsert(
    rna_template_table_t *table,
    const rna_template_t *template_rule
)
{
    if (!table || !template_rule || table->count > RNA_MAX_TEMPLATES) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = rna_template_validate(template_rule);
    if (err != ESP_OK) {
        return err;
    }

    for (size_t i = 0; i < table->count; ++i) {
        if (table->templates[i].id == template_rule->id) {
            copy_template_sanitized(&table->templates[i], template_rule);
            return ESP_OK;
        }
    }

    return rna_template_table_add(table, template_rule);
}

static esp_err_t build_template_from_fields(
    const char *template_text,
    const char *template_name,
    const char *amino_text,
    rna_template_t *out_template
)
{
    if (!template_text || !template_name || !amino_text || !out_template) {
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t template_id = 0;
    if (!parse_u32_field(template_text, &template_id) || template_id > UINT16_MAX) {
        return ESP_ERR_INVALID_ARG;
    }

    rna_template_clear(out_template);
    out_template->id = (rna_template_id_t)template_id;
    safe_copy(out_template->name, sizeof(out_template->name), template_name);

    if (!parse_amino_ids(
            amino_text,
            out_template->aminos,
            &out_template->amino_count
        )) {
        rna_template_clear(out_template);
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = rna_template_validate(out_template);
    if (err != ESP_OK) {
        rna_template_clear(out_template);
    }

    return err;
}

static esp_err_t ribosome_assign_template(
    ribosome_table_t *table,
    const char *mqtt_client_id,
    rna_template_id_t template_id
)
{
    if (!table || table->count > RIBOSOME_MAX_ENTRIES ||
        !mqtt_client_id || !rna_template_id_valid(template_id)) {
        return ESP_ERR_INVALID_ARG;
    }

    for (size_t i = 0; i < table->count; ++i) {
        if (strncmp(
                table->entries[i].mqtt_client_id,
                mqtt_client_id,
                RIBOSOME_MQTT_CLIENT_ID_LEN
            ) == 0) {
            table->entries[i].template_id = template_id;
            return ESP_OK;
        }
    }

    return ESP_ERR_NOT_FOUND;
}

static void hex_encode(const uint8_t *bytes, size_t len, char *out, size_t out_size)
{
    static const char k_hex[] = "0123456789abcdef";
    if (!bytes || !out || out_size < (len * 2 + 1)) {
        return;
    }

    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = k_hex[bytes[i] >> 4];
        out[i * 2 + 1] = k_hex[bytes[i] & 0x0Fu];
    }
    out[len * 2] = '\0';
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

    if (!strstr(pem, "-----BEGIN PUBLIC KEY-----") ||
        !strstr(pem, "-----END PUBLIC KEY-----")) {
        return ESP_ERR_INVALID_ARG;
    }

    return ESP_OK;
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

    uint8_t digest[32] = {0};
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    int rc = mbedtls_md_setup(&ctx, info, 0);
    if (rc == 0) rc = mbedtls_md_starts(&ctx);
    if (rc == 0) {
        for (const char *p = pem; *p; ++p) {
            if (*p == '\r') {
                continue;
            }
            unsigned char ch = (unsigned char)*p;
            rc = mbedtls_md_update(&ctx, &ch, 1);
            if (rc != 0) {
                break;
            }
        }
    }
    if (rc == 0) rc = mbedtls_md_finish(&ctx, digest);

    mbedtls_md_free(&ctx);

    if (rc == 0) {
        memcpy(out_key_id, digest, CONFIG_STORE_KEY_ID_LEN);
    }

    mbedtls_platform_zeroize(digest, sizeof(digest));
    return rc == 0 ? ESP_OK : ESP_FAIL;
}

static void generate_challenge(void)
{
    for (size_t i = 0; i < sizeof(s_challenge); i += sizeof(uint32_t)) {
        uint32_t r = esp_random();
        size_t remaining = sizeof(s_challenge) - i;
        size_t copy_len = remaining < sizeof(r) ? remaining : sizeof(r);
        memcpy(&s_challenge[i], &r, copy_len);
    }

    s_challenge_valid = true;
}

static esp_err_t hash_challenge(uint8_t out_hash[32])
{
    if (!out_hash || !s_challenge_valid) {
        return ESP_ERR_INVALID_STATE;
    }

    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) {
        return ESP_FAIL;
    }

    int rc = mbedtls_md(
        info,
        s_challenge,
        sizeof(s_challenge),
        out_hash
    );

    return rc == 0 ? ESP_OK : ESP_FAIL;
}

static esp_err_t verify_admin_signature(
    const uint8_t *signature,
    size_t signature_len
)
{
    if (!signature || signature_len == 0 || signature_len > ADMIN_SIGNATURE_MAX_LEN) {
        return ESP_ERR_INVALID_ARG;
    }

    zoneguard_config_t cfg;
    mbedtls_platform_zeroize(&cfg, sizeof(cfg));

    esp_err_t err = config_store_load(&cfg);
    if (err != ESP_OK) {
        mbedtls_platform_zeroize(&cfg, sizeof(cfg));
        return err;
    }

    uint8_t hash[32] = {0};
    err = hash_challenge(hash);
    if (err != ESP_OK) {
        mbedtls_platform_zeroize(hash, sizeof(hash));
        mbedtls_platform_zeroize(&cfg, sizeof(cfg));
        return err;
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    int rc = mbedtls_pk_parse_public_key(
        &pk,
        (const unsigned char *)cfg.issuer_public_key_pem,
        strlen(cfg.issuer_public_key_pem) + 1
    );

    if (rc == 0) {
        rc = mbedtls_pk_verify(
            &pk,
            MBEDTLS_MD_SHA256,
            hash,
            sizeof(hash),
            signature,
            signature_len
        );
    }

    mbedtls_pk_free(&pk);
    mbedtls_platform_zeroize(hash, sizeof(hash));
    mbedtls_platform_zeroize(&cfg, sizeof(cfg));

    return rc == 0 ? ESP_OK : ESP_ERR_INVALID_STATE;
}

static void close_window_task(void *arg)
{
    (void)arg;
    admin_server_stop();
    vTaskDelete(NULL);
}

static void window_timer_cb(void *arg)
{
    (void)arg;
    xTaskCreate(
        close_window_task,
        "admin_window_close",
        3072,
        NULL,
        5,
        NULL
    );
}

static esp_err_t restart_window_timer(uint32_t timeout_ms)
{
    if (timeout_ms == 0) {
        return ESP_OK;
    }

    if (!s_window_timer) {
        const esp_timer_create_args_t args = {
            .callback = window_timer_cb,
            .arg = NULL,
            .dispatch_method = ESP_TIMER_TASK,
            .name = "admin_window",
        };

        esp_err_t err = esp_timer_create(&args, &s_window_timer);
        if (err != ESP_OK) {
            return err;
        }
    }

    (void)esp_timer_stop(s_window_timer);
    return esp_timer_start_once(s_window_timer, (uint64_t)timeout_ms * 1000ULL);
}

static esp_err_t send_chunkf(httpd_req_t *req, const char *fmt, ...)
{
    char chunk[768];
    va_list args;
    va_list args_copy;
    va_start(args, fmt);
    va_copy(args_copy, args);
    int len = vsnprintf(chunk, sizeof(chunk), fmt, args);
    va_end(args);

    if (len < 0) {
        va_end(args_copy);
        return ESP_ERR_INVALID_SIZE;
    }

    if ((size_t)len < sizeof(chunk)) {
        va_end(args_copy);
        return httpd_resp_send_chunk(req, chunk, len);
    }

    char *heap_chunk = (char *)malloc((size_t)len + 1);
    if (!heap_chunk) {
        va_end(args_copy);
        return ESP_ERR_NO_MEM;
    }

    int heap_len = vsnprintf(heap_chunk, (size_t)len + 1, fmt, args_copy);
    va_end(args_copy);
    if (heap_len < 0 || heap_len != len) {
        free(heap_chunk);
        return ESP_ERR_INVALID_SIZE;
    }

    esp_err_t err = httpd_resp_send_chunk(req, heap_chunk, heap_len);
    free(heap_chunk);
    return err;
}

static esp_err_t send_escaped(httpd_req_t *req, const char *text)
{
    if (!text) {
        return ESP_OK;
    }

    for (const char *p = text; *p; ++p) {
        const char *escaped = NULL;
        switch (*p) {
        case '&':
            escaped = "&amp;";
            break;
        case '<':
            escaped = "&lt;";
            break;
        case '>':
            escaped = "&gt;";
            break;
        case '"':
            escaped = "&quot;";
            break;
        case '\'':
            escaped = "&#39;";
            break;
        default:
            break;
        }

        esp_err_t err = escaped ?
            httpd_resp_send_chunk(req, escaped, HTTPD_RESP_USE_STRLEN) :
            httpd_resp_send_chunk(req, p, 1);
        if (err != ESP_OK) {
            return err;
        }
    }

    return ESP_OK;
}

static esp_err_t redirect_to_root(httpd_req_t *req)
{
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/");
    return httpd_resp_sendstr(req, "");
}

static void generate_device_secret(uint8_t out_secret[RIBOSOME_DEVICE_SECRET_LEN])
{
    bool any_nonzero = false;

    for (size_t i = 0; i < RIBOSOME_DEVICE_SECRET_LEN; i += sizeof(uint32_t)) {
        uint32_t r = esp_random();
        size_t copy_len = RIBOSOME_DEVICE_SECRET_LEN - i;
        if (copy_len > sizeof(r)) {
            copy_len = sizeof(r);
        }
        memcpy(&out_secret[i], &r, copy_len);
    }

    for (size_t i = 0; i < RIBOSOME_DEVICE_SECRET_LEN; ++i) {
        any_nonzero = any_nonzero || out_secret[i] != 0;
    }
    if (!any_nonzero) {
        out_secret[0] = 1;
    }
}

static ribosome_table_entry_t *find_ribosome_entry(
    ribosome_table_t *table,
    const char *mqtt_client_id
)
{
    if (!table || table->count > RIBOSOME_MAX_ENTRIES || !mqtt_client_id) {
        return NULL;
    }

    for (size_t i = 0; i < table->count; ++i) {
        if (strncmp(
                table->entries[i].mqtt_client_id,
                mqtt_client_id,
                RIBOSOME_MQTT_CLIENT_ID_LEN
            ) == 0) {
            return &table->entries[i];
        }
    }

    return NULL;
}

static esp_err_t render_seen_devices(httpd_req_t *req, const ribosome_table_t *ribosomes)
{
    admin_seen_client_t snapshot[ADMIN_SEEN_CLIENTS_MAX];
    memset(snapshot, 0, sizeof(snapshot));

    portENTER_CRITICAL(&s_seen_lock);
    memcpy(snapshot, s_seen_clients, sizeof(snapshot));
    portEXIT_CRITICAL(&s_seen_lock);

    esp_err_t err = send_chunkf(
        req,
        "<h2>Dispositivos detectados no broker</h2>"
        "<table><thead><tr><th>MQTT client id</th><th>Status</th><th>Vistos</th><th>Ação</th></tr></thead><tbody>"
    );
    if (err != ESP_OK) {
        return err;
    }

    bool any = false;
    for (size_t i = 0; i < ADMIN_SEEN_CLIENTS_MAX; ++i) {
        if (!snapshot[i].in_use) {
            continue;
        }
        any = true;
        bool registered = ribosome_table_entry_exists(ribosomes, snapshot[i].client_id);

        err = send_chunkf(req, "<tr><td><code>");
        if (err != ESP_OK) {
            return err;
        }
        err = send_escaped(req, snapshot[i].client_id);
        if (err != ESP_OK) {
            return err;
        }
        err = send_chunkf(
            req,
            "</code></td><td>%s</td><td>%lu</td><td>",
            registered ? "cadastrado" : "pendente",
            (unsigned long)snapshot[i].seen_count
        );
        if (err != ESP_OK) {
            return err;
        }

        if (!registered) {
            err = send_chunkf(
                req,
                "<form class='inline' method='POST' action='/ribosome/provision'>"
                "<input type='hidden' name='mqtt_client_id' value='"
            );
            if (err != ESP_OK) {
                return err;
            }
            err = send_escaped(req, snapshot[i].client_id);
            if (err != ESP_OK) {
                return err;
            }
            err = send_chunkf(
                req,
                "'><input name='template_id' type='number' min='1' value='1'>"
                "<input name='epoch' type='number' min='1' value='1'>"
                "<button type='submit'>Autorizar</button></form>"
            );
        } else {
            err = send_chunkf(req, "<span class='muted'>pronto</span>");
        }
        if (err != ESP_OK) {
            return err;
        }
        err = send_chunkf(req, "</td></tr>");
        if (err != ESP_OK) {
            return err;
        }
    }

    if (!any) {
        err = send_chunkf(
            req,
            "<tr><td colspan='4' class='muted'>Nenhum cliente MQTT visto ainda.</td></tr>"
        );
        if (err != ESP_OK) {
            return err;
        }
    }

    return send_chunkf(req, "</tbody></table>");
}

static esp_err_t render_ribosomes(httpd_req_t *req, const ribosome_table_t *table)
{
    esp_err_t err = send_chunkf(
        req,
        "<h2>Ribosomes cadastrados</h2>"
        "<table><thead><tr><th>MQTT client id</th><th>RNA</th><th>Epoch</th><th>Device secret</th><th>Ações</th></tr></thead><tbody>"
    );
    if (err != ESP_OK) {
        return err;
    }

    if (!table || table->count == 0 || table->count > RIBOSOME_MAX_ENTRIES) {
        err = send_chunkf(
            req,
            "<tr><td colspan='5' class='muted'>Nenhum dispositivo cadastrado.</td></tr>"
        );
        if (err != ESP_OK) {
            return err;
        }
        return send_chunkf(req, "</tbody></table>");
    }

    for (size_t i = 0; i < table->count; ++i) {
        char secret_hex[ADMIN_DEVICE_SECRET_HEX_LEN + 1] = {0};
        hex_encode(
            table->entries[i].device_secret,
            sizeof(table->entries[i].device_secret),
            secret_hex,
            sizeof(secret_hex)
        );

        err = send_chunkf(req, "<tr><td><code>");
        if (err != ESP_OK) {
            return err;
        }
        err = send_escaped(req, table->entries[i].mqtt_client_id);
        if (err != ESP_OK) {
            return err;
        }
        err = send_chunkf(
            req,
            "</code></td><td>%u</td><td>%lu</td><td><code class='secret'>%s</code></td><td>",
            (unsigned)table->entries[i].template_id,
            (unsigned long)table->entries[i].epoch,
            secret_hex
        );
        if (err != ESP_OK) {
            return err;
        }

        err = send_chunkf(
            req,
            "<form class='inline' method='POST' action='/ribosome/regenerate' "
            "onsubmit=\"return confirm('Regenerar o device_secret deste dispositivo? O app precisara usar o novo valor.');\">"
            "<input type='hidden' name='mqtt_client_id' value='"
        );
        if (err != ESP_OK) {
            return err;
        }
        err = send_escaped(req, table->entries[i].mqtt_client_id);
        if (err != ESP_OK) {
            return err;
        }
        err = send_chunkf(
            req,
            "'><button type='submit'>Regenerar secret</button></form>"
            "<form class='inline' method='POST' action='/ribosome/remove' "
            "onsubmit=\"return confirm('Remover este dispositivo?');\">"
            "<input type='hidden' name='mqtt_client_id' value='"
        );
        if (err != ESP_OK) {
            return err;
        }
        err = send_escaped(req, table->entries[i].mqtt_client_id);
        if (err != ESP_OK) {
            return err;
        }
        err = send_chunkf(req, "'><button class='danger' type='submit'>Remover</button></form></td></tr>");
        if (err != ESP_OK) {
            return err;
        }
    }

    return send_chunkf(req, "</tbody></table>");
}

static esp_err_t render_templates(httpd_req_t *req, const rna_template_table_t *templates)
{
    esp_err_t err = send_chunkf(
        req,
        "<h2>RNA disponível</h2>"
        "<table><thead><tr><th>ID</th><th>Nome</th><th>Amino acids</th></tr></thead><tbody>"
    );
    if (err != ESP_OK) {
        return err;
    }

    if (!templates || templates->count == 0 || templates->count > RNA_MAX_TEMPLATES) {
        err = send_chunkf(req, "<tr><td colspan='3' class='muted'>Nenhum RNA carregado.</td></tr>");
        if (err != ESP_OK) {
            return err;
        }
        return send_chunkf(req, "</tbody></table>");
    }

    for (size_t i = 0; i < templates->count; ++i) {
        const rna_template_t *tpl = &templates->templates[i];
        err = send_chunkf(req, "<tr><td>%u</td><td>", (unsigned)tpl->id);
        if (err != ESP_OK) {
            return err;
        }
        err = send_escaped(req, tpl->name);
        if (err != ESP_OK) {
            return err;
        }
        err = send_chunkf(req, "</td><td>");
        if (err != ESP_OK) {
            return err;
        }
        for (size_t j = 0; j < tpl->amino_count; ++j) {
            err = send_chunkf(
                req,
                "%s%u",
                j == 0 ? "" : ",",
                (unsigned)tpl->aminos[j]
            );
            if (err != ESP_OK) {
                return err;
            }
        }
        err = send_chunkf(req, "</td></tr>");
        if (err != ESP_OK) {
            return err;
        }
    }

    return send_chunkf(req, "</tbody></table>");
}

static esp_err_t render_maintenance_page(httpd_req_t *req)
{
    ribosome_table_t *ribosomes = (ribosome_table_t *)calloc(1, sizeof(*ribosomes));
    rna_template_table_t *templates = (rna_template_table_t *)calloc(1, sizeof(*templates));
    if (!ribosomes || !templates) {
        free(ribosomes);
        free(templates);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "admin mem failed");
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = ribosome_store_load_or_init(ribosomes);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "ribosome load failed");
        goto done;
    }

    err = rna_membrane_load_or_init(templates);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "rna load failed");
        goto done;
    }

    httpd_resp_set_type(req, "text/html");
    err = send_chunkf(
        req,
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>BlindNet Admin</title><style>"
        "body{font-family:Arial,sans-serif;background:#101418;color:#f2f2f2;margin:0;padding:20px;}"
        ".wrap{max-width:1120px;margin:auto;}.panel{background:#181f26;padding:16px;border-radius:8px;margin:0 0 16px;}"
        "h1{font-size:22px;margin:0 0 12px;}h2{font-size:16px;margin:0 0 12px;}"
        "table{width:100%;border-collapse:collapse;margin:8px 0 0;}th,td{border-bottom:1px solid #2b3540;padding:8px;text-align:left;vertical-align:top;}"
        "th{color:#b8c7d7;font-size:12px;text-transform:uppercase;}code{word-break:break-all;color:#b8d7ff;}"
        ".secret{font-size:11px}.muted{color:#8fa0ad;font-size:13px}.hint{color:#9aa4ad;font-size:12px;line-height:1.4;}"
        "label{display:block;margin-top:10px;font-size:13px;color:#cbd5df;}input{box-sizing:border-box;padding:9px;border-radius:6px;border:1px solid #334;background:#0c1117;color:#fff;}"
        "form.inline{display:inline-flex;gap:6px;align-items:center;margin:2px 4px 2px 0;}form.inline input{width:76px;}"
        "button{padding:9px 11px;border:0;border-radius:6px;background:#2d7dff;color:#fff;font-weight:bold;cursor:pointer;}button.danger{background:#a33b3b;}"
        ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;}"
        ".full input{width:100%;margin-top:5px;}.full button{width:100%;margin-top:14px;}"
        "</style></head><body><main class='wrap'><h1>BlindNet Admin</h1>"
        "<p class='hint'>Janela administrativa desbloqueada temporariamente. O device_secret fica visivel aqui para o app criptografar o active_substance.</p>"
    );
    if (err != ESP_OK) {
        goto done;
    }

    err = send_chunkf(req, "<section class='panel'>");
    if (err == ESP_OK) {
        err = render_seen_devices(req, ribosomes);
    }
    if (err == ESP_OK) {
        err = send_chunkf(req, "</section><section class='panel'>");
    }
    if (err == ESP_OK) {
        err = render_ribosomes(req, ribosomes);
    }
    if (err == ESP_OK) {
        err = send_chunkf(req, "</section><section class='panel'>");
    }
    if (err == ESP_OK) {
        err = render_templates(req, templates);
    }
    if (err == ESP_OK) {
        err = send_chunkf(
            req,
            "</section><section class='grid'>"
            "<div class='panel full'><h2>Criar/alterar RNA</h2>"
            "<form method='POST' action='/membrane/template/set'>"
            "<label>Template id</label><input name='template_id' type='number' min='1' value='100' required>"
            "<label>Nome do template</label><input name='template_name' maxlength='31' value='DEVICE_CUSTOM' required>"
            "<label>Amino acids permitidos</label><input name='amino_ids' maxlength='48' value='1,2,7,8' required>"
            "<button type='submit'>Salvar RNA</button></form>"
            "<p class='hint'>1 ON, 2 OFF, 3 OPEN, 4 CLOSE, 5 SET_SPEED, 6 SET_LEVEL, 7 READ_STATE, 8 TOGGLE, 9 LOCK, 10 UNLOCK, 11 SET_TEMPERATURE, 12 SET_MODE.</p></div>"
            "<div class='panel full'><h2>Cadastrar manualmente</h2>"
            "<form method='POST' action='/ribosome/add'>"
            "<label>MQTT client id</label><input name='mqtt_client_id' maxlength='32' required>"
            "<label>Template id</label><input name='template_id' type='number' min='1' value='1' required>"
            "<label>Epoch</label><input name='epoch' type='number' min='0' value='1' required>"
            "<label>Device secret hex (32 bytes)</label><input name='device_secret_hex' maxlength='64' required>"
            "<button type='submit'>Cadastrar ribosome</button></form></div>"
            "<div class='panel full'><h2>Aplicar RNA ao dispositivo</h2>"
            "<form method='POST' action='/device/membrane/set'>"
            "<label>MQTT client id</label><input name='mqtt_client_id' maxlength='32' required>"
            "<label>Template id</label><input name='template_id' type='number' min='1' value='100' required>"
            "<label>Nome do template</label><input name='template_name' maxlength='31' value='DEVICE_CUSTOM' required>"
            "<label>Amino acids permitidos</label><input name='amino_ids' maxlength='48' value='1,2,7,8' required>"
            "<button type='submit'>Aplicar</button></form></div>"
            "</section></main></body></html>"
        );
    }
    if (err == ESP_OK) {
        err = httpd_resp_send_chunk(req, NULL, 0);
    }

done:
    mbedtls_platform_zeroize(ribosomes, sizeof(*ribosomes));
    mbedtls_platform_zeroize(templates, sizeof(*templates));
    free(ribosomes);
    free(templates);
    return err;
}

static void admin_server_clear_runtime_state(void)
{
    s_server = NULL;
    s_running = false;
    s_unlocked = false;
    s_challenge_valid = false;
    s_on_window_closed = NULL;
    s_window_ctx = NULL;
    mbedtls_platform_zeroize(s_challenge, sizeof(s_challenge));
}

static esp_err_t admin_server_stop_internal(bool notify_window_closed)
{
    if (!s_server) {
        admin_server_clear_runtime_state();
        return ESP_OK;
    }

    if (s_window_timer) {
        (void)esp_timer_stop(s_window_timer);
    }

    httpd_handle_t server = s_server;
    bool was_maintenance = s_mode == ADMIN_SERVER_MODE_MAINTENANCE;
    void (*on_window_closed)(void *ctx) = s_on_window_closed;
    void *window_ctx = s_window_ctx;

    s_unlocked = false;
    s_challenge_valid = false;
    mbedtls_platform_zeroize(s_challenge, sizeof(s_challenge));

    ESP_LOGW(TAG, "parando admin_server e liberando porta 80");

    esp_err_t err = httpd_stop(server);
    if (err == ESP_OK) {
        admin_server_clear_runtime_state();
    } else {
        ESP_LOGE(TAG, "httpd_stop falhou: %s", esp_err_to_name(err));
        s_on_window_closed = NULL;
        s_window_ctx = NULL;
    }

    if (notify_window_closed && was_maintenance && on_window_closed) {
        on_window_closed(window_ctx);
    }

    return err;
}

static esp_err_t admin_server_force_release_port80(void)
{
    if (!s_server && !s_running) {
        return ESP_OK;
    }

    ESP_LOGW(TAG, "forcando limpeza do HTTP admin antes de abrir janela");
    esp_err_t err = admin_server_stop_internal(false);
    vTaskDelay(pdMS_TO_TICKS(ADMIN_HTTPD_FORCE_STOP_DELAY_MS));
    return err;
}

static esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    if (s_mode == ADMIN_SERVER_MODE_MAINTENANCE) {
        if (!s_unlocked) {
            return httpd_resp_send(req, MAINTENANCE_LOCKED_PAGE, HTTPD_RESP_USE_STRLEN);
        }
        return render_maintenance_page(req);
    }
    return httpd_resp_send(req, HTML_PAGE, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t read_request_body(httpd_req_t *req, char *body, size_t body_size)
{
    if (!req || !body || body_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    int total = req->content_len;
    if (total <= 0 || (size_t)total >= body_size) {
        return ESP_ERR_INVALID_SIZE;
    }

    int received = 0;
    while (received < total) {
        int ret = httpd_req_recv(req, body + received, total - received);
        if (ret <= 0) {
            return ESP_FAIL;
        }
        received += ret;
    }

    body[received] = '\0';
    return ESP_OK;
}

static esp_err_t challenge_get_handler(httpd_req_t *req)
{
    if (s_mode != ADMIN_SERVER_MODE_MAINTENANCE) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not available");
        return ESP_FAIL;
    }

    if (!s_challenge_valid) {
        generate_challenge();
    }

    char hex[(sizeof(s_challenge) * 2) + 1] = {0};
    hex_encode(s_challenge, sizeof(s_challenge), hex, sizeof(hex));

    httpd_resp_set_type(req, "text/plain");
    return httpd_resp_send(req, hex, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t unlock_post_handler(httpd_req_t *req)
{
    char body[ADMIN_POST_BUF_SIZE] = {0};
    char signature_hex[ADMIN_SIGNATURE_MAX_LEN * 2 + 1] = {0};
    uint8_t signature[ADMIN_SIGNATURE_MAX_LEN] = {0};
    size_t signature_len = 0;
    esp_err_t result = ESP_FAIL;

    if (s_mode != ADMIN_SERVER_MODE_MAINTENANCE) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not available");
        goto cleanup;
    }

    if (!s_challenge_valid) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "challenge required");
        goto cleanup;
    }

    if (read_request_body(req, body, sizeof(body)) != ESP_OK ||
        !form_get_value(
            body,
            "signature_hex",
            signature_hex,
            sizeof(signature_hex)
        )) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid body");
        goto cleanup;
    }

    result = parse_hex(
        signature_hex,
        signature,
        sizeof(signature),
        &signature_len
    );
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid signature hex");
        goto cleanup;
    }

    result = verify_admin_signature(signature, signature_len);
    if (result != ESP_OK) {
        ESP_LOGW(TAG, "assinatura admin recusada");
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "signature rejected");
        goto cleanup;
    }

    s_unlocked = true;
    generate_challenge();
    (void)restart_window_timer(ADMIN_UNLOCKED_WINDOW_MS);

    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Refresh", "0; url=/");
    httpd_resp_sendstr(req, "<!doctype html><html><body>unlocked</body></html>");
    result = ESP_OK;

cleanup:
    mbedtls_platform_zeroize(body, sizeof(body));
    mbedtls_platform_zeroize(signature_hex, sizeof(signature_hex));
    mbedtls_platform_zeroize(signature, sizeof(signature));
    return result;
}

static esp_err_t ribosome_add_post_handler(httpd_req_t *req)
{
    char body[ADMIN_POST_BUF_SIZE] = {0};
    char mqtt_client_id[RIBOSOME_MQTT_CLIENT_ID_LEN] = {0};
    char template_text[16] = {0};
    char epoch_text[16] = {0};
    char secret_hex[ADMIN_DEVICE_SECRET_HEX_LEN + 1] = {0};
    uint8_t device_secret[RIBOSOME_DEVICE_SECRET_LEN] = {0};
    ribosome_table_t *table = (ribosome_table_t *)calloc(1, sizeof(*table));
    rna_template_table_t *templates = (rna_template_table_t *)calloc(1, sizeof(*templates));

    esp_err_t result = ESP_FAIL;
    if (!table || !templates) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "admin mem failed");
        result = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    if (s_mode != ADMIN_SERVER_MODE_MAINTENANCE) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not available");
        goto cleanup;
    }

    if (!s_unlocked) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "locked");
        goto cleanup;
    }

    if (read_request_body(req, body, sizeof(body)) != ESP_OK ||
        !form_get_value(body, "mqtt_client_id", mqtt_client_id, sizeof(mqtt_client_id)) ||
        !form_get_value(body, "template_id", template_text, sizeof(template_text)) ||
        !form_get_value(body, "epoch", epoch_text, sizeof(epoch_text)) ||
        !form_get_value(body, "device_secret_hex", secret_hex, sizeof(secret_hex))) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid body");
        goto cleanup;
    }

    uint32_t template_id = 0;
    uint32_t epoch = 0;
    if (!parse_u32_field(template_text, &template_id) ||
        !parse_u32_field(epoch_text, &epoch) ||
        parse_exact_hex(secret_hex, device_secret, sizeof(device_secret)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid fields");
        goto cleanup;
    }

    result = rna_membrane_load_or_init(templates);
    if (result != ESP_OK ||
        !rna_template_table_find(templates, (rna_template_id_t)template_id)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "template not found");
        goto cleanup;
    }

    result = ribosome_store_load_or_init(table);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "load failed");
        goto cleanup;
    }

    const ribosome_entry_config_t entry_config = {
        .mqtt_client_id = mqtt_client_id,
        .template_id = (rna_template_id_t)template_id,
        .epoch = epoch,
        .device_secret = device_secret,
    };

    result = ribosome_table_add_from_config(table, &entry_config);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "add failed");
        goto cleanup;
    }

    result = ribosome_store_save(table);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "save failed");
        goto cleanup;
    }

    httpd_resp_set_type(req, "text/plain");
    httpd_resp_sendstr(req, "ribosome added");

cleanup:
    mbedtls_platform_zeroize(body, sizeof(body));
    mbedtls_platform_zeroize(mqtt_client_id, sizeof(mqtt_client_id));
    mbedtls_platform_zeroize(template_text, sizeof(template_text));
    mbedtls_platform_zeroize(epoch_text, sizeof(epoch_text));
    mbedtls_platform_zeroize(secret_hex, sizeof(secret_hex));
    mbedtls_platform_zeroize(device_secret, sizeof(device_secret));
    if (table) {
        mbedtls_platform_zeroize(table, sizeof(*table));
        free(table);
    }
    if (templates) {
        mbedtls_platform_zeroize(templates, sizeof(*templates));
        free(templates);
    }
    return result;
}

static esp_err_t ribosome_provision_post_handler(httpd_req_t *req)
{
    char body[ADMIN_POST_BUF_SIZE] = {0};
    char mqtt_client_id[RIBOSOME_MQTT_CLIENT_ID_LEN] = {0};
    char template_text[16] = {0};
    char epoch_text[16] = {0};
    uint8_t device_secret[RIBOSOME_DEVICE_SECRET_LEN] = {0};
    ribosome_table_t *table = (ribosome_table_t *)calloc(1, sizeof(*table));
    rna_template_table_t *templates = (rna_template_table_t *)calloc(1, sizeof(*templates));

    esp_err_t result = ESP_FAIL;
    if (!table || !templates) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "admin mem failed");
        result = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    if (s_mode != ADMIN_SERVER_MODE_MAINTENANCE) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not available");
        goto cleanup;
    }

    if (!s_unlocked) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "locked");
        goto cleanup;
    }

    if (read_request_body(req, body, sizeof(body)) != ESP_OK ||
        !form_get_value(body, "mqtt_client_id", mqtt_client_id, sizeof(mqtt_client_id)) ||
        !form_get_value(body, "template_id", template_text, sizeof(template_text)) ||
        !form_get_value(body, "epoch", epoch_text, sizeof(epoch_text))) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid body");
        goto cleanup;
    }

    uint32_t template_id = 0;
    uint32_t epoch = 0;
    if (!parse_u32_field(template_text, &template_id) ||
        !parse_u32_field(epoch_text, &epoch) ||
        template_id > UINT16_MAX ||
        epoch == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid fields");
        goto cleanup;
    }

    result = rna_membrane_load_or_init(templates);
    if (result != ESP_OK ||
        !rna_template_table_find(templates, (rna_template_id_t)template_id)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "template not found");
        goto cleanup;
    }

    result = ribosome_store_load_or_init(table);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "load failed");
        goto cleanup;
    }

    generate_device_secret(device_secret);

    ribosome_entry_config_t entry_config = {
        .mqtt_client_id = mqtt_client_id,
        .template_id = (rna_template_id_t)template_id,
        .epoch = epoch,
        .device_secret = device_secret,
    };

    result = ribosome_table_add_from_config(table, &entry_config);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "add failed");
        goto cleanup;
    }

    result = ribosome_store_save(table);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "save failed");
        goto cleanup;
    }

    result = redirect_to_root(req);

cleanup:
    mbedtls_platform_zeroize(body, sizeof(body));
    mbedtls_platform_zeroize(mqtt_client_id, sizeof(mqtt_client_id));
    mbedtls_platform_zeroize(template_text, sizeof(template_text));
    mbedtls_platform_zeroize(epoch_text, sizeof(epoch_text));
    mbedtls_platform_zeroize(device_secret, sizeof(device_secret));
    if (table) {
        mbedtls_platform_zeroize(table, sizeof(*table));
        free(table);
    }
    if (templates) {
        mbedtls_platform_zeroize(templates, sizeof(*templates));
        free(templates);
    }
    return result;
}

static esp_err_t ribosome_regenerate_post_handler(httpd_req_t *req)
{
    char body[ADMIN_POST_BUF_SIZE] = {0};
    char mqtt_client_id[RIBOSOME_MQTT_CLIENT_ID_LEN] = {0};
    ribosome_table_t *table = (ribosome_table_t *)calloc(1, sizeof(*table));

    esp_err_t result = ESP_FAIL;
    if (!table) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "admin mem failed");
        result = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    if (s_mode != ADMIN_SERVER_MODE_MAINTENANCE) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not available");
        goto cleanup;
    }

    if (!s_unlocked) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "locked");
        goto cleanup;
    }

    if (read_request_body(req, body, sizeof(body)) != ESP_OK ||
        !form_get_value(body, "mqtt_client_id", mqtt_client_id, sizeof(mqtt_client_id))) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid body");
        goto cleanup;
    }

    result = ribosome_store_load_or_init(table);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "load failed");
        goto cleanup;
    }

    ribosome_table_entry_t *entry = find_ribosome_entry(table, mqtt_client_id);
    if (!entry) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "device not found");
        result = ESP_ERR_NOT_FOUND;
        goto cleanup;
    }

    generate_device_secret(entry->device_secret);
    entry->epoch = entry->epoch == UINT32_MAX ? 1 : entry->epoch + 1;

    result = ribosome_store_save(table);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "save failed");
        goto cleanup;
    }

    result = redirect_to_root(req);

cleanup:
    mbedtls_platform_zeroize(body, sizeof(body));
    mbedtls_platform_zeroize(mqtt_client_id, sizeof(mqtt_client_id));
    if (table) {
        mbedtls_platform_zeroize(table, sizeof(*table));
        free(table);
    }
    return result;
}

static esp_err_t membrane_template_set_post_handler(httpd_req_t *req)
{
    char body[ADMIN_POST_BUF_SIZE] = {0};
    char template_text[16] = {0};
    char template_name[RNA_TEMPLATE_NAME_LEN] = {0};
    char amino_text[64] = {0};
    rna_template_t template_rule;
    rna_template_table_t *templates = (rna_template_table_t *)calloc(1, sizeof(*templates));
    mbedtls_platform_zeroize(&template_rule, sizeof(template_rule));

    esp_err_t result = ESP_FAIL;
    if (!templates) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "admin mem failed");
        result = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    if (s_mode != ADMIN_SERVER_MODE_MAINTENANCE) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not available");
        goto cleanup;
    }

    if (!s_unlocked) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "locked");
        goto cleanup;
    }

    if (read_request_body(req, body, sizeof(body)) != ESP_OK ||
        !form_get_value(body, "template_id", template_text, sizeof(template_text)) ||
        !form_get_value(body, "template_name", template_name, sizeof(template_name)) ||
        !form_get_value(body, "amino_ids", amino_text, sizeof(amino_text))) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid body");
        goto cleanup;
    }

    result = build_template_from_fields(
        template_text,
        template_name,
        amino_text,
        &template_rule
    );
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid template");
        goto cleanup;
    }

    result = rna_membrane_load_or_init(templates);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "load failed");
        goto cleanup;
    }

    result = rna_template_table_upsert(templates, &template_rule);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "template rejected");
        goto cleanup;
    }

    result = rna_membrane_save(templates);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "save failed");
        goto cleanup;
    }

    httpd_resp_set_type(req, "text/plain");
    httpd_resp_sendstr(req, "membrane template saved");

cleanup:
    mbedtls_platform_zeroize(body, sizeof(body));
    mbedtls_platform_zeroize(template_text, sizeof(template_text));
    mbedtls_platform_zeroize(template_name, sizeof(template_name));
    mbedtls_platform_zeroize(amino_text, sizeof(amino_text));
    mbedtls_platform_zeroize(&template_rule, sizeof(template_rule));
    if (templates) {
        mbedtls_platform_zeroize(templates, sizeof(*templates));
        free(templates);
    }
    return result;
}

static esp_err_t device_membrane_set_post_handler(httpd_req_t *req)
{
    char body[ADMIN_POST_BUF_SIZE] = {0};
    char mqtt_client_id[RIBOSOME_MQTT_CLIENT_ID_LEN] = {0};
    char template_text[16] = {0};
    char template_name[RNA_TEMPLATE_NAME_LEN] = {0};
    char amino_text[64] = {0};
    rna_template_t template_rule;
    rna_template_table_t *templates = (rna_template_table_t *)calloc(1, sizeof(*templates));
    ribosome_table_t *table = (ribosome_table_t *)calloc(1, sizeof(*table));
    mbedtls_platform_zeroize(&template_rule, sizeof(template_rule));

    esp_err_t result = ESP_FAIL;
    if (!templates || !table) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "admin mem failed");
        result = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    if (s_mode != ADMIN_SERVER_MODE_MAINTENANCE) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not available");
        goto cleanup;
    }

    if (!s_unlocked) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "locked");
        goto cleanup;
    }

    if (read_request_body(req, body, sizeof(body)) != ESP_OK ||
        !form_get_value(body, "mqtt_client_id", mqtt_client_id, sizeof(mqtt_client_id)) ||
        !form_get_value(body, "template_id", template_text, sizeof(template_text)) ||
        !form_get_value(body, "template_name", template_name, sizeof(template_name)) ||
        !form_get_value(body, "amino_ids", amino_text, sizeof(amino_text))) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid body");
        goto cleanup;
    }

    result = build_template_from_fields(
        template_text,
        template_name,
        amino_text,
        &template_rule
    );
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid template");
        goto cleanup;
    }

    result = ribosome_store_load_or_init(table);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "device load failed");
        goto cleanup;
    }

    result = rna_membrane_load_or_init(templates);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "template load failed");
        goto cleanup;
    }

    result = rna_template_table_upsert(templates, &template_rule);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "template rejected");
        goto cleanup;
    }

    result = ribosome_assign_template(
        table,
        mqtt_client_id,
        template_rule.id
    );
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "device not found");
        goto cleanup;
    }

    result = rna_membrane_save(templates);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "template save failed");
        goto cleanup;
    }

    result = ribosome_store_save(table);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "device save failed");
        goto cleanup;
    }

    httpd_resp_set_type(req, "text/plain");
    httpd_resp_sendstr(req, "device membrane configured");

cleanup:
    mbedtls_platform_zeroize(body, sizeof(body));
    mbedtls_platform_zeroize(mqtt_client_id, sizeof(mqtt_client_id));
    mbedtls_platform_zeroize(template_text, sizeof(template_text));
    mbedtls_platform_zeroize(template_name, sizeof(template_name));
    mbedtls_platform_zeroize(amino_text, sizeof(amino_text));
    mbedtls_platform_zeroize(&template_rule, sizeof(template_rule));
    if (templates) {
        mbedtls_platform_zeroize(templates, sizeof(*templates));
        free(templates);
    }
    if (table) {
        mbedtls_platform_zeroize(table, sizeof(*table));
        free(table);
    }
    return result;
}

static esp_err_t ribosome_remove_post_handler(httpd_req_t *req)
{
    char body[ADMIN_POST_BUF_SIZE] = {0};
    char mqtt_client_id[RIBOSOME_MQTT_CLIENT_ID_LEN] = {0};
    ribosome_table_t *table = (ribosome_table_t *)calloc(1, sizeof(*table));

    esp_err_t result = ESP_FAIL;
    if (!table) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "admin mem failed");
        result = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    if (s_mode != ADMIN_SERVER_MODE_MAINTENANCE) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not available");
        goto cleanup;
    }

    if (!s_unlocked) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "locked");
        goto cleanup;
    }

    if (read_request_body(req, body, sizeof(body)) != ESP_OK ||
        !form_get_value(body, "mqtt_client_id", mqtt_client_id, sizeof(mqtt_client_id))) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid body");
        goto cleanup;
    }

    result = ribosome_store_load_or_init(table);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "load failed");
        goto cleanup;
    }

    result = ribosome_table_remove_entry(table, mqtt_client_id);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "remove failed");
        goto cleanup;
    }

    result = ribosome_store_save(table);
    if (result != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "save failed");
        goto cleanup;
    }

    httpd_resp_set_type(req, "text/plain");
    httpd_resp_sendstr(req, "ribosome removed");

cleanup:
    mbedtls_platform_zeroize(body, sizeof(body));
    mbedtls_platform_zeroize(mqtt_client_id, sizeof(mqtt_client_id));
    if (table) {
        mbedtls_platform_zeroize(table, sizeof(*table));
        free(table);
    }
    return result;
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
    if (s_mode != ADMIN_SERVER_MODE_BOOTSTRAP) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not available");
        return ESP_FAIL;
    }

    char body[ADMIN_POST_BUF_SIZE] = {0};
    char issuer_public_key_pem[512] = {0};
    char sta_ssid[32] = {0};
    char sta_password[64] = {0};
    char ap_ssid[32] = {0};
    char ap_password[64] = {0};
    zoneguard_config_t cfg;
    mbedtls_platform_zeroize(&cfg, sizeof(cfg));

    esp_err_t result = ESP_FAIL;

    int total = req->content_len;

    if (total <= 0 || total >= ADMIN_POST_BUF_SIZE) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid body");
        goto cleanup;
    }

    int received = 0;

    while (received < total) {
        int ret = httpd_req_recv(req, body + received, total - received);

        if (ret <= 0) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "recv failed");
            goto cleanup;
        }

        received += ret;
    }

    body[received] = '\0';

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
        goto cleanup;
    }

    if (strlen(sta_ssid) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "sta_ssid empty");
        goto cleanup;
    }

    if (strlen(ap_ssid) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ap_ssid empty");
        goto cleanup;
    }

    /*
     * WPA/WPA2 exige senha com pelo menos 8 caracteres.
     */
    if (strlen(ap_password) < 8) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "ap_password too short");
        goto cleanup;
    }

    if (validate_issuer_public_key_pem(issuer_public_key_pem) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid issuer public key");
        goto cleanup;
    }

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
        goto cleanup;
    }

    cfg.ap_channel = 6;
    cfg.ap_max_connections = 4;

    esp_err_t err = config_store_save(&cfg);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "falha ao salvar config: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "save failed");
        goto cleanup;
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

    result = ESP_OK;

cleanup:
    mbedtls_platform_zeroize(body, sizeof(body));
    mbedtls_platform_zeroize(issuer_public_key_pem, sizeof(issuer_public_key_pem));
    mbedtls_platform_zeroize(sta_ssid, sizeof(sta_ssid));
    mbedtls_platform_zeroize(sta_password, sizeof(sta_password));
    mbedtls_platform_zeroize(ap_ssid, sizeof(ap_ssid));
    mbedtls_platform_zeroize(ap_password, sizeof(ap_password));
    mbedtls_platform_zeroize(&cfg, sizeof(cfg));
    return result;
}

esp_err_t admin_server_start(const admin_server_config_t *config)
{
    if (s_running) {
        return ESP_OK;
    }

    s_mode = config ? config->mode : ADMIN_SERVER_MODE_BOOTSTRAP;
    s_on_window_closed = config ? config->on_window_closed : NULL;
    s_window_ctx = config ? config->ctx : NULL;
    s_unlocked = false;
    if (s_mode == ADMIN_SERVER_MODE_MAINTENANCE) {
        generate_challenge();
    } else {
        s_challenge_valid = false;
        mbedtls_platform_zeroize(s_challenge, sizeof(s_challenge));
    }

    httpd_config_t http_config = HTTPD_DEFAULT_CONFIG();

    /*
     * Mantém o servidor pequeno.
     */
    http_config.server_port = 80;
    http_config.max_uri_handlers = 10;
    http_config.max_open_sockets = 2;
    http_config.stack_size = s_mode == ADMIN_SERVER_MODE_BOOTSTRAP ?
        ADMIN_HTTPD_BOOTSTRAP_STACK_SIZE :
        ADMIN_HTTPD_STACK_SIZE;
    http_config.lru_purge_enable = true;

    esp_err_t err = ESP_FAIL;
    for (int attempt = 0; attempt < ADMIN_HTTPD_START_RETRIES; ++attempt) {
        err = httpd_start(&s_server, &http_config);
        if (err == ESP_OK) {
            break;
        }

        s_server = NULL;
        ESP_LOGW(
            TAG,
            "httpd_start falhou tentativa=%d/%d: %s",
            attempt + 1,
            ADMIN_HTTPD_START_RETRIES,
            esp_err_to_name(err)
        );
        vTaskDelay(pdMS_TO_TICKS(ADMIN_HTTPD_START_RETRY_DELAY_MS));
    }

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start falhou: %s", esp_err_to_name(err));
        admin_server_clear_runtime_state();
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

    httpd_uri_t challenge_uri = {
        .uri = "/challenge",
        .method = HTTP_GET,
        .handler = challenge_get_handler,
        .user_ctx = NULL
    };

    httpd_uri_t unlock_uri = {
        .uri = "/unlock",
        .method = HTTP_POST,
        .handler = unlock_post_handler,
        .user_ctx = NULL
    };

    httpd_uri_t ribosome_add_uri = {
        .uri = "/ribosome/add",
        .method = HTTP_POST,
        .handler = ribosome_add_post_handler,
        .user_ctx = NULL
    };

    httpd_uri_t ribosome_provision_uri = {
        .uri = "/ribosome/provision",
        .method = HTTP_POST,
        .handler = ribosome_provision_post_handler,
        .user_ctx = NULL
    };

    httpd_uri_t ribosome_regenerate_uri = {
        .uri = "/ribosome/regenerate",
        .method = HTTP_POST,
        .handler = ribosome_regenerate_post_handler,
        .user_ctx = NULL
    };

    httpd_uri_t ribosome_remove_uri = {
        .uri = "/ribosome/remove",
        .method = HTTP_POST,
        .handler = ribosome_remove_post_handler,
        .user_ctx = NULL
    };

    httpd_uri_t membrane_template_uri = {
        .uri = "/membrane/template/set",
        .method = HTTP_POST,
        .handler = membrane_template_set_post_handler,
        .user_ctx = NULL
    };

    httpd_uri_t device_membrane_uri = {
        .uri = "/device/membrane/set",
        .method = HTTP_POST,
        .handler = device_membrane_set_post_handler,
        .user_ctx = NULL
    };

    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &root_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &save_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &challenge_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &unlock_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &ribosome_add_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &ribosome_provision_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &ribosome_regenerate_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &ribosome_remove_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &membrane_template_uri));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &device_membrane_uri));

    s_running = true;

    ESP_LOGI(TAG, "admin_server iniciado em http://192.168.4.1/ modo=%d", s_mode);

    return ESP_OK;
}

esp_err_t admin_server_open_window(const admin_server_config_t *config, uint32_t timeout_ms)
{
    admin_server_config_t window_config = {
        .setup_ap_ssid = config ? config->setup_ap_ssid : NULL,
        .setup_ap_password = config ? config->setup_ap_password : NULL,
        .mode = ADMIN_SERVER_MODE_MAINTENANCE,
        .guardian_id = config ? config->guardian_id : 0,
        .zone_id = config ? config->zone_id : 0,
        .on_window_closed = config ? config->on_window_closed : NULL,
        .ctx = config ? config->ctx : NULL,
    };

    esp_err_t err = admin_server_force_release_port80();
    if (err != ESP_OK) {
        return err;
    }

    err = admin_server_start(&window_config);
    if (err != ESP_OK) {
        return err;
    }

    if (timeout_ms == 0) {
        timeout_ms = 30000;
    }

    ESP_LOGW(TAG, "janela admin aberta por %lu ms", (unsigned long)timeout_ms);
    return restart_window_timer(timeout_ms);
}

esp_err_t admin_server_stop(void)
{
    return admin_server_stop_internal(true);
}

bool admin_server_is_running(void)
{
    return s_running;
}

bool admin_server_is_unlocked(void)
{
    return s_unlocked;
}

void admin_server_lock(void)
{
    s_unlocked = false;
    generate_challenge();
}
