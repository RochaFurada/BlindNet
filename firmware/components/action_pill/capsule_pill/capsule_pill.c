#include "capsule_pill.h"

#include <string.h>

#include "mbedtls/md.h"

static size_t bounded_strlen(const char *text, size_t max_len)
{
    if (!text) return 0;

    size_t len = 0;
    while (len < max_len && text[len] != '\0') {
        len++;
    }
    return len;
}

static esp_err_t safe_copy_fixed(char *dst, size_t dst_size, const char *src)
{
    if (!dst || dst_size == 0 || !src) return ESP_ERR_INVALID_ARG;

    size_t len = bounded_strlen(src, dst_size);
    if (len == 0 || len >= dst_size) return ESP_ERR_INVALID_SIZE;

    memset(dst, 0, dst_size);
    memcpy(dst, src, len);
    return ESP_OK;
}

static void update_u8(mbedtls_md_context_t *ctx, uint8_t value)
{
    mbedtls_md_update(ctx, &value, sizeof(value));
}

static void update_u32_le(mbedtls_md_context_t *ctx, uint32_t value)
{
    uint8_t bytes[4] = {
        (uint8_t)(value & 0xFFu),
        (uint8_t)((value >> 8) & 0xFFu),
        (uint8_t)((value >> 16) & 0xFFu),
        (uint8_t)((value >> 24) & 0xFFu)
    };
    mbedtls_md_update(ctx, bytes, sizeof(bytes));
}

/*
 * Campos cobertos pela assinatura da capsula.
 * O campo signature fica fora, senao seria impossivel verificar.
 */
static esp_err_t capsule_update_canonical(mbedtls_md_context_t *ctx, const capsule_pill_t *capsule)
{
    if (!ctx || !capsule) return ESP_ERR_INVALID_ARG;

    update_u8(ctx, capsule->version);
    update_u8(ctx, (uint8_t)capsule->source);
    update_u8(ctx, capsule->risk_score);
    update_u32_le(ctx, capsule->device_id);
    update_u32_le(ctx, capsule->issued_ms);
    update_u32_le(ctx, capsule->expires_ms);

    mbedtls_md_update(ctx, (const uint8_t *)capsule->issuer, sizeof(capsule->issuer));
    mbedtls_md_update(ctx, (const uint8_t *)capsule->action, sizeof(capsule->action));
    mbedtls_md_update(ctx, capsule->device_tag, sizeof(capsule->device_tag));
    mbedtls_md_update(ctx, capsule->nonce, sizeof(capsule->nonce));
    mbedtls_md_update(ctx, capsule->active_hash, sizeof(capsule->active_hash));

    return ESP_OK;
}

/*
 * Comeca vazia; o active_hash e a assinatura aparecem depois que a capsula
 * for vinculada ao composto ativo.
 */
void capsule_pill_init(capsule_pill_t *capsule)
{
    if (!capsule) return;

    memset(capsule, 0, sizeof(*capsule));
    capsule->version = CAPSULE_PILL_VERSION;
    capsule->source = CAPSULE_PILL_SOURCE_UNKNOWN;
}

/*
 * Define a identidade semantica declarada: quem pediu, para qual dispositivo
 * e qual acao humana/abstrata foi solicitada.
 */
esp_err_t capsule_pill_set_identity(
    capsule_pill_t *capsule,
    uint32_t device_id,
    const char *issuer,
    const char *action
)
{
    if (!capsule || device_id == 0) return ESP_ERR_INVALID_ARG;

    esp_err_t err = safe_copy_fixed(capsule->issuer, sizeof(capsule->issuer), issuer);
    if (err != ESP_OK) return err;

    err = safe_copy_fixed(capsule->action, sizeof(capsule->action), action);
    if (err != ESP_OK) return err;

    capsule->device_id = device_id;
    return ESP_OK;
}

esp_err_t capsule_pill_set_nonce(
    capsule_pill_t *capsule,
    const uint8_t nonce[CAPSULE_PILL_NONCE_LEN]
)
{
    if (!capsule || !nonce) return ESP_ERR_INVALID_ARG;
    memcpy(capsule->nonce, nonce, CAPSULE_PILL_NONCE_LEN);
    return ESP_OK;
}

esp_err_t capsule_pill_set_device_tag(
    capsule_pill_t *capsule,
    const uint8_t device_tag[CAPSULE_PILL_DEVICE_TAG_LEN]
)
{
    if (!capsule || !device_tag) return ESP_ERR_INVALID_ARG;
    memcpy(capsule->device_tag, device_tag, CAPSULE_PILL_DEVICE_TAG_LEN);
    return ESP_OK;
}

esp_err_t capsule_pill_set_active_hash(
    capsule_pill_t *capsule,
    const uint8_t active_hash[ACTIVE_SUBSTANCE_HASH_LEN]
)
{
    if (!capsule || !active_hash) return ESP_ERR_INVALID_ARG;
    memcpy(capsule->active_hash, active_hash, ACTIVE_SUBSTANCE_HASH_LEN);
    return ESP_OK;
}

esp_err_t capsule_pill_bind_active(
    capsule_pill_t *capsule,
    const active_substance_t *substance
)
{
    if (!capsule || !substance) return ESP_ERR_INVALID_ARG;

    uint8_t hash[ACTIVE_SUBSTANCE_HASH_LEN];
    esp_err_t err = active_substance_hash(substance, hash);
    if (err != ESP_OK) return err;

    return capsule_pill_set_active_hash(capsule, hash);
}

/*
 * Valida forma e tempo. Politica fina entra depois: manifesto, risco,
 * permissoes por usuario e cache anti-replay.
 */
esp_err_t capsule_pill_validate_basic(
    const capsule_pill_t *capsule,
    uint32_t now_ms
)
{
    if (!capsule) return ESP_ERR_INVALID_ARG;
    if (capsule->version != CAPSULE_PILL_VERSION) return ESP_ERR_INVALID_VERSION;
    if (capsule->device_id == 0) return ESP_ERR_INVALID_ARG;
    if (capsule->issuer[0] == '\0' || capsule->action[0] == '\0') return ESP_ERR_INVALID_ARG;
    if (capsule->issued_ms == 0 || capsule->expires_ms <= capsule->issued_ms) {
        return ESP_ERR_INVALID_ARG;
    }
    if (now_ms != 0 && now_ms > capsule->expires_ms) return ESP_ERR_TIMEOUT;

    return ESP_OK;
}

/*
 * Confere se o comando real recebido e o mesmo comando autorizado.
 */
bool capsule_pill_matches_active(
    const capsule_pill_t *capsule,
    const active_substance_t *substance
)
{
    if (!capsule || !substance) return false;

    uint8_t hash[ACTIVE_SUBSTANCE_HASH_LEN];
    if (active_substance_hash(substance, hash) != ESP_OK) return false;

    return capsule_pill_constant_time_equal(capsule->active_hash, hash, sizeof(hash));
}

/*
 * MVP: HMAC-SHA256 por simplicidade. Depois pode evoluir para Ed25519
 * no app e chave publica no Guardian.
 */
esp_err_t capsule_pill_sign_hmac_sha256(
    capsule_pill_t *capsule,
    const uint8_t *key,
    size_t key_len
)
{
    if (!capsule || !key || key_len == 0) return ESP_ERR_INVALID_ARG;

    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return ESP_FAIL;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    int rc = mbedtls_md_setup(&ctx, info, 1);
    if (rc == 0) rc = mbedtls_md_hmac_starts(&ctx, key, key_len);
    if (rc == 0) rc = capsule_update_canonical(&ctx, capsule) == ESP_OK ? 0 : -1;
    if (rc == 0) rc = mbedtls_md_hmac_finish(&ctx, capsule->signature);

    mbedtls_md_free(&ctx);
    return rc == 0 ? ESP_OK : ESP_FAIL;
}

bool capsule_pill_verify_hmac_sha256(
    const capsule_pill_t *capsule,
    const uint8_t *key,
    size_t key_len
)
{
    if (!capsule || !key || key_len == 0) return false;

    capsule_pill_t copy = *capsule;
    uint8_t expected[CAPSULE_PILL_SIGNATURE_LEN];

    if (capsule_pill_sign_hmac_sha256(&copy, key, key_len) != ESP_OK) {
        return false;
    }

    memcpy(expected, copy.signature, sizeof(expected));
    return capsule_pill_constant_time_equal(capsule->signature, expected, sizeof(expected));
}

bool capsule_pill_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    if (!a || !b) return false;

    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }

    return diff == 0;
}

const char *capsule_pill_source_to_string(capsule_pill_source_t source)
{
    switch (source) {
        case CAPSULE_PILL_SOURCE_LOCAL_APP: return "LOCAL_APP";
        case CAPSULE_PILL_SOURCE_ETE: return "ETE";
        case CAPSULE_PILL_SOURCE_RTE: return "RTE";
        case CAPSULE_PILL_SOURCE_UNKNOWN:
        default: return "UNKNOWN";
    }
}
