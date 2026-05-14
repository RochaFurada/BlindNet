#include "capsule_pill.h"

#include <string.h>

#include "mbedtls/md.h"
#include "mbedtls/pk.h"

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

static bool bytes_all_zero(const uint8_t *bytes, size_t len)
{
    if (!bytes || len == 0) return true;

    uint8_t any = 0;
    for (size_t i = 0; i < len; ++i) {
        any |= bytes[i];
    }

    return any == 0;
}

/*
 * Campos cobertos pela assinatura do app/autorizador.
 * A assinatura e seu tamanho ficam fora, senao seria impossivel verificar.
 */
static esp_err_t capsule_update_signed_canonical(
    mbedtls_md_context_t *ctx,
    const capsule_pill_t *capsule
)
{
    if (!ctx || !capsule) return ESP_ERR_INVALID_ARG;

    update_u8(ctx, capsule->version);
    update_u8(ctx, capsule->flags);
    update_u8(ctx, capsule->max_hops);
    update_u8(ctx, capsule->action_class);
    update_u32_le(ctx, capsule->issued_ms);
    update_u32_le(ctx, capsule->expires_ms);
    mbedtls_md_update(ctx, capsule->network_id, sizeof(capsule->network_id));
    mbedtls_md_update(ctx, capsule->nonce, sizeof(capsule->nonce));
    mbedtls_md_update(ctx, capsule->active_hash, sizeof(capsule->active_hash));
    mbedtls_md_update(ctx, capsule->issuer_key_id, sizeof(capsule->issuer_key_id));
    update_u8(ctx, capsule->signature_alg);

    return ESP_OK;
}

static esp_err_t capsule_compute_signed_hash(
    const capsule_pill_t *capsule,
    uint8_t out_hash[CAPSULE_PILL_DIGEST_LEN]
)
{
    if (!capsule || !out_hash) return ESP_ERR_INVALID_ARG;

    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return ESP_FAIL;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    int rc = mbedtls_md_setup(&ctx, info, 0);
    if (rc == 0) rc = mbedtls_md_starts(&ctx);
    if (rc == 0) {
        rc = capsule_update_signed_canonical(&ctx, capsule) == ESP_OK ? 0 : -1;
    }
    if (rc == 0) rc = mbedtls_md_finish(&ctx, out_hash);

    mbedtls_md_free(&ctx);
    return rc == 0 ? ESP_OK : ESP_FAIL;
}

void capsule_pill_init(capsule_pill_t *capsule)
{
    if (!capsule) return;

    memset(capsule, 0, sizeof(*capsule));
    capsule->version = CAPSULE_PILL_VERSION;
    capsule->max_hops = 3;
    capsule->action_class = CAPSULE_PILL_ACTION_UNKNOWN;
    capsule->signature_alg = CAPSULE_PILL_SIGNATURE_NONE;
}

esp_err_t capsule_pill_configure(
    capsule_pill_t *capsule,
    capsule_pill_action_class_t action_class,
    uint8_t max_hops,
    uint32_t issued_ms,
    uint32_t expires_ms,
    const uint8_t network_id[CAPSULE_PILL_NETWORK_ID_LEN],
    const uint8_t nonce[CAPSULE_PILL_NONCE_LEN],
    const uint8_t issuer_key_id[CAPSULE_PILL_ISSUER_KEY_ID_LEN]
)
{
    if (!capsule || !network_id || !nonce || !issuer_key_id) {
        return ESP_ERR_INVALID_ARG;
    }
    if (max_hops == 0 || issued_ms == 0 || expires_ms <= issued_ms) {
        return ESP_ERR_INVALID_ARG;
    }
    if (action_class == CAPSULE_PILL_ACTION_UNKNOWN) {
        return ESP_ERR_INVALID_ARG;
    }

    capsule->version = CAPSULE_PILL_VERSION;
    capsule->flags = 0;
    capsule->max_hops = max_hops;
    capsule->action_class = (uint8_t)action_class;
    capsule->issued_ms = issued_ms;
    capsule->expires_ms = expires_ms;
    memcpy(capsule->network_id, network_id, CAPSULE_PILL_NETWORK_ID_LEN);
    memcpy(capsule->nonce, nonce, CAPSULE_PILL_NONCE_LEN);
    memcpy(capsule->issuer_key_id, issuer_key_id, CAPSULE_PILL_ISSUER_KEY_ID_LEN);

    capsule->signature_alg = CAPSULE_PILL_SIGNATURE_NONE;
    capsule->signature_len = 0;
    memset(capsule->signature, 0, sizeof(capsule->signature));

    return ESP_OK;
}

esp_err_t capsule_pill_set_active_hash(
    capsule_pill_t *capsule,
    const uint8_t active_hash[ACTIVE_SUBSTANCE_HASH_LEN]
)
{
    if (!capsule || !active_hash) return ESP_ERR_INVALID_ARG;

    memcpy(capsule->active_hash, active_hash, ACTIVE_SUBSTANCE_HASH_LEN);

    capsule->signature_len = 0;
    memset(capsule->signature, 0, sizeof(capsule->signature));

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

esp_err_t capsule_pill_set_signature(
    capsule_pill_t *capsule,
    capsule_pill_signature_alg_t alg,
    const uint8_t *signature,
    size_t signature_len
)
{
    if (!capsule || !signature) return ESP_ERR_INVALID_ARG;
    if (alg != CAPSULE_PILL_SIGNATURE_ECDSA_SHA256_DER) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (signature_len == 0 || signature_len > CAPSULE_PILL_SIGNATURE_MAX_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }

    capsule->signature_alg = (uint8_t)alg;
    capsule->signature_len = (uint8_t)signature_len;
    memset(capsule->signature, 0, sizeof(capsule->signature));
    memcpy(capsule->signature, signature, signature_len);

    return ESP_OK;
}

esp_err_t capsule_pill_set_signature_alg(
    capsule_pill_t *capsule,
    capsule_pill_signature_alg_t alg
)
{
    if (!capsule) return ESP_ERR_INVALID_ARG;
    if (alg != CAPSULE_PILL_SIGNATURE_ECDSA_SHA256_DER) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    capsule->signature_alg = (uint8_t)alg;
    capsule->signature_len = 0;
    memset(capsule->signature, 0, sizeof(capsule->signature));

    return ESP_OK;
}

esp_err_t capsule_pill_validate_basic(
    const capsule_pill_t *capsule,
    uint32_t now_ms
)
{
    if (!capsule) return ESP_ERR_INVALID_ARG;
    if (capsule->version != CAPSULE_PILL_VERSION) return ESP_ERR_INVALID_VERSION;
    if (capsule->max_hops == 0) return ESP_ERR_INVALID_ARG;
    if (capsule->action_class == CAPSULE_PILL_ACTION_UNKNOWN) return ESP_ERR_INVALID_ARG;
    if (capsule->issued_ms == 0 || capsule->expires_ms <= capsule->issued_ms) {
        return ESP_ERR_INVALID_ARG;
    }
    if (now_ms != 0 && now_ms > capsule->expires_ms) return ESP_ERR_TIMEOUT;

    if (bytes_all_zero(capsule->network_id, sizeof(capsule->network_id))) {
        return ESP_ERR_INVALID_ARG;
    }
    if (bytes_all_zero(capsule->nonce, sizeof(capsule->nonce))) {
        return ESP_ERR_INVALID_ARG;
    }
    if (bytes_all_zero(capsule->issuer_key_id, sizeof(capsule->issuer_key_id))) {
        return ESP_ERR_INVALID_ARG;
    }
    if (bytes_all_zero(capsule->active_hash, sizeof(capsule->active_hash))) {
        return ESP_ERR_INVALID_ARG;
    }

    if (capsule->signature_alg != CAPSULE_PILL_SIGNATURE_ECDSA_SHA256_DER) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (capsule->signature_len == 0 ||
        capsule->signature_len > CAPSULE_PILL_SIGNATURE_MAX_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }
    if (bytes_all_zero(capsule->signature, capsule->signature_len)) {
        return ESP_ERR_INVALID_ARG;
    }

    return ESP_OK;
}

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

esp_err_t capsule_pill_compute_signing_digest(
    const capsule_pill_t *capsule,
    uint8_t out_digest[CAPSULE_PILL_DIGEST_LEN]
)
{
    if (!capsule) return ESP_ERR_INVALID_ARG;
    if (capsule->signature_alg != CAPSULE_PILL_SIGNATURE_ECDSA_SHA256_DER) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    return capsule_compute_signed_hash(capsule, out_digest);
}

esp_err_t capsule_pill_compute_digest(
    const capsule_pill_t *capsule,
    uint8_t out_digest[CAPSULE_PILL_DIGEST_LEN]
)
{
    if (!capsule || !out_digest) return ESP_ERR_INVALID_ARG;

    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return ESP_FAIL;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    int rc = mbedtls_md_setup(&ctx, info, 0);
    if (rc == 0) rc = mbedtls_md_starts(&ctx);
    if (rc == 0) {
        rc = capsule_update_signed_canonical(&ctx, capsule) == ESP_OK ? 0 : -1;
    }
    if (rc == 0) {
        update_u8(&ctx, capsule->signature_len);
        mbedtls_md_update(&ctx, capsule->signature, capsule->signature_len);
        rc = mbedtls_md_finish(&ctx, out_digest);
    }

    mbedtls_md_free(&ctx);
    return rc == 0 ? ESP_OK : ESP_FAIL;
}

bool capsule_pill_verify_asymmetric(
    const capsule_pill_t *capsule,
    const uint8_t *public_key,
    size_t public_key_len
)
{
    if (!capsule || !public_key || public_key_len == 0) return false;
    if (capsule_pill_validate_basic(capsule, 0) != ESP_OK) return false;

    uint8_t signed_hash[CAPSULE_PILL_DIGEST_LEN];
    if (capsule_compute_signed_hash(capsule, signed_hash) != ESP_OK) {
        return false;
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    int rc = mbedtls_pk_parse_public_key(&pk, public_key, public_key_len);
    if (rc == 0 && !mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA)) {
        rc = -1;
    }
    if (rc == 0) {
        rc = mbedtls_pk_verify(
            &pk,
            MBEDTLS_MD_SHA256,
            signed_hash,
            sizeof(signed_hash),
            capsule->signature,
            capsule->signature_len
        );
    }

    mbedtls_pk_free(&pk);
    return rc == 0;
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

const char *capsule_pill_action_class_to_string(capsule_pill_action_class_t action_class)
{
    switch (action_class) {
        case CAPSULE_PILL_ACTION_MQTT: return "MQTT";
        case CAPSULE_PILL_ACTION_GPIO: return "GPIO";
        case CAPSULE_PILL_ACTION_POLICY: return "POLICY";
        case CAPSULE_PILL_ACTION_UNKNOWN:
        default: return "UNKNOWN";
    }
}

const char *capsule_pill_signature_alg_to_string(capsule_pill_signature_alg_t alg)
{
    switch (alg) {
        case CAPSULE_PILL_SIGNATURE_ECDSA_SHA256_DER: return "ECDSA_SHA256_DER";
        case CAPSULE_PILL_SIGNATURE_NONE:
        default: return "NONE";
    }
}
