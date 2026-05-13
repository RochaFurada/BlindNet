#include "action_pill.hpp"

#include <cstring>

#include "mbedtls/md.h"

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
 * Estado inicial do comprimido. hop_limit pequeno evita que flooding rode
 * pela malha indefinidamente no MVP.
 */
void action_pill_init(action_pill_t *pill)
{
    if (!pill) return;

    std::memset(pill, 0, sizeof(*pill));
    pill->version = ACTION_PILL_VERSION;
    pill->hop_limit = 3;
    capsule_pill_init(&pill->capsule);
    active_substance_init(&pill->active);
}

/*
 * Helper para montar um comprimido MQTT completo.
 * Isso prepara dados em memoria; nao envia pela malha e nao publica no broker.
 */
esp_err_t action_pill_set_mqtt(
    action_pill_t *pill,
    uint32_t pill_id,
    uint32_t device_id,
    const char *issuer,
    const char *action,
    capsule_pill_source_t source,
    uint8_t risk_score,
    const uint8_t device_tag[CAPSULE_PILL_DEVICE_TAG_LEN],
    const uint8_t nonce[CAPSULE_PILL_NONCE_LEN],
    const char *topic,
    const void *payload,
    size_t payload_len,
    uint32_t issued_ms,
    uint32_t expires_ms
)
{
    if (!pill) return ESP_ERR_INVALID_ARG;

    action_pill_init(pill);
    pill->pill_id = pill_id;

    esp_err_t err = active_substance_set_mqtt(
        &pill->active,
        topic,
        payload,
        payload_len,
        0,
        false
    );
    if (err != ESP_OK) return err;

    err = capsule_pill_set_identity(&pill->capsule, device_id, issuer, action);
    if (err != ESP_OK) return err;

    err = capsule_pill_set_device_tag(&pill->capsule, device_tag);
    if (err != ESP_OK) return err;

    err = capsule_pill_set_nonce(&pill->capsule, nonce);
    if (err != ESP_OK) return err;

    pill->capsule.source = source;
    pill->capsule.risk_score = risk_score;
    pill->capsule.issued_ms = issued_ms;
    pill->capsule.expires_ms = expires_ms;

    return action_pill_refresh_active_hash(pill);
}

/*
 * Valida as tres camadas:
 *   1. envelope basico do comprimido
 *   2. composto ativo
 *   3. capsula apontando para o hash do composto ativo
 */
esp_err_t action_pill_validate_basic(
    const action_pill_t *pill,
    uint32_t now_ms
)
{
    if (!pill) return ESP_ERR_INVALID_ARG;
    if (pill->version != ACTION_PILL_VERSION) return ESP_ERR_INVALID_VERSION;
    if (pill->hop_limit == 0 || pill->hop_count > pill->hop_limit) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = active_substance_validate(&pill->active);
    if (err != ESP_OK) return err;

    err = capsule_pill_validate_basic(&pill->capsule, now_ms);
    if (err != ESP_OK) return err;

    if (!action_pill_capsule_matches_active(pill)) {
        return ESP_ERR_INVALID_CRC;
    }

    return ESP_OK;
}

/*
 * Recalcula o hash do composto ativo dentro da capsula.
 * Chame antes de assinar se topic/payload tiverem mudado.
 */
esp_err_t action_pill_refresh_active_hash(action_pill_t *pill)
{
    if (!pill) return ESP_ERR_INVALID_ARG;
    return capsule_pill_bind_active(&pill->capsule, &pill->active);
}

bool action_pill_capsule_matches_active(const action_pill_t *pill)
{
    if (!pill) return false;
    return capsule_pill_matches_active(&pill->capsule, &pill->active);
}

esp_err_t action_pill_sign_hmac_sha256(
    action_pill_t *pill,
    const uint8_t *key,
    size_t key_len
)
{
    if (!pill) return ESP_ERR_INVALID_ARG;

    esp_err_t err = action_pill_refresh_active_hash(pill);
    if (err != ESP_OK) return err;

    return capsule_pill_sign_hmac_sha256(&pill->capsule, key, key_len);
}

bool action_pill_verify_hmac_sha256(
    const action_pill_t *pill,
    const uint8_t *key,
    size_t key_len
)
{
    if (!pill || !action_pill_capsule_matches_active(pill)) return false;
    return capsule_pill_verify_hmac_sha256(&pill->capsule, key, key_len);
}

/*
 * ID interno usado por cache anti-loop/anti-replay.
 * Ele identifica o conteudo autorizado, nao o envelope de cada salto.
 */
esp_err_t action_pill_compute_inner_id(
    const action_pill_t *pill,
    uint8_t out_id[ACTION_PILL_INNER_ID_LEN]
)
{
    if (!pill || !out_id) return ESP_ERR_INVALID_ARG;
    if (!action_pill_capsule_matches_active(pill)) return ESP_ERR_INVALID_CRC;

    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return ESP_FAIL;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    if (mbedtls_md_setup(&ctx, info, 0) != 0 ||
        mbedtls_md_starts(&ctx) != 0) {
        mbedtls_md_free(&ctx);
        return ESP_FAIL;
    }

    update_u8(&ctx, pill->version);
    update_u32_le(&ctx, pill->pill_id);
    update_u32_le(&ctx, pill->capsule.device_id);
    update_u32_le(&ctx, pill->capsule.issued_ms);
    update_u32_le(&ctx, pill->capsule.expires_ms);
    mbedtls_md_update(&ctx, pill->capsule.device_tag, sizeof(pill->capsule.device_tag));
    mbedtls_md_update(&ctx, pill->capsule.nonce, sizeof(pill->capsule.nonce));
    mbedtls_md_update(&ctx, pill->capsule.active_hash, sizeof(pill->capsule.active_hash));
    mbedtls_md_update(&ctx, pill->capsule.signature, sizeof(pill->capsule.signature));

    int rc = mbedtls_md_finish(&ctx, out_id);
    mbedtls_md_free(&ctx);

    return rc == 0 ? ESP_OK : ESP_FAIL;
}
