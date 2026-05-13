#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "active_substance.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAPSULE_PILL_VERSION 1
#define CAPSULE_PILL_DEVICE_TAG_LEN 32
#define CAPSULE_PILL_NONCE_LEN 16
#define CAPSULE_PILL_SIGNATURE_LEN 32
#define CAPSULE_PILL_ISSUER_LEN 32
#define CAPSULE_PILL_ACTION_LEN 24

/*
 * Capsule Pill = capsula.
 *
 * A capsula nao e o comando. Ela e a autorizacao que o Guardian analisa:
 * quem pediu, qual acao declarou, qual dispositivo/tag e o alvo, validade,
 * nonce anti-replay, hash do composto ativo e assinatura.
 */
typedef enum {
    CAPSULE_PILL_SOURCE_UNKNOWN = 0,
    CAPSULE_PILL_SOURCE_LOCAL_APP = 1,
    CAPSULE_PILL_SOURCE_ETE = 2,
    CAPSULE_PILL_SOURCE_RTE = 3
} capsule_pill_source_t;

/*
 * Autorizacao que viaja junto com o composto ativo.
 * active_hash deve ser SHA-256 do active_substance_t canonico.
 */
typedef struct {
    uint8_t version;
    capsule_pill_source_t source;
    uint8_t risk_score;
    uint8_t reserved0;
    uint32_t device_id;
    uint32_t issued_ms;
    uint32_t expires_ms;
    char issuer[CAPSULE_PILL_ISSUER_LEN];
    char action[CAPSULE_PILL_ACTION_LEN];
    uint8_t device_tag[CAPSULE_PILL_DEVICE_TAG_LEN];
    uint8_t nonce[CAPSULE_PILL_NONCE_LEN];
    uint8_t active_hash[ACTIVE_SUBSTANCE_HASH_LEN];
    uint8_t signature[CAPSULE_PILL_SIGNATURE_LEN];
} capsule_pill_t;

void capsule_pill_init(capsule_pill_t *capsule);

esp_err_t capsule_pill_set_identity(
    capsule_pill_t *capsule,
    uint32_t device_id,
    const char *issuer,
    const char *action
);

esp_err_t capsule_pill_set_nonce(
    capsule_pill_t *capsule,
    const uint8_t nonce[CAPSULE_PILL_NONCE_LEN]
);

esp_err_t capsule_pill_set_device_tag(
    capsule_pill_t *capsule,
    const uint8_t device_tag[CAPSULE_PILL_DEVICE_TAG_LEN]
);

esp_err_t capsule_pill_set_active_hash(
    capsule_pill_t *capsule,
    const uint8_t active_hash[ACTIVE_SUBSTANCE_HASH_LEN]
);

esp_err_t capsule_pill_bind_active(
    capsule_pill_t *capsule,
    const active_substance_t *substance
);

esp_err_t capsule_pill_validate_basic(
    const capsule_pill_t *capsule,
    uint32_t now_ms
);

bool capsule_pill_matches_active(
    const capsule_pill_t *capsule,
    const active_substance_t *substance
);

esp_err_t capsule_pill_sign_hmac_sha256(
    capsule_pill_t *capsule,
    const uint8_t *key,
    size_t key_len
);

bool capsule_pill_verify_hmac_sha256(
    const capsule_pill_t *capsule,
    const uint8_t *key,
    size_t key_len
);

bool capsule_pill_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len);

const char *capsule_pill_source_to_string(capsule_pill_source_t source);

#ifdef __cplusplus
}
#endif
