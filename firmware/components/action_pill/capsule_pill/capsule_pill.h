#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "active_substance.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAPSULE_PILL_VERSION 2
#define CAPSULE_PILL_NONCE_LEN 16
#define CAPSULE_PILL_NETWORK_ID_LEN 16
#define CAPSULE_PILL_ISSUER_KEY_ID_LEN 16
#define CAPSULE_PILL_SIGNATURE_MAX_LEN 96
#define CAPSULE_PILL_DIGEST_LEN 32

/*
 * Capsule Pill = capsula.
 *
 * A capsula nao e o comando e nao revela destino. Ela e o nucleo imutavel:
 * validade, limites de propagacao, classe generica, nonce, rede, hash do AS
 * cifrado e assinatura do app/autorizador.
 */
typedef enum {
    CAPSULE_PILL_ACTION_UNKNOWN = 0,
    CAPSULE_PILL_ACTION_MQTT = 1,
    CAPSULE_PILL_ACTION_GPIO = 2,
    CAPSULE_PILL_ACTION_POLICY = 3
} capsule_pill_action_class_t;

typedef enum {
    CAPSULE_PILL_SIGNATURE_NONE = 0,
    CAPSULE_PILL_SIGNATURE_ECDSA_SHA256_DER = 1
} capsule_pill_signature_alg_t;

/*
 * CP imutavel. Campos sensiveis como device_id real, topic MQTT e comando
 * ficam dentro do active_substance cifrado.
 */
typedef struct {
    uint8_t version;
    uint8_t flags;
    uint8_t max_hops;
    uint8_t action_class;
    uint32_t issued_ms;
    uint32_t expires_ms;
    uint8_t network_id[CAPSULE_PILL_NETWORK_ID_LEN];
    uint8_t nonce[CAPSULE_PILL_NONCE_LEN];
    uint8_t active_hash[ACTIVE_SUBSTANCE_HASH_LEN];
    uint8_t issuer_key_id[CAPSULE_PILL_ISSUER_KEY_ID_LEN];
    uint8_t signature_alg;
    uint8_t signature_len;
    uint8_t reserved0[2];
    uint8_t signature[CAPSULE_PILL_SIGNATURE_MAX_LEN];
} capsule_pill_t;

void capsule_pill_init(capsule_pill_t *capsule);

esp_err_t capsule_pill_configure(
    capsule_pill_t *capsule,
    capsule_pill_action_class_t action_class,
    uint8_t max_hops,
    uint32_t issued_ms,
    uint32_t expires_ms,
    const uint8_t network_id[CAPSULE_PILL_NETWORK_ID_LEN],
    const uint8_t nonce[CAPSULE_PILL_NONCE_LEN],
    const uint8_t issuer_key_id[CAPSULE_PILL_ISSUER_KEY_ID_LEN]
);

esp_err_t capsule_pill_set_active_hash(
    capsule_pill_t *capsule,
    const uint8_t active_hash[ACTIVE_SUBSTANCE_HASH_LEN]
);

esp_err_t capsule_pill_bind_active(
    capsule_pill_t *capsule,
    const active_substance_t *substance
);

esp_err_t capsule_pill_set_signature(
    capsule_pill_t *capsule,
    capsule_pill_signature_alg_t alg,
    const uint8_t *signature,
    size_t signature_len
);

esp_err_t capsule_pill_set_signature_alg(
    capsule_pill_t *capsule,
    capsule_pill_signature_alg_t alg
);

esp_err_t capsule_pill_validate_basic(
    const capsule_pill_t *capsule,
    uint32_t now_ms
);

bool capsule_pill_matches_active(
    const capsule_pill_t *capsule,
    const active_substance_t *substance
);

esp_err_t capsule_pill_compute_signing_digest(
    const capsule_pill_t *capsule,
    uint8_t out_digest[CAPSULE_PILL_DIGEST_LEN]
);

esp_err_t capsule_pill_compute_digest(
    const capsule_pill_t *capsule,
    uint8_t out_digest[CAPSULE_PILL_DIGEST_LEN]
);

bool capsule_pill_verify_asymmetric(
    const capsule_pill_t *capsule,
    const uint8_t *public_key,
    size_t public_key_len
);

bool capsule_pill_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len);

const char *capsule_pill_action_class_to_string(capsule_pill_action_class_t action_class);
const char *capsule_pill_signature_alg_to_string(capsule_pill_signature_alg_t alg);

#ifdef __cplusplus
}
#endif
