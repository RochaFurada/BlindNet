#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "active_substance.h"
#include "capsule_pill.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ACTION_PILL_VERSION 1
#define ACTION_PILL_INNER_ID_LEN 32

/*
 * Action Pill = comprimido.
 *
 * Esta e a unidade que viaja pela BlindNet:
 *   - capsule: autorizacao que o Guardian valida
 *   - active: comando real que podera ser publicado no MQTT
 *
 * O Guardian pode repassar o comprimido mesmo quando ele e o destino, e
 * executar uma copia local depois para nao revelar quem controla o alvo.
 */
typedef struct {
    uint8_t version;
    uint8_t hop_count;
    uint8_t hop_limit;
    uint8_t reserved0;
    uint32_t pill_id;
    capsule_pill_t capsule;
    active_substance_t active;
} action_pill_t;

void action_pill_init(action_pill_t *pill);

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
);

esp_err_t action_pill_validate_basic(
    const action_pill_t *pill,
    uint32_t now_ms
);

esp_err_t action_pill_refresh_active_hash(action_pill_t *pill);

bool action_pill_capsule_matches_active(const action_pill_t *pill);

esp_err_t action_pill_sign_hmac_sha256(
    action_pill_t *pill,
    const uint8_t *key,
    size_t key_len
);

bool action_pill_verify_hmac_sha256(
    const action_pill_t *pill,
    const uint8_t *key,
    size_t key_len
);

esp_err_t action_pill_compute_inner_id(
    const action_pill_t *pill,
    uint8_t out_id[ACTION_PILL_INNER_ID_LEN]
);

#ifdef __cplusplus
}
#endif
