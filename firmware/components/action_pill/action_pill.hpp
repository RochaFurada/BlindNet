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

#define ACTION_PILL_VERSION 3
#define ACTION_PILL_INNER_ID_LEN 32
#define ACTION_PILL_PEER_TAG_LEN 16
#define ACTION_PILL_TRANSIT_MAC_LEN 32

/*
 * Action Pill = comprimido.
 *
 * Esta e a unidade que viaja pela BlindNet:
 *   - camada externa: embalagem mutavel de transporte/relay
 *   - capsule: nucleo imutavel assinado pelo app/autorizador
 *   - active: comando cifrado e opaco para todos exceto o destino real
 *
 * O Guardian pode repassar o comprimido mesmo quando ele é o destino, e
 * executar uma cópia local depois para nao revelar quem controla o alvo.
 */
typedef struct {
    uint8_t version;
    uint8_t hop_count;
    uint8_t flags;
    uint8_t relay_attempt;
    uint32_t relay_id;
    uint32_t received_ms;
    uint8_t previous_hop_tag[ACTION_PILL_PEER_TAG_LEN];
    uint8_t transit_mac[ACTION_PILL_TRANSIT_MAC_LEN];
    capsule_pill_t capsule;
    active_substance_t active;
} action_pill_t;

void action_pill_init(action_pill_t *pill);

esp_err_t action_pill_set_encrypted(
    action_pill_t *pill,
    capsule_pill_action_class_t action_class,
    uint32_t issued_ms,
    uint32_t expires_ms,
    const uint8_t network_id[CAPSULE_PILL_NETWORK_ID_LEN],
    const uint8_t capsule_nonce[CAPSULE_PILL_NONCE_LEN],
    const uint8_t issuer_key_id[CAPSULE_PILL_ISSUER_KEY_ID_LEN],
    active_substance_cipher_t cipher,
    const uint8_t active_nonce[ACTIVE_SUBSTANCE_NONCE_LEN],
    const uint8_t active_tag[ACTIVE_SUBSTANCE_TAG_LEN],
    const void *ciphertext,
    size_t ciphertext_len
);

esp_err_t action_pill_make_relay_copy(
    const action_pill_t *input,
    action_pill_t *output,
    const uint8_t previous_hop_tag[ACTION_PILL_PEER_TAG_LEN],
    uint32_t relay_id,
    uint32_t received_ms
);

esp_err_t action_pill_precheck_for_relay(
    const action_pill_t *pill,
    uint32_t now_ms
);

esp_err_t action_pill_validate_authorized(
    const action_pill_t *pill,
    uint32_t now_ms,
    const uint8_t expected_network_id[CAPSULE_PILL_NETWORK_ID_LEN],
    const uint8_t expected_issuer_key_id[CAPSULE_PILL_ISSUER_KEY_ID_LEN],
    const uint8_t *issuer_public_key,
    size_t issuer_public_key_len
);

esp_err_t action_pill_refresh_active_hash(action_pill_t *pill);

bool action_pill_capsule_matches_active(const action_pill_t *pill);

bool action_pill_network_id_matches(
    const action_pill_t *pill,
    const uint8_t expected_network_id[CAPSULE_PILL_NETWORK_ID_LEN]
);

bool action_pill_issuer_key_matches(
    const action_pill_t *pill,
    const uint8_t expected_issuer_key_id[CAPSULE_PILL_ISSUER_KEY_ID_LEN]
);

bool action_pill_verify_capsule_signature(
    const action_pill_t *pill,
    const uint8_t *issuer_public_key,
    size_t issuer_public_key_len
);

esp_err_t action_pill_compute_capsule_digest(
    const action_pill_t *pill,
    uint8_t out_id[ACTION_PILL_INNER_ID_LEN]
);

esp_err_t action_pill_compute_inner_id(
    const action_pill_t *pill,
    uint8_t out_id[ACTION_PILL_INNER_ID_LEN]
);

#ifdef __cplusplus
}
#endif
