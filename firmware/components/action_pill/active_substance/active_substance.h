#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN
#define ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN 256
#endif

#define ACTIVE_SUBSTANCE_VERSION 2
#define ACTIVE_SUBSTANCE_HASH_LEN 32
#define ACTIVE_SUBSTANCE_NONCE_LEN 12
#define ACTIVE_SUBSTANCE_TAG_LEN 16

/*
 * Active Substance = composto ativo.
 *
 * Esta e a parte que efetivamente vira comando para o dispositivo IoT,
 * mas na BlindNet ela viaja opaca. O app do usuario cifra o conteudo
 * antes de criar o Action Pill; o Guardian so tenta abrir localmente
 * quando alguma chave de dispositivo permitir.
 */
typedef enum {
    ACTIVE_SUBSTANCE_CIPHER_UNKNOWN = 0,
    ACTIVE_SUBSTANCE_CIPHER_AES_128_GCM = 1,
    ACTIVE_SUBSTANCE_CIPHER_AES_256_GCM = 2,
    ACTIVE_SUBSTANCE_CIPHER_CHACHA20_POLY1305 = 3
} active_substance_cipher_t;

/*
 * Blob cifrado AEAD.
 *
 * O CP deve ser usado como AAD pelo app ao cifrar. Este modulo nao
 * descriptografa; ele apenas preserva bytes canonicos para hash, cache e
 * verificacao de vinculo CP -> AS.
 */
typedef struct {
    uint8_t version;
    uint8_t cipher;
    uint16_t ciphertext_len;
    uint8_t nonce[ACTIVE_SUBSTANCE_NONCE_LEN];
    uint8_t tag[ACTIVE_SUBSTANCE_TAG_LEN];
    uint8_t ciphertext[ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN];
} active_substance_t;

void active_substance_init(active_substance_t *substance);

esp_err_t active_substance_set_ciphertext(
    active_substance_t *substance,
    active_substance_cipher_t cipher,
    const uint8_t nonce[ACTIVE_SUBSTANCE_NONCE_LEN],
    const uint8_t tag[ACTIVE_SUBSTANCE_TAG_LEN],
    const void *ciphertext,
    size_t ciphertext_len
);

esp_err_t active_substance_validate(const active_substance_t *substance);

esp_err_t active_substance_hash(
    const active_substance_t *substance,
    uint8_t out_hash[ACTIVE_SUBSTANCE_HASH_LEN]
);

const char *active_substance_cipher_to_string(active_substance_cipher_t cipher);

#ifdef __cplusplus
}
#endif
