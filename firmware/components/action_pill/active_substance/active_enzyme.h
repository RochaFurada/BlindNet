#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "active_substance.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ACTIVE_ENZYME_DEVICE_SECRET_LEN 32
#define ACTIVE_ENZYME_AES_128_KEY_LEN 16
#define ACTIVE_ENZYME_AES_256_KEY_LEN 32
#define ACTIVE_ENZYME_KEY_MAX_LEN ACTIVE_ENZYME_AES_256_KEY_LEN
#define ACTIVE_ENZYME_PLAINTEXT_MAX_LEN ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN

/*
 * Tenta abrir um Active Substance usando um device_secret candidato.
 *
 * O active_enzyme nao escolhe o dispositivo e nao consulta a ribosome_table.
 * Ele apenas recebe um segredo candidato, deriva a chave AEAD e valida a tag.
 *
 * Derivacao de chave:
 *   HKDF-SHA256(
 *     ikm  = device_secret[32],
 *     salt = "BlindNet active enzyme salt v1" || epoch_le32 || active_nonce,
 *     info = "BlindNet active substance decrypt key v1" || as_version || cipher
 *   )
 *
 * O mesmo AAD usado pelo app ao cifrar deve ser passado aqui. Se ainda nao
 * houver AAD no fluxo, use aad = NULL e aad_len = 0.
 */
esp_err_t active_enzyme_decrypt_with_secret(
    const active_substance_t *substance,
    const uint8_t device_secret[ACTIVE_ENZYME_DEVICE_SECRET_LEN],
    uint32_t epoch,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *out_plaintext,
    size_t out_plaintext_size,
    size_t *out_plaintext_len
);

#ifdef __cplusplus
}
#endif
