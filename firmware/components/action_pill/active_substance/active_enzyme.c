#include "active_enzyme.h"

#include <stdbool.h>
#include <string.h>

#include "mbedtls/platform_util.h"
#include "psa/crypto.h"

#define ACTIVE_ENZYME_HKDF_DIGEST_LEN 32

static const char k_hkdf_salt_prefix[] = "BlindNet active enzyme salt v1";
static const char k_hkdf_info_prefix[] = "BlindNet active substance decrypt key v1";

static bool bytes_all_zero(const uint8_t *bytes, size_t len)
{
    if (!bytes || len == 0) {
        return true;
    }

    uint8_t any = 0;
    for (size_t i = 0; i < len; ++i) {
        any |= bytes[i];
    }

    return any == 0;
}

static void write_u32_le(uint8_t out[4], uint32_t value)
{
    out[0] = (uint8_t)(value & 0xFFu);
    out[1] = (uint8_t)((value >> 8) & 0xFFu);
    out[2] = (uint8_t)((value >> 16) & 0xFFu);
    out[3] = (uint8_t)((value >> 24) & 0xFFu);
}

static esp_err_t select_key_len(
    const active_substance_t *substance,
    size_t *out_key_len
)
{
    if (!substance || !out_key_len) {
        return ESP_ERR_INVALID_ARG;
    }

    switch ((active_substance_cipher_t)substance->cipher) {
        case ACTIVE_SUBSTANCE_CIPHER_AES_128_GCM:
            *out_key_len = ACTIVE_ENZYME_AES_128_KEY_LEN;
            return ESP_OK;

        case ACTIVE_SUBSTANCE_CIPHER_AES_256_GCM:
            *out_key_len = ACTIVE_ENZYME_AES_256_KEY_LEN;
            return ESP_OK;

        case ACTIVE_SUBSTANCE_CIPHER_CHACHA20_POLY1305:
            return ESP_ERR_NOT_SUPPORTED;

        case ACTIVE_SUBSTANCE_CIPHER_UNKNOWN:
        default:
            return ESP_ERR_NOT_SUPPORTED;
    }
}

static esp_err_t hmac_sha256(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *part1,
    size_t part1_len,
    const uint8_t *part2,
    size_t part2_len,
    uint8_t out[ACTIVE_ENZYME_HKDF_DIGEST_LEN]
)
{
    if (!key || key_len == 0 || !out ||
        (!part1 && part1_len != 0) ||
        (!part2 && part2_len != 0)) {
        return ESP_ERR_INVALID_ARG;
    }

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return ESP_FAIL;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, key_len * 8u);

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    status = psa_import_key(&attributes, key, key_len, &key_id);
    psa_reset_key_attributes(&attributes);

    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    size_t mac_len = 0;

    if (status == PSA_SUCCESS) {
        status = psa_mac_sign_setup(&op, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    }
    if (status == PSA_SUCCESS && part1_len != 0) {
        status = psa_mac_update(&op, part1, part1_len);
    }
    if (status == PSA_SUCCESS && part2_len != 0) {
        status = psa_mac_update(&op, part2, part2_len);
    }
    if (status == PSA_SUCCESS) {
        status = psa_mac_sign_finish(
            &op,
            out,
            ACTIVE_ENZYME_HKDF_DIGEST_LEN,
            &mac_len
        );
    }

    (void)psa_mac_abort(&op);
    if (!mbedtls_svc_key_id_is_null(key_id)) {
        (void)psa_destroy_key(key_id);
    }

    return status == PSA_SUCCESS && mac_len == ACTIVE_ENZYME_HKDF_DIGEST_LEN
        ? ESP_OK
        : ESP_FAIL;
}

static esp_err_t hkdf_sha256_one_block(
    const uint8_t *ikm,
    size_t ikm_len,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *out_key,
    size_t out_key_len
)
{
    if (!ikm || ikm_len == 0 || !salt || salt_len == 0 ||
        !info || info_len == 0 || !out_key || out_key_len == 0 ||
        out_key_len > ACTIVE_ENZYME_HKDF_DIGEST_LEN) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t prk[ACTIVE_ENZYME_HKDF_DIGEST_LEN] = {0};
    uint8_t t1[ACTIVE_ENZYME_HKDF_DIGEST_LEN] = {0};
    const uint8_t counter = 1;

    esp_err_t err = hmac_sha256(salt, salt_len, ikm, ikm_len, NULL, 0, prk);
    if (err != ESP_OK) {
        mbedtls_platform_zeroize(prk, sizeof(prk));
        return err;
    }

    err = hmac_sha256(prk, sizeof(prk), info, info_len, &counter, sizeof(counter), t1);

    if (err == ESP_OK) {
        memcpy(out_key, t1, out_key_len);
    }

    mbedtls_platform_zeroize(prk, sizeof(prk));
    mbedtls_platform_zeroize(t1, sizeof(t1));

    return err;
}

static esp_err_t derive_aead_key(
    const active_substance_t *substance,
    const uint8_t device_secret[ACTIVE_ENZYME_DEVICE_SECRET_LEN],
    uint32_t epoch,
    uint8_t out_key[ACTIVE_ENZYME_KEY_MAX_LEN],
    size_t *out_key_len
)
{
    if (!substance || !device_secret || !out_key || !out_key_len) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = select_key_len(substance, out_key_len);
    if (err != ESP_OK) {
        return err;
    }

    uint8_t salt[
        (sizeof(k_hkdf_salt_prefix) - 1) +
        sizeof(uint32_t) +
        ACTIVE_SUBSTANCE_NONCE_LEN
    ] = {0};
    size_t salt_len = 0;

    memcpy(&salt[salt_len], k_hkdf_salt_prefix, sizeof(k_hkdf_salt_prefix) - 1);
    salt_len += sizeof(k_hkdf_salt_prefix) - 1;

    write_u32_le(&salt[salt_len], epoch);
    salt_len += sizeof(uint32_t);

    memcpy(&salt[salt_len], substance->nonce, ACTIVE_SUBSTANCE_NONCE_LEN);
    salt_len += ACTIVE_SUBSTANCE_NONCE_LEN;

    uint8_t info[
        (sizeof(k_hkdf_info_prefix) - 1) +
        sizeof(substance->version) +
        sizeof(substance->cipher)
    ] = {0};
    size_t info_len = 0;

    memcpy(&info[info_len], k_hkdf_info_prefix, sizeof(k_hkdf_info_prefix) - 1);
    info_len += sizeof(k_hkdf_info_prefix) - 1;
    info[info_len++] = substance->version;
    info[info_len++] = substance->cipher;

    err = hkdf_sha256_one_block(
        device_secret,
        ACTIVE_ENZYME_DEVICE_SECRET_LEN,
        salt,
        salt_len,
        info,
        info_len,
        out_key,
        *out_key_len
    );

    mbedtls_platform_zeroize(salt, sizeof(salt));
    mbedtls_platform_zeroize(info, sizeof(info));

    return err;
}

static esp_err_t decrypt_aes_gcm(
    const active_substance_t *substance,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *out_plaintext
)
{
    if (!substance || !key || !out_plaintext) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t sealed[
        ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN + ACTIVE_SUBSTANCE_TAG_LEN
    ] = {0};
    const size_t sealed_len = substance->ciphertext_len + ACTIVE_SUBSTANCE_TAG_LEN;

    memcpy(sealed, substance->ciphertext, substance->ciphertext_len);
    memcpy(&sealed[substance->ciphertext_len], substance->tag, ACTIVE_SUBSTANCE_TAG_LEN);

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(sealed, sizeof(sealed));
        return ESP_FAIL;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_len * 8u);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);

    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    status = psa_import_key(&attributes, key, key_len, &key_id);
    psa_reset_key_attributes(&attributes);

    size_t plaintext_len = 0;
    if (status == PSA_SUCCESS) {
        status = psa_aead_decrypt(
            key_id,
            PSA_ALG_GCM,
            substance->nonce,
            ACTIVE_SUBSTANCE_NONCE_LEN,
            aad,
            aad_len,
            sealed,
            sealed_len,
            out_plaintext,
            substance->ciphertext_len,
            &plaintext_len
        );
    }

    if (!mbedtls_svc_key_id_is_null(key_id)) {
        (void)psa_destroy_key(key_id);
    }
    mbedtls_platform_zeroize(sealed, sizeof(sealed));

    if (status == PSA_SUCCESS && plaintext_len == substance->ciphertext_len) {
        return ESP_OK;
    }

    if (status == PSA_ERROR_INVALID_SIGNATURE) {
        return ESP_ERR_INVALID_STATE;
    }

    return ESP_FAIL;
}

esp_err_t active_enzyme_decrypt_with_secret(
    const active_substance_t *substance,
    const uint8_t device_secret[ACTIVE_ENZYME_DEVICE_SECRET_LEN],
    uint32_t epoch,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *out_plaintext,
    size_t out_plaintext_size,
    size_t *out_plaintext_len
)
{
    if (out_plaintext_len) {
        *out_plaintext_len = 0;
    }

    if (!substance || !device_secret || !out_plaintext || !out_plaintext_len) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!aad && aad_len != 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (bytes_all_zero(device_secret, ACTIVE_ENZYME_DEVICE_SECRET_LEN)) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = active_substance_validate_envelope(substance);
    if (err != ESP_OK) {
        return err;
    }

    if (out_plaintext_size < substance->ciphertext_len) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t key[ACTIVE_ENZYME_KEY_MAX_LEN] = {0};
    size_t key_len = 0;

    err = derive_aead_key(substance, device_secret, epoch, key, &key_len);
    if (err == ESP_OK) {
        err = decrypt_aes_gcm(
            substance,
            key,
            key_len,
            aad,
            aad_len,
            out_plaintext
        );
    }

    mbedtls_platform_zeroize(key, sizeof(key));

    if (err != ESP_OK) {
        mbedtls_platform_zeroize(out_plaintext, out_plaintext_size);
        return err;
    }

    *out_plaintext_len = substance->ciphertext_len;
    return ESP_OK;
}
