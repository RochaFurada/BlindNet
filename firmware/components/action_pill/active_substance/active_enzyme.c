#include "active_enzyme.h"

#include <stdbool.h>
#include <string.h>

#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

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

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) {
        return ESP_FAIL;
    }

    uint8_t prk[ACTIVE_ENZYME_HKDF_DIGEST_LEN] = {0};
    uint8_t t1[ACTIVE_ENZYME_HKDF_DIGEST_LEN] = {0};
    const uint8_t counter = 1;

    int rc = mbedtls_md_hmac(md_info, salt, salt_len, ikm, ikm_len, prk);
    if (rc != 0) {
        mbedtls_platform_zeroize(prk, sizeof(prk));
        return ESP_FAIL;
    }

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    rc = mbedtls_md_setup(&ctx, md_info, 1);
    if (rc == 0) {
        rc = mbedtls_md_hmac_starts(&ctx, prk, sizeof(prk));
    }
    if (rc == 0) {
        rc = mbedtls_md_hmac_update(&ctx, info, info_len);
    }
    if (rc == 0) {
        rc = mbedtls_md_hmac_update(&ctx, &counter, sizeof(counter));
    }
    if (rc == 0) {
        rc = mbedtls_md_hmac_finish(&ctx, t1);
    }

    mbedtls_md_free(&ctx);

    if (rc == 0) {
        memcpy(out_key, t1, out_key_len);
    }

    mbedtls_platform_zeroize(prk, sizeof(prk));
    mbedtls_platform_zeroize(t1, sizeof(t1));

    return rc == 0 ? ESP_OK : ESP_FAIL;
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

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int rc = mbedtls_gcm_setkey(
        &ctx,
        MBEDTLS_CIPHER_ID_AES,
        key,
        (unsigned int)(key_len * 8u)
    );

    if (rc == 0) {
        rc = mbedtls_gcm_auth_decrypt(
            &ctx,
            substance->ciphertext_len,
            substance->nonce,
            ACTIVE_SUBSTANCE_NONCE_LEN,
            aad,
            aad_len,
            substance->tag,
            ACTIVE_SUBSTANCE_TAG_LEN,
            substance->ciphertext,
            out_plaintext
        );
    }

    mbedtls_gcm_free(&ctx);

    if (rc == 0) {
        return ESP_OK;
    }

#ifdef MBEDTLS_ERR_GCM_AUTH_FAILED
    if (rc == MBEDTLS_ERR_GCM_AUTH_FAILED) {
        return ESP_ERR_INVALID_STATE;
    }
#endif

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
