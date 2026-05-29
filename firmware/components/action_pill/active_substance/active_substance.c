#include "active_substance.h"

#include <string.h>

#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

static void update_u8(mbedtls_md_context_t *ctx, uint8_t value)
{
    mbedtls_md_update(ctx, &value, sizeof(value));
}

static void update_u16_le(mbedtls_md_context_t *ctx, uint16_t value)
{
    uint8_t bytes[2] = {
        (uint8_t)(value & 0xFFu),
        (uint8_t)((value >> 8) & 0xFFu)
    };
    mbedtls_md_update(ctx, bytes, sizeof(bytes));
}

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

static bool c_string_field_valid(const char *field, size_t len)
{
    if (!field || len == 0 || field[0] == '\0') {
        return false;
    }

    for (size_t i = 0; i < len; ++i) {
        if (field[i] == '\0') {
            for (size_t j = i + 1; j < len; ++j) {
                if (field[j] != '\0') {
                    return false;
                }
            }
            return true;
        }
    }

    return false;
}

void active_substance_command_clear(active_substance_command_t *command)
{
    if (!command) return;
    mbedtls_platform_zeroize(command, sizeof(*command));
}

esp_err_t active_substance_command_validate(
    const active_substance_command_t *command
)
{
    if (!command) return ESP_ERR_INVALID_ARG;

    if (!c_string_field_valid(command->device_id, sizeof(command->device_id))) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!c_string_field_valid(command->topic, sizeof(command->topic))) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!bytes_all_zero(command->reserved, sizeof(command->reserved))) {
        return ESP_ERR_INVALID_ARG;
    }

    const amino_acid_t *acid = amino_acid_find(command->amino_id);
    if (!acid) {
        return ESP_ERR_NOT_FOUND;
    }
    if ((uint8_t)acid->value_type != command->payload_type) {
        return ESP_ERR_INVALID_ARG;
    }

    const int32_t *payload =
        command->payload_type == AMINO_VALUE_NONE ? NULL : &command->payload_i32;

    return amino_acid_validate_payload(command->amino_id, payload);
}

esp_err_t active_substance_parse_command(
    const void *plaintext,
    size_t plaintext_len,
    active_substance_command_t *out_command
)
{
    if (!plaintext || !out_command) return ESP_ERR_INVALID_ARG;
    if (plaintext_len != sizeof(active_substance_command_t)) {
        return ESP_ERR_INVALID_SIZE;
    }

    active_substance_command_clear(out_command);
    memcpy(out_command, plaintext, sizeof(*out_command));

    esp_err_t err = active_substance_command_validate(out_command);
    if (err != ESP_OK) {
        active_substance_command_clear(out_command);
    }

    return err;
}

/*
 * Inicializa em estado vazio e conhecido.
 */
void active_substance_init(active_substance_t *substance)
{
    if (!substance) return;

    mbedtls_platform_zeroize(substance, sizeof(*substance));
    substance->version = ACTIVE_SUBSTANCE_VERSION;
    substance->cipher = ACTIVE_SUBSTANCE_CIPHER_UNKNOWN;
}

/*
 * Define o AS como blob cifrado pelo app. O Guardian nao cria esta
 * criptografia; ele so carrega bytes e depois tenta abrir localmente quando
 * tiver uma chave candidata do dispositivo.
 */
esp_err_t active_substance_set_ciphertext(
    active_substance_t *substance,
    active_substance_cipher_t cipher,
    const uint8_t nonce[ACTIVE_SUBSTANCE_NONCE_LEN],
    const uint8_t tag[ACTIVE_SUBSTANCE_TAG_LEN],
    const void *ciphertext,
    size_t ciphertext_len
)
{
    if (!substance || !nonce || !tag || !ciphertext) return ESP_ERR_INVALID_ARG;
    if (ciphertext_len == 0 || ciphertext_len > ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }

    active_substance_init(substance);
    substance->cipher = (uint8_t)cipher;
    substance->ciphertext_len = (uint16_t)ciphertext_len;

    memcpy(substance->nonce, nonce, ACTIVE_SUBSTANCE_NONCE_LEN);
    memcpy(substance->tag, tag, ACTIVE_SUBSTANCE_TAG_LEN);
    memcpy(substance->ciphertext, ciphertext, ciphertext_len);

    return active_substance_validate_envelope(substance);
}

/*
 * Valida apenas o envelope cifrado do AS. Nao descriptografa, nao autentica
 * a tag AEAD e nao interpreta o comando real.
 */
esp_err_t active_substance_validate_envelope(const active_substance_t *substance)
{
    if (!substance) return ESP_ERR_INVALID_ARG;
    if (substance->version != ACTIVE_SUBSTANCE_VERSION) return ESP_ERR_INVALID_VERSION;

    if (substance->cipher != ACTIVE_SUBSTANCE_CIPHER_AES_128_GCM &&
        substance->cipher != ACTIVE_SUBSTANCE_CIPHER_AES_256_GCM &&
        substance->cipher != ACTIVE_SUBSTANCE_CIPHER_CHACHA20_POLY1305) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    if (substance->ciphertext_len == 0 ||
        substance->ciphertext_len > ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}

esp_err_t active_substance_validate(const active_substance_t *substance)
{
    return active_substance_validate_envelope(substance);
}

/*
 * Calcula o SHA-256 canonico do composto ativo cifrado.
 * Nao fazemos hash da struct inteira porque structs podem conter padding.
 */
esp_err_t active_substance_hash(
    const active_substance_t *substance,
    uint8_t out_hash[ACTIVE_SUBSTANCE_HASH_LEN]
)
{
    if (!substance || !out_hash) return ESP_ERR_INVALID_ARG;

    esp_err_t err = active_substance_validate_envelope(substance);
    if (err != ESP_OK) return err;

    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) return ESP_FAIL;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    if (mbedtls_md_setup(&ctx, info, 0) != 0 ||
        mbedtls_md_starts(&ctx) != 0) {
        mbedtls_md_free(&ctx);
        return ESP_FAIL;
    }

    update_u8(&ctx, substance->version);
    update_u8(&ctx, substance->cipher);
    update_u16_le(&ctx, substance->ciphertext_len);
    mbedtls_md_update(&ctx, substance->nonce, sizeof(substance->nonce));
    mbedtls_md_update(&ctx, substance->tag, sizeof(substance->tag));
    mbedtls_md_update(&ctx, substance->ciphertext, substance->ciphertext_len);

    int rc = mbedtls_md_finish(&ctx, out_hash);
    mbedtls_md_free(&ctx);

    return rc == 0 ? ESP_OK : ESP_FAIL;
}

const char *active_substance_cipher_to_string(active_substance_cipher_t cipher)
{
    switch (cipher) {
        case ACTIVE_SUBSTANCE_CIPHER_AES_128_GCM: return "AES_128_GCM";
        case ACTIVE_SUBSTANCE_CIPHER_AES_256_GCM: return "AES_256_GCM";
        case ACTIVE_SUBSTANCE_CIPHER_CHACHA20_POLY1305: return "CHACHA20_POLY1305";
        case ACTIVE_SUBSTANCE_CIPHER_UNKNOWN:
        default: return "UNKNOWN";
    }
}
