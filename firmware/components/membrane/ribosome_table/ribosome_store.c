#include "ribosome_store.h"

#include <string.h>

#include "mbedtls/platform_util.h"
#include "nvs.h"

#define RIBOSOME_STORE_MAGIC 0x5249424Fu
#define RIBOSOME_STORE_VERSION 2u

static const char *NVS_NS = "ribosome";
static const char *NVS_KEY = "table";

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t entry_count;
    ribosome_table_entry_t entries[RIBOSOME_MAX_ENTRIES];
    uint32_t checksum;
} ribosome_store_blob_t;

static uint32_t fnv1a32_update(uint32_t hash, const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;

    for (size_t i = 0; i < len; ++i) {
        hash ^= bytes[i];
        hash *= 16777619u;
    }

    return hash;
}

static uint32_t blob_checksum(const ribosome_store_blob_t *blob)
{
    uint32_t hash = 2166136261u;

    hash = fnv1a32_update(hash, &blob->magic, sizeof(blob->magic));
    hash = fnv1a32_update(hash, &blob->version, sizeof(blob->version));
    hash = fnv1a32_update(hash, &blob->entry_count, sizeof(blob->entry_count));
    hash = fnv1a32_update(hash, blob->entries, sizeof(blob->entries));

    return hash;
}

static esp_err_t table_to_blob(
    const ribosome_table_t *table,
    ribosome_store_blob_t *blob
)
{
    if (!table || !blob || table->count > RIBOSOME_MAX_ENTRIES) {
        return ESP_ERR_INVALID_ARG;
    }

    ribosome_table_t validated;
    esp_err_t err = ribosome_table_init(&validated);
    if (err != ESP_OK) {
        return err;
    }

    for (size_t i = 0; i < table->count; ++i) {
        err = ribosome_table_add_entry(&validated, &table->entries[i]);
        if (err != ESP_OK) {
            mbedtls_platform_zeroize(&validated, sizeof(validated));
            return err;
        }
    }

    mbedtls_platform_zeroize(blob, sizeof(*blob));
    blob->magic = RIBOSOME_STORE_MAGIC;
    blob->version = RIBOSOME_STORE_VERSION;
    blob->entry_count = (uint16_t)validated.count;

    for (size_t i = 0; i < validated.count; ++i) {
        blob->entries[i] = validated.entries[i];
    }

    blob->checksum = blob_checksum(blob);
    mbedtls_platform_zeroize(&validated, sizeof(validated));
    return ESP_OK;
}

static esp_err_t blob_to_table(
    const ribosome_store_blob_t *blob,
    ribosome_table_t *out_table
)
{
    if (!blob || !out_table) {
        return ESP_ERR_INVALID_ARG;
    }
    if (blob->magic != RIBOSOME_STORE_MAGIC ||
        blob->version != RIBOSOME_STORE_VERSION ||
        blob->entry_count > RIBOSOME_MAX_ENTRIES) {
        return ESP_ERR_INVALID_VERSION;
    }
    if (blob->checksum != blob_checksum(blob)) {
        return ESP_ERR_INVALID_CRC;
    }

    ribosome_table_t table;
    esp_err_t err = ribosome_table_init(&table);
    if (err != ESP_OK) {
        return err;
    }

    for (size_t i = 0; i < blob->entry_count; ++i) {
        err = ribosome_table_add_entry(&table, &blob->entries[i]);
        if (err != ESP_OK) {
            mbedtls_platform_zeroize(&table, sizeof(table));
            return err;
        }
    }

    *out_table = table;
    mbedtls_platform_zeroize(&table, sizeof(table));
    return ESP_OK;
}

esp_err_t ribosome_store_load(ribosome_table_t *out_table)
{
    if (!out_table) {
        return ESP_ERR_INVALID_ARG;
    }

    ribosome_table_init(out_table);

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return err;
    }

    ribosome_store_blob_t blob;
    size_t size = sizeof(blob);
    err = nvs_get_blob(handle, NVS_KEY, &blob, &size);
    nvs_close(handle);

    if (err != ESP_OK) {
        mbedtls_platform_zeroize(&blob, sizeof(blob));
        return err;
    }
    if (size != sizeof(blob)) {
        mbedtls_platform_zeroize(&blob, sizeof(blob));
        return ESP_ERR_INVALID_SIZE;
    }

    err = blob_to_table(&blob, out_table);
    mbedtls_platform_zeroize(&blob, sizeof(blob));
    return err;
}

esp_err_t ribosome_store_load_or_init(ribosome_table_t *out_table)
{
    if (!out_table) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = ribosome_store_load(out_table);
    if (err == ESP_OK) {
        return ESP_OK;
    }
    if (err != ESP_ERR_NVS_NOT_FOUND) {
        return err;
    }

    return ribosome_table_init(out_table);
}

esp_err_t ribosome_store_save(const ribosome_table_t *table)
{
    ribosome_store_blob_t blob;
    esp_err_t err = table_to_blob(table, &blob);
    if (err != ESP_OK) {
        mbedtls_platform_zeroize(&blob, sizeof(blob));
        return err;
    }

    nvs_handle_t handle;
    err = nvs_open(NVS_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        mbedtls_platform_zeroize(&blob, sizeof(blob));
        return err;
    }

    err = nvs_set_blob(handle, NVS_KEY, &blob, sizeof(blob));
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    nvs_close(handle);
    mbedtls_platform_zeroize(&blob, sizeof(blob));
    return err;
}

esp_err_t ribosome_store_erase(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return err == ESP_ERR_NVS_NOT_FOUND ? ESP_OK : err;
    }

    err = nvs_erase_key(handle, NVS_KEY);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        err = ESP_OK;
    }
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    nvs_close(handle);
    return err;
}
