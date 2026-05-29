#include "ribosome_table.h"

#include <string.h>

#include "mbedtls/platform_util.h"

static bool string_valid(const char *value, size_t max_len)
{
    if (!value || value[0] == '\0') {
        return false;
    }

    for (size_t i = 0; i < max_len; ++i) {
        if (value[i] == '\0') {
            return true;
        }
    }

    return false;
}

static bool table_count_valid(const ribosome_table_t *table)
{
    return table && table->count <= RIBOSOME_MAX_ENTRIES;
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

static void copy_entry_sanitized(
    ribosome_table_entry_t *dst,
    const ribosome_table_entry_t *src
)
{
    ribosome_table_clear_entry(dst);

    strncpy(
        dst->mqtt_client_id,
        src->mqtt_client_id,
        RIBOSOME_MQTT_CLIENT_ID_LEN - 1
    );

    dst->template_id = src->template_id;
    dst->epoch = src->epoch;
    memcpy(dst->device_secret, src->device_secret, RIBOSOME_DEVICE_SECRET_LEN);
}

bool ribosome_template_id_valid(rna_template_id_t template_id)
{
    return rna_template_id_valid(template_id);
}

void ribosome_table_clear_entry(ribosome_table_entry_t *entry)
{
    if (!entry) {
        return;
    }

    mbedtls_platform_zeroize(entry, sizeof(*entry));
}

esp_err_t ribosome_table_init(ribosome_table_t *table)
{
    if (!table) {
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_platform_zeroize(table, sizeof(*table));
    return ESP_OK;
}

esp_err_t ribosome_table_make_entry(
    const ribosome_entry_config_t *config,
    ribosome_table_entry_t *out_entry
)
{
    if (!config || !out_entry || !config->device_secret) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!string_valid(config->mqtt_client_id, RIBOSOME_MQTT_CLIENT_ID_LEN)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!ribosome_template_id_valid(config->template_id)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (bytes_all_zero(config->device_secret, RIBOSOME_DEVICE_SECRET_LEN)) {
        return ESP_ERR_INVALID_ARG;
    }

    ribosome_table_clear_entry(out_entry);

    strncpy(
        out_entry->mqtt_client_id,
        config->mqtt_client_id,
        RIBOSOME_MQTT_CLIENT_ID_LEN - 1
    );

    out_entry->template_id = config->template_id;
    out_entry->epoch = config->epoch;
    memcpy(out_entry->device_secret, config->device_secret, RIBOSOME_DEVICE_SECRET_LEN);

    return ESP_OK;
}

bool ribosome_table_entry_exists(
    const ribosome_table_t *table,
    const char *mqtt_client_id
)
{
    if (!table_count_valid(table) ||
        !string_valid(mqtt_client_id, RIBOSOME_MQTT_CLIENT_ID_LEN)) {
        return false;
    }

    for (size_t i = 0; i < table->count; ++i) {
        if (strncmp(
                table->entries[i].mqtt_client_id,
                mqtt_client_id,
                RIBOSOME_MQTT_CLIENT_ID_LEN
            ) == 0) {
            return true;
        }
    }

    return false;
}

esp_err_t ribosome_table_add_entry(
    ribosome_table_t *table,
    const ribosome_table_entry_t *entry
)
{
    if (!table_count_valid(table) || !entry) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!string_valid(entry->mqtt_client_id, RIBOSOME_MQTT_CLIENT_ID_LEN)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!ribosome_template_id_valid(entry->template_id)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (bytes_all_zero(entry->device_secret, RIBOSOME_DEVICE_SECRET_LEN)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (table->count >= RIBOSOME_MAX_ENTRIES) {
        return ESP_ERR_NO_MEM;
    }
    if (ribosome_table_entry_exists(table, entry->mqtt_client_id)) {
        return ESP_ERR_INVALID_STATE;
    }

    copy_entry_sanitized(&table->entries[table->count], entry);
    table->count++;

    return ESP_OK;
}

esp_err_t ribosome_table_add_from_config(
    ribosome_table_t *table,
    const ribosome_entry_config_t *config
)
{
    if (!table_count_valid(table) || !config) {
        return ESP_ERR_INVALID_ARG;
    }
    if (table->count >= RIBOSOME_MAX_ENTRIES) {
        return ESP_ERR_NO_MEM;
    }
    if (!string_valid(config->mqtt_client_id, RIBOSOME_MQTT_CLIENT_ID_LEN)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (ribosome_table_entry_exists(table, config->mqtt_client_id)) {
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err = ribosome_table_make_entry(config, &table->entries[table->count]);
    if (err != ESP_OK) {
        ribosome_table_clear_entry(&table->entries[table->count]);
        return err;
    }

    table->count++;
    return ESP_OK;
}

esp_err_t ribosome_table_remove_entry(
    ribosome_table_t *table,
    const char *mqtt_client_id
)
{
    if (!table_count_valid(table) ||
        !string_valid(mqtt_client_id, RIBOSOME_MQTT_CLIENT_ID_LEN)) {
        return ESP_ERR_INVALID_ARG;
    }

    for (size_t i = 0; i < table->count; ++i) {
        if (strncmp(
                table->entries[i].mqtt_client_id,
                mqtt_client_id,
                RIBOSOME_MQTT_CLIENT_ID_LEN
            ) != 0) {
            continue;
        }

        for (size_t j = i; j + 1 < table->count; ++j) {
            copy_entry_sanitized(&table->entries[j], &table->entries[j + 1]);
        }

        table->count--;
        ribosome_table_clear_entry(&table->entries[table->count]);
        return ESP_OK;
    }

    return ESP_ERR_NOT_FOUND;
}

esp_err_t ribosome_table_get_entry(
    const ribosome_table_t *table,
    const char *mqtt_client_id,
    ribosome_table_entry_t *out_entry
)
{
    if (!table_count_valid(table) || !out_entry ||
        !string_valid(mqtt_client_id, RIBOSOME_MQTT_CLIENT_ID_LEN)) {
        return ESP_ERR_INVALID_ARG;
    }

    for (size_t i = 0; i < table->count; ++i) {
        if (strncmp(
                table->entries[i].mqtt_client_id,
                mqtt_client_id,
                RIBOSOME_MQTT_CLIENT_ID_LEN
            ) == 0) {
            copy_entry_sanitized(out_entry, &table->entries[i]);
            return ESP_OK;
        }
    }

    return ESP_ERR_NOT_FOUND;
}

size_t ribosome_table_count(const ribosome_table_t *table)
{
    if (!table_count_valid(table)) {
        return 0;
    }

    return table->count;
}
