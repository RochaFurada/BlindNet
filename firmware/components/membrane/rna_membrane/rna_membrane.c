#include "rna_membrane.h"

#include <stddef.h>
#include <string.h>

#include "nvs.h"

#define RNA_STORE_MAGIC 0x524E414Du
#define RNA_STORE_VERSION 2u
#define RNA_STORE_CHECKSUM_OFFSET offsetof(rna_store_blob_t, checksum)

static const char *NVS_NS = "rna_membrane";
static const char *NVS_KEY = "templates";

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t template_count;
    rna_template_t templates[RNA_MAX_TEMPLATES];
    uint32_t checksum;
} rna_store_blob_t;

static const rna_template_t RNA_DEFAULT_TEMPLATES[] = {
    {
        .id = RNA_TEMPLATE_ID_LIGHT_SWITCH,
        .name = "LIGHT_SWITCH",
        .amino_count = 4,
        .aminos = {
            AMINO_ON,
            AMINO_OFF,
            AMINO_TOGGLE,
            AMINO_READ_STATE,
        },
    },
    {
        .id = RNA_TEMPLATE_ID_OUTLET,
        .name = "OUTLET",
        .amino_count = 4,
        .aminos = {
            AMINO_ON,
            AMINO_OFF,
            AMINO_TOGGLE,
            AMINO_READ_STATE,
        },
    },
    {
        .id = RNA_TEMPLATE_ID_DOOR,
        .name = "DOOR",
        .amino_count = 5,
        .aminos = {
            AMINO_OPEN,
            AMINO_CLOSE,
            AMINO_LOCK,
            AMINO_UNLOCK,
            AMINO_READ_STATE,
        },
    },
    {
        .id = RNA_TEMPLATE_ID_AIR_CONDITIONER,
        .name = "AIR_CONDITIONER",
        .amino_count = 6,
        .aminos = {
            AMINO_ON,
            AMINO_OFF,
            AMINO_SET_TEMPERATURE,
            AMINO_SET_SPEED,
            AMINO_SET_MODE,
            AMINO_READ_STATE,
        },
    },
    {
        .id = RNA_TEMPLATE_ID_DIMMER,
        .name = "DIMMER",
        .amino_count = 5,
        .aminos = {
            AMINO_ON,
            AMINO_OFF,
            AMINO_TOGGLE,
            AMINO_SET_LEVEL,
            AMINO_READ_STATE,
        },
    },
    {
        .id = RNA_TEMPLATE_ID_FAN,
        .name = "FAN",
        .amino_count = 5,
        .aminos = {
            AMINO_ON,
            AMINO_OFF,
            AMINO_TOGGLE,
            AMINO_SET_SPEED,
            AMINO_READ_STATE,
        },
    },
    {
        .id = RNA_TEMPLATE_ID_SENSOR_READONLY,
        .name = "SENSOR_READ_ONLY",
        .amino_count = 1,
        .aminos = {
            AMINO_READ_STATE,
        },
    },
};

static uint32_t fnv1a_update(
    uint32_t hash,
    const void *data,
    size_t len
)
{
    const uint8_t *bytes = (const uint8_t *)data;
    for (size_t i = 0; i < len; ++i) {
        hash ^= bytes[i];
        hash *= 16777619u;
    }

    return hash;
}

static uint32_t blob_checksum(const rna_store_blob_t *blob)
{
    return fnv1a_update(2166136261u, blob, RNA_STORE_CHECKSUM_OFFSET);
}

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

static bool table_count_valid(const rna_template_table_t *table)
{
    return table && table->count <= RNA_MAX_TEMPLATES;
}

static void copy_template_sanitized(
    rna_template_t *dst,
    const rna_template_t *src
)
{
    rna_template_clear(dst);
    dst->id = src->id;
    dst->amino_count = src->amino_count;
    dst->flags = src->flags;

    strncpy(dst->name, src->name, RNA_TEMPLATE_NAME_LEN - 1);
    memcpy(dst->aminos, src->aminos, sizeof(dst->aminos));
}

static bool template_id_exists(
    const rna_template_table_t *table,
    rna_template_id_t template_id
)
{
    return rna_template_table_find(table, template_id) != NULL;
}

static esp_err_t table_to_blob(
    const rna_template_table_t *table,
    rna_store_blob_t *blob
)
{
    if (!table_count_valid(table) || !blob || table->count == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    rna_template_table_t validated;
    esp_err_t err = rna_template_table_init(&validated);
    if (err != ESP_OK) {
        return err;
    }

    for (size_t i = 0; i < table->count; ++i) {
        err = rna_template_table_add(&validated, &table->templates[i]);
        if (err != ESP_OK) {
            return err;
        }
    }

    memset(blob, 0, sizeof(*blob));
    blob->magic = RNA_STORE_MAGIC;
    blob->version = RNA_STORE_VERSION;
    blob->template_count = (uint16_t)validated.count;
    memcpy(blob->templates, validated.templates, sizeof(blob->templates));
    blob->checksum = blob_checksum(blob);

    return ESP_OK;
}

static esp_err_t blob_to_table(
    const rna_store_blob_t *blob,
    rna_template_table_t *out_table
)
{
    if (!blob || !out_table) {
        return ESP_ERR_INVALID_ARG;
    }
    if (blob->magic != RNA_STORE_MAGIC ||
        blob->version != RNA_STORE_VERSION ||
        blob->template_count == 0 ||
        blob->template_count > RNA_MAX_TEMPLATES) {
        return ESP_ERR_INVALID_VERSION;
    }
    if (blob->checksum != blob_checksum(blob)) {
        return ESP_ERR_INVALID_CRC;
    }

    rna_template_table_t table;
    esp_err_t err = rna_template_table_init(&table);
    if (err != ESP_OK) {
        return err;
    }

    for (size_t i = 0; i < blob->template_count; ++i) {
        err = rna_template_table_add(&table, &blob->templates[i]);
        if (err != ESP_OK) {
            rna_template_table_init(&table);
            return err;
        }
    }

    *out_table = table;
    return ESP_OK;
}

void rna_template_clear(rna_template_t *template_rule)
{
    if (template_rule) {
        memset(template_rule, 0, sizeof(*template_rule));
    }
}

esp_err_t rna_template_validate(const rna_template_t *template_rule)
{
    if (!template_rule ||
        !rna_template_id_valid(template_rule->id) ||
        !string_valid(template_rule->name, RNA_TEMPLATE_NAME_LEN) ||
        template_rule->amino_count == 0 ||
        template_rule->amino_count > RNA_TEMPLATE_MAX_AMINOS) {
        return ESP_ERR_INVALID_ARG;
    }

    for (uint8_t i = 0; i < template_rule->amino_count; ++i) {
        amino_acid_id_t amino_id = template_rule->aminos[i];
        if (!amino_acid_id_valid(amino_id)) {
            return ESP_ERR_INVALID_ARG;
        }

        for (uint8_t j = 0; j < i; ++j) {
            if (template_rule->aminos[j] == amino_id) {
                return ESP_ERR_INVALID_ARG;
            }
        }
    }

    return ESP_OK;
}

bool rna_template_id_valid(rna_template_id_t template_id)
{
    return template_id != RNA_TEMPLATE_ID_INVALID;
}

esp_err_t rna_template_table_init(rna_template_table_t *table)
{
    if (!table) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(table, 0, sizeof(*table));
    return ESP_OK;
}

esp_err_t rna_template_table_add(
    rna_template_table_t *table,
    const rna_template_t *template_rule
)
{
    if (!table_count_valid(table) || !template_rule) {
        return ESP_ERR_INVALID_ARG;
    }
    if (table->count >= RNA_MAX_TEMPLATES) {
        return ESP_ERR_NO_MEM;
    }
    if (rna_template_validate(template_rule) != ESP_OK) {
        return ESP_ERR_INVALID_ARG;
    }
    if (template_id_exists(table, template_rule->id)) {
        return ESP_ERR_INVALID_STATE;
    }

    copy_template_sanitized(&table->templates[table->count], template_rule);
    table->count++;

    return ESP_OK;
}

const rna_template_t *rna_template_table_find(
    const rna_template_table_t *table,
    rna_template_id_t template_id
)
{
    if (!table_count_valid(table) || !rna_template_id_valid(template_id)) {
        return NULL;
    }

    for (size_t i = 0; i < table->count; ++i) {
        if (table->templates[i].id == template_id) {
            return &table->templates[i];
        }
    }

    return NULL;
}

bool rna_template_has_capability(
    const rna_template_t *template_rule,
    amino_acid_id_t amino_id
)
{
    if (!template_rule || !amino_acid_id_valid(amino_id)) {
        return false;
    }
    if (template_rule->amino_count > RNA_TEMPLATE_MAX_AMINOS) {
        return false;
    }

    for (uint8_t i = 0; i < template_rule->amino_count; ++i) {
        if (template_rule->aminos[i] == amino_id) {
            return true;
        }
    }

    return false;
}

bool rna_template_allows(
    const rna_template_t *template_rule,
    amino_acid_id_t amino_id
)
{
    return rna_template_has_capability(template_rule, amino_id);
}

bool rna_template_table_has_capability(
    const rna_template_table_t *table,
    rna_template_id_t template_id,
    amino_acid_id_t amino_id
)
{
    const rna_template_t *template_rule =
        rna_template_table_find(table, template_id);
    return rna_template_has_capability(template_rule, amino_id);
}

bool rna_template_table_allows(
    const rna_template_table_t *table,
    rna_template_id_t template_id,
    amino_acid_id_t amino_id
)
{
    return rna_template_table_has_capability(table, template_id, amino_id);
}

const rna_template_t *rna_membrane_defaults(size_t *out_count)
{
    if (out_count) {
        *out_count = sizeof(RNA_DEFAULT_TEMPLATES) /
            sizeof(RNA_DEFAULT_TEMPLATES[0]);
    }

    return RNA_DEFAULT_TEMPLATES;
}

esp_err_t rna_membrane_load_defaults(rna_template_table_t *out_table)
{
    if (!out_table) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = rna_template_table_init(out_table);
    if (err != ESP_OK) {
        return err;
    }

    size_t count = 0;
    const rna_template_t *defaults = rna_membrane_defaults(&count);
    for (size_t i = 0; i < count; ++i) {
        err = rna_template_table_add(out_table, &defaults[i]);
        if (err != ESP_OK) {
            rna_template_table_init(out_table);
            return err;
        }
    }

    return ESP_OK;
}

esp_err_t rna_membrane_load(rna_template_table_t *out_table)
{
    if (!out_table) {
        return ESP_ERR_INVALID_ARG;
    }

    rna_template_table_init(out_table);

    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return err;
    }

    rna_store_blob_t blob;
    size_t len = sizeof(blob);
    err = nvs_get_blob(handle, NVS_KEY, &blob, &len);
    nvs_close(handle);
    if (err != ESP_OK) {
        return err;
    }
    if (len != sizeof(blob)) {
        return ESP_ERR_INVALID_SIZE;
    }

    return blob_to_table(&blob, out_table);
}

esp_err_t rna_membrane_load_or_init(rna_template_table_t *out_table)
{
    if (!out_table) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = rna_membrane_load(out_table);
    if (err == ESP_OK) {
        return ESP_OK;
    }
    if (err != ESP_ERR_NVS_NOT_FOUND) {
        return err;
    }

    err = rna_membrane_load_defaults(out_table);
    if (err != ESP_OK) {
        return err;
    }

    return rna_membrane_save(out_table);
}

esp_err_t rna_membrane_save(const rna_template_table_t *table)
{
    rna_store_blob_t blob;
    esp_err_t err = table_to_blob(table, &blob);
    if (err != ESP_OK) {
        return err;
    }

    nvs_handle_t handle;
    err = nvs_open(NVS_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_blob(handle, NVS_KEY, &blob, sizeof(blob));
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }

    nvs_close(handle);
    return err;
}

esp_err_t rna_membrane_erase(void)
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
