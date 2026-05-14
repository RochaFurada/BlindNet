#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#include "rna_membrane.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RIBOSOME_MQTT_CLIENT_ID_LEN 33
#define RIBOSOME_DEVICE_SECRET_LEN 32
#define RIBOSOME_MAX_ENTRIES 20

typedef struct {
    char mqtt_client_id[RIBOSOME_MQTT_CLIENT_ID_LEN];
    rna_template_id_t template_id;
    uint32_t epoch;
    uint8_t device_secret[RIBOSOME_DEVICE_SECRET_LEN];
} ribosome_table_entry_t;

typedef struct {
    ribosome_table_entry_t entries[RIBOSOME_MAX_ENTRIES];
    size_t count;
} ribosome_table_t;

typedef struct {
    const char *mqtt_client_id;
    rna_template_id_t template_id;
    uint32_t epoch;
    const uint8_t *device_secret;
} ribosome_entry_config_t;

esp_err_t ribosome_table_init(ribosome_table_t *table);
void ribosome_table_clear_entry(ribosome_table_entry_t *entry);

esp_err_t ribosome_table_make_entry(
    const ribosome_entry_config_t *config,
    ribosome_table_entry_t *out_entry
);

esp_err_t ribosome_table_add_entry(
    ribosome_table_t *table,
    const ribosome_table_entry_t *entry
);

esp_err_t ribosome_table_add_from_config(
    ribosome_table_t *table,
    const ribosome_entry_config_t *config
);

esp_err_t ribosome_table_remove_entry(
    ribosome_table_t *table,
    const char *mqtt_client_id
);

esp_err_t ribosome_table_get_entry(
    const ribosome_table_t *table,
    const char *mqtt_client_id,
    ribosome_table_entry_t *out_entry
);

bool ribosome_table_entry_exists(
    const ribosome_table_t *table,
    const char *mqtt_client_id
);

size_t ribosome_table_count(const ribosome_table_t *table);
bool ribosome_template_id_valid(rna_template_id_t template_id);

#ifdef __cplusplus
}
#endif
