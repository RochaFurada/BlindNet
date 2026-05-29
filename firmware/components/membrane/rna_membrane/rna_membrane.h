#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "amino_acids.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RNA_TEMPLATE_NAME_LEN 32
#define RNA_TEMPLATE_MAX_AMINOS 12
#define RNA_MAX_TEMPLATES 16

typedef uint16_t rna_template_id_t;

#define RNA_TEMPLATE_ID_INVALID         0u
#define RNA_TEMPLATE_ID_LIGHT_SWITCH    1u
#define RNA_TEMPLATE_ID_OUTLET          2u
#define RNA_TEMPLATE_ID_DOOR            3u
#define RNA_TEMPLATE_ID_AIR_CONDITIONER 4u
#define RNA_TEMPLATE_ID_DIMMER          5u
#define RNA_TEMPLATE_ID_FAN             6u
#define RNA_TEMPLATE_ID_SENSOR_READONLY 7u

typedef struct {
    rna_template_id_t id;
    char name[RNA_TEMPLATE_NAME_LEN];
    uint8_t amino_count;
    amino_acid_id_t aminos[RNA_TEMPLATE_MAX_AMINOS];
    uint32_t flags;
} rna_template_t;

typedef struct {
    rna_template_t templates[RNA_MAX_TEMPLATES];
    size_t count;
} rna_template_table_t;

void rna_template_clear(rna_template_t *template_rule);
bool rna_template_id_valid(rna_template_id_t template_id);
esp_err_t rna_template_validate(const rna_template_t *template_rule);

esp_err_t rna_template_table_init(rna_template_table_t *table);
esp_err_t rna_template_table_add(
    rna_template_table_t *table,
    const rna_template_t *template_rule
);

const rna_template_t *rna_template_table_find(
    const rna_template_table_t *table,
    rna_template_id_t template_id
);

bool rna_template_allows(
    const rna_template_t *template_rule,
    amino_acid_id_t amino_id
);

bool rna_template_has_capability(
    const rna_template_t *template_rule,
    amino_acid_id_t amino_id
);

bool rna_template_table_allows(
    const rna_template_table_t *table,
    rna_template_id_t template_id,
    amino_acid_id_t amino_id
);

bool rna_template_table_has_capability(
    const rna_template_table_t *table,
    rna_template_id_t template_id,
    amino_acid_id_t amino_id
);

const rna_template_t *rna_membrane_defaults(size_t *out_count);
esp_err_t rna_membrane_load_defaults(rna_template_table_t *out_table);

esp_err_t rna_membrane_load(rna_template_table_t *out_table);
esp_err_t rna_membrane_load_or_init(rna_template_table_t *out_table);
esp_err_t rna_membrane_save(const rna_template_table_t *table);
esp_err_t rna_membrane_erase(void);

#ifdef __cplusplus
}
#endif
