#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AMINO_INVALID = 0,
    AMINO_ON = 1,
    AMINO_OFF = 2,
    AMINO_OPEN = 3,
    AMINO_CLOSE = 4,
    AMINO_SET_SPEED = 5,
    AMINO_SET_LEVEL = 6,
    AMINO_READ_STATE = 7,
    AMINO_TOGGLE = 8,
    AMINO_LOCK = 9,
    AMINO_UNLOCK = 10,
    AMINO_SET_TEMPERATURE = 11,
    AMINO_SET_MODE = 12
} amino_acid_id_t;

typedef enum {
    AMINO_VALUE_NONE = 0,
    AMINO_VALUE_BOOL,
    AMINO_VALUE_INT
} amino_value_type_t;

#define AMINO_FLAG_MUTATES_STATE (1u << 0)
#define AMINO_FLAG_READ_ONLY     (1u << 1)

typedef struct {
    amino_acid_id_t id;
    const char *name;
    amino_value_type_t value_type;
    uint32_t flags;
} amino_acid_t;

size_t amino_acids_count(void);
const amino_acid_t *amino_acids_all(size_t *out_count);

const amino_acid_t *amino_acid_find(amino_acid_id_t id);
bool amino_acid_id_valid(amino_acid_id_t id);
bool amino_acid_value_type_valid(amino_value_type_t type);

esp_err_t amino_acid_validate_payload(
    amino_acid_id_t id,
    const int32_t *value
);

esp_err_t amino_acid_validate_value(
    amino_acid_id_t id,
    const int32_t *value
);

#ifdef __cplusplus
}
#endif

