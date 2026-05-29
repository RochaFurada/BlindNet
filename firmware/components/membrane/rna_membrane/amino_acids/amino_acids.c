#include "amino_acids.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static const amino_acid_t AMINO_ACIDS[] = {
    {
        .id = AMINO_ON,
        .name = "ON",
        .value_type = AMINO_VALUE_NONE,
        .flags = AMINO_FLAG_MUTATES_STATE,
    },
    {
        .id = AMINO_OFF,
        .name = "OFF",
        .value_type = AMINO_VALUE_NONE,
        .flags = AMINO_FLAG_MUTATES_STATE,
    },
    {
        .id = AMINO_OPEN,
        .name = "OPEN",
        .value_type = AMINO_VALUE_NONE,
        .flags = AMINO_FLAG_MUTATES_STATE,
    },
    {
        .id = AMINO_CLOSE,
        .name = "CLOSE",
        .value_type = AMINO_VALUE_NONE,
        .flags = AMINO_FLAG_MUTATES_STATE,
    },
    {
        .id = AMINO_SET_SPEED,
        .name = "SET_SPEED",
        .value_type = AMINO_VALUE_INT,
        .flags = AMINO_FLAG_MUTATES_STATE,
    },
    {
        .id = AMINO_SET_LEVEL,
        .name = "SET_LEVEL",
        .value_type = AMINO_VALUE_INT,
        .flags = AMINO_FLAG_MUTATES_STATE,
    },
    {
        .id = AMINO_READ_STATE,
        .name = "READ_STATE",
        .value_type = AMINO_VALUE_NONE,
        .flags = AMINO_FLAG_READ_ONLY,
    },
    {
        .id = AMINO_TOGGLE,
        .name = "TOGGLE",
        .value_type = AMINO_VALUE_NONE,
        .flags = AMINO_FLAG_MUTATES_STATE,
    },
    {
        .id = AMINO_LOCK,
        .name = "LOCK",
        .value_type = AMINO_VALUE_NONE,
        .flags = AMINO_FLAG_MUTATES_STATE,
    },
    {
        .id = AMINO_UNLOCK,
        .name = "UNLOCK",
        .value_type = AMINO_VALUE_NONE,
        .flags = AMINO_FLAG_MUTATES_STATE,
    },
    {
        .id = AMINO_SET_TEMPERATURE,
        .name = "SET_TEMPERATURE",
        .value_type = AMINO_VALUE_INT,
        .flags = AMINO_FLAG_MUTATES_STATE,
    },
    {
        .id = AMINO_SET_MODE,
        .name = "SET_MODE",
        .value_type = AMINO_VALUE_INT,
        .flags = AMINO_FLAG_MUTATES_STATE,
    },
};

size_t amino_acids_count(void)
{
    return ARRAY_SIZE(AMINO_ACIDS);
}

const amino_acid_t *amino_acids_all(size_t *out_count)
{
    if (out_count) {
        *out_count = amino_acids_count();
    }

    return AMINO_ACIDS;
}

bool amino_acid_value_type_valid(amino_value_type_t type)
{
    switch (type) {
        case AMINO_VALUE_NONE:
        case AMINO_VALUE_BOOL:
        case AMINO_VALUE_INT:
            return true;
        default:
            return false;
    }
}

const amino_acid_t *amino_acid_find(amino_acid_id_t id)
{
    for (size_t i = 0; i < amino_acids_count(); ++i) {
        if (AMINO_ACIDS[i].id == id) {
            return &AMINO_ACIDS[i];
        }
    }

    return NULL;
}

bool amino_acid_id_valid(amino_acid_id_t id)
{
    return amino_acid_find(id) != NULL;
}

esp_err_t amino_acid_validate_payload(
    amino_acid_id_t id,
    const int32_t *value
)
{
    const amino_acid_t *acid = amino_acid_find(id);
    if (!acid) {
        return ESP_ERR_NOT_FOUND;
    }

    if (acid->value_type == AMINO_VALUE_NONE) {
        return value ? ESP_ERR_INVALID_ARG : ESP_OK;
    }

    if (!value) {
        return ESP_ERR_INVALID_ARG;
    }

    if (acid->value_type == AMINO_VALUE_BOOL &&
        *value != 0 &&
        *value != 1) {
        return ESP_ERR_INVALID_ARG;
    }

    return ESP_OK;
}

esp_err_t amino_acid_validate_value(
    amino_acid_id_t id,
    const int32_t *value
)
{
    return amino_acid_validate_payload(id, value);
}
