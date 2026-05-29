#pragma once

#include "esp_err.h"
#include "ribosome_table.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t ribosome_store_load(ribosome_table_t *out_table);
esp_err_t ribosome_store_load_or_init(ribosome_table_t *out_table);
esp_err_t ribosome_store_save(const ribosome_table_t *table);
esp_err_t ribosome_store_erase(void);

#ifdef __cplusplus
}
#endif
