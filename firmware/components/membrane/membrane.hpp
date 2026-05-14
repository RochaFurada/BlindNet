#pragma once

#include "esp_err.h"

#include "amino_acids.h"
#include "ribosome_store.h"
#include "ribosome_table.h"
#include "rna_membrane.h"

struct MembraneState final {
    ribosome_table_t ribosome_table;
    rna_template_table_t rna_templates;
};

class Membrane final {
public:
    esp_err_t init();
    esp_err_t save() const;

    bool has_capability(
        const ribosome_table_entry_t &device,
        amino_acid_id_t amino_id,
        const int32_t *payload
    ) const;

    const MembraneState &state() const;
    MembraneState &state();

private:
    MembraneState state_{};
    bool initialized_ = false;
};
