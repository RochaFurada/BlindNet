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

    bool initialized() const;

    bool allows(
        const ribosome_table_entry_t &device,
        amino_acid_id_t amino_id,
        const int32_t *payload
    ) const;

    esp_err_t get_device(
        const char *mqtt_client_id,
        ribosome_table_entry_t *out_device
    ) const;

    esp_err_t add_device(const ribosome_entry_config_t &config);
    esp_err_t remove_device(const char *mqtt_client_id);

    esp_err_t assign_template(
        const char *mqtt_client_id,
        rna_template_id_t template_id
    );

    const rna_template_t *find_template(rna_template_id_t template_id) const;
    bool template_in_use(rna_template_id_t template_id) const;

    esp_err_t add_template(const rna_template_t &template_rule);
    esp_err_t replace_template(const rna_template_t &template_rule);
    esp_err_t remove_template(rna_template_id_t template_id);

    const MembraneState &state() const;

private:
    MembraneState state_{};
    bool initialized_ = false;
};
