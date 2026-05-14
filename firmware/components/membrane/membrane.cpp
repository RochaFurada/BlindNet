#include "membrane.hpp"

esp_err_t Membrane::init()
{
    esp_err_t err = ribosome_store_load_or_init(&state_.ribosome_table);
    if (err != ESP_OK) {
        initialized_ = false;
        return err;
    }

    err = rna_membrane_load_or_init(&state_.rna_templates);
    if (err != ESP_OK) {
        initialized_ = false;
        return err;
    }

    initialized_ = true;
    return ESP_OK;
}

esp_err_t Membrane::save() const
{
    if (!initialized_) {
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err = ribosome_store_save(&state_.ribosome_table);
    if (err != ESP_OK) {
        return err;
    }

    return rna_membrane_save(&state_.rna_templates);
}

bool Membrane::has_capability(
    const ribosome_table_entry_t &device,
    amino_acid_id_t amino_id,
    const int32_t *payload
) const
{
    if (!initialized_) {
        return false;
    }
    if (amino_acid_validate_payload(amino_id, payload) != ESP_OK) {
        return false;
    }

    return rna_template_table_has_capability(
        &state_.rna_templates,
        device.template_id,
        amino_id
    );
}

const MembraneState &Membrane::state() const
{
    return state_;
}

MembraneState &Membrane::state()
{
    return state_;
}
