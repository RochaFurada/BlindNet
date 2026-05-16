#include "membrane.hpp"

#include <string.h>

static bool mqtt_client_id_valid(const char *mqtt_client_id)
{
    if (!mqtt_client_id || mqtt_client_id[0] == '\0') {
        return false;
    }

    for (size_t i = 0; i < RIBOSOME_MQTT_CLIENT_ID_LEN; ++i) {
        if (mqtt_client_id[i] == '\0') {
            return true;
        }
    }

    return false;
}

static bool mqtt_client_id_equal(const char *a, const char *b)
{
    return strncmp(a, b, RIBOSOME_MQTT_CLIENT_ID_LEN) == 0;
}

static ribosome_table_entry_t *find_device_slot(
    ribosome_table_t *table,
    const char *mqtt_client_id
)
{
    if (!table || !mqtt_client_id_valid(mqtt_client_id)) {
        return nullptr;
    }

    for (size_t i = 0; i < table->count; ++i) {
        if (mqtt_client_id_equal(
                table->entries[i].mqtt_client_id,
                mqtt_client_id
            )) {
            return &table->entries[i];
        }
    }

    return nullptr;
}

static rna_template_t *find_template_slot(
    rna_template_table_t *table,
    rna_template_id_t template_id
)
{
    if (!table || !rna_template_id_valid(template_id)) {
        return nullptr;
    }

    for (size_t i = 0; i < table->count; ++i) {
        if (table->templates[i].id == template_id) {
            return &table->templates[i];
        }
    }

    return nullptr;
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

bool Membrane::initialized() const
{
    return initialized_;
}

bool Membrane::allows(
    const ribosome_table_entry_t &device,
    amino_acid_id_t amino_id,
    const int32_t *payload
) const
{
    if (!initialized_) {
        return false;
    }
    if (!ribosome_template_id_valid(device.template_id)) {
        return false;
    }
    if (amino_acid_validate_payload(amino_id, payload) != ESP_OK) {
        return false;
    }

    const rna_template_t *template_rule = find_template(device.template_id);
    return rna_template_allows(template_rule, amino_id);
}

esp_err_t Membrane::get_device(
    const char *mqtt_client_id,
    ribosome_table_entry_t *out_device
) const
{
    if (!initialized_) {
        return ESP_ERR_INVALID_STATE;
    }

    return ribosome_table_get_entry(
        &state_.ribosome_table,
        mqtt_client_id,
        out_device
    );
}

esp_err_t Membrane::add_device(const ribosome_entry_config_t &config)
{
    if (!initialized_) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!find_template(config.template_id)) {
        return ESP_ERR_NOT_FOUND;
    }

    return ribosome_table_add_from_config(&state_.ribosome_table, &config);
}

esp_err_t Membrane::remove_device(const char *mqtt_client_id)
{
    if (!initialized_) {
        return ESP_ERR_INVALID_STATE;
    }

    return ribosome_table_remove_entry(&state_.ribosome_table, mqtt_client_id);
}

esp_err_t Membrane::assign_template(
    const char *mqtt_client_id,
    rna_template_id_t template_id
)
{
    if (!initialized_) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!find_template(template_id)) {
        return ESP_ERR_NOT_FOUND;
    }

    ribosome_table_entry_t *slot = find_device_slot(
        &state_.ribosome_table,
        mqtt_client_id
    );
    if (!slot) {
        return mqtt_client_id_valid(mqtt_client_id)
            ? ESP_ERR_NOT_FOUND
            : ESP_ERR_INVALID_ARG;
    }

    slot->template_id = template_id;
    return ESP_OK;
}

const rna_template_t *Membrane::find_template(
    rna_template_id_t template_id
) const
{
    if (!initialized_) {
        return nullptr;
    }

    return rna_template_table_find(&state_.rna_templates, template_id);
}

bool Membrane::template_in_use(rna_template_id_t template_id) const
{
    if (!initialized_ || !rna_template_id_valid(template_id)) {
        return false;
    }

    for (size_t i = 0; i < state_.ribosome_table.count; ++i) {
        if (state_.ribosome_table.entries[i].template_id == template_id) {
            return true;
        }
    }

    return false;
}

esp_err_t Membrane::add_template(const rna_template_t &template_rule)
{
    if (!initialized_) {
        return ESP_ERR_INVALID_STATE;
    }

    return rna_template_table_add(&state_.rna_templates, &template_rule);
}

esp_err_t Membrane::replace_template(const rna_template_t &template_rule)
{
    if (!initialized_) {
        return ESP_ERR_INVALID_STATE;
    }
    if (rna_template_validate(&template_rule) != ESP_OK) {
        return ESP_ERR_INVALID_ARG;
    }

    rna_template_t *slot = find_template_slot(
        &state_.rna_templates,
        template_rule.id
    );
    if (!slot) {
        return ESP_ERR_NOT_FOUND;
    }

    copy_template_sanitized(slot, &template_rule);
    return ESP_OK;
}

esp_err_t Membrane::remove_template(rna_template_id_t template_id)
{
    if (!initialized_) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!rna_template_id_valid(template_id)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (template_in_use(template_id)) {
        return ESP_ERR_INVALID_STATE;
    }

    for (size_t i = 0; i < state_.rna_templates.count; ++i) {
        if (state_.rna_templates.templates[i].id != template_id) {
            continue;
        }

        for (size_t j = i; j + 1 < state_.rna_templates.count; ++j) {
            copy_template_sanitized(
                &state_.rna_templates.templates[j],
                &state_.rna_templates.templates[j + 1]
            );
        }

        state_.rna_templates.count--;
        rna_template_clear(
            &state_.rna_templates.templates[state_.rna_templates.count]
        );
        return ESP_OK;
    }

    return ESP_ERR_NOT_FOUND;
}

const MembraneState &Membrane::state() const
{
    return state_;
}
