use crate::ffi::rna_membrane;
use crate::platform::amino_acids::AminoAcidId;
use crate::platform::{esp_result, Result};

pub use crate::ffi::rna_membrane::{
    RnaTemplateId, RnaTemplateRaw, RnaTemplateTableRaw, RNA_MAX_TEMPLATES,
    RNA_TEMPLATE_ID_AIR_CONDITIONER, RNA_TEMPLATE_ID_DIMMER, RNA_TEMPLATE_ID_DOOR,
    RNA_TEMPLATE_ID_FAN, RNA_TEMPLATE_ID_INVALID, RNA_TEMPLATE_ID_LIGHT_SWITCH,
    RNA_TEMPLATE_ID_OUTLET, RNA_TEMPLATE_ID_SENSOR_READONLY, RNA_TEMPLATE_MAX_AMINOS,
    RNA_TEMPLATE_NAME_LEN,
};

pub fn clear(template: &mut RnaTemplateRaw) {
    unsafe { rna_membrane::rna_template_clear(template) }
}

pub fn id_valid(template_id: RnaTemplateId) -> bool {
    unsafe { rna_membrane::rna_template_id_valid(template_id) }
}

pub fn validate(template: &RnaTemplateRaw) -> Result {
    esp_result(unsafe { rna_membrane::rna_template_validate(template) })
}

pub fn table_init(table: &mut RnaTemplateTableRaw) -> Result {
    esp_result(unsafe { rna_membrane::rna_template_table_init(table) })
}

pub fn table_add(table: &mut RnaTemplateTableRaw, template: &RnaTemplateRaw) -> Result {
    esp_result(unsafe { rna_membrane::rna_template_table_add(table, template) })
}

pub fn table_find(
    table: &RnaTemplateTableRaw,
    template_id: RnaTemplateId,
) -> Option<*const RnaTemplateRaw> {
    let template = unsafe { rna_membrane::rna_template_table_find(table, template_id) };
    if template.is_null() {
        None
    } else {
        Some(template)
    }
}

pub fn allows(template: &RnaTemplateRaw, amino_id: AminoAcidId) -> bool {
    unsafe { rna_membrane::rna_template_allows(template, amino_id) }
}

pub fn has_capability(template: &RnaTemplateRaw, amino_id: AminoAcidId) -> bool {
    unsafe { rna_membrane::rna_template_has_capability(template, amino_id) }
}

pub fn table_allows(
    table: &RnaTemplateTableRaw,
    template_id: RnaTemplateId,
    amino_id: AminoAcidId,
) -> bool {
    unsafe { rna_membrane::rna_template_table_allows(table, template_id, amino_id) }
}

pub fn table_has_capability(
    table: &RnaTemplateTableRaw,
    template_id: RnaTemplateId,
    amino_id: AminoAcidId,
) -> bool {
    unsafe { rna_membrane::rna_template_table_has_capability(table, template_id, amino_id) }
}

pub fn defaults() -> (*const RnaTemplateRaw, usize) {
    let mut count = 0;
    let templates = unsafe { rna_membrane::rna_membrane_defaults(&mut count) };
    (templates, count)
}

pub fn load_defaults(out_table: &mut RnaTemplateTableRaw) -> Result {
    esp_result(unsafe { rna_membrane::rna_membrane_load_defaults(out_table) })
}

pub fn load(out_table: &mut RnaTemplateTableRaw) -> Result {
    esp_result(unsafe { rna_membrane::rna_membrane_load(out_table) })
}

pub fn load_or_init(out_table: &mut RnaTemplateTableRaw) -> Result {
    esp_result(unsafe { rna_membrane::rna_membrane_load_or_init(out_table) })
}

pub fn save(table: &RnaTemplateTableRaw) -> Result {
    esp_result(unsafe { rna_membrane::rna_membrane_save(table) })
}

pub fn erase() -> Result {
    esp_result(unsafe { rna_membrane::rna_membrane_erase() })
}

pub fn template_invalid() -> RnaTemplateId {
    RNA_TEMPLATE_ID_INVALID
}

pub fn template_light_switch() -> RnaTemplateId {
    RNA_TEMPLATE_ID_LIGHT_SWITCH
}

pub fn template_outlet() -> RnaTemplateId {
    RNA_TEMPLATE_ID_OUTLET
}

pub fn template_door() -> RnaTemplateId {
    RNA_TEMPLATE_ID_DOOR
}

pub fn template_air_conditioner() -> RnaTemplateId {
    RNA_TEMPLATE_ID_AIR_CONDITIONER
}

pub fn template_dimmer() -> RnaTemplateId {
    RNA_TEMPLATE_ID_DIMMER
}

pub fn template_sensor_readonly() -> RnaTemplateId {
    RNA_TEMPLATE_ID_SENSOR_READONLY
}
