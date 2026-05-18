use core::ffi::c_char;

use crate::ffi::amino_acids::AminoAcidId;
use crate::ffi::EspErr;

pub const RNA_TEMPLATE_NAME_LEN: usize = 32;
pub const RNA_TEMPLATE_MAX_AMINOS: usize = 12;
pub const RNA_MAX_TEMPLATES: usize = 16;

pub type RnaTemplateId = u16;

pub const RNA_TEMPLATE_ID_INVALID: RnaTemplateId = 0;
pub const RNA_TEMPLATE_ID_LIGHT_SWITCH: RnaTemplateId = 1;
pub const RNA_TEMPLATE_ID_OUTLET: RnaTemplateId = 2;
pub const RNA_TEMPLATE_ID_DOOR: RnaTemplateId = 3;
pub const RNA_TEMPLATE_ID_AIR_CONDITIONER: RnaTemplateId = 4;
pub const RNA_TEMPLATE_ID_DIMMER: RnaTemplateId = 5;
pub const RNA_TEMPLATE_ID_FAN: RnaTemplateId = 6;
pub const RNA_TEMPLATE_ID_SENSOR_READONLY: RnaTemplateId = 7;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RnaTemplateRaw {
    pub id: RnaTemplateId,
    pub name: [c_char; RNA_TEMPLATE_NAME_LEN],
    pub amino_count: u8,
    pub aminos: [AminoAcidId; RNA_TEMPLATE_MAX_AMINOS],
    pub flags: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RnaTemplateTableRaw {
    pub templates: [RnaTemplateRaw; RNA_MAX_TEMPLATES],
    pub count: usize,
}

unsafe extern "C" {
    pub fn rna_template_clear(template_rule: *mut RnaTemplateRaw);
    pub fn rna_template_id_valid(template_id: RnaTemplateId) -> bool;
    pub fn rna_template_validate(template_rule: *const RnaTemplateRaw) -> EspErr;
    pub fn rna_template_table_init(table: *mut RnaTemplateTableRaw) -> EspErr;
    pub fn rna_template_table_add(
        table: *mut RnaTemplateTableRaw,
        template_rule: *const RnaTemplateRaw,
    ) -> EspErr;
    pub fn rna_template_table_find(
        table: *const RnaTemplateTableRaw,
        template_id: RnaTemplateId,
    ) -> *const RnaTemplateRaw;
    pub fn rna_template_allows(template_rule: *const RnaTemplateRaw, amino_id: AminoAcidId)
        -> bool;
    pub fn rna_template_has_capability(
        template_rule: *const RnaTemplateRaw,
        amino_id: AminoAcidId,
    ) -> bool;
    pub fn rna_template_table_allows(
        table: *const RnaTemplateTableRaw,
        template_id: RnaTemplateId,
        amino_id: AminoAcidId,
    ) -> bool;
    pub fn rna_template_table_has_capability(
        table: *const RnaTemplateTableRaw,
        template_id: RnaTemplateId,
        amino_id: AminoAcidId,
    ) -> bool;
    pub fn rna_membrane_defaults(out_count: *mut usize) -> *const RnaTemplateRaw;
    pub fn rna_membrane_load_defaults(out_table: *mut RnaTemplateTableRaw) -> EspErr;
    pub fn rna_membrane_load(out_table: *mut RnaTemplateTableRaw) -> EspErr;
    pub fn rna_membrane_load_or_init(out_table: *mut RnaTemplateTableRaw) -> EspErr;
    pub fn rna_membrane_save(table: *const RnaTemplateTableRaw) -> EspErr;
    pub fn rna_membrane_erase() -> EspErr;
}
