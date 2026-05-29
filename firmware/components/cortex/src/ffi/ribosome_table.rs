use core::ffi::c_char;

use crate::ffi::rna_membrane::RnaTemplateId;
use crate::ffi::EspErr;

pub const RIBOSOME_MQTT_CLIENT_ID_LEN: usize = 33;
pub const RIBOSOME_DEVICE_SECRET_LEN: usize = 32;
pub const RIBOSOME_MAX_ENTRIES: usize = 20;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RibosomeTableEntryRaw {
    pub mqtt_client_id: [c_char; RIBOSOME_MQTT_CLIENT_ID_LEN],
    pub template_id: RnaTemplateId,
    pub epoch: u32,
    pub device_secret: [u8; RIBOSOME_DEVICE_SECRET_LEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RibosomeTableRaw {
    pub entries: [RibosomeTableEntryRaw; RIBOSOME_MAX_ENTRIES],
    pub count: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RibosomeEntryConfigRaw {
    pub mqtt_client_id: *const c_char,
    pub template_id: RnaTemplateId,
    pub epoch: u32,
    pub device_secret: *const u8,
}

unsafe extern "C" {
    pub fn ribosome_table_init(table: *mut RibosomeTableRaw) -> EspErr;
    pub fn ribosome_table_clear_entry(entry: *mut RibosomeTableEntryRaw);
    pub fn ribosome_table_make_entry(
        config: *const RibosomeEntryConfigRaw,
        out_entry: *mut RibosomeTableEntryRaw,
    ) -> EspErr;
    pub fn ribosome_table_add_entry(
        table: *mut RibosomeTableRaw,
        entry: *const RibosomeTableEntryRaw,
    ) -> EspErr;
    pub fn ribosome_table_add_from_config(
        table: *mut RibosomeTableRaw,
        config: *const RibosomeEntryConfigRaw,
    ) -> EspErr;
    pub fn ribosome_table_remove_entry(
        table: *mut RibosomeTableRaw,
        mqtt_client_id: *const c_char,
    ) -> EspErr;
    pub fn ribosome_table_get_entry(
        table: *const RibosomeTableRaw,
        mqtt_client_id: *const c_char,
        out_entry: *mut RibosomeTableEntryRaw,
    ) -> EspErr;
    pub fn ribosome_table_entry_exists(
        table: *const RibosomeTableRaw,
        mqtt_client_id: *const c_char,
    ) -> bool;
    pub fn ribosome_table_count(table: *const RibosomeTableRaw) -> usize;
    pub fn ribosome_template_id_valid(template_id: RnaTemplateId) -> bool;
}
