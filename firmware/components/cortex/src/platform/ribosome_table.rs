use core::ffi::c_char;

use crate::ffi::ribosome_table;
use crate::ffi::rna_membrane::RnaTemplateId;
use crate::platform::{esp_result, Result};

pub use crate::ffi::ribosome_table::{
    RibosomeEntryConfigRaw, RibosomeTableEntryRaw, RibosomeTableRaw, RIBOSOME_DEVICE_SECRET_LEN,
    RIBOSOME_MAX_ENTRIES, RIBOSOME_MQTT_CLIENT_ID_LEN,
};

pub fn init(table: &mut RibosomeTableRaw) -> Result {
    esp_result(unsafe { ribosome_table::ribosome_table_init(table) })
}

pub fn clear_entry(entry: &mut RibosomeTableEntryRaw) {
    unsafe { ribosome_table::ribosome_table_clear_entry(entry) }
}

pub fn make_entry(
    config: &RibosomeEntryConfigRaw,
    out_entry: &mut RibosomeTableEntryRaw,
) -> Result {
    esp_result(unsafe { ribosome_table::ribosome_table_make_entry(config, out_entry) })
}

pub fn add_entry(table: &mut RibosomeTableRaw, entry: &RibosomeTableEntryRaw) -> Result {
    esp_result(unsafe { ribosome_table::ribosome_table_add_entry(table, entry) })
}

pub fn add_from_config(table: &mut RibosomeTableRaw, config: &RibosomeEntryConfigRaw) -> Result {
    esp_result(unsafe { ribosome_table::ribosome_table_add_from_config(table, config) })
}

pub fn remove_entry(table: &mut RibosomeTableRaw, mqtt_client_id: *const c_char) -> Result {
    esp_result(unsafe { ribosome_table::ribosome_table_remove_entry(table, mqtt_client_id) })
}

pub fn get_entry(
    table: &RibosomeTableRaw,
    mqtt_client_id: *const c_char,
    out_entry: &mut RibosomeTableEntryRaw,
) -> Result {
    esp_result(unsafe {
        ribosome_table::ribosome_table_get_entry(table, mqtt_client_id, out_entry)
    })
}

pub fn entry_exists(table: &RibosomeTableRaw, mqtt_client_id: *const c_char) -> bool {
    unsafe { ribosome_table::ribosome_table_entry_exists(table, mqtt_client_id) }
}

pub fn count(table: &RibosomeTableRaw) -> usize {
    unsafe { ribosome_table::ribosome_table_count(table) }
}

pub fn template_id_valid(template_id: RnaTemplateId) -> bool {
    unsafe { ribosome_table::ribosome_template_id_valid(template_id) }
}
