use crate::ffi::ribosome_store;
use crate::ffi::ribosome_table::RibosomeTableRaw;
use crate::platform::{esp_result, Result};

pub fn load(out_table: &mut RibosomeTableRaw) -> Result {
    esp_result(unsafe { ribosome_store::ribosome_store_load(out_table) })
}

pub fn load_or_init(out_table: &mut RibosomeTableRaw) -> Result {
    esp_result(unsafe { ribosome_store::ribosome_store_load_or_init(out_table) })
}

pub fn save(table: &RibosomeTableRaw) -> Result {
    esp_result(unsafe { ribosome_store::ribosome_store_save(table) })
}

pub fn erase() -> Result {
    esp_result(unsafe { ribosome_store::ribosome_store_erase() })
}
