use crate::ffi::ribosome_table::RibosomeTableRaw;
use crate::ffi::EspErr;

unsafe extern "C" {
    pub fn ribosome_store_load(out_table: *mut RibosomeTableRaw) -> EspErr;
    pub fn ribosome_store_load_or_init(out_table: *mut RibosomeTableRaw) -> EspErr;
    pub fn ribosome_store_save(table: *const RibosomeTableRaw) -> EspErr;
    pub fn ribosome_store_erase() -> EspErr;
}
