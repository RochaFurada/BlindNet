use crate::ffi::amino_acids;
use crate::platform::{esp_result, Result};

pub use crate::ffi::amino_acids::{
    AminoAcidId, AminoAcidRaw, AminoValueType, AMINO_CLOSE, AMINO_FLAG_MUTATES_STATE,
    AMINO_FLAG_READ_ONLY, AMINO_INVALID, AMINO_LOCK, AMINO_OFF, AMINO_ON, AMINO_OPEN,
    AMINO_READ_STATE, AMINO_SET_LEVEL, AMINO_SET_MODE, AMINO_SET_SPEED, AMINO_SET_TEMPERATURE,
    AMINO_TOGGLE, AMINO_UNLOCK, AMINO_VALUE_BOOL, AMINO_VALUE_INT, AMINO_VALUE_NONE,
};

pub fn count() -> usize {
    unsafe { amino_acids::amino_acids_count() }
}

pub fn all() -> (*const AminoAcidRaw, usize) {
    let mut count = 0;
    let acids = unsafe { amino_acids::amino_acids_all(&mut count) };
    (acids, count)
}

pub fn find(id: AminoAcidId) -> Option<*const AminoAcidRaw> {
    let acid = unsafe { amino_acids::amino_acid_find(id) };
    if acid.is_null() {
        None
    } else {
        Some(acid)
    }
}

pub fn id_valid(id: AminoAcidId) -> bool {
    unsafe { amino_acids::amino_acid_id_valid(id) }
}

pub fn value_type_valid(value_type: AminoValueType) -> bool {
    unsafe { amino_acids::amino_acid_value_type_valid(value_type) }
}

pub fn validate_payload(id: AminoAcidId, value: Option<&i32>) -> Result {
    let value = value.map_or(core::ptr::null(), |value| value as *const i32);
    esp_result(unsafe { amino_acids::amino_acid_validate_payload(id, value) })
}

pub fn validate_value(id: AminoAcidId, value: Option<&i32>) -> Result {
    let value = value.map_or(core::ptr::null(), |value| value as *const i32);
    esp_result(unsafe { amino_acids::amino_acid_validate_value(id, value) })
}

pub fn value_none() -> AminoValueType {
    AMINO_VALUE_NONE
}

pub fn value_bool() -> AminoValueType {
    AMINO_VALUE_BOOL
}

pub fn value_int() -> AminoValueType {
    AMINO_VALUE_INT
}
