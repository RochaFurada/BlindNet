use core::ffi::c_char;

use crate::ffi::EspErr;

pub type AminoAcidId = i32;
pub const AMINO_INVALID: AminoAcidId = 0;
pub const AMINO_ON: AminoAcidId = 1;
pub const AMINO_OFF: AminoAcidId = 2;
pub const AMINO_OPEN: AminoAcidId = 3;
pub const AMINO_CLOSE: AminoAcidId = 4;
pub const AMINO_SET_SPEED: AminoAcidId = 5;
pub const AMINO_SET_LEVEL: AminoAcidId = 6;
pub const AMINO_READ_STATE: AminoAcidId = 7;
pub const AMINO_TOGGLE: AminoAcidId = 8;
pub const AMINO_LOCK: AminoAcidId = 9;
pub const AMINO_UNLOCK: AminoAcidId = 10;
pub const AMINO_SET_TEMPERATURE: AminoAcidId = 11;
pub const AMINO_SET_MODE: AminoAcidId = 12;

pub type AminoValueType = i32;
pub const AMINO_VALUE_NONE: AminoValueType = 0;
pub const AMINO_VALUE_BOOL: AminoValueType = 1;
pub const AMINO_VALUE_INT: AminoValueType = 2;

pub const AMINO_FLAG_MUTATES_STATE: u32 = 1 << 0;
pub const AMINO_FLAG_READ_ONLY: u32 = 1 << 1;

#[repr(C)]
pub struct AminoAcidRaw {
    pub id: AminoAcidId,
    pub name: *const c_char,
    pub value_type: AminoValueType,
    pub flags: u32,
}

unsafe extern "C" {
    pub fn amino_acids_count() -> usize;
    pub fn amino_acids_all(out_count: *mut usize) -> *const AminoAcidRaw;
    pub fn amino_acid_find(id: AminoAcidId) -> *const AminoAcidRaw;
    pub fn amino_acid_id_valid(id: AminoAcidId) -> bool;
    pub fn amino_acid_value_type_valid(value_type: AminoValueType) -> bool;
    pub fn amino_acid_validate_payload(id: AminoAcidId, value: *const i32) -> EspErr;
    pub fn amino_acid_validate_value(id: AminoAcidId, value: *const i32) -> EspErr;
}
