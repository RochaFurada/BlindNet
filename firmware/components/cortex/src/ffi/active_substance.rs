use core::ffi::{c_char, c_void};

use crate::ffi::amino_acids::AminoAcidId;
use crate::ffi::EspErr;

pub const ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN: usize = 256;
pub const ACTIVE_SUBSTANCE_VERSION: u8 = 2;
pub const ACTIVE_SUBSTANCE_HASH_LEN: usize = 32;
pub const ACTIVE_SUBSTANCE_NONCE_LEN: usize = 12;
pub const ACTIVE_SUBSTANCE_TAG_LEN: usize = 16;
pub const ACTIVE_SUBSTANCE_DEVICE_ID_LEN: usize = 32;
pub const ACTIVE_SUBSTANCE_TOPIC_LEN: usize = 32;
pub const ACTIVE_SUBSTANCE_COMMAND_RESERVED_LEN: usize = 3;

pub type ActiveSubstanceCipher = i32;
pub const ACTIVE_SUBSTANCE_CIPHER_UNKNOWN: ActiveSubstanceCipher = 0;
pub const ACTIVE_SUBSTANCE_CIPHER_AES_128_GCM: ActiveSubstanceCipher = 1;
pub const ACTIVE_SUBSTANCE_CIPHER_AES_256_GCM: ActiveSubstanceCipher = 2;
pub const ACTIVE_SUBSTANCE_CIPHER_CHACHA20_POLY1305: ActiveSubstanceCipher = 3;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ActiveSubstanceCommandRaw {
    pub device_id: [c_char; ACTIVE_SUBSTANCE_DEVICE_ID_LEN],
    pub topic: [c_char; ACTIVE_SUBSTANCE_TOPIC_LEN],
    pub amino_id: AminoAcidId,
    pub payload_type: u8,
    pub reserved: [u8; ACTIVE_SUBSTANCE_COMMAND_RESERVED_LEN],
    pub payload_i32: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ActiveSubstanceRaw {
    pub version: u8,
    pub cipher: u8,
    pub ciphertext_len: u16,
    pub nonce: [u8; ACTIVE_SUBSTANCE_NONCE_LEN],
    pub tag: [u8; ACTIVE_SUBSTANCE_TAG_LEN],
    pub ciphertext: [u8; ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN],
}

unsafe extern "C" {
    pub fn active_substance_command_clear(command: *mut ActiveSubstanceCommandRaw);
    pub fn active_substance_command_validate(command: *const ActiveSubstanceCommandRaw) -> EspErr;
    pub fn active_substance_parse_command(
        plaintext: *const c_void,
        plaintext_len: usize,
        out_command: *mut ActiveSubstanceCommandRaw,
    ) -> EspErr;
    pub fn active_substance_init(substance: *mut ActiveSubstanceRaw);
    pub fn active_substance_set_ciphertext(
        substance: *mut ActiveSubstanceRaw,
        cipher: ActiveSubstanceCipher,
        nonce: *const u8,
        tag: *const u8,
        ciphertext: *const c_void,
        ciphertext_len: usize,
    ) -> EspErr;
    pub fn active_substance_validate_envelope(substance: *const ActiveSubstanceRaw) -> EspErr;
    pub fn active_substance_validate(substance: *const ActiveSubstanceRaw) -> EspErr;
    pub fn active_substance_hash(substance: *const ActiveSubstanceRaw, out_hash: *mut u8)
        -> EspErr;
    pub fn active_substance_cipher_to_string(cipher: ActiveSubstanceCipher) -> *const c_char;
}
