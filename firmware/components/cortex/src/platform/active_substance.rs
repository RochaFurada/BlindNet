use core::ffi::{c_char, c_void};

use crate::ffi::active_substance;
use crate::platform::{esp_result, Result};

pub use crate::ffi::active_substance::{
    ActiveSubstanceCipher, ActiveSubstanceRaw, ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN,
    ACTIVE_SUBSTANCE_CIPHER_AES_128_GCM, ACTIVE_SUBSTANCE_CIPHER_AES_256_GCM,
    ACTIVE_SUBSTANCE_CIPHER_CHACHA20_POLY1305, ACTIVE_SUBSTANCE_CIPHER_UNKNOWN,
    ACTIVE_SUBSTANCE_HASH_LEN, ACTIVE_SUBSTANCE_NONCE_LEN, ACTIVE_SUBSTANCE_TAG_LEN,
    ACTIVE_SUBSTANCE_VERSION,
};

pub fn init(substance: &mut ActiveSubstanceRaw) {
    unsafe { active_substance::active_substance_init(substance) };
}

pub fn set_ciphertext(
    substance: &mut ActiveSubstanceRaw,
    cipher: ActiveSubstanceCipher,
    nonce: &[u8; ACTIVE_SUBSTANCE_NONCE_LEN],
    tag: &[u8; ACTIVE_SUBSTANCE_TAG_LEN],
    ciphertext: &[u8],
) -> Result {
    esp_result(unsafe {
        active_substance::active_substance_set_ciphertext(
            substance,
            cipher,
            nonce.as_ptr(),
            tag.as_ptr(),
            ciphertext.as_ptr().cast::<c_void>(),
            ciphertext.len(),
        )
    })
}

pub fn validate_envelope(substance: &ActiveSubstanceRaw) -> Result {
    esp_result(unsafe { active_substance::active_substance_validate_envelope(substance) })
}

pub fn validate(substance: &ActiveSubstanceRaw) -> Result {
    esp_result(unsafe { active_substance::active_substance_validate(substance) })
}

pub fn hash(substance: &ActiveSubstanceRaw) -> Result<[u8; ACTIVE_SUBSTANCE_HASH_LEN]> {
    let mut out_hash = [0u8; ACTIVE_SUBSTANCE_HASH_LEN];
    let err = unsafe { active_substance::active_substance_hash(substance, out_hash.as_mut_ptr()) };
    if err == crate::ffi::ESP_OK {
        Ok(out_hash)
    } else {
        Err(err)
    }
}

pub fn cipher_to_string(cipher: ActiveSubstanceCipher) -> *const c_char {
    unsafe { active_substance::active_substance_cipher_to_string(cipher) }
}
