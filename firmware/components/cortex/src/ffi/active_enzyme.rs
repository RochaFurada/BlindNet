use crate::ffi::active_substance::{ActiveSubstanceRaw, ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN};
use crate::ffi::EspErr;

pub const ACTIVE_ENZYME_DEVICE_SECRET_LEN: usize = 32;
pub const ACTIVE_ENZYME_AES_128_KEY_LEN: usize = 16;
pub const ACTIVE_ENZYME_AES_256_KEY_LEN: usize = 32;
pub const ACTIVE_ENZYME_KEY_MAX_LEN: usize = ACTIVE_ENZYME_AES_256_KEY_LEN;
pub const ACTIVE_ENZYME_PLAINTEXT_MAX_LEN: usize = ACTIVE_SUBSTANCE_CIPHERTEXT_MAX_LEN;

unsafe extern "C" {
    pub fn active_enzyme_decrypt_with_secret(
        substance: *const ActiveSubstanceRaw,
        device_secret: *const u8,
        epoch: u32,
        aad: *const u8,
        aad_len: usize,
        out_plaintext: *mut u8,
        out_plaintext_size: usize,
        out_plaintext_len: *mut usize,
    ) -> EspErr;
}
