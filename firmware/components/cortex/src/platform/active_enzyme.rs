use core::ptr;

use crate::ffi::active_enzyme;
use crate::platform::{esp_result, Result};

pub use crate::ffi::active_enzyme::{
    ACTIVE_ENZYME_AES_128_KEY_LEN, ACTIVE_ENZYME_AES_256_KEY_LEN, ACTIVE_ENZYME_DEVICE_SECRET_LEN,
    ACTIVE_ENZYME_KEY_MAX_LEN, ACTIVE_ENZYME_PLAINTEXT_MAX_LEN,
};
pub use crate::ffi::active_substance::ActiveSubstanceRaw;

pub fn decrypt_with_secret(
    substance: &ActiveSubstanceRaw,
    device_secret: &[u8; ACTIVE_ENZYME_DEVICE_SECRET_LEN],
    epoch: u32,
    aad: Option<&[u8]>,
    out_plaintext: &mut [u8],
    out_plaintext_len: &mut usize,
) -> Result {
    let (aad_ptr, aad_len) = aad.map_or((ptr::null(), 0), |aad| (aad.as_ptr(), aad.len()));
    esp_result(unsafe {
        active_enzyme::active_enzyme_decrypt_with_secret(
            substance,
            device_secret.as_ptr(),
            epoch,
            aad_ptr,
            aad_len,
            out_plaintext.as_mut_ptr(),
            out_plaintext.len(),
            out_plaintext_len,
        )
    })
}
