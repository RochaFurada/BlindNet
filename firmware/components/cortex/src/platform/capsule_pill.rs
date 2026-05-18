use core::ffi::c_char;

use crate::ffi::active_substance::{ActiveSubstanceRaw, ACTIVE_SUBSTANCE_HASH_LEN};
use crate::ffi::capsule_pill;
use crate::platform::{esp_result, Result};

pub use crate::ffi::capsule_pill::{
    CapsulePillActionClass, CapsulePillRaw, CapsulePillSignatureAlg, CAPSULE_PILL_ACTION_GPIO,
    CAPSULE_PILL_ACTION_MQTT, CAPSULE_PILL_ACTION_POLICY, CAPSULE_PILL_ACTION_UNKNOWN,
    CAPSULE_PILL_DIGEST_LEN, CAPSULE_PILL_ISSUER_KEY_ID_LEN, CAPSULE_PILL_NETWORK_ID_LEN,
    CAPSULE_PILL_NONCE_LEN, CAPSULE_PILL_SIGNATURE_ECDSA_SHA256_DER,
    CAPSULE_PILL_SIGNATURE_MAX_LEN, CAPSULE_PILL_SIGNATURE_NONE, CAPSULE_PILL_VERSION,
};

pub fn init(capsule: &mut CapsulePillRaw) {
    unsafe { capsule_pill::capsule_pill_init(capsule) };
}

pub fn configure(
    capsule: &mut CapsulePillRaw,
    action_class: CapsulePillActionClass,
    issued_ms: u32,
    expires_ms: u32,
    network_id: &[u8; CAPSULE_PILL_NETWORK_ID_LEN],
    nonce: &[u8; CAPSULE_PILL_NONCE_LEN],
    issuer_key_id: &[u8; CAPSULE_PILL_ISSUER_KEY_ID_LEN],
) -> Result {
    esp_result(unsafe {
        capsule_pill::capsule_pill_configure(
            capsule,
            action_class,
            issued_ms,
            expires_ms,
            network_id.as_ptr(),
            nonce.as_ptr(),
            issuer_key_id.as_ptr(),
        )
    })
}

pub fn set_active_hash(
    capsule: &mut CapsulePillRaw,
    active_hash: &[u8; ACTIVE_SUBSTANCE_HASH_LEN],
) -> Result {
    esp_result(unsafe { capsule_pill::capsule_pill_set_active_hash(capsule, active_hash.as_ptr()) })
}

pub fn bind_active(capsule: &mut CapsulePillRaw, substance: &ActiveSubstanceRaw) -> Result {
    esp_result(unsafe { capsule_pill::capsule_pill_bind_active(capsule, substance) })
}

pub fn set_signature(
    capsule: &mut CapsulePillRaw,
    alg: CapsulePillSignatureAlg,
    signature: &[u8],
) -> Result {
    esp_result(unsafe {
        capsule_pill::capsule_pill_set_signature(capsule, alg, signature.as_ptr(), signature.len())
    })
}

pub fn set_signature_alg(capsule: &mut CapsulePillRaw, alg: CapsulePillSignatureAlg) -> Result {
    esp_result(unsafe { capsule_pill::capsule_pill_set_signature_alg(capsule, alg) })
}

pub fn validate_basic(capsule: &CapsulePillRaw, now_ms: u32) -> Result {
    esp_result(unsafe { capsule_pill::capsule_pill_validate_basic(capsule, now_ms) })
}

pub fn matches_active(capsule: &CapsulePillRaw, substance: &ActiveSubstanceRaw) -> bool {
    unsafe { capsule_pill::capsule_pill_matches_active(capsule, substance) }
}

pub fn compute_signing_digest(capsule: &CapsulePillRaw) -> Result<[u8; CAPSULE_PILL_DIGEST_LEN]> {
    let mut out = [0u8; CAPSULE_PILL_DIGEST_LEN];
    let err =
        unsafe { capsule_pill::capsule_pill_compute_signing_digest(capsule, out.as_mut_ptr()) };
    if err == crate::ffi::ESP_OK {
        Ok(out)
    } else {
        Err(err)
    }
}

pub fn compute_digest(capsule: &CapsulePillRaw) -> Result<[u8; CAPSULE_PILL_DIGEST_LEN]> {
    let mut out = [0u8; CAPSULE_PILL_DIGEST_LEN];
    let err = unsafe { capsule_pill::capsule_pill_compute_digest(capsule, out.as_mut_ptr()) };
    if err == crate::ffi::ESP_OK {
        Ok(out)
    } else {
        Err(err)
    }
}

pub fn verify_asymmetric(capsule: &CapsulePillRaw, public_key: &[u8]) -> bool {
    unsafe {
        capsule_pill::capsule_pill_verify_asymmetric(capsule, public_key.as_ptr(), public_key.len())
    }
}

pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && unsafe {
            capsule_pill::capsule_pill_constant_time_equal(a.as_ptr(), b.as_ptr(), a.len())
        }
}

pub fn action_class_to_string(action_class: CapsulePillActionClass) -> *const c_char {
    unsafe { capsule_pill::capsule_pill_action_class_to_string(action_class) }
}

pub fn signature_alg_to_string(alg: CapsulePillSignatureAlg) -> *const c_char {
    unsafe { capsule_pill::capsule_pill_signature_alg_to_string(alg) }
}
