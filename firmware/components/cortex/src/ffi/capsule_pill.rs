use core::ffi::c_char;

use crate::ffi::active_substance::{ActiveSubstanceRaw, ACTIVE_SUBSTANCE_HASH_LEN};
use crate::ffi::EspErr;

pub const CAPSULE_PILL_VERSION: u8 = 3;
pub const CAPSULE_PILL_NONCE_LEN: usize = 16;
pub const CAPSULE_PILL_NETWORK_ID_LEN: usize = 16;
pub const CAPSULE_PILL_ISSUER_KEY_ID_LEN: usize = 16;
pub const CAPSULE_PILL_SIGNATURE_MAX_LEN: usize = 96;
pub const CAPSULE_PILL_DIGEST_LEN: usize = 32;

pub type CapsulePillActionClass = i32;
pub const CAPSULE_PILL_ACTION_UNKNOWN: CapsulePillActionClass = 0;
pub const CAPSULE_PILL_ACTION_MQTT: CapsulePillActionClass = 1;
pub const CAPSULE_PILL_ACTION_GPIO: CapsulePillActionClass = 2;
pub const CAPSULE_PILL_ACTION_POLICY: CapsulePillActionClass = 3;

pub type CapsulePillSignatureAlg = i32;
pub const CAPSULE_PILL_SIGNATURE_NONE: CapsulePillSignatureAlg = 0;
pub const CAPSULE_PILL_SIGNATURE_ECDSA_SHA256_DER: CapsulePillSignatureAlg = 1;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CapsulePillRaw {
    pub version: u8,
    pub flags: u8,
    pub action_class: u8,
    pub reserved0: u8,
    pub issued_ms: u32,
    pub expires_ms: u32,
    pub network_id: [u8; CAPSULE_PILL_NETWORK_ID_LEN],
    pub nonce: [u8; CAPSULE_PILL_NONCE_LEN],
    pub active_hash: [u8; ACTIVE_SUBSTANCE_HASH_LEN],
    pub issuer_key_id: [u8; CAPSULE_PILL_ISSUER_KEY_ID_LEN],
    pub signature_alg: u8,
    pub signature_len: u8,
    pub reserved1: [u8; 2],
    pub signature: [u8; CAPSULE_PILL_SIGNATURE_MAX_LEN],
}

unsafe extern "C" {
    pub fn capsule_pill_init(capsule: *mut CapsulePillRaw);
    pub fn capsule_pill_configure(
        capsule: *mut CapsulePillRaw,
        action_class: CapsulePillActionClass,
        issued_ms: u32,
        expires_ms: u32,
        network_id: *const u8,
        nonce: *const u8,
        issuer_key_id: *const u8,
    ) -> EspErr;
    pub fn capsule_pill_set_active_hash(
        capsule: *mut CapsulePillRaw,
        active_hash: *const u8,
    ) -> EspErr;
    pub fn capsule_pill_bind_active(
        capsule: *mut CapsulePillRaw,
        substance: *const ActiveSubstanceRaw,
    ) -> EspErr;
    pub fn capsule_pill_set_signature(
        capsule: *mut CapsulePillRaw,
        alg: CapsulePillSignatureAlg,
        signature: *const u8,
        signature_len: usize,
    ) -> EspErr;
    pub fn capsule_pill_set_signature_alg(
        capsule: *mut CapsulePillRaw,
        alg: CapsulePillSignatureAlg,
    ) -> EspErr;
    pub fn capsule_pill_validate_basic(capsule: *const CapsulePillRaw, now_ms: u32) -> EspErr;
    pub fn capsule_pill_matches_active(
        capsule: *const CapsulePillRaw,
        substance: *const ActiveSubstanceRaw,
    ) -> bool;
    pub fn capsule_pill_compute_signing_digest(
        capsule: *const CapsulePillRaw,
        out_digest: *mut u8,
    ) -> EspErr;
    pub fn capsule_pill_compute_digest(
        capsule: *const CapsulePillRaw,
        out_digest: *mut u8,
    ) -> EspErr;
    pub fn capsule_pill_verify_asymmetric(
        capsule: *const CapsulePillRaw,
        public_key: *const u8,
        public_key_len: usize,
    ) -> bool;
    pub fn capsule_pill_constant_time_equal(a: *const u8, b: *const u8, len: usize) -> bool;
    pub fn capsule_pill_action_class_to_string(
        action_class: CapsulePillActionClass,
    ) -> *const c_char;
    pub fn capsule_pill_signature_alg_to_string(alg: CapsulePillSignatureAlg) -> *const c_char;
}
