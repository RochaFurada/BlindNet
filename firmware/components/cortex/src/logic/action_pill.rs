use core::mem::MaybeUninit;

use crate::platform;
use crate::platform::active_substance;
use crate::platform::active_substance::ActiveSubstanceRaw;
use crate::platform::capsule_pill;
use crate::platform::capsule_pill::CapsulePillRaw;
use crate::platform::Result;

pub const ACTION_PILL_INNER_ID_LEN: usize = capsule_pill::CAPSULE_PILL_DIGEST_LEN;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ActionPill {
    pub capsule: CapsulePillRaw,
    pub active: ActiveSubstanceRaw,
}

pub fn init(pill: &mut ActionPill) {
    *pill = zeroed_action_pill();
}

pub fn set_ready(
    pill: &mut ActionPill,
    capsule: &CapsulePillRaw,
    active: &ActiveSubstanceRaw,
) -> Result {
    active_substance::validate_envelope(active)?;

    if !capsule_pill::matches_active(capsule, active) {
        return Err(platform::ESP_ERR_INVALID_CRC);
    }

    init(pill);
    pill.capsule = *capsule;
    pill.active = *active;
    Ok(())
}

pub fn precheck_for_relay(pill: &ActionPill, now_ms: u32) -> Result {
    active_substance::validate_envelope(&pill.active)?;
    capsule_pill::validate_basic(&pill.capsule, now_ms)
}

pub fn validate_authorized(
    pill: &ActionPill,
    now_ms: u32,
    expected_network_id: &[u8; capsule_pill::CAPSULE_PILL_NETWORK_ID_LEN],
    expected_issuer_key_id: &[u8; capsule_pill::CAPSULE_PILL_ISSUER_KEY_ID_LEN],
    issuer_public_key: &[u8],
) -> Result {
    precheck_for_relay(pill, now_ms)?;

    if !network_id_matches(pill, expected_network_id) {
        return Err(platform::ESP_ERR_INVALID_STATE);
    }

    if !issuer_key_matches(pill, expected_issuer_key_id) {
        return Err(platform::ESP_ERR_INVALID_STATE);
    }

    if !capsule_matches_active(pill) {
        return Err(platform::ESP_ERR_INVALID_CRC);
    }

    if !verify_capsule_signature(pill, issuer_public_key) {
        return Err(platform::ESP_ERR_INVALID_STATE);
    }

    Ok(())
}

pub fn capsule_matches_active(pill: &ActionPill) -> bool {
    capsule_pill::matches_active(&pill.capsule, &pill.active)
}

pub fn network_id_matches(
    pill: &ActionPill,
    expected_network_id: &[u8; capsule_pill::CAPSULE_PILL_NETWORK_ID_LEN],
) -> bool {
    capsule_pill::constant_time_equal(&pill.capsule.network_id, expected_network_id)
}

pub fn issuer_key_matches(
    pill: &ActionPill,
    expected_issuer_key_id: &[u8; capsule_pill::CAPSULE_PILL_ISSUER_KEY_ID_LEN],
) -> bool {
    capsule_pill::constant_time_equal(&pill.capsule.issuer_key_id, expected_issuer_key_id)
}

pub fn verify_capsule_signature(pill: &ActionPill, issuer_public_key: &[u8]) -> bool {
    capsule_pill::verify_asymmetric(&pill.capsule, issuer_public_key)
}

pub fn compute_capsule_digest(pill: &ActionPill) -> Result<[u8; ACTION_PILL_INNER_ID_LEN]> {
    if ACTION_PILL_INNER_ID_LEN != capsule_pill::CAPSULE_PILL_DIGEST_LEN {
        return Err(platform::ESP_ERR_INVALID_ARG);
    }

    capsule_pill::compute_digest(&pill.capsule)
}

pub fn compute_inner_id(pill: &ActionPill) -> Result<[u8; ACTION_PILL_INNER_ID_LEN]> {
    compute_capsule_digest(pill)
}

fn zeroed_action_pill() -> ActionPill {
    let raw = MaybeUninit::<ActionPill>::zeroed();
    unsafe { raw.assume_init() }
}
