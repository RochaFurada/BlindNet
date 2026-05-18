use zeroize::Zeroize;

use crate::platform;
use crate::platform::active_enzyme;
use crate::platform::active_substance;
use crate::platform::capsule_pill;
use crate::platform::ribosome_table;
use crate::platform::ribosome_table::{RibosomeTableEntryRaw, RibosomeTableRaw};
use crate::platform::stomach_cp_cache;
use crate::platform::stomach_cp_cache::StomachCpCache;
use crate::platform::Result;

use super::action_pill::{self, ActionPill};

const _: () = assert!(stomach_cp_cache::STOMACH_CP_CACHE_SIZE > 0);
const _: () =
    assert!(stomach_cp_cache::STOMACH_CP_DIGEST_LEN == action_pill::ACTION_PILL_INNER_ID_LEN);

#[repr(C)]
pub struct StomachSeenResult {
    pub status: platform::EspErr,
    pub seen: bool,
    pub digest: [u8; action_pill::ACTION_PILL_INNER_ID_LEN],
}

impl StomachSeenResult {
    pub fn new() -> Self {
        Self {
            status: platform::ESP_OK,
            seen: false,
            digest: [0u8; action_pill::ACTION_PILL_INNER_ID_LEN],
        }
    }
}

impl Default for StomachSeenResult {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
pub struct DigestedActiveSubstance {
    pub command: active_substance::ActiveSubstanceCommandRaw,
    pub device: RibosomeTableEntryRaw,
}

impl DigestedActiveSubstance {
    pub fn new() -> Self {
        let mut result = Self {
            command: active_substance::new_command(),
            device: empty_ribosome_entry(),
        };

        result.clear();
        result
    }

    pub fn clear(&mut self) {
        active_substance::clear_command(&mut self.command);
        ribosome_table::clear_entry(&mut self.device);
    }
}

impl Default for DigestedActiveSubstance {
    fn default() -> Self {
        Self::new()
    }
}

pub struct StructValidator;

impl StructValidator {
    pub fn ap_validate(pill: &ActionPill, now_ms: u32) -> Result {
        action_pill::precheck_for_relay(pill, now_ms)
    }

    #[allow(non_snake_case)]
    pub fn APvalidate(pill: &ActionPill, now_ms: u32) -> Result {
        Self::ap_validate(pill, now_ms)
    }
}

pub struct CapsuleVerifier;

impl CapsuleVerifier {
    pub fn verify(
        pill: &ActionPill,
        expected_network_id: &[u8; capsule_pill::CAPSULE_PILL_NETWORK_ID_LEN],
        expected_issuer_key_id: &[u8; capsule_pill::CAPSULE_PILL_ISSUER_KEY_ID_LEN],
        issuer_public_key: &[u8],
    ) -> bool {
        if !action_pill::network_id_matches(pill, expected_network_id) {
            return false;
        }

        if !action_pill::issuer_key_matches(pill, expected_issuer_key_id) {
            return false;
        }

        if !action_pill::capsule_matches_active(pill) {
            return false;
        }

        action_pill::verify_capsule_signature(pill, issuer_public_key)
    }
}

pub struct CapsuleDigester;

impl CapsuleDigester {
    pub fn digest_active_substance(
        pill: &ActionPill,
        devices: &RibosomeTableRaw,
        aad: Option<&[u8]>,
        out_result: &mut DigestedActiveSubstance,
    ) -> Result {
        out_result.clear();

        if !table_count_valid(devices) {
            return Err(platform::ESP_ERR_INVALID_ARG);
        }

        active_substance::validate_envelope(&pill.active)?;

        if devices.count == 0 {
            return Err(platform::ESP_ERR_NOT_FOUND);
        }

        for candidate in devices.entries.iter().take(devices.count) {
            if !device_secret_valid(&candidate.device_secret) {
                continue;
            }

            let mut plaintext = [0u8; active_enzyme::ACTIVE_ENZYME_PLAINTEXT_MAX_LEN];
            let mut plaintext_len = 0;
            match active_enzyme::decrypt_with_secret(
                &pill.active,
                &candidate.device_secret,
                candidate.epoch,
                aad,
                &mut plaintext,
                &mut plaintext_len,
            ) {
                Ok(()) => {
                    let parse_result = active_substance::parse_command(
                        &plaintext[..plaintext_len],
                        &mut out_result.command,
                    );
                    plaintext.zeroize();
                    parse_result?;

                    out_result.device = *candidate;
                    return Ok(());
                }
                Err(err)
                    if err == platform::ESP_ERR_NOT_SUPPORTED
                        || err == platform::ESP_ERR_INVALID_SIZE
                        || err == platform::ESP_ERR_INVALID_ARG =>
                {
                    plaintext.zeroize();
                    return Err(err);
                }
                Err(_) => {
                    plaintext.zeroize();
                    continue;
                }
            }
        }

        out_result.clear();
        Err(platform::ESP_ERR_NOT_FOUND)
    }
}

pub struct Stomach {
    cp_cache: StomachCpCache,
}

impl Stomach {
    pub fn new() -> Self {
        Self {
            cp_cache: StomachCpCache::new(),
        }
    }

    pub fn clear_seen_cache(&mut self) {
        self.cp_cache.clear();
    }

    pub fn seen_or_add_cp(&mut self, pill: &ActionPill) -> StomachSeenResult {
        let mut result = StomachSeenResult::new();

        match action_pill::compute_capsule_digest(pill) {
            Ok(digest) => {
                result.status = platform::ESP_OK;
                result.seen = self.cp_cache.seen_or_add(&digest);
                result.digest = digest;
            }
            Err(err) => {
                result.status = err;
                result.seen = false;
            }
        }

        result
    }

    pub fn precheck_for_relay(&self, pill: &ActionPill, now_ms: u32) -> Result {
        action_pill::precheck_for_relay(pill, now_ms)
    }

    pub fn validate_authorized(
        &self,
        pill: &ActionPill,
        now_ms: u32,
        expected_network_id: &[u8; capsule_pill::CAPSULE_PILL_NETWORK_ID_LEN],
        expected_issuer_key_id: &[u8; capsule_pill::CAPSULE_PILL_ISSUER_KEY_ID_LEN],
        issuer_public_key: &[u8],
    ) -> Result {
        action_pill::validate_authorized(
            pill,
            now_ms,
            expected_network_id,
            expected_issuer_key_id,
            issuer_public_key,
        )
    }

    pub fn seen_cache(&self) -> &StomachCpCache {
        &self.cp_cache
    }
}

impl Default for Stomach {
    fn default() -> Self {
        Self::new()
    }
}

pub fn ap_validate(pill: &ActionPill, now_ms: u32) -> Result {
    StructValidator::ap_validate(pill, now_ms)
}

pub fn capsule_verify(
    pill: &ActionPill,
    expected_network_id: &[u8; capsule_pill::CAPSULE_PILL_NETWORK_ID_LEN],
    expected_issuer_key_id: &[u8; capsule_pill::CAPSULE_PILL_ISSUER_KEY_ID_LEN],
    issuer_public_key: &[u8],
) -> bool {
    CapsuleVerifier::verify(
        pill,
        expected_network_id,
        expected_issuer_key_id,
        issuer_public_key,
    )
}

pub fn digest_active_substance(
    pill: &ActionPill,
    devices: &RibosomeTableRaw,
    aad: Option<&[u8]>,
    out_result: &mut DigestedActiveSubstance,
) -> Result {
    CapsuleDigester::digest_active_substance(pill, devices, aad, out_result)
}

fn table_count_valid(table: &RibosomeTableRaw) -> bool {
    table.count <= ribosome_table::RIBOSOME_MAX_ENTRIES
}

fn device_secret_valid(secret: &[u8; ribosome_table::RIBOSOME_DEVICE_SECRET_LEN]) -> bool {
    let mut any = 0u8;
    for byte in secret {
        any |= *byte;
    }
    any != 0
}

fn empty_ribosome_entry() -> RibosomeTableEntryRaw {
    RibosomeTableEntryRaw {
        mqtt_client_id: [0; ribosome_table::RIBOSOME_MQTT_CLIENT_ID_LEN],
        template_id: 0,
        epoch: 0,
        device_secret: [0u8; ribosome_table::RIBOSOME_DEVICE_SECRET_LEN],
    }
}
