use core::ffi::{c_char, c_int};

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
const ESP_LOG_WARN: c_int = 2;
const ESP_LOG_INFO: c_int = 3;
const TAG_STOMACH: &[u8] = b"cortex_stomach\0";

unsafe extern "C" {
    fn esp_log_write(level: c_int, tag: *const c_char, format: *const c_char, ...);
}

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
        expected_issuer_key_id: &[u8; capsule_pill::CAPSULE_PILL_ISSUER_KEY_ID_LEN],
        issuer_public_key: &[u8],
    ) -> bool {
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
        log_digest_start(
            devices.count,
            pill.active.cipher,
            pill.active.ciphertext_len,
        );

        if !table_count_valid(devices) {
            log_digest_result(platform::ESP_ERR_INVALID_ARG);
            return Err(platform::ESP_ERR_INVALID_ARG);
        }

        if let Err(err) = active_substance::validate_envelope(&pill.active) {
            log_digest_result(err);
            return Err(err);
        }

        if devices.count == 0 {
            log_digest_result(platform::ESP_ERR_NOT_FOUND);
            return Err(platform::ESP_ERR_NOT_FOUND);
        }

        for (index, candidate) in devices.entries.iter().take(devices.count).enumerate() {
            if !device_secret_valid(&candidate.device_secret) {
                continue;
            }

            log_candidate(index, candidate.epoch);
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
                    if let Err(err) = parse_result {
                        log_candidate_result(index, err);
                        log_digest_result(err);
                        return Err(err);
                    }

                    out_result.device = *candidate;
                    log_candidate_result(index, platform::ESP_OK);
                    log_digest_ok(index, out_result.command.amino_id as u32);
                    log_digest_result(platform::ESP_OK);
                    return Ok(());
                }
                Err(err)
                    if err == platform::ESP_ERR_NOT_SUPPORTED
                        || err == platform::ESP_ERR_INVALID_SIZE
                        || err == platform::ESP_ERR_INVALID_ARG =>
                {
                    plaintext.zeroize();
                    log_candidate_result(index, err);
                    log_digest_result(err);
                    return Err(err);
                }
                Err(_) => {
                    plaintext.zeroize();
                    log_candidate_result(index, platform::ESP_ERR_NOT_FOUND);
                    continue;
                }
            }
        }

        out_result.clear();
        log_digest_result(platform::ESP_ERR_NOT_FOUND);
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
                log_seen(result.status, result.seen, &result.digest);
            }
            Err(err) => {
                result.status = err;
                result.seen = false;
                log_seen(result.status, result.seen, &result.digest);
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
        expected_issuer_key_id: &[u8; capsule_pill::CAPSULE_PILL_ISSUER_KEY_ID_LEN],
        issuer_public_key: &[u8],
    ) -> Result {
        let result =
            validate_authorized_with_trace(pill, now_ms, expected_issuer_key_id, issuer_public_key);
        log_authorized_result(match result {
            Ok(()) => platform::ESP_OK,
            Err(err) => err,
        });
        result
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
    expected_issuer_key_id: &[u8; capsule_pill::CAPSULE_PILL_ISSUER_KEY_ID_LEN],
    issuer_public_key: &[u8],
) -> bool {
    CapsuleVerifier::verify(pill, expected_issuer_key_id, issuer_public_key)
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

fn log_tag() -> *const c_char {
    TAG_STOMACH.as_ptr().cast()
}

fn digest_prefix(digest: &[u8; action_pill::ACTION_PILL_INNER_ID_LEN]) -> u32 {
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

fn log_seen(
    status: platform::EspErr,
    seen: bool,
    digest: &[u8; action_pill::ACTION_PILL_INNER_ID_LEN],
) {
    unsafe {
        esp_log_write(
            ESP_LOG_INFO,
            log_tag(),
            c"cp cache status=0x%08x seen=%u digest=%08x".as_ptr(),
            status as u32,
            if seen { 1u32 } else { 0u32 },
            digest_prefix(digest),
        );
    }
}

fn log_authorized_result(err: platform::EspErr) {
    let level = if err == platform::ESP_OK {
        ESP_LOG_INFO
    } else {
        ESP_LOG_WARN
    };
    unsafe {
        esp_log_write(
            level,
            log_tag(),
            c"capsule authorized err=0x%08x".as_ptr(),
            err as u32,
        );
    }
}

fn validate_authorized_with_trace(
    pill: &ActionPill,
    now_ms: u32,
    expected_issuer_key_id: &[u8; capsule_pill::CAPSULE_PILL_ISSUER_KEY_ID_LEN],
    issuer_public_key: &[u8],
) -> Result {
    action_pill::precheck_for_relay(pill, now_ms)?;

    if !action_pill::issuer_key_matches(pill, expected_issuer_key_id) {
        log_auth_bytes(
            c"issuer_key_id mismatch".as_ptr(),
            &pill.capsule.issuer_key_id,
            expected_issuer_key_id,
        );
        return Err(platform::ESP_ERR_INVALID_STATE);
    }

    if !action_pill::capsule_matches_active(pill) {
        log_auth_reason(c"active_hash mismatch".as_ptr());
        return Err(platform::ESP_ERR_INVALID_CRC);
    }

    if !action_pill::verify_capsule_signature(pill, issuer_public_key) {
        log_auth_reason(c"signature invalid".as_ptr());
        return Err(platform::ESP_ERR_INVALID_STATE);
    }

    Ok(())
}

fn log_auth_reason(reason: *const c_char) {
    unsafe {
        esp_log_write(ESP_LOG_WARN, log_tag(), c"auth fail: %s".as_ptr(), reason);
    }
}

fn log_auth_bytes(reason: *const c_char, got: &[u8], expected: &[u8]) {
    unsafe {
        esp_log_write(
            ESP_LOG_WARN,
            log_tag(),
            c"auth fail: %s got=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x expected=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x".as_ptr(),
            reason,
            byte_at(got, 0),
            byte_at(got, 1),
            byte_at(got, 2),
            byte_at(got, 3),
            byte_at(got, 4),
            byte_at(got, 5),
            byte_at(got, 6),
            byte_at(got, 7),
            byte_at(got, 8),
            byte_at(got, 9),
            byte_at(got, 10),
            byte_at(got, 11),
            byte_at(got, 12),
            byte_at(got, 13),
            byte_at(got, 14),
            byte_at(got, 15),
            byte_at(expected, 0),
            byte_at(expected, 1),
            byte_at(expected, 2),
            byte_at(expected, 3),
            byte_at(expected, 4),
            byte_at(expected, 5),
            byte_at(expected, 6),
            byte_at(expected, 7),
            byte_at(expected, 8),
            byte_at(expected, 9),
            byte_at(expected, 10),
            byte_at(expected, 11),
            byte_at(expected, 12),
            byte_at(expected, 13),
            byte_at(expected, 14),
            byte_at(expected, 15),
        );
    }
}

fn byte_at(bytes: &[u8], index: usize) -> u32 {
    bytes.get(index).copied().unwrap_or(0) as u32
}

fn log_digest_start(device_count: usize, cipher: u8, ciphertext_len: u16) {
    unsafe {
        esp_log_write(
            ESP_LOG_INFO,
            log_tag(),
            c"digest start devices=%u cipher=%u ciphertext_len=%u".as_ptr(),
            device_count as u32,
            cipher as u32,
            ciphertext_len as u32,
        );
    }
}

fn log_candidate(index: usize, epoch: u32) {
    unsafe {
        esp_log_write(
            ESP_LOG_INFO,
            log_tag(),
            c"try ribosome index=%u epoch=%u".as_ptr(),
            index as u32,
            epoch,
        );
    }
}

fn log_candidate_result(index: usize, err: platform::EspErr) {
    let level = if err == platform::ESP_OK {
        ESP_LOG_INFO
    } else {
        ESP_LOG_WARN
    };
    unsafe {
        esp_log_write(
            level,
            log_tag(),
            c"ribosome index=%u err=0x%08x".as_ptr(),
            index as u32,
            err as u32,
        );
    }
}

fn log_digest_ok(index: usize, amino_id: u32) {
    unsafe {
        esp_log_write(
            ESP_LOG_INFO,
            log_tag(),
            c"digest ok ribosome=%u amino=%u".as_ptr(),
            index as u32,
            amino_id,
        );
    }
}

fn log_digest_result(err: platform::EspErr) {
    let level = if err == platform::ESP_OK {
        ESP_LOG_INFO
    } else {
        ESP_LOG_WARN
    };
    unsafe {
        esp_log_write(
            level,
            log_tag(),
            c"digest result err=0x%08x".as_ptr(),
            err as u32,
        );
    }
}
