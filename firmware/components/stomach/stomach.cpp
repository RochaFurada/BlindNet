#include "stomach.hpp"

#include <cstring>

namespace {

bool digest_equals(
    const uint8_t left[ACTION_PILL_INNER_ID_LEN],
    const uint8_t right[ACTION_PILL_INNER_ID_LEN]
)
{
    return std::memcmp(left, right, ACTION_PILL_INNER_ID_LEN) == 0;
}

bool table_count_valid(const ribosome_table_t &table)
{
    return table.count <= RIBOSOME_MAX_ENTRIES;
}

bool device_secret_valid(const uint8_t secret[RIBOSOME_DEVICE_SECRET_LEN])
{
    if (!secret) {
        return false;
    }

    uint8_t any = 0;
    for (std::size_t i = 0; i < RIBOSOME_DEVICE_SECRET_LEN; ++i) {
        any |= secret[i];
    }

    return any != 0;
}

void clear_digested_active(DigestedActiveSubstance *result)
{
    if (!result) {
        return;
    }

    std::memset(result->plaintext, 0, sizeof(result->plaintext));
    result->plaintext_len = 0;
    ribosome_table_clear_entry(&result->device);
}

} // namespace

void StomachCpCache::clear()
{
    std::memset(entries_, 0, sizeof(entries_));
    next_ = 0;
    count_ = 0;
}

bool StomachCpCache::contains(const uint8_t digest[ACTION_PILL_INNER_ID_LEN]) const
{
    if (!digest) {
        return false;
    }

    for (std::size_t i = 0; i < count_; ++i) {
        if (digest_equals(entries_[i], digest)) {
            return true;
        }
    }

    return false;
}

bool StomachCpCache::seen_or_add(const uint8_t digest[ACTION_PILL_INNER_ID_LEN])
{
    if (!digest) {
        return true;
    }

    if (contains(digest)) {
        return true;
    }

    std::memcpy(entries_[next_], digest, ACTION_PILL_INNER_ID_LEN);
    next_ = (next_ + 1) % kCapacity;

    if (count_ < kCapacity) {
        ++count_;
    }

    return false;
}

std::size_t StomachCpCache::count() const
{
    return count_;
}

void Stomach::clear_seen_cache()
{
    cp_cache_.clear();
}

StomachSeenResult Stomach::seen_or_add_cp(const action_pill_t &pill)
{
    StomachSeenResult result = {};

    result.status = action_pill_compute_capsule_digest(&pill, result.digest);
    if (result.status != ESP_OK) {
        result.seen = false;
        return result;
    }

    result.seen = cp_cache_.seen_or_add(result.digest);
    return result;
}

esp_err_t Stomach::precheck_for_relay(const action_pill_t &pill, uint32_t now_ms) const
{
    return action_pill_precheck_for_relay(&pill, now_ms);
}

esp_err_t Stomach::validate_authorized(
    const action_pill_t &pill,
    uint32_t now_ms,
    const uint8_t expected_network_id[CAPSULE_PILL_NETWORK_ID_LEN],
    const uint8_t expected_issuer_key_id[CAPSULE_PILL_ISSUER_KEY_ID_LEN],
    const uint8_t *issuer_public_key,
    std::size_t issuer_public_key_len
) const
{
    return action_pill_validate_authorized(
        &pill,
        now_ms,
        expected_network_id,
        expected_issuer_key_id,
        issuer_public_key,
        issuer_public_key_len
    );
}

const StomachCpCache &Stomach::seen_cache() const
{
    return cp_cache_;
}

esp_err_t StructValidator::APvalidate(const action_pill_t &pill, uint32_t now_ms)
{
    return action_pill_precheck_for_relay(&pill, now_ms);
}

bool CapsuleVerifier::verify(
    const action_pill_t &pill,
    const uint8_t expected_network_id[CAPSULE_PILL_NETWORK_ID_LEN],
    const uint8_t expected_issuer_key_id[CAPSULE_PILL_ISSUER_KEY_ID_LEN],
    const uint8_t *issuer_public_key,
    std::size_t issuer_public_key_len
)
{
    if (!action_pill_network_id_matches(&pill, expected_network_id)) {
        return false;
    }

    if (!action_pill_issuer_key_matches(&pill, expected_issuer_key_id)) {
        return false;
    }

    if (!action_pill_capsule_matches_active(&pill)) {
        return false;
    }

    return action_pill_verify_capsule_signature(&pill, issuer_public_key, issuer_public_key_len);
}

esp_err_t CapsuleDigester::digest_active_substance(
    const action_pill_t &pill,
    const ribosome_table_t &devices,
    const uint8_t *aad,
    std::size_t aad_len,
    DigestedActiveSubstance *out_result
)
{
    if (out_result) {
        clear_digested_active(out_result);
    }

    if (!table_count_valid(devices) || !out_result) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!aad && aad_len != 0) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = active_substance_validate_envelope(&pill.active);
    if (err != ESP_OK) {
        return err;
    }

    if (devices.count == 0) {
        return ESP_ERR_NOT_FOUND;
    }

    for (std::size_t i = 0; i < devices.count; ++i) {
        const ribosome_table_entry_t &candidate = devices.entries[i];

        if (!device_secret_valid(candidate.device_secret)) {
            continue;
        }

        std::size_t plaintext_len = 0;
        err = active_enzyme_decrypt_with_secret(
            &pill.active,
            candidate.device_secret,
            candidate.epoch,
            aad,
            aad_len,
            out_result->plaintext,
            sizeof(out_result->plaintext),
            &plaintext_len
        );

        if (err == ESP_OK) {
            out_result->plaintext_len = plaintext_len;
            out_result->device = candidate;
            return ESP_OK;
        }

        if (err == ESP_ERR_NOT_SUPPORTED ||
            err == ESP_ERR_INVALID_SIZE ||
            err == ESP_ERR_INVALID_ARG) {
            return err;
        }
    }

    clear_digested_active(out_result);
    return ESP_ERR_NOT_FOUND;
}
