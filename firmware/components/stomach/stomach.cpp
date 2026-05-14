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
    const uint8_t *issuer_public_key,
    std::size_t issuer_public_key_len
) const
{
    return action_pill_validate_authorized(
        &pill,
        now_ms,
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
    const uint8_t *issuer_public_key,
    std::size_t issuer_public_key_len
)
{
    if (!action_pill_capsule_matches_active(&pill)) {
        return false;
    }

    return action_pill_verify_capsule_signature(&pill, issuer_public_key, issuer_public_key_len);
}

active_substance_t CapsuleDigester::digest_active_substance(
    const action_pill_t &pill,
    uint8_t out_id[ACTION_PILL_INNER_ID_LEN]
)
{
    active_substance_t result = {};
    esp_err_t err = action_pill_compute_inner_id(&pill, out_id);
}
