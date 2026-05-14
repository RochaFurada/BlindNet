#pragma once

#include <cstddef>
#include <cstdint>

#include "esp_err.h"
#include "action_pill.hpp"

#ifndef STOMACH_CP_CACHE_SIZE
#define STOMACH_CP_CACHE_SIZE 16
#endif

static_assert(STOMACH_CP_CACHE_SIZE > 0, "STOMACH_CP_CACHE_SIZE must be > 0");

struct StomachSeenResult {
    esp_err_t status;
    bool seen;
    uint8_t digest[ACTION_PILL_INNER_ID_LEN];
};

// Primeira camada de digestão do Action Pill. Foca em validar o CP imutável e
// o cache local de CPs vistos recentemente, para evitar processamento pesado de AS e assinatura quando possível.
class StomachCpCache final {
public:
    static constexpr std::size_t kCapacity = STOMACH_CP_CACHE_SIZE;

    void clear();

    bool contains(const uint8_t digest[ACTION_PILL_INNER_ID_LEN]) const;

    /*
     * Returns true when the digest was already present.
     * Returns false when the digest is new and has been inserted.
     */
    bool seen_or_add(const uint8_t digest[ACTION_PILL_INNER_ID_LEN]);

    std::size_t count() const;

private:
    uint8_t entries_[kCapacity][ACTION_PILL_INNER_ID_LEN] = {};
    std::size_t next_ = 0;
    std::size_t count_ = 0;
};
// Segunda camada de digestão do Action Pill. Valida o CP imutável e a assinatura, e faz checks básicos de AS cifrado.
class StructValidator final {
public:
    static esp_err_t APvalidate(const action_pill_t &pill, uint32_t now_ms);
};

// Terceira camada de digestão do Action Pill. Valida a assinatura do CP imutável.
class CapsuleVerifier final {
public:
    static bool verify(
        const action_pill_t &pill,
        const uint8_t *issuer_public_key,
        std::size_t issuer_public_key_len
    );
};

class CapsuleDigester final {
    public:
    static esp_err_t digest_active_substance(
        const action_pill_t &pill,
        uint8_t out_id[ACTION_PILL_INNER_ID_LEN]
    );

};



class Stomach final {
public:
    void clear_seen_cache();

    /*
     * First digestion barrier: compute cp_digest locally from the immutable CP
     * and check whether this Guardian has seen it recently.
     */
    StomachSeenResult seen_or_add_cp(const action_pill_t &pill);

    esp_err_t precheck_for_relay(const action_pill_t &pill, uint32_t now_ms) const;

    esp_err_t validate_authorized(
        const action_pill_t &pill,
        uint32_t now_ms,
        const uint8_t *issuer_public_key,
        std::size_t issuer_public_key_len
    ) const;

    const StomachCpCache &seen_cache() const;

private:
    StomachCpCache cp_cache_;
};
