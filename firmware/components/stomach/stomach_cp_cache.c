#include "stomach_cp_cache.h"

#include <string.h>

#include "mbedtls/platform_util.h"

static bool digest_equals(
    const uint8_t left[STOMACH_CP_DIGEST_LEN],
    const uint8_t right[STOMACH_CP_DIGEST_LEN]
) {
    return memcmp(left, right, STOMACH_CP_DIGEST_LEN) == 0;
}

void stomach_cp_cache_init(stomach_cp_cache_t *cache) {
    stomach_cp_cache_clear(cache);
}

void stomach_cp_cache_clear(stomach_cp_cache_t *cache) {
    if (!cache) {
        return;
    }

    mbedtls_platform_zeroize(cache->entries, sizeof(cache->entries));
    cache->next = 0;
    cache->count = 0;
}

bool stomach_cp_cache_contains(
    const stomach_cp_cache_t *cache,
    const uint8_t digest[STOMACH_CP_DIGEST_LEN]
) {
    if (!cache || !digest) {
        return false;
    }

    for (size_t i = 0; i < cache->count; ++i) {
        if (digest_equals(cache->entries[i], digest)) {
            return true;
        }
    }

    return false;
}

bool stomach_cp_cache_seen_or_add(
    stomach_cp_cache_t *cache,
    const uint8_t digest[STOMACH_CP_DIGEST_LEN]
) {
    if (!cache || !digest) {
        return true;
    }

    if (stomach_cp_cache_contains(cache, digest)) {
        return true;
    }

    memcpy(cache->entries[cache->next], digest, STOMACH_CP_DIGEST_LEN);
    cache->next = (cache->next + 1) % STOMACH_CP_CACHE_SIZE;

    if (cache->count < STOMACH_CP_CACHE_SIZE) {
        ++cache->count;
    }

    return false;
}

size_t stomach_cp_cache_count(const stomach_cp_cache_t *cache) {
    return cache ? cache->count : 0;
}
