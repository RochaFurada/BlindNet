#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef STOMACH_CP_CACHE_SIZE
#define STOMACH_CP_CACHE_SIZE 16
#endif

#define STOMACH_CP_DIGEST_LEN 32

#if STOMACH_CP_CACHE_SIZE <= 0
#error "STOMACH_CP_CACHE_SIZE must be > 0"
#endif

typedef struct {
    uint8_t entries[STOMACH_CP_CACHE_SIZE][STOMACH_CP_DIGEST_LEN];
    size_t next;
    size_t count;
} stomach_cp_cache_t;

void stomach_cp_cache_init(stomach_cp_cache_t *cache);
void stomach_cp_cache_clear(stomach_cp_cache_t *cache);

bool stomach_cp_cache_contains(
    const stomach_cp_cache_t *cache,
    const uint8_t digest[STOMACH_CP_DIGEST_LEN]
);

bool stomach_cp_cache_seen_or_add(
    stomach_cp_cache_t *cache,
    const uint8_t digest[STOMACH_CP_DIGEST_LEN]
);

size_t stomach_cp_cache_count(const stomach_cp_cache_t *cache);
