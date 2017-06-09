/*
 * This file is part of selfrando.
 * Copyright (c) 2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <OS.h>

#if RANDOLIB_IS_WIN32
#include <intrin.h>
#endif

#define KEYSTREAM_ONLY
#include "chacha_private.h"

#define KEY_WORDS       8
#define IV_WORDS        2
#define CHACHA_PAGES    4

struct chacha_state {
    chacha_ctx ctx;
    uint32_t num_words;
    uint32_t words_idx;
    uint32_t words[0];
};

// FIXME: maybe store this inside os::API???
struct chacha_state *chacha_rng_state;

static RANDO_SECTION constexpr size_t chacha_state_size() {
    return CHACHA_PAGES * os::kPageSize;
}

static RANDO_SECTION constexpr size_t chacha_state_words() {
    return (chacha_state_size() - sizeof(struct chacha_state)) / sizeof(uint32_t);
}

static RANDO_SECTION void chacha_rekey() {
    chacha_rng_state->num_words = chacha_state_words();
    // FIXME: zero out chacha_rng_state->words???
    chacha_encrypt_bytes(&chacha_rng_state->ctx,
                         reinterpret_cast<u8*>(chacha_rng_state->words),
                         reinterpret_cast<u8*>(chacha_rng_state->words),
                         chacha_rng_state->num_words * sizeof(uint32_t));

    // Use the first 8+2 words of the new keystream as the new key+IV
    chacha_keysetup(&chacha_rng_state->ctx,
                    reinterpret_cast<u8*>(&chacha_rng_state->words[0]),
                    32 * KEY_WORDS,
                    0);
    chacha_ivsetup(&chacha_rng_state->ctx,
                   reinterpret_cast<u8*>(&chacha_rng_state->words[KEY_WORDS]));
    chacha_rng_state->words_idx = KEY_WORDS + IV_WORDS;
}

RANDO_SECTION void _TRaP_chacha_init(uint32_t key[KEY_WORDS],
                                     uint32_t iv[IV_WORDS]) {
    if (chacha_rng_state == nullptr) {
        chacha_rng_state = reinterpret_cast<struct chacha_state*>(
            os::API::mmap(nullptr, chacha_state_size(),
                          os::PagePermissions::RW,
                          true));
    }
    chacha_keysetup(&chacha_rng_state->ctx, reinterpret_cast<u8*>(key), 32 * KEY_WORDS, 0);
    chacha_ivsetup(&chacha_rng_state->ctx, reinterpret_cast<u8*>(iv));
    chacha_rekey();
}

RANDO_SECTION void _TRaP_chacha_finish() {
    if (chacha_rng_state != nullptr) {
        os::API::munmap(chacha_rng_state, chacha_state_size(), true);
        chacha_rng_state = nullptr;
    }
}

RANDO_SECTION uint32_t _TRaP_chacha_random_u32() {
    if (chacha_rng_state->words_idx >= chacha_rng_state->num_words)
        chacha_rekey();
    return chacha_rng_state->words[chacha_rng_state->words_idx++];
}

RANDO_SECTION uint32_t _TRaP_chacha_random(uint32_t max) {
    if (max == 0)
        return 0;

#if RANDOLIB_IS_POSIX
    auto clz = __builtin_clz(max);
#elif RANDOLIB_IS_WIN32
    DWORD clz = 0;
    if (!_BitScanReverse(&clz, max))
        return 0;
    clz = 31 - clz;
#else
#error Unknown OS
#endif
    auto mask = static_cast<uint32_t>(-1) >> clz;
    for (;;) {
        // Clip rand to next power of 2 after "max"
        // This ensures that we always have
        // P(rand < max) > 0.5
        auto rand = _TRaP_chacha_random_u32() & mask;
        if (rand < max)
            return rand;
    }
}
