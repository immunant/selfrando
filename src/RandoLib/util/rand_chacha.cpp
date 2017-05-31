/*
 * This file is part of selfrando.
 * Copyright (c) 2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <OS.h>

#define KEYSTREAM_ONLY
#include "chacha_private.h"

#define KEY_WORDS   8
#define IV_WORDS    2

struct chacha_state {
    chacha_ctx ctx;
    uint32_t num_words;
    uint32_t words_idx;
    uint32_t words[0];
};

// FIXME: maybe store this inside os::API???
struct chacha_state *chacha_rng_state;

static RANDO_SECTION void chacha_rekey() {
    chacha_rng_state->num_words = (kPageSize - sizeof(struct chacha_state)) / sizeof(uint32_t);
    // FIXME: zero out chacha_rng_state->words???
    chacha_encrypt_bytes(&chacha_rng_state->ctx,
                         chacha_rng_state->words,
                         chacha_rng_state->words,
                         chacha_rng_state->num_words * sizeof(uint32_t));

    chacha_keysetup(&chacha_rng_state->ctx,
                    &chacha_rng_state->words[0],
                    32 * KEY_WORDS,
                    0);
    chacha_ivsetup(&chacha_rng_state->ctx,
                   &chacha_rng_state->words[KEY_WORDS],
                   32 * IV_WORDS);
    chacha_rng_state->words_idx = KEY_WORDS + IV_WORDS;
}

RANDO_SECTION void _TRaP_chacha_init(uint32_t key[KEY_WORDS],
                                     uint32_t iv[IV_WORDS]) {
    if (chacha_rng_state == nullptr) {
        chacha_rng_state = os::API::mmap(nullptr, os::kPageSize,
                                         PagePermissions::RW,
                                         true);
    }
    chacha_keysetup(&chacha_rng_state->ctx, key, 32 * KEY_WORDS, 0);
    chacha_ivsetup(&chacha_rng_state, iv, 32 * IV_WORDS);
    chacha_rekey();
}

RANDO_SECTION void _TRaP_chacha_finish() {
    if (chacha_rng_state != nullptr) {
        os::API::munmap(chacha_rng_state, os::kPageSize, true);
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

    // TODO: implement
    return 0;
}
