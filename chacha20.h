#ifndef CHACHA20_H
#define CHACHA20_H
#pragma once

#include <stdint.h>

/* Context for a ChaCha20 block. */
struct chacha20_context {
  uint32_t state[16];
};

/* Initializes the state in a ChaCha20 context. The counter should be
   incremented for every block in the stream, while the nonce should be created
   anew once per stream. */
void chacha20_init_state(struct chacha20_context* ctx, uint32_t key[8],
                         uint32_t nonce[3], uint32_t counter);

/* Runs the ChaCha20 algorithm to create a block of the keystream and writes
   it to a destination buffer. */
void chacha20_block(const struct chacha20_context* ctx, char* dest);

/* Prints a human-readable representation of the ChaCha20 state to stdout. */
void chacha20_debug_state(const struct chacha20_context* ctx);

/* Runs the ChaCha20 algorithm to create a block of the keystream, then
   prints a human-readable representation of the block to stdout. */
void chacha20_debug_block(const struct chacha20_context* ctx);

/* Encrypts the plaintext, with length plaintext_length, into the ciphertext. 
   Doing so increments the counter for each block of keystream used. */
void chacha20_encrypt(struct chacha20_context* ctx, char* plaintext,
                      size_t plaintext_length, char* ciphertext);




#endif /* CHACHA20_H */