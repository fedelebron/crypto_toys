#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "chacha20.h"

void chacha20_init_state(struct chacha20_context* ctx, uint32_t key[8],
                         uint32_t nonce[3], uint32_t counter) {
  
  uint32_t* state = ctx->state;
  state[0] = 0x61707865; // ChaCha20 constants
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  
  for (int i = 0; i < 8; ++i) {
    state[4 + i] = key[i];
  }
  
  state[12] = counter;
  for (int i = 0; i < 3; ++i) {
    ctx->state[13 + i] = nonce[i];
  }
}

static uint32_t rol(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

static void do_quarter_round(uint32_t state[16], 
                             int ai, int bi, int ci, int di) {
  
  uint32_t a = state[ai];
  uint32_t b = state[bi];
  uint32_t c = state[ci];
  uint32_t d = state[di];
  
  a += b; d ^= a; d = rol(d, 16);
  c += d; b ^= c; b = rol(b, 12);
  a += b; d ^= a; d = rol(d, 8);
  c += d; b ^= c; b = rol(b, 7);
  
  state[ai] = a;
  state[bi] = b;
  state[ci] = c;
  state[di] = d;
}

static void do_round(uint32_t state[16]) {
  do_quarter_round(state, 0, 4, 8,  12);
  do_quarter_round(state, 1, 5, 9,  13);
  do_quarter_round(state, 2, 6, 10, 14);
  do_quarter_round(state, 3, 7, 11, 15);
  do_quarter_round(state, 0, 5, 10, 15);
  do_quarter_round(state, 1, 6, 11, 12);
  do_quarter_round(state, 2, 7, 8,  13);
  do_quarter_round(state, 3, 4, 9,  14);
}

void chacha20_block(const struct chacha20_context* ctx, char* dest) {
  uint32_t working_state[16];
  memcpy(working_state, ctx->state, 16 * sizeof(uint32_t));
  
  for (int i = 0; i < 10; i++) {
    do_round(working_state);
  }
  
  for (int i = 0; i < 16; i++) {
    // Little-endian serialization
    uint32_t v = working_state[i] + ctx->state[i];
    *dest++ = 0xFF & (v);
    *dest++ = 0xFF & (v >> 8);
    *dest++ = 0xFF & (v >> 16);
    *dest++ = 0xFF & (v >> 24);
  }
}


void chacha20_debug_block(const struct chacha20_context* ctx) {
  uint32_t working_state[16];
  memcpy(working_state, ctx->state, 16 * sizeof(uint32_t));
  
  for (int i = 0; i < 10; i++) {
    do_round(working_state);
  }
  
  for (int i = 0; i < 16; i++) {
    working_state[i] += ctx->state[i];
    printf("%08x ", working_state[i]);
    if (i % 4 == 3) {
      printf("\n");
    }
  }
}


void chacha20_debug_state(const struct chacha20_context* ctx) {
  for (int i = 0; i < 16; i++) {
    printf("%08x ", ctx->state[i]);
    if (i % 4 == 3) {
      printf("\n");
    }
  }
}

void chacha20_encrypt(struct chacha20_context* ctx, char* plaintext,
                      size_t plaintext_length, char* ciphertext) {
  
  if (ciphertext == NULL) {
    ciphertext = plaintext;
  }
  
  uint8_t      keystream[64];
  unsigned int text_offset = 0;
  
  size_t bytes_remaining = plaintext_length;
  while (bytes_remaining != 0) {
    // Generate keystream block, increment position for next loop
    chacha20_block(ctx, keystream);
    ctx->state[12]++;
    
    //                 min(bytes_remaining, 64)
    size_t xor_bytes = (bytes_remaining > 64 ? 64 : bytes_remaining);
    for (int i = 0; i < xor_bytes; i++) {
      ciphertext[text_offset + i] = keystream[i] ^ plaintext[text_offset + i];
    }
    
	text_offset     += xor_bytes;
    bytes_remaining -= xor_bytes;
  }
}
