#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "chacha20.h"

void chacha20_init_state(struct chacha20_context* ctx, uint32_t key[8],
                         uint32_t nonce[3], uint32_t counter) {
  uint32_t* state = ctx->state;
  state[0] = 0x61707865;
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

uint32_t rol(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

void chacha20_do_quarter_round(uint32_t state[16], int ai, int bi, int ci,
                               int di) {
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

void chacha20_do_round(uint32_t state[16]) {
  chacha20_do_quarter_round(state, 0, 4, 8, 12);
  chacha20_do_quarter_round(state, 1, 5, 9, 13);
  chacha20_do_quarter_round(state, 2, 6, 10, 14);
  chacha20_do_quarter_round(state, 3, 7, 11, 15);
  chacha20_do_quarter_round(state, 0, 5, 10, 15);
  chacha20_do_quarter_round(state, 1, 6, 11, 12);
  chacha20_do_quarter_round(state, 2, 7, 8, 13);
  chacha20_do_quarter_round(state, 3, 4, 9, 14);
}

void chacha20_serialize_state(struct chacha20_context* ctx, char dest[64]) {
  memcpy(dest, ctx->state, 64);
}

void chacha20_block(struct chacha20_context* ctx) {
  uint32_t working_state[16];
  memcpy(working_state, ctx->state, 16 * sizeof(uint32_t));
  for (int i = 0; i < 10; ++i) {
    chacha20_do_round(working_state);
  }
  for (int i = 0; i < 16; ++i) {
    ctx->state[i] += working_state[i];
  }
}

void chacha20_dump_state(struct chacha20_context* ctx) {
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      printf("%08x ", ctx->state[4 * i + j]);
    }
    printf("\n");
  }
}

void chacha20_encrypt(struct chacha20_context* ctx, char* plaintext,
                      size_t plaintext_length, char* ciphertext) {
  size_t plaintext_blocks = plaintext_length >> 6;
  char serialize_buffer[64];
  for (int j = 0; j < plaintext_blocks; ++j) {
    struct chacha20_context key_ctx;
    memcpy(&key_ctx, ctx, sizeof(key_ctx));
    key_ctx.state[12] += j;  // horrid.
    chacha20_block(&key_ctx);
    chacha20_serialize_state(&key_ctx, serialize_buffer);
    for (int k = 0; k < 64; ++k) {
      ciphertext[j * 64 + k] = serialize_buffer[k] ^ plaintext[j * 64 + k];
    }
  }
  size_t remainder = plaintext_length % 64;
  if (remainder != 0) {
    struct chacha20_context key_ctx;
    memcpy(&key_ctx, ctx, sizeof(key_ctx));
    key_ctx.state[12] += plaintext_blocks;  // horrid.
    chacha20_block(&key_ctx);
    chacha20_serialize_state(&key_ctx, serialize_buffer);
    for (int k = 0; k < remainder; ++k) {
      ciphertext[plaintext_blocks * 64 + k] =
        serialize_buffer[k] ^ plaintext[plaintext_blocks * 64 + k];
    }
  }
}
