#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "chacha20.h"
#include "poly1305.h"

void aead_chacha20_poly1305_encrypt(uint32_t key[8], uint32_t nonce[3],
                                    char* plaintext, size_t plaintext_length,
                                    const char* additional_data,
                                    size_t additional_data_length,
                                    uint8_t tag[16]) {
  struct chacha20_context ctx;
  chacha20_init_state(&ctx, key, nonce, /*counter=*/0);

  // Only the first 32 bytes of this will be used for the key.
  uint8_t poly1305_key[64];
  chacha20_block(&ctx, poly1305_key);
  
  ctx.state[CHACHA_COUNTER] = 1;
  // We cast to char* here,
  chacha20_encrypt(&ctx, plaintext, plaintext_length);

  // The authenticated message will be the concatenation of:
  // * The authenticated data.
  // * Zero-padding of the authenticated data up to a multiple of 16 bytes.
  // * The ciphertext.
  // * Zero-padding of the ciphertext up to a multiple of 16 bytes.
  // * The length of the additional data as a 64-bit LE integer.
  // * The length of the ciphertext as a 64-bit LE integer.
  size_t padding1 = 16 - (additional_data_length & 0xF);
  size_t padding2 = 16 - (plaintext_length & 0xF);
  size_t message_length =
      additional_data_length + padding1 + plaintext_length + padding2 + 8 + 8;
  char* message = malloc(message_length);
  char* original_message = message;

  memcpy(message, additional_data, additional_data_length);
  message += additional_data_length;
  memset(message, 0, padding1);
  message += padding1;
  // Note the plaintext has been encrypted at this point, we are writing the
  // ciphertext here.
  memcpy(message, plaintext, plaintext_length);
  message += plaintext_length;
  memset(message, 0, padding2);
  message += padding2;
  uint64_t additional_data_length_64 = additional_data_length;
  *message++ = 0xFF & additional_data_length_64;
  *message++ = 0xFF & (additional_data_length_64 >> 8);
  *message++ = 0xFF & (additional_data_length_64 >> 16);
  *message++ = 0xFF & (additional_data_length_64 >> 24);
  *message++ = 0xFF & (additional_data_length_64 >> 32);
  *message++ = 0xFF & (additional_data_length_64 >> 40);
  *message++ = 0xFF & (additional_data_length_64 >> 48);
  *message++ = 0xFF & (additional_data_length_64 >> 56);
  uint64_t plaintext_length_64 = plaintext_length;
  *message++ = 0xFF & plaintext_length_64;
  *message++ = 0xFF & (plaintext_length_64 >> 8);
  *message++ = 0xFF & (plaintext_length_64 >> 16);
  *message++ = 0xFF & (plaintext_length_64 >> 24);
  *message++ = 0xFF & (plaintext_length_64 >> 32);
  *message++ = 0xFF & (plaintext_length_64 >> 40);
  *message++ = 0xFF & (plaintext_length_64 >> 48);
  *message++ = 0xFF & (plaintext_length_64 >> 56);
  
  poly1305_mac(poly1305_key, original_message, message_length, tag);

  free(original_message);
}
