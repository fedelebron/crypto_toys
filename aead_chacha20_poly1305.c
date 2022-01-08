#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "chacha20.h"
#include "poly1305.h"

void write_8_byte_le(char* dest, uint64_t number) {
  *dest++ = 0xFF & number;
  *dest++ = 0xFF & (number >> 8);
  *dest++ = 0xFF & (number >> 16);
  *dest++ = 0xFF & (number >> 24);
  *dest++ = 0xFF & (number >> 32);
  *dest++ = 0xFF & (number >> 40);
  *dest++ = 0xFF & (number >> 48);
  *dest   = 0xFF & (number >> 56);
}

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
  write_8_byte_le(message, additional_data_length);
  message += 8;
  write_8_byte_le(message, plaintext_length);
  
  poly1305_mac(poly1305_key, original_message, message_length, tag);

  free(original_message);
}
  

int aead_chacha20_poly1305_decrypt(uint32_t key[8], uint32_t nonce[3],
                                   char* ciphertext, size_t ciphertext_length,
                                   const char* additional_data,
                                   size_t additional_data_length,
                                   uint8_t tag[16]) {
  struct chacha20_context ctx;
  chacha20_init_state(&ctx, key, nonce, /*counter=*/0);

  // Only the first 32 bytes of this will be used for the key.
  uint8_t poly1305_key[64];
  chacha20_block(&ctx, poly1305_key);
  
  // The authenticated message will be the concatenation of:
  // * The authenticated data.
  // * Zero-padding of the authenticated data up to a multiple of 16 bytes.
  // * The ciphertext.
  // * Zero-padding of the ciphertext up to a multiple of 16 bytes.
  // * The length of the additional data as a 64-bit LE integer.
  // * The length of the ciphertext as a 64-bit LE integer.
  size_t padding1 = 16 - (additional_data_length & 0xF);
  size_t padding2 = 16 - (ciphertext_length & 0xF);
  size_t message_length =
      additional_data_length + padding1 + ciphertext_length + padding2 + 8 + 8;
  char* message = malloc(message_length);
  char* original_message = message;

  memcpy(message, additional_data, additional_data_length);
  message += additional_data_length;
  memset(message, 0, padding1);
  message += padding1;
  memcpy(message, ciphertext, ciphertext_length);
  message += ciphertext_length;
  memset(message, 0, padding2);
  message += padding2;
  write_8_byte_le(message, additional_data_length);
  message += 8;
  write_8_byte_le(message, ciphertext_length);
  
  uint8_t resulting_tag[16];
  poly1305_mac(poly1305_key, original_message, message_length, resulting_tag);

  for (int i = 0; i < 16; ++i) {
    if (tag[i] != resulting_tag[i]) return 1;
  }

  
  ctx.state[CHACHA_COUNTER] = 1;
  chacha20_encrypt(&ctx, ciphertext, ciphertext_length);

  free(original_message);

  return 0;
}
