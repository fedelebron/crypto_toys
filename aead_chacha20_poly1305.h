#ifndef AEAD_CHACHA20_POLY1305_H
#define AEAD_CHACHA20_POLY1305_H
#pragma once

#include <stdint.h>
#include <stddef.h>

/* Encrypts the given plaintext, and MACs the plaintext and the additional data,
   outputing a 128-bit tag. */
void aead_chacha20_poly1305_encrypt(uint32_t key[8], uint32_t nonce[3],
                                    char* plaintext, size_t plaintext_length,
                                    const char* additional_data,
                                    size_t additional_data_length,
                                    uint8_t tag[16]);

/* Decrypts the AEAD ciphertext, validating the additional data. If the
   computed tag does not correspond to the authenticated data, the function
   does not write the decrypted data to ciphertext, and returns 0. Otherwise,
   the decrypted data is written to ciphertext, and 0 is returned. */
int aead_chacha20_poly1305_decrypt(uint32_t key[8], uint32_t nonce[3],
                                   char* ciphertext, size_t ciphertext_length,
                                   const char* additional_data,
                                   size_t additional_data_length,
                                   uint8_t tag[16]);


#endif /* AEAD_CHACHA20_POLY1305_H */
