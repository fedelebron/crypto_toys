#include "aead_chacha20_poly1305.h"
#include <stdio.h>

int main() {
  char plaintext[114] = "Ladies and Gentlemen of the class of '99: If I could "
                        "offer you only one tip for the future, sunscreen "
                        "would be it.";
  char additional_data[12] = {'P', 'Q', 'R', 'S', 0xc0, 0xc1,
                              0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};
  uint32_t key[8] = {0x83828180, 0x87868584, 0x8b8a8988, 0x8f8e8d8c,
                     0x93929190, 0x97969594, 0x9b9a9998, 0x9f9e9d9c};

  uint32_t nonce[3] = {7, 0x43424140, 0x47464544};

  uint8_t tag[16];
  aead_chacha20_poly1305_encrypt(key, nonce, plaintext, 114, additional_data,
                                 12, tag);

  printf("Ciphertext:\n");
  for (int i = 0; i < 8; ++i) {
	for (int j = 0; j < 16; ++j) {
	  int idx = 16 * i + j;
	  if (idx >= 114) break;
	  printf("%02x ", (unsigned char)plaintext[idx]);
	}
	printf("\n");
  }
  printf("Tag:\n");
  for (int i = 0; i < 16; ++i) {
    if (i > 0) printf(":");
    printf("%02x", (unsigned char)tag[i]);
  }
  printf("\n");

  int success = aead_chacha20_poly1305_decrypt(
      key, nonce, plaintext, /*plaintext_length=*/114, additional_data,
      /*additional_data_length=*/12, tag);

  if (success != 0) {
    fprintf(stderr, "Failed to authenticate encrypted message.\n");
    return success;
  }

  printf("Authentication successful.\nDecrypted message:\n");
  for (int i = 0; i < 114; ++i) {
    printf("%c", plaintext[i]);
  }
  printf("\n");

  return 1;
}
