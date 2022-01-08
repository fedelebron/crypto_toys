#include <stdio.h>
#include <stdint.h>

#include "chacha20.h"

int main() {
  /* IVs from the RFC. */
  uint32_t key[8] = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                     0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c};
  uint32_t nonce[3] = {0x9000000, 0x4a000000, 0x00000000};
  uint32_t count = 1;
  
  uint8_t buffer[64];
  
  struct chacha20_context ctx;
  chacha20_init_state(&ctx, key, nonce, count);
  
  printf("=== Single block computation ===\n");
  printf("Initial block:\n");
  chacha20_debug_state(&ctx);
  
  printf("Final block:\n");
  chacha20_debug_block(&ctx);
  
  printf("Keystream block:\n");
  chacha20_block(&ctx, buffer);
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 16; ++j) {
      printf("%02x ", (unsigned char)buffer[16 * i + j]);
    }
    printf("\n");
  }
  
  printf("=== Full stream encryption calculation ===\n");
  // We change the nonce as per the RFC.
  nonce[0] = 0x00000000;
  chacha20_init_state(&ctx, key, nonce, count);
  
  char plaintext[114] = "Ladies and Gentlemen of the class of '99: If I could "
                        "offer you only one tip for the future, sunscreen "
                        "would be it.";
  
  char ciphertext[114];
  chacha20_encrypt(&ctx, plaintext, 114, ciphertext);
  
  printf("Ciphertext:\n");
  for (int i = 0; i < 8; ++i) {
    for (int j = 0; j < 16; ++j) {
      int idx = 16 * i + j;
      if (idx >= 114) break;
      printf("%02x ", (unsigned char)ciphertext[idx]);
    }
    printf("\n");
  }
  
  
  
  return 0;
}
