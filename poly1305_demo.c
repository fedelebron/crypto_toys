#include "poly1305.h"
#include <stdio.h>

int main(void) {
  unsigned char key[32] = {0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
                           0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
                           0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
                           0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b};
  char plaintext[34] = "Cryptographic Forum Research Group";
  size_t plaintext_length = 34;
  
  unsigned char tag[16];
  poly1305_mac(key, plaintext, plaintext_length,  tag);
  
  for (int i = 0; i < 16; ++i) {
    if (i > 0) printf(":");
    printf("%02x", tag[i]);
  }
  printf("\n");
}
