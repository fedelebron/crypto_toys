#include <stdint.h>
#include <gmp.h>

void poly1305_mac(unsigned char key[32], char* plaintext, size_t plaintext_length, unsigned char tag[16]);
