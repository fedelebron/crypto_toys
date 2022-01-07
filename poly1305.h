#include <stddef.h>

/* Computes the 128-bit Poly1305 MAC given a 256-bit key and an arbitrary 
   length plaintext. The key must meet the properties explained in IETF RFC
   7539.
*/
void poly1305_mac(unsigned char key[32], char* plaintext,
                  size_t plaintext_length, unsigned char tag[16]);
