#ifndef POLY1305_H
#define POLY1305_H
#pagman once


#include <stddef.h>
#include <stdint.h>

/* Computes the 128-bit Poly1305 MAC given a 256-bit key and an arbitrary 
   length plaintext. The key must meet the properties explained in IETF RFC
   7539.
*/
void poly1305_mac(uint8_t key[32], char* plaintext,
                  size_t plaintext_length, uint8_t tag[16]);



#endif /* POLY1305_H */
