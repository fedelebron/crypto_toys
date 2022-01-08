#include "poly1305.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>

void poly1305_clamp(unsigned char r[16]) {
  r[3] &= 15;
  r[7] &= 15;
  r[11] &= 15;
  r[15] &= 15;
  r[4] &= 252;
  r[8] &= 252;
  r[12] &= 252;
}

void poly1305_mac(uint8_t key[32], char* plaintext,
                  size_t plaintext_length, uint8_t tag[16]) {
  // The gist of this function is computing:
  // a = s + \sum_{i=0}^{n-1} b_i * r^{n - i}
  // where b_i is 2^(8 * j) times the i'th 16-byte block of plaintext, and j is
  // the length in bytes of that 16-byte block, which can be less than 16 for
  // the last block, which may need to be zero-padded. The blocks are read
  // as little-endian 16-byte words.
  // Here (r, s) = key, where we ensure some properties about r just in case,
  // via clamping.

  memset(tag, 0, 16);
  mpz_t r, s;
  mpz_inits(r, s, NULL);

  // We must clamp r before loading it as a number.
  poly1305_clamp(key); 
  mpz_import(r, 1, 1, 16, -1, 0, key); 
  mpz_import(s, 1, 1, 16, -1, 0, key + 16); 

  // The RFC has a typo and calls this `accumulator` here, and
  // nowhere else.
  mpz_t a;
  mpz_init(a);

  // p = 2^130 - 5.
  mpz_t p, one;
  mpz_inits(p, one, NULL);
  mpz_set_ui(one, 1);
  mpz_mul_2exp(p, one, 130);
  mpz_sub_ui(p, p, 5);


  mpz_t n, nadd;
  mpz_inits(n, nadd, NULL);
  for (int i = 0; i < plaintext_length; i += 16) {
    // j will be the number of bytes in this block.
    int j = i + 16;
    if (j > plaintext_length) j = plaintext_length;
    j -= i;

    mpz_import(n, 1, 1, j, -1, 0, plaintext + i); 

    // We must add 2^(8 * j) to n, before adding n to a.
    mpz_mul_2exp(nadd, one, 8 * j);
    mpz_add(a, a, nadd);

    // a := ((a + n) * r) % p .
    mpz_add(a, a, n);
    mpz_mul(a, a, r);
    mpz_mod(a, a, p);
  }

  mpz_add(a, a, s);

  mpz_export(tag, NULL, -1, 1, 0, 0, a);
 
  mpz_clears(a, r, s, p, one, n, nadd, NULL);
}
