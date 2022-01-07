#include "poly1305.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void poly1305_clamp(unsigned char r[16]) {
  r[3] &= 15;
  r[7] &= 15;
  r[11] &= 15;
  r[15] &= 15;
  r[4] &= 252;
  r[8] &= 252;
  r[12] &= 252;
}

void poly1305_mac(unsigned char key[32], char* plaintext,
                  size_t plaintext_length, unsigned char tag[16]) {
  memset(tag, 0, 16);
  mpz_t r, s;
  mpz_inits(r, s, NULL);

  // We must clamp r before loading it as a number.
  poly1305_clamp(key); 
  mpz_import(r, 1, 1, 16, -1, 0, key); 
  mpz_import(s, 1, 1, 16, -1, 0, key + 16); 

  gmp_printf("r = %Zx\ns = %Zx\n", r, s);

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

  gmp_printf("p = %Zd\n", p);

  mpz_t n, nadd;
  mpz_inits(n, nadd, NULL);
  for (int i = 0; i < plaintext_length; i += 16) {
    // j will be the number of bytes in this block.
    int j = i + 16;
    if (j > plaintext_length) j = plaintext_length;
    j -= i;

    mpz_import(n, 1, 1, j, -1, 0, plaintext + i); 

    // We must add 2^(8 * j) to n.
    mpz_mul_2exp(nadd, one, 8 * j);
    mpz_add(a, a, nadd);

    mpz_add(a, a, n);
    mpz_mul(a, a, r);
    mpz_mod(a, a, p);

    printf("A block of %d bytes.\n", j);
    gmp_printf("  It has n = %Zx.\n  After, a = %Zx.\n", n, a);
  }

  mpz_add(a, a, s);
  gmp_printf("The final accumulator is %Zx.\n", a);

  mpz_export(tag, NULL, -1, 1, 0, 0, a);
 
  mpz_clears(a, r, s, p, one, n, nadd, NULL);
}
