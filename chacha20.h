#include <stdint.h>

/* Context for a ChaCha20 block. */
struct chacha20_context {
  uint32_t state[16];
};

/* Initializes the state in a ChaCha20 context. The counter should be
   incremented for every block in the stream, while the nonce should be created
   anew once per stream. */
void chacha20_init_state(struct chacha20_context* ctx, uint32_t key[8],
                         uint32_t nonce[3], uint32_t counter);

/* Runs the ChaCha20 algorithm to create a block of the keystream. */
void chacha20_block(struct chacha20_context* ctx);

/* Serializes the ChaCha20 state into a keystream block, to be xor'd with
   the plaintext. */
void chacha20_serialize_state(struct chacha20_context* ctx, char dest[64]);

/* Encrypt the plaintext, with length plaintext_length, into the ciphertext. */
void chacha20_encrypt(struct chacha20_context* ctx, char* plaintext,
                      size_t plaintext_length, char* ciphertext);

/* Dumps a human-readable representation of the ChaCha20 state to stdout. */
void chacha20_dump_state(struct chacha20_context* ctx);
