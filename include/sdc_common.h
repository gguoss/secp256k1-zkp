/* copyriht 2016, author:GavinGuo*/

#ifndef _SDC_COMMON_H_
#define _SDC_COMMON_H_

#include "secp256k1.h"
#include "secp256k1_ecdh.h"
#include "secp256k1_rangeproof.h"

typedef struct {
  unsigned char data[32];
} secp256k1_privkey, sdc_sharekey;

typedef struct {
  unsigned char data[33];
} sdc_commit;

typedef struct {
  unsigned char data[5134];
  int len;
} sdc_proof;

/* Compute the public key for a secret key.
 * Returns: 1: secret was valid, public key stores
 *          0: secret was invalid, try again
 * Args:    ctx: pointer to a context object, initialized for signing (cannot be NULL)
 * Out:     pubkey: pointer to the created public key (cannot be NULL)
 * Out:     privkey: pointer to the created private key (cannot be NULL)	    
 *
 */
int sdc_rand256(const secp256k1_context *ctx,
		secp256k1_pubkey *pubkey,
        secp256k1_privkey *privkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Compute an EC Diffie-Hellman secret in constant time
 *  Returns: 1: exponentiation was successful
 *           0: scalar was invalid (zero or overflow)
 *  Args:    ctx: pointer to a context object (cannot be NULL)
 *  Out:     sdc_sharekey: a 32-byte array which will be poplated by an ECDH
 *           secp256k1_pubkey: a 64-byte. secret computed from the point and scalar
 *  In:      pubkey: a pointer to a secp256k1_pubkey containing an initialized public key
 *           privkey: a 32-byte scalar with which to multiply the pointer
 */
int sdc_share_blind(
    const secp256k1_context *ctx,
    sdc_sharekey *sharekey,
    secp256k1_pubkey *sharepubkey,
    const secp256k1_pubkey *pubkey,
    const secp256k1_privkey *privkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Generate a pedersen commitment.
 *  Returns 1: commitment successfully created.
 *          0: error
 *  In:     ctx: pointer to a context object, initialized for signing and Pedersen commitment (cannot be NULL)
 *          privkey: pointer to a 32-byte blinding factor (cannot be NULL)
 *          value: unsigned 64-bit integer value to commit to.
 *  Out:    commit: pointer to a 33-byte array for the commitment (cannot be NULL)
 *
 *  Blinding factors can be generated and verified in the same way as secp256k1 private keys for ECDSA.
 */
int sdc_pedersen_commit(
    const secp256k1_context *ctx,
    sdc_commit *commit,
    const secp256k1_privkey *privkey,
    const uint64_t value
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

int sdc_rangeproof_sign(
    const secp256k1_context *ctx,
    sdc_proof *proof,
    const uint64_t min_value,
    const sdc_commit *commit,
    const secp256k1_privkey *privkey,
    const unsigned char *nonce,
    const int exp,
    const int min_bits,
    const uint64_t value
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

int sdc_rangeproof_verify(
    const secp256k1_context *ctx,
    uint64_t *min_value,
    uint64_t *max_value,
    const sdc_commit *commit,
    const sdc_proof *proof
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

int sdc_pedersen_blind_sum(
    const secp256k1_context *ctx,
    const secp256k1_privkey *k1,
    const unsigned char opt,
    const secp256k1_privkey *k2,
    secp256k1_privkey *blind_out
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

int sdc_pedersen_verify_tally(
    const secp256k1_context *ctx,
    const sdc_commit *commitP,
    const unsigned char opt,
    const sdc_commit *commitN1,
    const sdc_commit *commitN2
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

int sdc_encrypt(
    unsigned char *plaintext,
    int plaintext_len,
    unsigned char *key,
    unsigned char *iv,
    unsigned char *ciphertext);

int sdc_decrypt(
    unsigned char *ciphertext,
    int ciphertext_len,
    unsigned char *key,
    unsigned char *iv,
    unsigned char *plaintext);

#endif
