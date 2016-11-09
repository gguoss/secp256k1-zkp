/**********************************************************************
 * Copyright (c) 2015-2016 Andrew Poelstra  Gavin Guo                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_ECDH_MAIN_
#define _SECP256K1_MODULE_ECDH_MAIN_

#include "include/sdc_common.h"
#include "include/secp256k1_ecdh.h"
#include "ecmult_const_impl.h"

int secp256k1_ecdh(const secp256k1_context* ctx, unsigned char *result, const secp256k1_pubkey *point, const unsigned char *scalar) {
    int ret = 0;
    int overflow = 0;
    secp256k1_gej res;
    secp256k1_ge pt;
    secp256k1_scalar s;
    ARG_CHECK(result != NULL);
    ARG_CHECK(point != NULL);
    ARG_CHECK(scalar != NULL);
    (void)ctx;

    secp256k1_pubkey_load(ctx, &pt, point);
    secp256k1_scalar_set_b32(&s, scalar, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&s)) {
        ret = 0;
    } else {
        unsigned char x[32];
        unsigned char y[1];
        secp256k1_sha256_t sha;

        secp256k1_ecmult_const(&res, &pt, &s);
        secp256k1_ge_set_gej(&pt, &res);
        /* Compute a hash of the point in compressed form
         * Note we cannot use secp256k1_eckey_pubkey_serialize here since it does not
         * expect its output to be secret and has a timing sidechannel. */
        secp256k1_fe_normalize(&pt.x);
        secp256k1_fe_normalize(&pt.y);
        secp256k1_fe_get_b32(x, &pt.x);
        y[0] = 0x02 | secp256k1_fe_is_odd(&pt.y);

        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, y, sizeof(y));
        secp256k1_sha256_write(&sha, x, sizeof(x));
        secp256k1_sha256_finalize(&sha, result);
        ret = 1;
    }

    secp256k1_scalar_clear(&s);
    return ret;
}

int sdc_share_blind(
    const secp256k1_context *ctx,
    sdc_sharekey *sharekey,
    secp256k1_pubkey *sharepubkey,
    const secp256k1_pubkey *pubkey,
    const secp256k1_privkey *privkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4)
{
    ARG_CHECK(sharekey != NULL);
    if (1 == secp256k1_ecdh(ctx, sharekey->data, pubkey, privkey->data)) {
        return secp256k1_ec_pubkey_create(ctx, sharepubkey, sharekey->data);
    }
    else {
        return 0;
    }
}

#endif
