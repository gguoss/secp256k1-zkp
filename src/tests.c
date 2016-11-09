/**********************************************************************
 * Copyright (c) 2013-2016 Pieter Wuille, Gregory Maxwell Gavin Guo   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include "include/sdc_common.h"
#include "secp256k1.c"

#ifdef ENABLE_OPENSSL_TESTS
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"
#endif

#include "contrib/lax_der_parsing.c"
#include "contrib/lax_der_privatekey_parsing.c"

#if !defined(VG_CHECK)
# if defined(VALGRIND)
#  include <valgrind/memcheck.h>
#  define VG_UNDEF(x,y) VALGRIND_MAKE_MEM_UNDEFINED((x),(y))
#  define VG_CHECK(x,y) VALGRIND_CHECK_MEM_IS_DEFINED((x),(y))
# else
#  define VG_UNDEF(x,y)
#  define VG_CHECK(x,y)
# endif
#endif

static secp256k1_context *ctx = NULL;

void sdc_help()
{
    printf("1-sdc_rand256() return(sk pk)\n");
    printf("2-sdc_share_blind(sk_self, pk_target) return(sk_share, pk_share)\n");
    printf("3-sdc_pedersen_commit(sk, amount) return(commit)\n");
    printf("4-sdc_rangeproof_sign(sk, commit, amount, EXP, MINBIT) return(proof)\n");
    printf("5-sdc_rangeproof_verify(commit, proof) return(min, max)\n");
    printf("6-sdc_pedersen_blind_sum(sk_base, '+'or'-', commit_diff, commit_new) return ('True'or'False'\n");
    printf("8-sdc_encrypt(pk, message_origin) return(message)\n");
    printf("9-sdc_decrypt(sk, message) return(message_origin)\n");
    printf("10-sdc_pedersen_blind_utxo(sk_in_list, sk_out_list) return(sk_out_result)\n");
    printf("11-sdc_pedersen_verify_utxo(commit_in_list, commit_out_list) return('True'or'False')\n");
}

void atomic_print(unsigned char elm)
{
    if (elm & 0xf0) {
        printf("%x", elm);
    }
    else {
        printf("0%x", elm);
    }
}

void print(const unsigned char *str, int len) {
    int i = 0;
    for (; i < len - 1; i++) {
        atomic_print(str[i]);
    }
    atomic_print(str[i]);
    printf("\n");
}

unsigned char char2hex(unsigned char byte)
{
    return byte - '0' < 10 ? byte - '0' : byte - 'a' + 10;
}

int parse(const unsigned char *str, unsigned char *data)
{
    int i = 0;
    for (; i < strlen(str); i = i + 2) {
        data[i/2] = char2hex(str[i]) * 16 + char2hex(str[i + 1]);
    }
    return i/2;
}

void sdc_pedersen_blind_utxo(char *argv2, char *argv3)
{
    char seps[] = ",";
    char *token;
    int pct = 0, nct = 0;
    unsigned char blinds[10][32];
    token = strtok(argv2, seps);
    while (token != NULL) {
        if (parse(token, blinds[pct++]) != 32) {
            perror("input blind error, not 32 bytes.\n");
            abort();
        }
        token = strtok(NULL, seps);
    }
    token = strtok(argv3, seps);
    while (token != NULL) {
        if (parse(token, blinds[pct + nct++])!= 32) {
            perror("output blind error. not 32 bytes.\n");
            abort();
        }
        token = strtok(NULL, seps);
    }
    unsigned char blind_out[32];
    const unsigned char *bptr[10];
    int i = 0;
    for (; i < pct + nct; i++) {
        bptr[i] = blinds[i];
    }
    secp256k1_pedersen_blind_sum(ctx, blind_out, bptr, pct + nct, pct);
    printf("sk_out_result:");
    print(blind_out, 32);
}

void sdc_pedersen_verify_utxo(char *argv2, char *argv3)
{
    char seps[] = ",";
    char *token;
    int pct = 0, nct = 0;
    unsigned char pcommits[10][33];
    unsigned char ncommits[10][33];
    token = strtok(argv2, seps);
    while (token != NULL) {
        if (parse(token, pcommits[pct++]) != 33) {
            perror("cin input commits error, not 33 bytes.\n");
            abort();
        }
        token = strtok(NULL, seps);
    }
    token = strtok(argv3, seps);
    while (token != NULL) {
        if (parse(token, ncommits[nct++]) != 33) {
            perror("cin output commits error, not 33 bytes.\n");
            abort();
        }
        token = strtok(NULL, seps);
    }
    int i;
    const unsigned char *cptr[10];
    for (i = 0; i < pct; i++) {
        cptr[i] = pcommits[i];
    }
    for (; i < pct + nct; i++) {
        cptr[i] = ncommits[i - pct];
    }
    if (secp256k1_pedersen_verify_tally(ctx, &cptr[0], pct, &cptr[pct], nct, 0)) {
        printf("Result:True\n");
    }
    else {
        printf("Result:False\n");
    }
}

int main(int argc, char **argv) {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_pedersen_context_initialize(ctx);
    secp256k1_rangeproof_context_initialize(ctx);
    if (argc == 1) {
        sdc_help();
    }
    else {
        if (memcmp(argv[1], "sdc_rand256", 11) == 0) {
            secp256k1_pubkey pubkey;
            secp256k1_privkey privkey;
            sdc_rand256(ctx, &pubkey, &privkey);
            printf("%s", "sk:");
            print(privkey.data, 32);
            printf("%s", "pk:");
            print(pubkey.data, 64);
        }
        else if (memcmp(argv[1], "sdc_share_blind", 15) == 0) {
            secp256k1_privkey privkey;
            if (parse(argv[2], privkey.data) != 32) {
                perror("privkey lenth not equal 32.");
                abort();
            }
            secp256k1_pubkey pubkey;
            if (parse(argv[3], pubkey.data) != 64) {
                perror("pubkey lenth not equal 64.");
                abort();
            }
            sdc_sharekey sharekey;
            secp256k1_pubkey sharepubkey;
            sdc_share_blind(ctx, &sharekey, &sharepubkey, &pubkey, &privkey);
            printf("sk_share:");
            print(sharekey.data, 32);
            printf("pk_share:");
            print(sharepubkey.data, 64);
        }
        else if (memcmp(argv[1], "sdc_pedersen_commit", 18) == 0) {
            secp256k1_privkey privkey;
            if (parse(argv[2], privkey.data) != 32) {
                perror("privkey lenth not equal 32.");
                abort();
            }
            uint64_t value = atol(argv[3]);
            sdc_commit commit;
            sdc_pedersen_commit(ctx, &commit, &privkey, value);
            printf("commit:");
            print(commit.data, 33);
        }
        else if (memcmp(argv[1], "sdc_rangeproof_sign", 19) == 0) {
            secp256k1_privkey privkey;
            if (parse(argv[2], privkey.data) != 32) {
                perror("privkey lenth not euqal 32.");
                abort();
            }
            sdc_commit commit;
            if (parse(argv[3], commit.data) != 33) {
                perror("commit--argv[3] not equal 33");
                abort();
            }
            unsigned char nonce[32] = {};
            unsigned char time_str[48];
            time_t timep;
            struct tm *p;
            time(&timep);
            p = localtime(&timep);
            sprintf(time_str, "%d%d%d%d%d%d", p->tm_year, p->tm_mon, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec);
            secp256k1_rfc6979_hmac_sha256_initialize(&secp256k1_test_rng, time_str, 48);
            secp256k1_rand256(nonce);

            uint64_t value = atol(argv[4]);
            int exp = atoi(argv[5]);
            int min_bits = atoi(argv[6]);
            sdc_proof proof;
            sdc_rangeproof_sign(ctx, &proof, 0, &commit, &privkey, nonce, exp, min_bits, value);
            printf("proof:");
            print(proof.data, proof.len);
            printf("proof_len:%d\n", proof.len);
        }
        else if (memcmp(argv[1], "sdc_rangeproof_verify", 20) == 0) {
            uint64_t min_value;
            uint64_t max_value;
            sdc_commit commit;
            if (parse(argv[2], commit.data) != 33) {
                perror("commit argv[2] is not 33");
                abort();
            }
            sdc_proof proof;
            proof.len = parse(argv[3], proof.data);
            sdc_rangeproof_verify(ctx, &min_value, &max_value, &commit, &proof);
            printf("min:%llu\nmax:%llu\n", min_value, max_value);
        }
        else if (memcmp(argv[1], "sdc_pedersen_blind_sum", 20) == 0) {
            secp256k1_privkey k1, k2, blind_out;
            if (parse(argv[2], k1.data) != 32) {
                perror("sk_base not 32bytes.");
                abort();
            }
            unsigned char opt;
            if (memcmp(argv[3], "+", 1) == 0) {
                opt = '+';
            }
            else if (memcmp(argv[3], "-", 1) == 0) {
                opt = '-';
            }
            else {
                perror("only + or -.");
                abort();
            }
            if (parse(argv[4], k2.data) != 32) {
                perror("sk_diff not 32 bytes.");
                abort();
            }
            sdc_pedersen_blind_sum(ctx, &k1, opt, &k2, &blind_out);
            printf("sk_new:");
            print(blind_out.data, 32);
        }
        else if (memcmp(argv[1], "sdc_pedersen_verify_tally", 25) == 0) {
            sdc_commit commitP, commitN1, commitN2;
            if (parse(argv[2], commitP.data) != 33) {
                perror("commit_base must 33 bytes.");
                abort();
            }
            unsigned char opt;
            if (memcmp(argv[3], "+", 1) == 0) {
                opt = '+';
            }
            else if (memcmp(argv[3], "-", 1) == 0) {
                opt = '-';
            }
            else {
                perror("only + or -.");
                abort();
            }
            if (parse(argv[4], commitN1.data) != 33) {
                perror("commit_diff must 33 bytes.");
                abort();
            }
            if (parse(argv[5], commitN2.data) != 33) {
                perror("commit_new must 33 bytes.");
                abort();
            }
            int success = sdc_pedersen_verify_tally(ctx, &commitP, opt, &commitN1, &commitN2);
            if (success) {
                printf("result:True\n");
            }
            else {
                printf("result:False\n");
            }
        }
        else if (memcmp(argv[1], "sdc_encrypt", 11) == 0) {
            ERR_load_crypto_strings();
            OpenSSL_add_all_algorithms();
            OPENSSL_config(NULL);
            const unsigned char *iv = "aes-128-ctr";
            unsigned char pk[33];
            if (parse(argv[2], pk) != 32) {
                perror("pk lenth must 32 bytes.");
                abort();
            }
            pk[33] = '\0';
            unsigned char plaintext[1024] = {};
            int plaintext_len = strlen(argv[3]);
            memcpy(plaintext, argv[3], plaintext_len);
            unsigned char ciphertext[1024] = {};
            int ciphertext_len = sdc_encrypt(plaintext, plaintext_len, pk, iv, ciphertext);
            printf("ciphertext:");
            print(ciphertext, ciphertext_len);
            printf("ciphertext_len:%d\n", ciphertext_len);
            EVP_cleanup();
            ERR_free_strings();
        }
        else if (memcmp(argv[1], "sdc_decrypt", 11) == 0) {
            ERR_load_crypto_strings();
            OpenSSL_add_all_algorithms();
            OPENSSL_config(NULL);
            const unsigned char *iv = "aes-128-ctr";
            unsigned char sk[33];
            if (parse(argv[2], sk) != 32) {
                perror("sk must 32 bytes.\n");
                abort();
            }
            sk[32] = '\0';
            unsigned char ciphertext[1024] = {};
            int ciphertext_len = strlen(argv[3]) / 2;
            if (parse(argv[3], ciphertext) != ciphertext_len) {
                perror("ciphertext parse error.\n");
                abort();
            }
            unsigned char plaintext[1024] = {};
            int plaintext_len = sdc_decrypt(ciphertext, ciphertext_len, sk, iv, plaintext);
            printf("plaintext:");
            int i;
            for (i = 0; i < plaintext_len; i++) {
                printf("%c", plaintext[i]);
            }
            printf("\nplaintext_len:%d\n", plaintext_len);
            EVP_cleanup();
            ERR_free_strings();
        }
        else if (memcmp(argv[1], "sdc_pedersen_blind_utxo", 23) == 0) {
            if (argc == 3) {
                sdc_pedersen_blind_utxo(argv[2], NULL);
            }
            else if (argc == 4) {
                sdc_pedersen_blind_utxo(argv[2], argv[3]);
            }
            else {
                perror("parametes error.\n");
                abort();
            }
        }
        else if (memcmp(argv[1], "sdc_pedersen_verify_utxo", 24) == 0) {
            if (argc == 3) {
                sdc_pedersen_verify_utxo(argv[2], NULL);
            }
            else if (argc == 4) {
                sdc_pedersen_verify_utxo(argv[2], argv[3]);
            }
            else {
                perror("parametes error.\n");
                abort();
            }
        }
        else {
            printf("parameters error.");
        }
    }
    secp256k1_context_destroy(ctx);
    return 0;
}
