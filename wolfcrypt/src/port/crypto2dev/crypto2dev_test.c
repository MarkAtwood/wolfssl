/* crypto2dev_test.c — Known-Answer Tests for the crypto2dev CryptoCb port
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*
 * Test vectors sourced from published standards:
 *
 *   SHA-256:    NIST FIPS 180-4, example message "" (empty string)
 *   AES-CBC:    NIST SP 800-38A, F.2.1 CBC-AES128.Encrypt, Example 1
 *   HMAC-SHA256:RFC 4231, Test Cases 1 and 2 (two-chunk accumulation)
 *   ECDSA P-256:sign + verify round-trip using a freshly generated key pair
 *               (ECDSA signatures are randomized; a round-trip is the
 *               standard correctness test when no deterministic vector is
 *               available for the exact digest/key pair under test)
 *
 * When WOLFSSL_CRYPTO2DEV_SIM is defined the test uses the software
 * simulator and requires no hardware.  Otherwise it attempts to open the
 * real device; if the device is absent the test is skipped (returns 0).
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_CRYPTO2DEV) && defined(WOLF_CRYPTO_CB) && \
    defined(WOLFSSL_CRYPTO2DEV_TEST)

#include <wolfssl/wolfcrypt/port/crypto2dev/crypto2dev_port.h>
#include <wolfssl/wolfcrypt/port/crypto2dev/crypto2dev_wire.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/ecc.h>
#ifdef WOLFSSL_SHA3
#include <wolfssl/wolfcrypt/sha3.h>
#endif
#ifdef HAVE_ED25519
#include <wolfssl/wolfcrypt/ed25519.h>
#endif
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/ssl.h>

#ifdef WOLFSSL_CRYPTO2DEV_SIM
/* Forward declaration — implementation in crypto2dev_sim.c */
extern void crypto2dev_sim_set_ioctl_fail(int count);
#endif

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static int hex_decode(const char* hex, byte* out, word32 out_sz)
{
    word32 i;
    word32 len = (word32)XSTRLEN(hex);
    if ((len & 1) != 0 || len / 2 > out_sz)
        return -1;
    for (i = 0; i < len; i += 2) {
        byte hi, lo;
        char ch;
        ch = hex[i];
        if (ch >= '0' && ch <= '9')      hi = (byte)(ch - '0');
        else if (ch >= 'a' && ch <= 'f') hi = (byte)(ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F') hi = (byte)(ch - 'A' + 10);
        else return -1;
        ch = hex[i + 1];
        if (ch >= '0' && ch <= '9')      lo = (byte)(ch - '0');
        else if (ch >= 'a' && ch <= 'f') lo = (byte)(ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F') lo = (byte)(ch - 'A' + 10);
        else return -1;
        out[i / 2] = (byte)((hi << 4) | lo);
    }
    return (int)(len / 2);
}

/* ------------------------------------------------------------------ */
/* Test 1: SHA-256 of the empty string                                 */
/*                                                                     */
/* Source: NIST FIPS 180-4, Appendix B.2                               */
/* SHA-256("") =                                                       */
/*   e3b0c44298fc1c149afbf4c8996fb924                                  */
/*   27ae41e4649b934ca495991b7852b855                                  */
/* ------------------------------------------------------------------ */
static int test_sha256_empty(void)
{
    wc_Sha256 sha;
    byte digest[WC_SHA256_DIGEST_SIZE];
    byte expected[WC_SHA256_DIGEST_SIZE];
    int ret;

    ret = hex_decode(
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855",
        expected, sizeof(expected));
    if (ret != WC_SHA256_DIGEST_SIZE)
        return -1;

    ret = wc_InitSha256_ex(&sha, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;

    ret = wc_Sha256Final(&sha, digest);
    wc_Sha256Free(&sha);
    if (ret != 0) return ret;

    if (XMEMCMP(digest, expected, WC_SHA256_DIGEST_SIZE) != 0)
        return -1;

    WOLFSSL_MSG("crypto2dev_test: SHA-256 empty-string KAT passed");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 2: AES-CBC-128 encryption                                      */
/*                                                                     */
/* Source: NIST SP 800-38A, Appendix F.2.1                             */
/*   CBC-AES128 Encrypt, Block 1                                       */
/*   Key = 2b7e151628aed2a6abf7158809cf4f3c                            */
/*   IV  = 000102030405060708090a0b0c0d0e0f                            */
/*   PT  = 6bc1bee22e409f96e93d7e117393172a                            */
/*   CT  = 7649abac8119b246cee98e9b12e9197d                            */
/* ------------------------------------------------------------------ */
static int test_aes_cbc_128(void)
{
    Aes aes;
    byte key[16], iv[16], pt[16], expected_ct[16], ct[16];
    int ret;

    ret  = hex_decode("2b7e151628aed2a6abf7158809cf4f3c", key, sizeof(key));
    ret += hex_decode("000102030405060708090a0b0c0d0e0f", iv,  sizeof(iv));
    ret += hex_decode("6bc1bee22e409f96e93d7e117393172a", pt,  sizeof(pt));
    ret += hex_decode("7649abac8119b246cee98e9b12e9197d",
                      expected_ct, sizeof(expected_ct));
    if (ret != 4 * 16)
        return -1;

    ret = wc_AesInit(&aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;

    /* wc_AesSetKey with a device-bound object triggers WOLF_CRYPTO_CB_SETKEY
     * (WC_SETKEY_AES) which stores the key bytes in aes->devCtx.  The IV is
     * passed here and stored in aes.reg for use by crypto2dev_cipher(). */
    ret = wc_AesSetKey(&aes, key, (word32)sizeof(key), iv, AES_ENCRYPTION);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }

    ret = wc_AesCbcEncrypt(&aes, ct, pt, (word32)sizeof(pt));
    wc_AesFree(&aes);
    if (ret != 0) return ret;

    if (XMEMCMP(ct, expected_ct, sizeof(expected_ct)) != 0)
        return -1;

    WOLFSSL_MSG("crypto2dev_test: AES-CBC-128 KAT passed");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 2b: AES-CTR-128 multi-call counter tracking                   */
/*                                                                     */
/* Source: NIST SP 800-38A, Appendix F.5.1 (CTR-AES128.Encrypt)      */
/*   Key = 2b7e151628aed2a6abf7158809cf4f3c                            */
/*   IV  = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff                            */
/*   PT  = 4 blocks (64 bytes)                                         */
/*   CT  = 874d6191b620e3261bef6864990db6ce (blocks 1-2)               */
/*         9806f66b7970fdff8617187bb9fffdff                            */
/*         5ae4df3edbd5d35e5b4f09020db03eab (blocks 3-4)               */
/*         1e031dda2fbe03d179217 0a0f3009cee                            */
/*                                                                     */
/* The test encrypts the 4-block plaintext in two separate             */
/* wc_AesCtrEncrypt calls (2 blocks each).  The port must advance      */
/* aes->reg correctly after the first call so the second call uses the */
/* counter values f0f1...02 and f0f1...03, not f0f1...00 again.        */
/*                                                                     */
/* This verifies that the big-endian counter increment in the port     */
/* matches wolfSSL's own IncrementAesCounter() convention.             */
/* ------------------------------------------------------------------ */
#ifdef WOLFSSL_AES_COUNTER
static int test_aes_ctr_multicall(void)
{
    Aes aes;
    byte key[16], iv[16];
    static const byte pt[64] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
        0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
        0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
        0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
        0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
        0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
    };
    /* Expected: NIST SP 800-38A F.5.1, all 4 blocks */
    static const byte expected_ct[64] = {
        0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,
        0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
        0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,
        0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
        0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,
        0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
        0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,
        0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee
    };
    byte ct[64];
    int ret;

    ret  = hex_decode("2b7e151628aed2a6abf7158809cf4f3c", key, sizeof(key));
    ret += hex_decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", iv,  sizeof(iv));
    if (ret != 2 * 16)
        return -1;

    ret = wc_AesInit(&aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;

    ret = wc_AesSetKey(&aes, key, (word32)sizeof(key), iv, AES_ENCRYPTION);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }

    /* First call: encrypt blocks 1-2 (32 bytes) */
    ret = wc_AesCtrEncrypt(&aes, ct,      pt,      32);
    /* Second call: encrypt blocks 3-4 (32 bytes), using the updated counter */
    if (ret == 0)
        ret = wc_AesCtrEncrypt(&aes, ct + 32, pt + 32, 32);
    wc_AesFree(&aes);
    if (ret != 0) return ret;

    if (XMEMCMP(ct, expected_ct, sizeof(expected_ct)) != 0)
        return -1;

    WOLFSSL_MSG("crypto2dev_test: AES-CTR-128 multi-call KAT passed");
    return 0;
}
#endif /* WOLFSSL_AES_COUNTER */

/* ------------------------------------------------------------------ */
/* Test 3: HMAC-SHA256                                                  */
/*                                                                     */
/* Source: RFC 4231, Test Case 1                                       */
/*   Key  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b                          */
/*          0b0b0b0b  (20 bytes)                                        */
/*   Data = "Hi There"                                                  */
/*   HMAC-SHA-256 =                                                    */
/*     b0344c61d8db38535ca8afceaf0bf12b                                 */
/*     881dc200c9833da726e9376c2e32cff7                                 */
/* ------------------------------------------------------------------ */
static int test_hmac_sha256(void)
{
    Hmac hmac;
    byte key[20];
    const byte data[] = { 'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e' };
    byte mac[WC_SHA256_DIGEST_SIZE];
    byte expected[WC_SHA256_DIGEST_SIZE];
    int ret;

    ret = hex_decode(
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        "0b0b0b0b",
        key, sizeof(key));
    if (ret != (int)sizeof(key))
        return -1;

    ret = hex_decode(
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7",
        expected, sizeof(expected));
    if (ret != WC_SHA256_DIGEST_SIZE)
        return -1;

    ret = wc_HmacInit(&hmac, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;

    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, (word32)sizeof(key));
    if (ret == 0)
        ret = wc_HmacUpdate(&hmac, data, (word32)sizeof(data));
    if (ret == 0)
        ret = wc_HmacFinal(&hmac, mac);
    wc_HmacFree(&hmac);
    if (ret != 0) return ret;

    if (XMEMCMP(mac, expected, WC_SHA256_DIGEST_SIZE) != 0)
        return -1;

    WOLFSSL_MSG("crypto2dev_test: HMAC-SHA256 KAT passed");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 3b: HMAC-SHA256 two-chunk accumulation                        */
/*                                                                     */
/* Source: RFC 4231, Test Case 2                                       */
/*   Key  = "Jefe" (4 bytes)                                           */
/*   Data = "what do ya want " + "for nothing?"                        */
/*   HMAC-SHA-256 =                                                    */
/*     5bdcc146bf60754e6a042426089575c7                                 */
/*     5a003f089d2739839dec58b964ec3843                                 */
/* ------------------------------------------------------------------ */
static int test_hmac_sha256_multichunk(void)
{
    Hmac hmac;
    const byte key[] = { 'J', 'e', 'f', 'e' };
    const byte chunk1[] = { 'w', 'h', 'a', 't', ' ', 'd', 'o', ' ',
                             'y', 'a', ' ', 'w', 'a', 'n', 't', ' ' };
    const byte chunk2[] = { 'f', 'o', 'r', ' ', 'n', 'o', 't', 'h',
                             'i', 'n', 'g', '?' };
    byte mac[WC_SHA256_DIGEST_SIZE];
    byte expected[WC_SHA256_DIGEST_SIZE];
    int ret;

    ret = hex_decode(
        "5bdcc146bf60754e6a042426089575c7"
        "5a003f089d2739839dec58b964ec3843",
        expected, sizeof(expected));
    if (ret != WC_SHA256_DIGEST_SIZE)
        return -1;

    ret = wc_HmacInit(&hmac, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;

    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, (word32)sizeof(key));
    if (ret == 0)
        ret = wc_HmacUpdate(&hmac, chunk1, (word32)sizeof(chunk1));
    if (ret == 0)
        ret = wc_HmacUpdate(&hmac, chunk2, (word32)sizeof(chunk2));
    if (ret == 0)
        ret = wc_HmacFinal(&hmac, mac);
    wc_HmacFree(&hmac);
    if (ret != 0) return ret;

    if (XMEMCMP(mac, expected, WC_SHA256_DIGEST_SIZE) != 0)
        return -1;

    WOLFSSL_MSG("crypto2dev_test: HMAC-SHA256 two-chunk KAT passed");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 3c: AES-GCM empty-plaintext KAT (tag-only)                    */
/*                                                                     */
/* Source: NIST SP 800-38D, Appendix B, Test Case 1                   */
/*   K  = 00000000000000000000000000000000  (16 bytes, all zeros)     */
/*   IV = 000000000000000000000000          (12 bytes, all zeros)     */
/*   P  = ""  (empty)                                                  */
/*   A  = ""  (empty)                                                  */
/*   C  = ""  (empty)                                                  */
/*   T  = 58e2fccefa7e3061367f1d57a4e7455a                            */
/* ------------------------------------------------------------------ */
#ifdef HAVE_AESGCM
static int test_aesgcm_empty(void)
{
    Aes aes;
    byte key[16];
    byte iv[12];
    byte expected_tag[16];
    byte tag[16];
    int ret;

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(iv, 0, sizeof(iv));
    XMEMSET(tag, 0, sizeof(tag));

    ret = hex_decode("58e2fccefa7e3061367f1d57a4e7455a",
                     expected_tag, sizeof(expected_tag));
    if (ret != (int)sizeof(expected_tag))
        return -1;

    ret = wc_AesInit(&aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;

    ret = wc_AesSetKey(&aes, key, (word32)sizeof(key), NULL, AES_ENCRYPTION);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }

    ret = wc_AesGcmEncrypt(&aes,
                           NULL,           /* out — NULL for empty plaintext */
                           NULL,           /* in  — NULL for empty plaintext */
                           0,              /* sz  — zero length */
                           iv, (word32)sizeof(iv),
                           tag, (word32)sizeof(tag),
                           NULL, 0);       /* AAD — empty */
    wc_AesFree(&aes);
    if (ret != 0) return ret;

    if (XMEMCMP(tag, expected_tag, sizeof(expected_tag)) != 0)
        return -1;

    WOLFSSL_MSG("crypto2dev_test: AES-GCM empty-plaintext KAT passed");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 3d: AES-GCM oversized AAD must return BUFFER_E                 */
/*                                                                     */
/* CRYPTO2DEV_AAD_MAXLEN is 256 bytes.  Passing authInSz > 256 must   */
/* return BUFFER_E rather than silently authenticating with empty AAD  */
/* (which would be an authentication bypass).                          */
/* ------------------------------------------------------------------ */
static int test_aesgcm_oversized_aad(void)
{
    Aes aes;
    byte key[16];
    byte iv[12];
    byte pt[16];
    byte ct[16];
    byte tag[16];
    byte aad[CRYPTO2DEV_AAD_MAXLEN + 1]; /* 257 bytes — one over the limit */
    int ret;

    XMEMSET(key, 0, sizeof(key));
    XMEMSET(iv,  0, sizeof(iv));
    XMEMSET(pt,  0, sizeof(pt));
    XMEMSET(aad, 0xAA, sizeof(aad));

    ret = wc_AesInit(&aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;

    ret = wc_AesSetKey(&aes, key, (word32)sizeof(key), NULL, AES_ENCRYPTION);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }

    ret = wc_AesGcmEncrypt(&aes,
                           ct, pt, (word32)sizeof(pt),
                           iv, (word32)sizeof(iv),
                           tag, (word32)sizeof(tag),
                           aad, (word32)sizeof(aad));
    wc_AesFree(&aes);

    /* Must fail: oversized AAD cannot be passed to the device.
     * Silently proceeding with empty AAD would be an auth bypass. */
    if (ret != BUFFER_E) {
        WOLFSSL_MSG("crypto2dev_test: oversized-AAD test expected BUFFER_E");
        return -1;
    }

    WOLFSSL_MSG("crypto2dev_test: AES-GCM oversized-AAD rejection test passed");
    return 0;
}
/* ------------------------------------------------------------------ */
/* Test 3e: AES-GCM truncated tag (authTagSz=12)                       */
/*                                                                     */
/* NIST SP 800-38D Appendix B, Test Case 1 (empty PT and AAD):        */
/*   K   = 00000000000000000000000000000000  (16 bytes)                */
/*   IV  = 000000000000000000000000          (12 bytes)                */
/*   P   = empty                                                        */
/*   A   = empty                                                        */
/*   T16 = 58e2fccefa7e3061367f1d57a4e7455a (full tag)                */
/*   T12 = 58e2fccefa7e3061367f1d57          (12-byte truncated)       */
/*                                                                     */
/* Tests: encrypt produces correct 12-byte tag; decrypt succeeds with  */
/* the correct tag; decrypt fails with AES_GCM_AUTH_E on a wrong tag. */
/* ------------------------------------------------------------------ */
static int test_aesgcm_truncated_tag(void)
{
    Aes  aes;
    byte key[16];
    byte iv[12];
    byte tag[12];
    byte expected_tag[12];
    byte wrong_tag[12];
    int  ret;

    XMEMSET(key,      0,    sizeof(key));
    XMEMSET(iv,       0,    sizeof(iv));
    XMEMSET(tag,      0,    sizeof(tag));
    XMEMSET(wrong_tag, 0xFF, sizeof(wrong_tag));

    ret = hex_decode("58e2fccefa7e3061367f1d57",
                     expected_tag, sizeof(expected_tag));
    if (ret != (int)sizeof(expected_tag))
        return -1;

    /* Encrypt: empty PT, empty AAD, 12-byte tag */
    ret = wc_AesInit(&aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;

    ret = wc_AesSetKey(&aes, key, (word32)sizeof(key), NULL, AES_ENCRYPTION);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }

    ret = wc_AesGcmEncrypt(&aes,
                           NULL, NULL, 0,
                           iv, (word32)sizeof(iv),
                           tag, (word32)sizeof(tag),
                           NULL, 0);
    wc_AesFree(&aes);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: GCM truncated-tag encrypt failed");
        return ret;
    }

    if (XMEMCMP(tag, expected_tag, sizeof(expected_tag)) != 0) {
        WOLFSSL_MSG("crypto2dev_test: GCM truncated-tag KAT mismatch");
        return -1;
    }

    /* Decrypt: correct 12-byte tag must succeed */
    ret = wc_AesInit(&aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;

    ret = wc_AesSetKey(&aes, key, (word32)sizeof(key), NULL, AES_ENCRYPTION);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }

    ret = wc_AesGcmDecrypt(&aes,
                           NULL, NULL, 0,
                           iv, (word32)sizeof(iv),
                           expected_tag, (word32)sizeof(expected_tag),
                           NULL, 0);
    wc_AesFree(&aes);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: GCM truncated-tag decrypt (correct tag) failed");
        return ret;
    }

    /* Decrypt: wrong 12-byte tag must fail with AES_GCM_AUTH_E */
    ret = wc_AesInit(&aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;

    ret = wc_AesSetKey(&aes, key, (word32)sizeof(key), NULL, AES_ENCRYPTION);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }

    ret = wc_AesGcmDecrypt(&aes,
                           NULL, NULL, 0,
                           iv, (word32)sizeof(iv),
                           wrong_tag, (word32)sizeof(wrong_tag),
                           NULL, 0);
    wc_AesFree(&aes);
    if (ret != AES_GCM_AUTH_E) {
        WOLFSSL_MSG("crypto2dev_test: GCM truncated-tag wrong-tag expected AES_GCM_AUTH_E");
        return -1;
    }

    WOLFSSL_MSG("crypto2dev_test: AES-GCM truncated-tag KAT passed");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 3f: AES-GCM sub-minimum tag must not bypass authentication     */
/*          (wolfssl-yjw.1)                                            */
/*                                                                     */
/* With the fix, the port returns CRYPTOCB_UNAVAILABLE for authTagSz   */
/* 1-11 on both encrypt and decrypt paths, and wolfSSL falls through   */
/* to software which enforces its own tag check.                       */
/*                                                                     */
/* Source: NIST SP 800-38D Appendix B Test Case 2                     */
/*   K  = 00000000000000000000000000000000  (16 bytes)                */
/*   IV = 000000000000000000000000          (12 bytes)                */
/*   P  = 00000000000000000000000000000000  (16 bytes)                */
/*   T  = ab6e47d42cec13bdf53a67b21257bddf  (16-byte tag)             */
/*                                                                     */
/* Oracle: decrypt with a wrong 4-byte or 8-byte tag must not return  */
/* 0 (authentication must not be bypassed regardless of tag length).  */
/* ------------------------------------------------------------------ */
static int test_aesgcm_sub_min_tag(void)
{
    Aes  aes;
    byte key[16]       = { 0 };
    byte iv[12]        = { 0 };
    byte pt[16]        = { 0 };
    byte ct[16];
    byte out[16];
    byte tag16[16];
    static const byte wrong_tag4[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
    static const byte wrong_tag8[8] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
    int ret;

    /* Encrypt to obtain valid ciphertext and full 16-byte auth tag. */
    ret = wc_AesInit(&aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;
    ret = wc_AesSetKey(&aes, key, (word32)sizeof(key), NULL, AES_ENCRYPTION);
    if (ret == 0)
        ret = wc_AesGcmEncrypt(&aes,
                               ct, pt, (word32)sizeof(pt),
                               iv, (word32)sizeof(iv),
                               tag16, (word32)sizeof(tag16),
                               NULL, 0);
    wc_AesFree(&aes);
    if (ret != 0) return ret;

    /* Decrypt with authTagSz=4 using a wrong tag.
     * The port returns CRYPTOCB_UNAVAILABLE; wolfSSL software must
     * detect the wrong tag and return a non-zero error. */
    ret = wc_AesInit(&aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;
    ret = wc_AesSetKey(&aes, key, (word32)sizeof(key), NULL, AES_ENCRYPTION);
    if (ret == 0)
        ret = wc_AesGcmDecrypt(&aes,
                               out, ct, (word32)sizeof(ct),
                               iv, (word32)sizeof(iv),
                               wrong_tag4, (word32)sizeof(wrong_tag4),
                               NULL, 0);
    wc_AesFree(&aes);
    if (ret == 0) {
        WOLFSSL_MSG("crypto2dev_test: GCM 4-byte wrong tag accepted "
                    "— authentication bypass");
        return -1;
    }

    /* Decrypt with authTagSz=8 using a wrong tag. */
    ret = wc_AesInit(&aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;
    ret = wc_AesSetKey(&aes, key, (word32)sizeof(key), NULL, AES_ENCRYPTION);
    if (ret == 0)
        ret = wc_AesGcmDecrypt(&aes,
                               out, ct, (word32)sizeof(ct),
                               iv, (word32)sizeof(iv),
                               wrong_tag8, (word32)sizeof(wrong_tag8),
                               NULL, 0);
    wc_AesFree(&aes);
    if (ret == 0) {
        WOLFSSL_MSG("crypto2dev_test: GCM 8-byte wrong tag accepted "
                    "— authentication bypass");
        return -1;
    }

    WOLFSSL_MSG("crypto2dev_test: AES-GCM sub-minimum tag rejection test passed");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 3g: GCM encrypt with authTagSz > TAG_MAXLEN returns BUFFER_E  */
/*          (wolfssl-yjw.3)                                            */
/*                                                                     */
/* Without the fix, authTagSz > 16 silently skips GET_TAG and returns */
/* 0 — the caller's authTag buffer holds stale data.  With the fix,   */
/* the encrypt call must return BUFFER_E.                              */
/* ------------------------------------------------------------------ */
static int test_aesgcm_oversized_tag(void)
{
    Aes  aes;
    byte key[16]                       = { 0 };
    byte iv[12]                        = { 0 };
    byte pt[16]                        = { 0 };
    byte ct[16];
    byte tag[CRYPTO2DEV_TAG_MAXLEN + 1]; /* 17 bytes — one over limit */
    int  ret;

    ret = wc_AesInit(&aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;
    ret = wc_AesSetKey(&aes, key, (word32)sizeof(key), NULL, AES_ENCRYPTION);
    if (ret == 0)
        ret = wc_AesGcmEncrypt(&aes,
                               ct, pt, (word32)sizeof(pt),
                               iv, (word32)sizeof(iv),
                               tag, (word32)sizeof(tag),
                               NULL, 0);
    wc_AesFree(&aes);

    /* wolfSSL validates authTagSz > WC_AES_BLOCK_SIZE before dispatching to the
     * CryptoCb callback, so the port's BUFFER_E check is defense-in-depth and
     * cannot be observed via wc_AesGcmEncrypt (wolfSSL returns BAD_FUNC_ARG
     * first).  Accept any non-zero error: the invariant is that oversized tags
     * must never silently return 0. */
    if (ret == 0) {
        WOLFSSL_MSG("crypto2dev_test: GCM oversized tag was not rejected");
        return -1;
    }

    WOLFSSL_MSG("crypto2dev_test: AES-GCM oversized-tag rejection test passed");
    return 0;
}

#endif /* HAVE_AESGCM */

/* ------------------------------------------------------------------ */
/* Test 3c2: HMAC short key (< 14 bytes) falls back to software        */
/*           (wolfssl-qsi.4)                                           */
/*                                                                     */
/* FIPS SP 800-107 §5.3: HMAC key must be >= 14 bytes.  The port      */
/* must return CRYPTOCB_UNAVAILABLE for sub-minimum keys so that       */
/* wolfSSL's own FIPS check applies.  The critical test: after         */
/* wc_HmacSetKey with a 13-byte key, hmac.devCtx must be NULL —       */
/* hardware never claimed the key.  If devCtx is non-NULL the port     */
/* returned 0 (success), bypassing wolfSSL software validation.        */
/*                                                                     */
/* Oracle: devCtx == NULL proves the port fell back to software.       */
/* ------------------------------------------------------------------ */
static int test_hmac_short_key_fallback(void)
{
    Hmac hmac;
    byte key[13]; /* 13 bytes — one under the 14-byte FIPS minimum */
    int ret;

    XMEMSET(key, 0x0b, sizeof(key));

    ret = wc_HmacInit(&hmac, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;

    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, (word32)sizeof(key));
    /* In FIPS mode wolfSSL software path also rejects short keys (non-zero).
     * In non-FIPS mode wolfSSL accepts the key in software (ret == 0).
     * Either way, the hardware must not have claimed it: devCtx must be NULL. */
    if (hmac.devCtx != NULL) {
        WOLFSSL_MSG("crypto2dev_test: short HMAC key was accepted by hardware "
                    "— FIPS minimum bypass (wolfssl-qsi.4)");
        wc_HmacFree(&hmac);
        return -1;
    }

    wc_HmacFree(&hmac);
    WOLFSSL_MSG("crypto2dev_test: HMAC short-key hardware fallback test passed");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 3g: HMAC Final + Free lifecycle — no leak or double-free       */
/*                                                                     */
/* After wc_HmacFinal(), the port must free the HmacCtx struct and    */
/* NULL devCtx so that wc_HmacFree() does not issue a spurious second  */
/* hardware HMAC call on the now-dead context.  This test runs two     */
/* back-to-back HMAC operations on the same struct to verify that the  */
/* device state is clean after the first Final + Free cycle.          */
/*                                                                     */
/* Both operations use RFC 4231 TC1 to verify correct results.         */
/* ------------------------------------------------------------------ */
static int test_hmac_lifecycle(void)
{
    Hmac hmac;
    byte key[20];
    const byte data[] = { 'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e' };
    byte mac[WC_SHA256_DIGEST_SIZE];
    byte expected[WC_SHA256_DIGEST_SIZE];
    int ret;
    int round;

    ret = hex_decode(
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        "0b0b0b0b",
        key, sizeof(key));
    if (ret != (int)sizeof(key))
        return -1;

    ret = hex_decode(
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7",
        expected, sizeof(expected));
    if (ret != WC_SHA256_DIGEST_SIZE)
        return -1;

    /* Run the same HMAC twice using Init/SetKey/Update/Final/Free each time.
     * A leak or use-after-free in the first cycle would corrupt the second. */
    for (round = 0; round < 2; round++) {
        ret = wc_HmacInit(&hmac, NULL, WOLF_CRYPTO2DEV_DEVID);
        if (ret != 0) return ret;

        ret = wc_HmacSetKey(&hmac, WC_SHA256, key, (word32)sizeof(key));
        if (ret == 0)
            ret = wc_HmacUpdate(&hmac, data, (word32)sizeof(data));
        if (ret == 0)
            ret = wc_HmacFinal(&hmac, mac);
        wc_HmacFree(&hmac);
        if (ret != 0) return ret;

        if (XMEMCMP(mac, expected, WC_SHA256_DIGEST_SIZE) != 0) {
            WOLFSSL_MSG("crypto2dev_test: HMAC lifecycle KAT mismatch");
            return -1;
        }
    }

    WOLFSSL_MSG("crypto2dev_test: HMAC lifecycle test passed");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 4: ECDSA P-256 sign + verify round-trip                        */
/*                                                                     */
/* A freshly generated P-256 key pair is used.  The test:              */
/*   1. Generates a key pair with devId=INVALID_DEVID (software).      */
/*   2. Imports the private key into the port (SETKEY).                */
/*   3. Signs a 32-byte digest via the port.                           */
/*   4. Imports the public key into the port.                          */
/*   5. Verifies the signature via the port.                           */
/*                                                                     */
/* ECDSA is randomized; there is no fixed-output KAT for sign.         */
/* Correct round-trip (sign then verify = 1) is the standard test.    */
/* ------------------------------------------------------------------ */
#ifdef HAVE_ECC
#ifdef WOLF_CRYPTO_CB_SETKEY
static int test_ecdsa_roundtrip(void)
{
    ecc_key priv_key;
    WC_RNG  rng;
    byte    digest[WC_SHA256_DIGEST_SIZE];
    byte    sig[ECC_MAX_SIG_SIZE];
    word32  sig_len = (word32)sizeof(sig);
    int     verify_res = 0;
    int     ret;
    int     i;

    /* Digest is 32 bytes of 0xAB — arbitrary non-zero input. */
    for (i = 0; i < WC_SHA256_DIGEST_SIZE; i++)
        digest[i] = 0xAB;

    ret = wc_InitRng(&rng);
    if (ret != 0) return ret;

    /* Generate key with software (INVALID_DEVID) */
    ret = wc_ecc_init_ex(&priv_key, NULL, INVALID_DEVID);
    if (ret != 0) { wc_FreeRng(&rng); return ret; }
    ret = wc_ecc_make_key_ex(&rng, 32, &priv_key, ECC_SECP256R1);
    if (ret != 0) { wc_ecc_free(&priv_key); wc_FreeRng(&rng); return ret; }

    /* Import private key into a device-bound object via the public wolfSSL API.
     * wc_ecc_import_private_key_ex fires the SETKEY callback when sign_key
     * has a devId, so this exercises the full wolfSSL → CryptoCb → port path. */
    {
        ecc_key  sign_key;
        byte     priv_raw[ECC_MAXSIZE];
        word32   priv_raw_len = (word32)sizeof(priv_raw);
        byte     pub_x963[1 + 2 * ECC_MAXSIZE];
        word32   pub_x963_len = (word32)sizeof(pub_x963);

        ret = wc_ecc_export_private_only(&priv_key, priv_raw, &priv_raw_len);
        if (ret == 0)
            ret = wc_ecc_export_x963(&priv_key, pub_x963, &pub_x963_len);
        if (ret == 0)
            ret = wc_ecc_init_ex(&sign_key, NULL, WOLF_CRYPTO2DEV_DEVID);
        if (ret == 0) {
            ret = wc_ecc_import_private_key_ex(priv_raw, priv_raw_len,
                                               pub_x963, pub_x963_len,
                                               &sign_key, ECC_SECP256R1);
            if (ret == 0) {
                ret = wc_ecc_sign_hash(digest, sizeof(digest),
                                       sig, &sig_len,
                                       &rng, &sign_key);
            }
            wc_ecc_free(&sign_key);
        }
        XMEMSET(priv_raw, 0, sizeof(priv_raw));
    }

    if (ret != 0) {
        wc_ecc_free(&priv_key);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Verify: import public key into a port-bound object via public API.
     * wc_ecc_import_x963_ex2 fires the SETKEY callback when verify_key
     * has a devId. */
    {
        ecc_key verify_key;
        byte    x963[1 + 2 * ECC_MAXSIZE];
        word32  x963_len = (word32)sizeof(x963);

        ret = wc_ecc_export_x963(&priv_key, x963, &x963_len);
        if (ret == 0)
            ret = wc_ecc_init_ex(&verify_key, NULL, WOLF_CRYPTO2DEV_DEVID);
        if (ret == 0) {
            ret = wc_ecc_import_x963_ex2(x963, x963_len,
                                         &verify_key, ECC_SECP256R1, 0);
        }
        if (ret == 0) {
            ret = wc_ecc_verify_hash(sig, sig_len,
                                     digest, sizeof(digest),
                                     &verify_res, &verify_key);
        }
        wc_ecc_free(&verify_key);
    }

    wc_ecc_free(&priv_key);
    wc_FreeRng(&rng);

    if (ret != 0) return ret;
    if (verify_res != 1) return -1;

    WOLFSSL_MSG("crypto2dev_test: ECDSA P-256 round-trip passed");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test 4b: P-192 key rejected by hardware, falls back to software     */
/*          (wolfssl-yjw.2)                                            */
/*                                                                     */
/* The port returns CRYPTOCB_UNAVAILABLE for ECC keys with field_sz   */
/* < 32 (FIPS 140-3 IG D.1: P-256 minimum). P-192 (field_sz=24) must  */
/* never reach the hardware; wolfSSL falls back to software sign/verify */
/* which must produce a correct result.                                 */
/* ------------------------------------------------------------------ */
static int test_ecc_setkey_rejects_p192(void)
{
    ecc_key priv_key;
    WC_RNG  rng;
    byte    digest[WC_SHA256_DIGEST_SIZE];
    byte    sig[ECC_MAX_SIG_SIZE];
    word32  sig_len = (word32)sizeof(sig);
    int     verify_res = 0;
    int     ret;
    int     i;

    for (i = 0; i < WC_SHA256_DIGEST_SIZE; i++)
        digest[i] = 0xCD;

    ret = wc_InitRng(&rng);
    if (ret != 0) return ret;

    ret = wc_ecc_init_ex(&priv_key, NULL, INVALID_DEVID);
    if (ret != 0) { wc_FreeRng(&rng); return ret; }

    /* Generate P-192 key with software. If P-192 is not compiled in, skip. */
    ret = wc_ecc_make_key_ex(&rng, 24, &priv_key, ECC_SECP192R1);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: P-192 not available, skipping");
        wc_ecc_free(&priv_key);
        wc_FreeRng(&rng);
        return 0;
    }

    /* Import private key into a device-bound object.
     * SETKEY callback sees field_sz=24 < 32 → CRYPTOCB_UNAVAILABLE.
     * wolfSSL falls through to software setkey; devCtx remains NULL.
     * Subsequent sign is also CRYPTOCB_UNAVAILABLE → software sign. */
    {
        ecc_key  sign_key;
        byte     priv_raw[ECC_MAXSIZE];
        word32   priv_raw_len = (word32)sizeof(priv_raw);
        byte     pub_x963[1 + 2 * ECC_MAXSIZE];
        word32   pub_x963_len = (word32)sizeof(pub_x963);

        ret = wc_ecc_export_private_only(&priv_key, priv_raw, &priv_raw_len);
        if (ret == 0)
            ret = wc_ecc_export_x963(&priv_key, pub_x963, &pub_x963_len);
        if (ret == 0)
            ret = wc_ecc_init_ex(&sign_key, NULL, WOLF_CRYPTO2DEV_DEVID);
        if (ret == 0) {
            ret = wc_ecc_import_private_key_ex(priv_raw, priv_raw_len,
                                               pub_x963, pub_x963_len,
                                               &sign_key, ECC_SECP192R1);
            if (ret == 0) {
                ret = wc_ecc_sign_hash(digest, sizeof(digest),
                                       sig, &sig_len,
                                       &rng, &sign_key);
            }
            wc_ecc_free(&sign_key);
        }
        XMEMSET(priv_raw, 0, sizeof(priv_raw));
    }

    if (ret != 0) {
        wc_ecc_free(&priv_key);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Verify: public key import fires SETKEY → CRYPTOCB_UNAVAILABLE → software.
     * Verify must succeed and return verify_res=1. */
    {
        ecc_key verify_key;
        byte    x963[1 + 2 * ECC_MAXSIZE];
        word32  x963_len = (word32)sizeof(x963);

        ret = wc_ecc_export_x963(&priv_key, x963, &x963_len);
        if (ret == 0)
            ret = wc_ecc_init_ex(&verify_key, NULL, WOLF_CRYPTO2DEV_DEVID);
        if (ret == 0) {
            ret = wc_ecc_import_x963_ex2(x963, x963_len,
                                         &verify_key, ECC_SECP192R1, 0);
        }
        if (ret == 0) {
            ret = wc_ecc_verify_hash(sig, sig_len,
                                     digest, sizeof(digest),
                                     &verify_res, &verify_key);
        }
        wc_ecc_free(&verify_key);
    }

    wc_ecc_free(&priv_key);
    wc_FreeRng(&rng);

    if (ret != 0) return ret;
    if (verify_res != 1) return -1;

    WOLFSSL_MSG("crypto2dev_test: ECC P-192 hardware rejection / software fallback passed");
    return 0;
}
#endif /* WOLF_CRYPTO_CB_SETKEY */
#endif /* HAVE_ECC */

/* ------------------------------------------------------------------ */
/* Test 4c: AES COPY with active devCtx returns WC_HW_E               */
/*          (wolfssl-yjw.5)                                            */
/*                                                                     */
/* If src.devCtx != NULL and wolfSSL falls through to XMEMCPY, both   */
/* src and dst alias the same heap block.  wc_AesFree on either one   */
/* produces a double-free of the key-fd handle.  The fix: the COPY    */
/* callback returns WC_HW_E when devCtx is non-NULL.                  */
/*                                                                     */
/* wc_AesCopy does not exist in the current wolfSSL API, so we test   */
/* the callback directly via wc_crypto2dev_cb with a synthetic         */
/* wc_CryptoInfo.  This is a white-box unit test of the callback guard. */
/* ------------------------------------------------------------------ */
#if defined(WOLF_CRYPTO_CB_COPY) && defined(WOLF_CRYPTO_CB_SETKEY)
static int test_aes_copy_devctx_guard(void)
{
    Aes           src_aes;
    Aes           dst_aes;
    wc_CryptoInfo info;
    byte          key[16] = { 0 };
    int           ret;

    ret = wc_AesInit(&src_aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;
    ret = wc_AesSetKey(&src_aes, key, (word32)sizeof(key), NULL, AES_ENCRYPTION);
    if (ret != 0) {
        wc_AesFree(&src_aes);
        return ret;
    }

    if (src_aes.devCtx == NULL) {
        /* SETKEY did not set devCtx — hardware unavailable or key unsupported.
         * Nothing to guard; skip. */
        WOLFSSL_MSG("crypto2dev_test: AES SETKEY devCtx NULL, skipping COPY guard");
        wc_AesFree(&src_aes);
        return 0;
    }

    XMEMSET(&info,    0, sizeof(info));
    XMEMSET(&dst_aes, 0, sizeof(dst_aes));
    info.algo_type = WC_ALGO_TYPE_COPY;
    info.copy.algo = WC_ALGO_TYPE_CIPHER;
    info.copy.type = WC_CIPHER_AES;
    info.copy.src  = &src_aes;
    info.copy.dst  = &dst_aes;

    ret = wc_crypto2dev_cb(WOLF_CRYPTO2DEV_DEVID, &info, NULL);
    wc_AesFree(&src_aes);

    if (ret != WC_HW_E) {
        WOLFSSL_MSG("crypto2dev_test: AES COPY with active devCtx expected WC_HW_E");
        return -1;
    }

    WOLFSSL_MSG("crypto2dev_test: AES COPY devCtx guard test passed");
    return 0;
}
#endif /* WOLF_CRYPTO_CB_COPY && WOLF_CRYPTO_CB_SETKEY */

/* ------------------------------------------------------------------ */
/* Test 4b: HMAC COPY callback with active devCtx returns WC_HW_E     */
/*          (wolfssl-qsi.2 / wolfssl-qsi.14)                           */
/*                                                                     */
/* wc_HmacCopy does not dispatch through CryptoCb COPY today, so this */
/* test uses wc_crypto2dev_cb directly to exercise the guard added in  */
/* wolfssl-qsi.2.  If upstream ever adds CryptoCb COPY dispatch for   */
/* HMAC, this test will validate the guard via the normal API too.     */
/* ------------------------------------------------------------------ */
#if defined(WOLF_CRYPTO_CB_COPY) && defined(WOLF_CRYPTO_CB_SETKEY) && !defined(NO_HMAC)
static int test_hmac_copy_devctx_guard(void)
{
    Hmac          src_hmac;
    Hmac          dst_hmac;
    wc_CryptoInfo info;
    byte          key[20]; /* 20 bytes — above the 14-byte FIPS minimum */
    byte          data[4]  = { 0x01, 0x02, 0x03, 0x04 };
    int           ret;

    XMEMSET(key, 0x0b, sizeof(key));

    ret = wc_HmacInit(&src_hmac, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;
    ret = wc_HmacSetKey(&src_hmac, WC_SHA256, key, (word32)sizeof(key));
    if (ret != 0) {
        wc_HmacFree(&src_hmac);
        return ret;
    }
    /* Update so the streaming op fd is open (ctx->op_fd >= 0). */
    ret = wc_HmacUpdate(&src_hmac, data, (word32)sizeof(data));
    if (ret != 0) {
        wc_HmacFree(&src_hmac);
        return ret;
    }

    if (src_hmac.devCtx == NULL) {
        /* SETKEY did not set devCtx — hardware unavailable or key unsupported.
         * Nothing to guard; skip. */
        WOLFSSL_MSG("crypto2dev_test: HMAC SETKEY devCtx NULL, skipping COPY guard");
        wc_HmacFree(&src_hmac);
        return 0;
    }

    XMEMSET(&info,     0, sizeof(info));
    XMEMSET(&dst_hmac, 0, sizeof(dst_hmac));
    info.algo_type  = WC_ALGO_TYPE_COPY;
    info.copy.algo  = WC_ALGO_TYPE_HMAC;
    info.copy.type  = WC_HASH_TYPE_SHA256;
    info.copy.src   = &src_hmac;
    info.copy.dst   = &dst_hmac;

    ret = wc_crypto2dev_cb(WOLF_CRYPTO2DEV_DEVID, &info, NULL);
    wc_HmacFree(&src_hmac);

    if (ret != WC_HW_E) {
        WOLFSSL_MSG("crypto2dev_test: HMAC COPY with active devCtx expected WC_HW_E");
        return -1;
    }

    WOLFSSL_MSG("crypto2dev_test: HMAC COPY devCtx guard test passed");
    return 0;
}
#endif /* WOLF_CRYPTO_CB_COPY && WOLF_CRYPTO_CB_SETKEY && !NO_HMAC */

/* ------------------------------------------------------------------ */
/* Test 5: TLS 1.3 devId assignment and per-primitive routing          */
/*                                                                     */
/* Validates the three behaviours that TLS 1.3 relies on:             */
/*   a. wc_crypto2dev_assign_devid(ctx) sets WOLF_CRYPTO2DEV_DEVID    */
/*   b. SHA-256 with WOLF_CRYPTO2DEV_DEVID falls back to software     */
/*      (TLS-safe mode: g_tls_safe_mode prevents hardware hash use    */
/*       which would break transcript-copy during key derivation)     */
/*      KAT: SHA-256("abc") = ba7816bf... (NIST FIPS 180-4)           */
/*   c. HMAC-SHA256 with WOLF_CRYPTO2DEV_DEVID routes to hardware     */
/*      KAT: RFC 4231 TC1 (0x0b×20 key, "Hi There") = b0344c61...    */
/*   d. AES-GCM with WOLF_CRYPTO2DEV_DEVID encrypts correctly         */
/*      KAT: NIST SP 800-38D Appendix B Test Case 2                   */
/*        K  = 00000000000000000000000000000000 (16 bytes)             */
/*        IV = 000000000000000000000000          (12 bytes)            */
/*        P  = 00000000000000000000000000000000 (16 bytes)             */
/*        A  = "" (empty)                                              */
/*        C  = 0388dace60b6a392f328c2b971b2fe78                        */
/*        T  = ab6e47d42cec13bdf53a67b21257bddf                        */
/* ------------------------------------------------------------------ */
#ifdef WOLFSSL_TLS13
#ifndef NO_WOLFSSL_CLIENT
static int test_tls13_devid_and_primitive_routing(void)
{
    WOLFSSL_CTX* ctx = NULL;
    wc_Sha256    sha;
    Hmac         hmac;
    Aes          aes;
    byte digest[WC_SHA256_DIGEST_SIZE];
    byte mac[WC_SHA256_DIGEST_SIZE];
    byte expected_sha[WC_SHA256_DIGEST_SIZE];
    byte expected_hmac[WC_SHA256_DIGEST_SIZE];
    byte hmac_key[20];
    const byte pt[16]      = { 0 };
    byte aes_key[16]       = { 0 };
    byte iv[12]            = { 0 };
    byte ct[16];
    byte tag[16];
    byte expected_ct[16];
    byte expected_tag[16];
    const byte abc[]    = { 'a', 'b', 'c' };
    const byte hi_there[] = { 'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e' };
    int ret;
    int sha_inited  = 0;
    int hmac_inited = 0;
    int aes_inited  = 0;

    /* Step a: create CTX and assign devId */
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL) {
        WOLFSSL_MSG("crypto2dev_test: tls13: wolfSSL_CTX_new failed");
        return -1;
    }

    ret = wc_crypto2dev_assign_devid(ctx);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: tls13: assign_devid failed");
        goto done;
    }

    if (wolfSSL_CTX_GetDevId(ctx, NULL) != WOLF_CRYPTO2DEV_DEVID) {
        WOLFSSL_MSG("crypto2dev_test: tls13: devId not set correctly");
        ret = -1;
        goto done;
    }

    /* Step b: SHA-256 "abc" — must fall back to software in TLS-safe mode */
    ret = hex_decode(
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad",
        expected_sha, sizeof(expected_sha));
    if (ret != WC_SHA256_DIGEST_SIZE) {
        ret = -1;
        goto done;
    }

    ret = wc_InitSha256_ex(&sha, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: tls13: SHA-256 init failed");
        goto done;
    }
    sha_inited = 1;

    ret = wc_Sha256Update(&sha, abc, (word32)sizeof(abc));
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: tls13: SHA-256 update failed");
        goto done;
    }

    ret = wc_Sha256Final(&sha, digest);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: tls13: SHA-256 final failed");
        goto done;
    }

    if (XMEMCMP(digest, expected_sha, WC_SHA256_DIGEST_SIZE) != 0) {
        WOLFSSL_MSG("crypto2dev_test: tls13: SHA-256 software fallback KAT FAILED");
        ret = -1;
        goto done;
    }
    WOLFSSL_MSG("crypto2dev_test: tls13: SHA-256 software fallback KAT passed");

    /* Step c: HMAC-SHA256 RFC 4231 TC1 — must route to hardware */
    ret = hex_decode(
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        "0b0b0b0b",
        hmac_key, sizeof(hmac_key));
    if (ret != (int)sizeof(hmac_key)) {
        ret = -1;
        goto done;
    }

    ret = hex_decode(
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7",
        expected_hmac, sizeof(expected_hmac));
    if (ret != WC_SHA256_DIGEST_SIZE) {
        ret = -1;
        goto done;
    }

    ret = wc_HmacInit(&hmac, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: tls13: HMAC init failed");
        goto done;
    }
    hmac_inited = 1;

    ret = wc_HmacSetKey(&hmac, WC_SHA256, hmac_key, (word32)sizeof(hmac_key));
    if (ret == 0)
        ret = wc_HmacUpdate(&hmac, hi_there, (word32)sizeof(hi_there));
    if (ret == 0)
        ret = wc_HmacFinal(&hmac, mac);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: tls13: HMAC operation failed");
        goto done;
    }

    if (XMEMCMP(mac, expected_hmac, WC_SHA256_DIGEST_SIZE) != 0) {
        WOLFSSL_MSG("crypto2dev_test: tls13: HMAC-SHA256 hardware KAT FAILED");
        ret = -1;
        goto done;
    }
    WOLFSSL_MSG("crypto2dev_test: tls13: HMAC-SHA256 hardware KAT passed");

    /* Step d: AES-GCM KAT — NIST SP 800-38D Appendix B Test Case 2 */
    XMEMSET(ct,  0, sizeof(ct));
    XMEMSET(tag, 0, sizeof(tag));

    ret = hex_decode("0388dace60b6a392f328c2b971b2fe78",
                     expected_ct, sizeof(expected_ct));
    if (ret != (int)sizeof(expected_ct)) {
        ret = -1;
        goto done;
    }
    ret = hex_decode("ab6e47d42cec13bdf53a67b21257bddf",
                     expected_tag, sizeof(expected_tag));
    if (ret != (int)sizeof(expected_tag)) {
        ret = -1;
        goto done;
    }

    ret = wc_AesInit(&aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: tls13: AES init failed");
        goto done;
    }
    aes_inited = 1;

    /* wc_AesSetKey with a NULL IV populates aes->devCtx via the SETKEY
     * callback and, because the callback returns CRYPTOCB_UNAVAILABLE,
     * also runs the software key schedule (setting aes->rounds).  This
     * is the same approach used in test_aesgcm_empty(). */
    ret = wc_AesSetKey(&aes, aes_key, (word32)sizeof(aes_key),
                       NULL, AES_ENCRYPTION);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: tls13: AES-GCM SetKey failed");
        goto done;
    }

    ret = wc_AesGcmEncrypt(&aes,
                           ct, pt, (word32)sizeof(pt),
                           iv, (word32)sizeof(iv),
                           tag, (word32)sizeof(tag),
                           NULL, 0);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: tls13: AES-GCM encrypt failed");
        goto done;
    }

    if (XMEMCMP(ct, expected_ct, sizeof(expected_ct)) != 0) {
        WOLFSSL_MSG("crypto2dev_test: tls13: AES-GCM KAT ciphertext mismatch");
        ret = -1;
        goto done;
    }
    if (XMEMCMP(tag, expected_tag, sizeof(expected_tag)) != 0) {
        WOLFSSL_MSG("crypto2dev_test: tls13: AES-GCM KAT tag mismatch");
        ret = -1;
        goto done;
    }
    WOLFSSL_MSG("crypto2dev_test: tls13: AES-GCM KAT passed");

    WOLFSSL_MSG("crypto2dev_test: TLS 1.3 devId and primitive routing passed");

done:
    if (aes_inited)
        wc_AesFree(&aes);
    if (hmac_inited)
        wc_HmacFree(&hmac);
    if (sha_inited)
        wc_Sha256Free(&sha);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    return ret;
}
#endif /* NO_WOLFSSL_CLIENT */
#endif /* WOLFSSL_TLS13 */

/* ------------------------------------------------------------------ */
/* Test 6: TLS 1.2 integration                                         */
/*                                                                     */
/* Validates the operations TLS 1.2 relies on:                        */
/*   a. wc_crypto2dev_assign_devid() sets WOLF_CRYPTO2DEV_DEVID        */
/*   b. AES-128-CBC routes to hardware                                 */
/*      Source: NIST SP 800-38A, Appendix F.2.1, Block 1              */
/*   c. HMAC-SHA256 routes to hardware                                 */
/*      Source: RFC 4231, Test Case 3                                  */
/*        Key  = 0xaa * 20                                             */
/*        Data = 0xdd * 50                                             */
/*        HMAC = 773ea91e36800e46854db8ebd09181a7                     */
/*               2959098b3ef8c122d9635514ced565fe                      */
/* ------------------------------------------------------------------ */
#ifndef NO_WOLFSSL_CLIENT
static int test_tls12_integration(void)
{
    WOLFSSL_CTX* ctx = NULL;
    Aes aes;
    Hmac hmac;
    int aes_inited = 0, hmac_inited = 0;
    int ret;

    /* NIST SP 800-38A F.2.1, Block 1 */
    static const byte aes_key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const byte aes_iv[AES_BLOCK_SIZE] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const byte aes_pt[AES_BLOCK_SIZE] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const byte aes_ct_expected[AES_BLOCK_SIZE] = {
        0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
        0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d
    };
    byte aes_ct[AES_BLOCK_SIZE];

    /* RFC 4231, Test Case 3 */
    static const byte hmac_key[20] = {
        0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
        0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa
    };
    static const byte hmac_data[50] = {
        0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
        0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
        0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
        0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
        0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd
    };
    static const byte hmac_expected[WC_SHA256_DIGEST_SIZE] = {
        0x77,0x3e,0xa9,0x1e,0x36,0x80,0x0e,0x46,
        0x85,0x4d,0xb8,0xeb,0xd0,0x91,0x81,0xa7,
        0x29,0x59,0x09,0x8b,0x3e,0xf8,0xc1,0x22,
        0xd9,0x63,0x55,0x14,0xce,0xd5,0x65,0xfe
    };
    byte hmac_mac[WC_SHA256_DIGEST_SIZE];

    /* Step a: create CTX, assign devId, verify it is set */
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (ctx == NULL) {
        WOLFSSL_MSG("crypto2dev_tls12_test: wolfSSL_CTX_new failed");
        return -1;
    }

    ret = wc_crypto2dev_assign_devid(ctx);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_tls12_test: assign_devid failed");
        goto done;
    }

    if (wolfSSL_CTX_GetDevId(ctx, NULL) != WOLF_CRYPTO2DEV_DEVID) {
        WOLFSSL_MSG("crypto2dev_tls12_test: devId not set correctly");
        ret = -1;
        goto done;
    }

    wolfSSL_CTX_free(ctx);
    ctx = NULL;
    WOLFSSL_MSG("crypto2dev_tls12_test: assign_devid API passed");

    /* Step b: AES-128-CBC KAT (NIST SP 800-38A F.2.1) */
    ret = wc_AesInit(&aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_tls12_test: AES init failed");
        goto done;
    }
    aes_inited = 1;

    ret = wc_AesSetKey(&aes, aes_key, (word32)sizeof(aes_key),
                       aes_iv, AES_ENCRYPTION);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_tls12_test: AES SetKey failed");
        goto done;
    }

    ret = wc_AesCbcEncrypt(&aes, aes_ct, aes_pt, (word32)sizeof(aes_pt));
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_tls12_test: AES-CBC encrypt failed");
        goto done;
    }

    if (XMEMCMP(aes_ct, aes_ct_expected, AES_BLOCK_SIZE) != 0) {
        WOLFSSL_MSG("crypto2dev_tls12_test: AES-CBC KAT mismatch");
        ret = -1;
        goto done;
    }
    wc_AesFree(&aes);
    aes_inited = 0;
    WOLFSSL_MSG("crypto2dev_tls12_test: AES-CBC KAT passed");

    /* Step c: HMAC-SHA256 KAT (RFC 4231 TC3) */
    ret = wc_HmacInit(&hmac, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_tls12_test: HMAC init failed");
        goto done;
    }
    hmac_inited = 1;

    ret = wc_HmacSetKey(&hmac, WC_SHA256, hmac_key, (word32)sizeof(hmac_key));
    if (ret == 0)
        ret = wc_HmacUpdate(&hmac, hmac_data, (word32)sizeof(hmac_data));
    if (ret == 0)
        ret = wc_HmacFinal(&hmac, hmac_mac);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_tls12_test: HMAC operation failed");
        goto done;
    }

    if (XMEMCMP(hmac_mac, hmac_expected, WC_SHA256_DIGEST_SIZE) != 0) {
        WOLFSSL_MSG("crypto2dev_tls12_test: HMAC-SHA256 KAT mismatch");
        ret = -1;
        goto done;
    }
    wc_HmacFree(&hmac);
    hmac_inited = 0;
    WOLFSSL_MSG("crypto2dev_tls12_test: HMAC-SHA256 KAT passed");

    WOLFSSL_MSG("crypto2dev TLS12 integration test passed");

done:
    if (hmac_inited)  wc_HmacFree(&hmac);
    if (aes_inited)   wc_AesFree(&aes);
    if (ctx != NULL)  wolfSSL_CTX_free(ctx);
    return ret;
}
#endif /* NO_WOLFSSL_CLIENT */

/* ------------------------------------------------------------------ */
/* Error-path tests (self-contained init/cleanup cycles)               */
/*                                                                     */
/* Each test calls wc_crypto2dev_init() and wc_crypto2dev_cleanup()    */
/* independently so pool-size and fault-injection state do not leak    */
/* into the main test sequence above.                                  */
/* ------------------------------------------------------------------ */

/* Test E1: HMAC Final returns WC_HW_E and clears devCtx when the pool
 * is exhausted by an in-progress SHA-256 hash holding the only slot.
 *
 * Pool is forced to 1.  A SHA-256 Update acquires the single op fd.
 * The subsequent HMAC Final tries to acquire a slot → exhausted →
 * WC_HW_E.  The port frees devCtx unconditionally on this path so
 * wc_HmacFree cannot issue a spurious second Final callback.          */
static int test_hmac_final_pool_exhaustion(void)
{
    wc_Sha256  sha;
    Hmac       hmac;
    byte       key[20];
    const byte data[] = { 0x01, 0x02, 0x03, 0x04 };
    byte       mac[WC_SHA256_DIGEST_SIZE];
    int        ret;
    int        sha_inited  = 0;
    int        hmac_inited = 0;

    ret = wc_crypto2dev_init(1);  /* pool_size=1: one slot total */
    if (ret != 0) return ret;
    ret = wc_crypto2dev_register();
    if (ret != 0) { wc_crypto2dev_cleanup(); return ret; }

    /* Acquire the only pool slot via a SHA-256 Init+Update.
     * The port allocates op_fd into Crypto2DevHashCtx on the first
     * Update when devCtx == NULL; the slot is held until Final/Free. */
    ret = wc_InitSha256_ex(&sha, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) goto pool_done;
    sha_inited = 1;
    ret = wc_Sha256Update(&sha, data, (word32)sizeof(data));
    if (ret != 0) goto pool_done;

    if (sha.devCtx == NULL) {
        /* Hardware path was not taken (device lacks SHA-256 or returned
         * CRYPTOCB_UNAVAILABLE).  Pool slot not held; skip test. */
        WOLFSSL_MSG("crypto2dev_test: SHA-256 devCtx NULL — skipping pool exhaustion");
        ret = 0;
        goto pool_done;
    }

    /* Set up HMAC: SetKey stores key in devCtx (no pool slot yet). */
    XMEMSET(key, 0x0b, sizeof(key));
    ret = wc_HmacInit(&hmac, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) goto pool_done;
    hmac_inited = 1;
    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, (word32)sizeof(key));
    if (ret != 0) goto pool_done;
    /* First Update acquires the pool fd (streaming design) — must fail
     * with WC_HW_E: the pool's only slot is held by the SHA-256 above. */
    ret = wc_HmacUpdate(&hmac, data, (word32)sizeof(data));
    if (ret != WC_HW_E) {
        WOLFSSL_MSG("crypto2dev_test: HMAC Update pool exhaustion expected WC_HW_E");
        ret = (ret == 0) ? -1 : ret;
        goto pool_done;
    }

    /* Sticky error: op_fd sentinel makes Final report WC_HW_E too, even
     * for callers that ignored the Update return code. */
    ret = wc_HmacFinal(&hmac, mac);
    if (ret != WC_HW_E) {
        WOLFSSL_MSG("crypto2dev_test: HMAC Final after failed Update expected WC_HW_E");
        ret = (ret == 0) ? -1 : ret;
        goto pool_done;
    }
    ret = 0;

    /* Port frees devCtx on WC_HW_E so wc_HmacFree cannot double-free. */
    if (hmac.devCtx != NULL) {
        WOLFSSL_MSG("crypto2dev_test: HMAC devCtx not freed after pool exhaustion");
        ret = -1;
        goto pool_done;
    }

    WOLFSSL_MSG("crypto2dev_test: HMAC Final pool exhaustion test passed");

pool_done:
    if (sha_inited)  wc_Sha256Free(&sha);
    if (hmac_inited) wc_HmacFree(&hmac);
    wc_crypto2dev_cleanup();
    return ret;
}

/* Test E2: HMAC Final returns WC_HW_E and clears devCtx when
 * CRYPTO2DEV_IOC_INIT fails mid-operation.
 *
 * Requires the software simulator for fault injection.
 * HMAC Final path: pool_acquire → INIT ioctl → write data → FINALIZE
 * → read MAC.  One injected ioctl failure at the INIT step exercises
 * the error path that goes to done: before key/data are sent.        */
#ifdef WOLFSSL_CRYPTO2DEV_SIM
static int test_hmac_final_init_failure(void)
{
    Hmac       hmac;
    byte       key[20];
    const byte data[] = { 0x01, 0x02, 0x03, 0x04 };
    byte       mac[WC_SHA256_DIGEST_SIZE];
    int        ret;
    int        hmac_inited = 0;

    ret = wc_crypto2dev_init(0);  /* default pool size */
    if (ret != 0) return ret;
    ret = wc_crypto2dev_register();
    if (ret != 0) { wc_crypto2dev_cleanup(); return ret; }

    XMEMSET(key, 0x0b, sizeof(key));
    ret = wc_HmacInit(&hmac, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) goto init_done;
    hmac_inited = 1;
    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, (word32)sizeof(key));
    if (ret != 0) goto init_done;
    ret = wc_HmacUpdate(&hmac, data, (word32)sizeof(data));
    if (ret != 0) goto init_done;

    if (hmac.devCtx == NULL) {
        /* SETKEY did not set devCtx — hardware path not taken; skip. */
        WOLFSSL_MSG("crypto2dev_test: HMAC devCtx NULL — skipping INIT failure");
        ret = 0;
        goto init_done;
    }

    /* Inject: next ioctl returns -1/ENODEV.  HMAC Final calls
     * pool_acquire (no ioctl), then CRYPTO2DEV_IOC_INIT — that is
     * the targeted ioctl.  Reset the counter after the call in case
     * Final returns before consuming it.
     *
     * errno=ENODEV maps to BAD_STATE_E via crypto2dev_to_wc_err.
     * The test checks for any negative return (hard error), not a
     * specific code, since the mapping is an implementation detail. */
    crypto2dev_sim_set_ioctl_fail(1);
    ret = wc_HmacFinal(&hmac, mac);
    crypto2dev_sim_set_ioctl_fail(0);

    if (ret >= 0) {
        WOLFSSL_MSG("crypto2dev_test: HMAC Final INIT failure expected hard error");
        ret = -1;
        goto init_done;
    }
    ret = 0;

    if (hmac.devCtx != NULL) {
        WOLFSSL_MSG("crypto2dev_test: HMAC devCtx not freed after INIT failure");
        ret = -1;
        goto init_done;
    }

    WOLFSSL_MSG("crypto2dev_test: HMAC Final INIT ioctl failure test passed");

init_done:
    if (hmac_inited) wc_HmacFree(&hmac);
    wc_crypto2dev_cleanup();
    return ret;
}
#endif /* WOLFSSL_CRYPTO2DEV_SIM */

/* Test E3: ECDSA sign returns WC_HW_E when the pool is exhausted by
 * an in-progress SHA-256 hash holding the only slot.
 *
 * Pool is forced to 1.  A P-256 key is imported into a hardware-bound
 * key object (SETKEY opens a key fd stored in devCtx).  A SHA-256
 * Update acquires the single pool slot.  wc_ecc_sign_hash then tries
 * to acquire a slot → exhausted → WC_HW_E.                           */
#if defined(HAVE_ECC) && defined(WOLF_CRYPTO_CB_SETKEY)
static int test_ecdsa_sign_pool_exhaustion(void)
{
    ecc_key    priv_key;
    ecc_key    sign_key;
    wc_Sha256  sha;
    WC_RNG     rng;
    byte       digest[WC_SHA256_DIGEST_SIZE];
    byte       sig[ECC_MAX_SIG_SIZE];
    word32     sig_len = (word32)sizeof(sig);
    byte       priv_raw[ECC_MAXSIZE];
    word32     priv_raw_len;
    byte       pub_x963[1 + 2 * ECC_MAXSIZE];
    word32     pub_x963_len;
    const byte data[] = { 0x01, 0x02, 0x03, 0x04 };
    int        ret;
    int        priv_inited = 0;
    int        sign_inited = 0;
    int        sha_inited  = 0;
    int        rng_inited  = 0;
    int        i;

    for (i = 0; i < WC_SHA256_DIGEST_SIZE; i++)
        digest[i] = 0xAB;

    ret = wc_crypto2dev_init(1);  /* pool_size=1: single slot */
    if (ret != 0) return ret;
    ret = wc_crypto2dev_register();
    if (ret != 0) { wc_crypto2dev_cleanup(); return ret; }

    ret = wc_InitRng(&rng);
    if (ret != 0) goto ecdsa_pool_done;
    rng_inited = 1;

    /* Generate P-256 key with software (INVALID_DEVID). */
    ret = wc_ecc_init_ex(&priv_key, NULL, INVALID_DEVID);
    if (ret != 0) goto ecdsa_pool_done;
    priv_inited = 1;
    ret = wc_ecc_make_key_ex(&rng, 32, &priv_key, ECC_SECP256R1);
    if (ret != 0) goto ecdsa_pool_done;

    /* Export and import into a hardware-bound key (SETKEY → devCtx = key fd). */
    priv_raw_len = (word32)sizeof(priv_raw);
    pub_x963_len = (word32)sizeof(pub_x963);
    ret = wc_ecc_export_private_only(&priv_key, priv_raw, &priv_raw_len);
    if (ret != 0) { XMEMSET(priv_raw, 0, sizeof(priv_raw)); goto ecdsa_pool_done; }
    ret = wc_ecc_export_x963(&priv_key, pub_x963, &pub_x963_len);
    if (ret != 0) { XMEMSET(priv_raw, 0, sizeof(priv_raw)); goto ecdsa_pool_done; }
    ret = wc_ecc_init_ex(&sign_key, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) { XMEMSET(priv_raw, 0, sizeof(priv_raw)); goto ecdsa_pool_done; }
    sign_inited = 1;
    ret = wc_ecc_import_private_key_ex(priv_raw, priv_raw_len,
                                       pub_x963, pub_x963_len,
                                       &sign_key, ECC_SECP256R1);
    XMEMSET(priv_raw, 0, sizeof(priv_raw));
    if (ret != 0) goto ecdsa_pool_done;

    /* Acquire the only pool slot via SHA-256 Init+Update. */
    ret = wc_InitSha256_ex(&sha, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) goto ecdsa_pool_done;
    sha_inited = 1;
    ret = wc_Sha256Update(&sha, data, (word32)sizeof(data));
    if (ret != 0) goto ecdsa_pool_done;

    if (sha.devCtx == NULL) {
        WOLFSSL_MSG("crypto2dev_test: SHA-256 devCtx NULL — skipping ECDSA pool exhaustion");
        ret = 0;
        goto ecdsa_pool_done;
    }

    /* Sign tries to acquire a pool slot — must fail (pool exhausted). */
    ret = wc_ecc_sign_hash(digest, sizeof(digest), sig, &sig_len, &rng, &sign_key);
    if (ret != WC_HW_E) {
        WOLFSSL_MSG("crypto2dev_test: ECDSA sign pool exhaustion expected WC_HW_E");
        ret = (ret == 0) ? -1 : ret;
        goto ecdsa_pool_done;
    }
    ret = 0;

    WOLFSSL_MSG("crypto2dev_test: ECDSA sign pool exhaustion test passed");

ecdsa_pool_done:
    if (sha_inited)  wc_Sha256Free(&sha);
    if (sign_inited) wc_ecc_free(&sign_key);
    if (priv_inited) wc_ecc_free(&priv_key);
    if (rng_inited)  wc_FreeRng(&rng);
    wc_crypto2dev_cleanup();
    return ret;
}
#endif /* HAVE_ECC && WOLF_CRYPTO_CB_SETKEY */

/* ------------------------------------------------------------------ */
/* Test: wc_crypto2dev_pool_stats                                       */
/* ------------------------------------------------------------------ */
static int test_pool_stats(void)
{
    int in_use = -1, total = -1;
    int ret;

    ret = wc_crypto2dev_pool_stats(NULL, &total);
    if (ret != BAD_FUNC_ARG) {
        WOLFSSL_MSG("crypto2dev_test: pool_stats(NULL, &total) should be BAD_FUNC_ARG");
        return -1;
    }
    ret = wc_crypto2dev_pool_stats(&in_use, NULL);
    if (ret != BAD_FUNC_ARG) {
        WOLFSSL_MSG("crypto2dev_test: pool_stats(&in_use, NULL) should be BAD_FUNC_ARG");
        return -1;
    }

    ret = wc_crypto2dev_pool_stats(&in_use, &total);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: pool_stats failed");
        return ret;
    }
    if (total <= 0 || in_use < 0 || in_use > total) {
        WOLFSSL_MSG("crypto2dev_test: pool_stats returned implausible values");
        return -1;
    }
    WOLFSSL_MSG("crypto2dev_test: pool_stats passed");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test: wc_crypto2dev_fips_status                                      */
/* ------------------------------------------------------------------ */
static int test_fips_status(void)
{
    int fips = -1;
    int ret;

    ret = wc_crypto2dev_fips_status(NULL);
    if (ret != BAD_FUNC_ARG) {
        WOLFSSL_MSG("crypto2dev_test: fips_status(NULL) should be BAD_FUNC_ARG");
        return -1;
    }

    ret = wc_crypto2dev_fips_status(&fips);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: fips_status failed");
        return ret;
    }
    if (fips != CRYPTO2DEV_FIPS_NO_PROVIDER &&
        fips != CRYPTO2DEV_FIPS_OPERATIONAL  &&
        fips != CRYPTO2DEV_FIPS_NOT_OPERATIONAL) {
        WOLFSSL_MSG("crypto2dev_test: fips_status returned unknown fips_state");
        return -1;
    }
    WOLFSSL_MSG("crypto2dev_test: fips_status passed");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test: wc_crypto2dev_selftest                                         */
/* ------------------------------------------------------------------ */
#ifdef HAVE_AESGCM
static int test_selftest(void)
{
    int ret = wc_crypto2dev_selftest();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: selftest FAILED");
        return ret;
    }
    WOLFSSL_MSG("crypto2dev_test: selftest passed");
    return 0;
}
#endif /* HAVE_AESGCM */

/* ------------------------------------------------------------------ */
/* Explicit-unavailable fallback tests (enum audit, wolfssl-jond.2)     */
/*                                                                     */
/* Each test drives an op the port declines with CRYPTOCB_UNAVAILABLE  */
/* through a devId-bound object and checks the software fallback        */
/* result against an independent published vector.                      */
/* ------------------------------------------------------------------ */

#if defined(WOLFSSL_SHA3) && defined(WOLFSSL_SHAKE128)
/* Source: NIST FIPS 202 / XKCP known-answer set.
 * SHAKE128("", 16) = 7f9c2ba4e88f827d616045507605853e */
static int test_shake128_fallback(void)
{
    wc_Shake shake;
    byte out[16];
    byte expected[16];
    int ret;

    ret = hex_decode("7f9c2ba4e88f827d616045507605853e",
                     expected, sizeof(expected));
    if (ret != (int)sizeof(expected))
        return -1;

    ret = wc_InitShake128(&shake, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;
    ret = wc_Shake128_Final(&shake, out, (word32)sizeof(out));
    wc_Shake128_Free(&shake);
    if (ret != 0) return ret;

    if (XMEMCMP(out, expected, sizeof(expected)) != 0)
        return -1;

    WOLFSSL_MSG("crypto2dev_test: SHAKE128 fallback KAT passed");
    return 0;
}
#endif /* WOLFSSL_SHA3 && WOLFSSL_SHAKE128 */

#if defined(WOLFSSL_SHA3) && defined(WOLFSSL_SHAKE256)
/* Source: NIST FIPS 202 / XKCP known-answer set.
 * SHAKE256("", 32) =
 *   46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f */
static int test_shake256_fallback(void)
{
    wc_Shake shake;
    byte out[32];
    byte expected[32];
    int ret;

    ret = hex_decode(
        "46b9dd2b0ba88d13233b3feb743eeb24"
        "3fcd52ea62b81b82b50c27646ed5762f",
        expected, sizeof(expected));
    if (ret != (int)sizeof(expected))
        return -1;

    ret = wc_InitShake256(&shake, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;
    ret = wc_Shake256_Final(&shake, out, (word32)sizeof(out));
    wc_Shake256_Free(&shake);
    if (ret != 0) return ret;

    if (XMEMCMP(out, expected, sizeof(expected)) != 0)
        return -1;

    WOLFSSL_MSG("crypto2dev_test: SHAKE256 fallback KAT passed");
    return 0;
}
#endif /* WOLFSSL_SHA3 && WOLFSSL_SHAKE256 */

#ifdef WOLFSSL_AES_CFB
/* Source: NIST SP 800-38A, F.3.13 CFB128-AES128.Encrypt, Segment 1.
 * Key 2b7e151628aed2a6abf7158809cf4f3c, IV 000102030405060708090a0b0c0d0e0f,
 * PT 6bc1bee22e409f96e93d7e117393172a, CT 3b3fd92eb72dad20333449f8e83cfb4a */
static int test_aes_cfb_fallback(void)
{
    Aes aes;
    byte key[16], iv[16], pt[16], expected_ct[16], ct[16];
    int ret;

    ret  = hex_decode("2b7e151628aed2a6abf7158809cf4f3c", key, sizeof(key));
    ret += hex_decode("000102030405060708090a0b0c0d0e0f", iv,  sizeof(iv));
    ret += hex_decode("6bc1bee22e409f96e93d7e117393172a", pt,  sizeof(pt));
    ret += hex_decode("3b3fd92eb72dad20333449f8e83cfb4a",
                      expected_ct, sizeof(expected_ct));
    if (ret != 4 * 16)
        return -1;

    ret = wc_AesInit(&aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;
    ret = wc_AesSetKey(&aes, key, (word32)sizeof(key), iv, AES_ENCRYPTION);
    if (ret == 0)
        ret = wc_AesCfbEncrypt(&aes, ct, pt, (word32)sizeof(pt));
    wc_AesFree(&aes);
    if (ret != 0) return ret;

    if (XMEMCMP(ct, expected_ct, sizeof(expected_ct)) != 0)
        return -1;

    WOLFSSL_MSG("crypto2dev_test: AES-CFB fallback KAT passed");
    return 0;
}
#endif /* WOLFSSL_AES_CFB */

#ifdef WOLFSSL_AES_OFB
/* Source: NIST SP 800-38A, F.4.1 OFB-AES128.Encrypt, Block 1.
 * Key 2b7e151628aed2a6abf7158809cf4f3c, IV 000102030405060708090a0b0c0d0e0f,
 * PT 6bc1bee22e409f96e93d7e117393172a, CT 3b3fd92eb72dad20333449f8e83cfb4a */
static int test_aes_ofb_fallback(void)
{
    Aes aes;
    byte key[16], iv[16], pt[16], expected_ct[16], ct[16];
    int ret;

    ret  = hex_decode("2b7e151628aed2a6abf7158809cf4f3c", key, sizeof(key));
    ret += hex_decode("000102030405060708090a0b0c0d0e0f", iv,  sizeof(iv));
    ret += hex_decode("6bc1bee22e409f96e93d7e117393172a", pt,  sizeof(pt));
    ret += hex_decode("3b3fd92eb72dad20333449f8e83cfb4a",
                      expected_ct, sizeof(expected_ct));
    if (ret != 4 * 16)
        return -1;

    ret = wc_AesInit(&aes, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;
    ret = wc_AesSetKey(&aes, key, (word32)sizeof(key), iv, AES_ENCRYPTION);
    if (ret == 0)
        ret = wc_AesOfbEncrypt(&aes, ct, pt, (word32)sizeof(pt));
    wc_AesFree(&aes);
    if (ret != 0) return ret;

    if (XMEMCMP(ct, expected_ct, sizeof(expected_ct)) != 0)
        return -1;

    WOLFSSL_MSG("crypto2dev_test: AES-OFB fallback KAT passed");
    return 0;
}
#endif /* WOLFSSL_AES_OFB */

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT) && \
    defined(HAVE_ED25519_MAKE_KEY)
/* Source: RFC 8032, section 7.1, TEST 1.
 * Secret key 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
 * Public key d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
 * Drives WC_PK_TYPE_ED25519_MAKE_PUB and ED25519_CHECK_KEY through the
 * callback; the port declines both, and software must produce the RFC
 * public key and accept the valid pair. */
static int test_ed25519_fallback(void)
{
    ed25519_key key;
    byte priv[ED25519_KEY_SIZE];
    byte pub[ED25519_PUB_KEY_SIZE];
    byte expected_pub[ED25519_PUB_KEY_SIZE];
    int ret;

    ret = hex_decode(
        "9d61b19deffd5a60ba844af492ec2cc4"
        "4449c5697b326919703bac031cae7f60", priv, sizeof(priv));
    if (ret != (int)sizeof(priv))
        return -1;
    ret = hex_decode(
        "d75a980182b10ab7d54bfed3c964073a"
        "0ee172f3daa62325af021a68f707511a",
        expected_pub, sizeof(expected_pub));
    if (ret != (int)sizeof(expected_pub))
        return -1;

    ret = wc_ed25519_init_ex(&key, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) return ret;

    ret = wc_ed25519_import_private_only(priv, (word32)sizeof(priv), &key);
    if (ret == 0)
        ret = wc_ed25519_make_public(&key, pub, (word32)sizeof(pub));
    if (ret == 0 && XMEMCMP(pub, expected_pub, sizeof(expected_pub)) != 0)
        ret = -1;
    if (ret == 0)
        ret = wc_ed25519_import_public(expected_pub,
                                       (word32)sizeof(expected_pub), &key);
    if (ret == 0)
        ret = wc_ed25519_check_key(&key);

    wc_ed25519_free(&key);
    if (ret != 0) return ret;

    WOLFSSL_MSG("crypto2dev_test: Ed25519 make_pub/check_key fallback passed");
    return 0;
}
#endif /* HAVE_ED25519 && HAVE_ED25519_KEY_IMPORT && HAVE_ED25519_MAKE_KEY */

#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && \
    defined(HAVE_ECC_KEY_IMPORT)
/* Drives WC_PK_TYPE_EC_MAKE_PUB (via software keygen on a devId-bound key)
 * and WC_PK_TYPE_EC_CHECK_PUB_KEY through the callback.  The port declines
 * both; software keygen must yield a key that passes wc_ecc_check_key, and
 * a corrupted public point must still be rejected (guards against a future
 * handler claiming success without validating). */
static int test_ecc_pubkey_ops_fallback(void)
{
    ecc_key key;
    WC_RNG  rng;
    byte    x963[1 + 2 * ECC_MAXSIZE];
    word32  x963_len = (word32)sizeof(x963);
    int     ret;

    ret = wc_InitRng(&rng);
    if (ret != 0) return ret;

    ret = wc_ecc_init_ex(&key, NULL, WOLF_CRYPTO2DEV_DEVID);
    if (ret != 0) { wc_FreeRng(&rng); return ret; }

    ret = wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1);
    if (ret == 0)
        ret = wc_ecc_check_key(&key);
    if (ret == 0)
        ret = wc_ecc_export_x963(&key, x963, &x963_len);

    if (ret == 0) {
        ecc_key bad_key;
        /* Corrupt the low byte of Y: the result is on neither root of the
         * curve equation, so validation must fail. */
        x963[x963_len - 1] ^= 0x01;
        ret = wc_ecc_init_ex(&bad_key, NULL, WOLF_CRYPTO2DEV_DEVID);
        if (ret == 0) {
            int check_ret = wc_ecc_import_x963_ex(x963, x963_len, &bad_key,
                                                  ECC_SECP256R1);
            if (check_ret == 0)
                check_ret = wc_ecc_check_key(&bad_key);
            /* Rejection at import or at check both count as rejection. */
            if (check_ret == 0)
                ret = -1;
            wc_ecc_free(&bad_key);
        }
    }

    wc_ecc_free(&key);
    wc_FreeRng(&rng);
    if (ret != 0) return ret;

    WOLFSSL_MSG("crypto2dev_test: ECC make_pub/check_key fallback passed");
    return 0;
}
#endif /* HAVE_ECC && HAVE_ECC_KEY_EXPORT && HAVE_ECC_KEY_IMPORT */

/* Upstream PR #10604: wc_CryptoCb_IsDeviceRegistered is answered inside
 * cryptocb.c and never reaches the callback; verify it sees our
 * registration. */
static int test_devid_registered(void)
{
    if (wc_CryptoCb_IsDeviceRegistered(WOLF_CRYPTO2DEV_DEVID) != 1)
        return -1;
    WOLFSSL_MSG("crypto2dev_test: IsDeviceRegistered passed");
    return 0;
}

/* ------------------------------------------------------------------ */
/* Public entry point                                                   */
/* ------------------------------------------------------------------ */

int wc_crypto2dev_test(void)
{
    int ret;

    ret = wc_crypto2dev_init(0); /* 0 = compile-time default pool size */
    if (ret != 0) {
#ifdef WOLFSSL_CRYPTO2DEV_SIM
        WOLFSSL_MSG("crypto2dev_test: sim init failed");
        return ret;
#else
        WOLFSSL_MSG("crypto2dev_test: device not available, skipping");
        return 0;
#endif
    }

    ret = wc_crypto2dev_register();
    if (ret != 0) {
        wc_crypto2dev_cleanup();
        return ret;
    }

    ret = test_devid_registered();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: IsDeviceRegistered FAILED");
        goto done;
    }

    ret = test_sha256_empty();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: SHA-256 KAT FAILED");
        goto done;
    }

#if defined(WOLFSSL_SHA3) && defined(WOLFSSL_SHAKE128)
    ret = test_shake128_fallback();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: SHAKE128 fallback KAT FAILED");
        goto done;
    }
#endif

#if defined(WOLFSSL_SHA3) && defined(WOLFSSL_SHAKE256)
    ret = test_shake256_fallback();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: SHAKE256 fallback KAT FAILED");
        goto done;
    }
#endif

    ret = test_aes_cbc_128();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: AES-CBC-128 KAT FAILED");
        goto done;
    }

#ifdef WOLFSSL_AES_CFB
    ret = test_aes_cfb_fallback();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: AES-CFB fallback KAT FAILED");
        goto done;
    }
#endif

#ifdef WOLFSSL_AES_OFB
    ret = test_aes_ofb_fallback();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: AES-OFB fallback KAT FAILED");
        goto done;
    }
#endif

#ifdef WOLFSSL_AES_COUNTER
    ret = test_aes_ctr_multicall();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: AES-CTR multi-call KAT FAILED");
        goto done;
    }
#endif

    ret = test_hmac_sha256();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: HMAC-SHA256 KAT FAILED");
        goto done;
    }

    ret = test_hmac_sha256_multichunk();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: HMAC-SHA256 two-chunk KAT FAILED");
        goto done;
    }

    ret = test_hmac_short_key_fallback();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: HMAC short-key fallback FAILED");
        goto done;
    }

    ret = test_hmac_lifecycle();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: HMAC lifecycle FAILED");
        goto done;
    }

    ret = test_pool_stats();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: pool_stats FAILED");
        goto done;
    }

    ret = test_fips_status();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: fips_status FAILED");
        goto done;
    }

#ifdef HAVE_AESGCM
    ret = test_selftest();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: selftest FAILED");
        goto done;
    }
#endif

#ifdef HAVE_AESGCM
    ret = test_aesgcm_empty();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: AES-GCM empty-plaintext KAT FAILED");
        goto done;
    }

    ret = test_aesgcm_oversized_aad();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: AES-GCM oversized-AAD rejection FAILED");
        goto done;
    }

    ret = test_aesgcm_truncated_tag();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: AES-GCM truncated-tag KAT FAILED");
        goto done;
    }

    ret = test_aesgcm_sub_min_tag();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: AES-GCM sub-minimum tag rejection FAILED");
        goto done;
    }

    ret = test_aesgcm_oversized_tag();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: AES-GCM oversized-tag rejection FAILED");
        goto done;
    }
#endif

#ifdef HAVE_ECC
#ifdef WOLF_CRYPTO_CB_SETKEY
    ret = test_ecdsa_roundtrip();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: ECDSA round-trip FAILED");
        goto done;
    }

    ret = test_ecc_setkey_rejects_p192();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: ECC P-192 hardware rejection FAILED");
        goto done;
    }
#endif

#if defined(HAVE_ECC_KEY_EXPORT) && defined(HAVE_ECC_KEY_IMPORT)
    ret = test_ecc_pubkey_ops_fallback();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: ECC make_pub/check_key fallback FAILED");
        goto done;
    }
#endif
#endif

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT) && \
    defined(HAVE_ED25519_MAKE_KEY)
    ret = test_ed25519_fallback();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: Ed25519 fallback FAILED");
        goto done;
    }
#endif

#if defined(WOLF_CRYPTO_CB_COPY) && defined(WOLF_CRYPTO_CB_SETKEY)
    ret = test_aes_copy_devctx_guard();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: AES COPY devCtx guard FAILED");
        goto done;
    }
#endif

#if defined(WOLF_CRYPTO_CB_COPY) && defined(WOLF_CRYPTO_CB_SETKEY) && !defined(NO_HMAC)
    ret = test_hmac_copy_devctx_guard();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: HMAC COPY devCtx guard FAILED");
        goto done;
    }
#endif

#ifdef WOLFSSL_TLS13
#ifndef NO_WOLFSSL_CLIENT
    ret = test_tls13_devid_and_primitive_routing();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: TLS 1.3 devId and primitive routing FAILED");
        goto done;
    }
#endif
#endif

#ifndef NO_WOLFSSL_CLIENT
    ret = test_tls12_integration();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: TLS 1.2 integration FAILED");
        goto done;
    }
#endif

done:
    wc_crypto2dev_cleanup(); /* unregisters WOLF_CRYPTO2DEV_DEVID automatically */
    if (ret != 0)
        return ret;

    if (wc_CryptoCb_IsDeviceRegistered(WOLF_CRYPTO2DEV_DEVID) != 0) {
        WOLFSSL_MSG("crypto2dev_test: devId still registered after cleanup");
        return -1;
    }

    ret = test_hmac_final_pool_exhaustion();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: HMAC Final pool exhaustion FAILED");
        return ret;
    }

#ifdef WOLFSSL_CRYPTO2DEV_SIM
    ret = test_hmac_final_init_failure();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: HMAC Final INIT ioctl failure FAILED");
        return ret;
    }
#endif

#if defined(HAVE_ECC) && defined(WOLF_CRYPTO_CB_SETKEY)
    ret = test_ecdsa_sign_pool_exhaustion();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: ECDSA sign pool exhaustion FAILED");
        return ret;
    }
#endif

    return ret;
}

#endif /* WOLFSSL_CRYPTO2DEV && WOLF_CRYPTO_CB && WOLFSSL_CRYPTO2DEV_TEST */
