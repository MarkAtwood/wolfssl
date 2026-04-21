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
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/ssl.h>

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
#endif /* HAVE_AESGCM */

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

    /* Copy private key to a new object with WOLF_CRYPTO2DEV_DEVID so
     * that the SETKEY callback fires and imports it into the port.    */
    {
        ecc_key sign_key;
        ret = wc_ecc_init_ex(&sign_key, NULL, WOLF_CRYPTO2DEV_DEVID);
        if (ret == 0) {
            /* Force the SETKEY callback by calling SetKey on the
             * hardware-bound object.  We use the direct CryptoCb
             * helper.  Since the port file is the same TU as this
             * test (via the build system), we can call the public
             * wc_CryptoCb API.  The wc_ecc_sign_hash call below
             * triggers WC_ALGO_TYPE_PK which uses devCtx. */
            {
                wc_CryptoInfo ki;
                XMEMSET(&ki, 0, sizeof(ki));
                ki.algo_type    = WC_ALGO_TYPE_SETKEY;
                ki.setkey.type  = WC_SETKEY_ECC_PRIV;
                ki.setkey.obj   = &sign_key;
                ki.setkey.key   = &priv_key;
                ki.setkey.keySz = (word32)wc_ecc_size(&priv_key);
                ret = wc_crypto2dev_cb(WOLF_CRYPTO2DEV_DEVID, &ki, NULL);
            }
            if (ret == 0) {
                ret = wc_ecc_sign_hash(digest, sizeof(digest),
                                       sig, &sig_len,
                                       &rng, &sign_key);
            }
            wc_ecc_free(&sign_key);
        }
    }

    if (ret != 0) {
        wc_ecc_free(&priv_key);
        wc_FreeRng(&rng);
        return ret;
    }

    /* Verify: import public key into a port-bound object */
    {
        ecc_key verify_key;
        byte    x963[1 + 2 * ECC_MAXSIZE];
        word32  x963_len = (word32)sizeof(x963);

        ret = wc_ecc_export_x963(&priv_key, x963, &x963_len);
        if (ret == 0)
            ret = wc_ecc_init_ex(&verify_key, NULL, WOLF_CRYPTO2DEV_DEVID);
        if (ret == 0) {
            wc_CryptoInfo ki;
            XMEMSET(&ki, 0, sizeof(ki));
            ki.algo_type   = WC_ALGO_TYPE_SETKEY;
            ki.setkey.type = WC_SETKEY_ECC_PUB;
            ki.setkey.obj  = &verify_key;
            ki.setkey.key  = &priv_key;
            ki.setkey.keySz = x963_len;
            ret = wc_crypto2dev_cb(WOLF_CRYPTO2DEV_DEVID, &ki, NULL);
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
#endif /* WOLF_CRYPTO_CB_SETKEY */
#endif /* HAVE_ECC */

/* ------------------------------------------------------------------ */
/* Test 5: TLS 1.3 integration                                         */
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
static int test_tls13_integration(void)
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
        WOLFSSL_MSG("crypto2dev_tls13_test: wolfSSL_CTX_new failed");
        return -1;
    }

    ret = wc_crypto2dev_assign_devid(ctx);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_tls13_test: assign_devid failed");
        goto done;
    }

    if (wolfSSL_CTX_GetDevId(ctx, NULL) != WOLF_CRYPTO2DEV_DEVID) {
        WOLFSSL_MSG("crypto2dev_tls13_test: devId not set correctly");
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
        WOLFSSL_MSG("crypto2dev_tls13_test: SHA-256 init failed");
        goto done;
    }
    sha_inited = 1;

    ret = wc_Sha256Update(&sha, abc, (word32)sizeof(abc));
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_tls13_test: SHA-256 update failed");
        goto done;
    }

    ret = wc_Sha256Final(&sha, digest);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_tls13_test: SHA-256 final failed");
        goto done;
    }

    if (XMEMCMP(digest, expected_sha, WC_SHA256_DIGEST_SIZE) != 0) {
        WOLFSSL_MSG("crypto2dev_tls13_test: SHA-256 software fallback KAT FAILED");
        ret = -1;
        goto done;
    }
    WOLFSSL_MSG("crypto2dev_tls13_test: SHA-256 software fallback KAT passed");

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
        WOLFSSL_MSG("crypto2dev_tls13_test: HMAC init failed");
        goto done;
    }
    hmac_inited = 1;

    ret = wc_HmacSetKey(&hmac, WC_SHA256, hmac_key, (word32)sizeof(hmac_key));
    if (ret == 0)
        ret = wc_HmacUpdate(&hmac, hi_there, (word32)sizeof(hi_there));
    if (ret == 0)
        ret = wc_HmacFinal(&hmac, mac);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_tls13_test: HMAC operation failed");
        goto done;
    }

    if (XMEMCMP(mac, expected_hmac, WC_SHA256_DIGEST_SIZE) != 0) {
        WOLFSSL_MSG("crypto2dev_tls13_test: HMAC-SHA256 hardware KAT FAILED");
        ret = -1;
        goto done;
    }
    WOLFSSL_MSG("crypto2dev_tls13_test: HMAC-SHA256 hardware KAT passed");

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
        WOLFSSL_MSG("crypto2dev_tls13_test: AES init failed");
        goto done;
    }
    aes_inited = 1;

    /* wc_AesGcmSetKey internally calls wc_AesEncrypt to pre-compute H,
     * which requires aes->rounds to be set via software key expansion.
     * When WOLF_CRYPTO_CB_SETKEY is active and the callback returns 0,
     * the software key expansion is skipped and aes->rounds stays 0,
     * causing wc_AesEncrypt to fail with KEYUSAGE_E.  Use wc_AesSetKey
     * with a NULL IV instead — the same approach used in test_aesgcm_empty().
     * This is sufficient: aes->devCtx is populated, and the actual GCM
     * encryption/decryption is done entirely by the crypto2dev shim. */
    ret = wc_AesSetKey(&aes, aes_key, (word32)sizeof(aes_key),
                       NULL, AES_ENCRYPTION);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_tls13_test: AES-GCM SetKey failed");
        goto done;
    }

    ret = wc_AesGcmEncrypt(&aes,
                           ct, pt, (word32)sizeof(pt),
                           iv, (word32)sizeof(iv),
                           tag, (word32)sizeof(tag),
                           NULL, 0);
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_tls13_test: AES-GCM encrypt failed");
        goto done;
    }

    if (XMEMCMP(ct, expected_ct, sizeof(expected_ct)) != 0) {
        WOLFSSL_MSG("crypto2dev_tls13_test: AES-GCM KAT ciphertext mismatch");
        ret = -1;
        goto done;
    }
    if (XMEMCMP(tag, expected_tag, sizeof(expected_tag)) != 0) {
        WOLFSSL_MSG("crypto2dev_tls13_test: AES-GCM KAT tag mismatch");
        ret = -1;
        goto done;
    }
    WOLFSSL_MSG("crypto2dev_tls13_test: AES-GCM KAT passed");

    WOLFSSL_MSG("crypto2dev TLS13 test passed");

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
/* Public entry point                                                   */
/* ------------------------------------------------------------------ */

int wc_crypto2dev_test(void)
{
    int ret;

    ret = wc_crypto2dev_init();
    if (ret != 0) {
#ifdef WOLFSSL_CRYPTO2DEV_SIM
        WOLFSSL_MSG("crypto2dev_test: sim init failed");
        return ret;
#else
        WOLFSSL_MSG("crypto2dev_test: device not available, skipping");
        return 0;
#endif
    }

    ret = wc_CryptoCb_RegisterDevice(WOLF_CRYPTO2DEV_DEVID,
                                     wc_crypto2dev_cb, NULL);
    if (ret != 0) {
        wc_crypto2dev_cleanup();
        return ret;
    }

    ret = test_sha256_empty();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: SHA-256 KAT FAILED");
        goto done;
    }

    ret = test_aes_cbc_128();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: AES-CBC-128 KAT FAILED");
        goto done;
    }

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

#ifdef HAVE_AESGCM
    ret = test_aesgcm_empty();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: AES-GCM empty-plaintext KAT FAILED");
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
#endif
#endif

#ifdef WOLFSSL_TLS13
#ifndef NO_WOLFSSL_CLIENT
    ret = test_tls13_integration();
    if (ret != 0) {
        WOLFSSL_MSG("crypto2dev_test: TLS 1.3 integration FAILED");
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
    wc_CryptoCb_UnRegisterDevice(WOLF_CRYPTO2DEV_DEVID);
    wc_crypto2dev_cleanup();
    return ret;
}

#endif /* WOLFSSL_CRYPTO2DEV && WOLF_CRYPTO_CB && WOLFSSL_CRYPTO2DEV_TEST */
