/* crypto2dev_port.c — wolfSSL CryptoCb port for Linux /dev/crypto2dev
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
 * wolfSSL CryptoCb port for the Linux /dev/crypto2dev kernel interface.
 *
 * Build guards: WOLFSSL_CRYPTO2DEV && WOLF_CRYPTO_CB
 *
 * Usage:
 *   wc_crypto2dev_init();
 *   wc_CryptoCb_RegisterDevice(WOLF_CRYPTO2DEV_DEVID, wc_crypto2dev_cb, NULL);
 *   wc_InitRng_ex(&rng, NULL, WOLF_CRYPTO2DEV_DEVID);
 *   ...
 *   wc_crypto2dev_cleanup();
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_CRYPTO2DEV) && defined(WOLF_CRYPTO_CB)

#ifndef WOLF_CRYPTO_CB_FREE
#error "WOLFSSL_CRYPTO2DEV requires WOLF_CRYPTO_CB_FREE — enable with --enable-crypto2dev"
#endif

#include <wolfssl/wolfcrypt/port/crypto2dev/crypto2dev_port.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/ssl.h>
#ifdef NO_INLINE
#include <wolfssl/wolfcrypt/misc.h>
#else
#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>
#endif

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

#ifdef WOLFSSL_CRYPTO2DEV_SIM
#include <wolfssl/wolfcrypt/port/crypto2dev/crypto2dev_sim.h>
#endif

/* Minimum crypto2dev constants needed for KEY fd lifecycle.
 * Full ioctl definitions are in ~/WORK/WOLFKM/include/uapi/crypto2dev_ioctl.h.
 * We replicate only what is used here to avoid a build-time dependency on
 * the out-of-tree header. */
#ifndef CRYPTO2DEV_IOC_MAGIC
#define CRYPTO2DEV_IOC_MAGIC         ((unsigned char)0xC2)
#endif
#ifndef CRYPTO2DEV_ALGO_MAXLEN
#define CRYPTO2DEV_ALGO_MAXLEN       32
#endif
#ifndef CRYPTO2DEV_PROVIDER_MAXLEN
#define CRYPTO2DEV_PROVIDER_MAXLEN   32
#endif
#ifndef CRYPTO2DEV_KEY_PRIVATE
#define CRYPTO2DEV_KEY_PRIVATE       1
#define CRYPTO2DEV_KEY_PUBLIC        2
#define CRYPTO2DEV_KEY_PAIR          3
#define CRYPTO2DEV_KEY_SYMMETRIC     4
#endif
#ifndef CRYPTO2DEV_KEY_IMPORT_MAXLEN
#define CRYPTO2DEV_KEY_IMPORT_MAXLEN 8192
#endif

struct crypto2dev_key_import_op {
    char  algo    [CRYPTO2DEV_ALGO_MAXLEN];
    char  provider[CRYPTO2DEV_PROVIDER_MAXLEN];
    unsigned int key_type;
    unsigned int exportable;
    unsigned int keylen;
    unsigned char _pad[4];
};
#ifndef CRYPTO2DEV_IOC_KEY_IMPORT
#define CRYPTO2DEV_IOC_KEY_IMPORT  _IOW(CRYPTO2DEV_IOC_MAGIC, 11, \
                                        struct crypto2dev_key_import_op)
#endif

/* OPERATION fd lifecycle */
#ifndef CRYPTO2DEV_KEY_MAXLEN
#define CRYPTO2DEV_KEY_MAXLEN          128   /* max inline key in INIT */
#endif
#ifndef CRYPTO2DEV_IV_MAXLEN
#define CRYPTO2DEV_IV_MAXLEN           32
#endif
#ifndef CRYPTO2DEV_AAD_MAXLEN
#define CRYPTO2DEV_AAD_MAXLEN          256
#endif
#ifndef CRYPTO2DEV_TAG_MAXLEN
#define CRYPTO2DEV_TAG_MAXLEN          16
#endif
#ifndef CRYPTO2DEV_HASH_MAXLEN
#define CRYPTO2DEV_HASH_MAXLEN         64    /* max digest: SHA-512 = 64 bytes */
#endif
#ifndef CRYPTO2DEV_SIG_MAXLEN
#define CRYPTO2DEV_SIG_MAXLEN          512   /* max sig: RSA-4096 DER = 512 bytes */
#endif
#ifndef CRYPTO2DEV_PUBKEY_MAXLEN
#define CRYPTO2DEV_PUBKEY_MAXLEN       256
#endif
#ifndef CRYPTO2DEV_KDF_SALT_MAXLEN
#define CRYPTO2DEV_KDF_SALT_MAXLEN     64
#endif
#ifndef CRYPTO2DEV_KDF_INFO_MAXLEN
#define CRYPTO2DEV_KDF_INFO_MAXLEN     256
#endif
#ifndef CRYPTO2DEV_KDF_OKM_MAXLEN
#define CRYPTO2DEV_KDF_OKM_MAXLEN      64
#endif

#ifndef CRYPTO2DEV_OP_ENCRYPT
#define CRYPTO2DEV_OP_ENCRYPT          1
#define CRYPTO2DEV_OP_DECRYPT          2
#define CRYPTO2DEV_OP_HASH             3
#endif

/* OPERATION fd ioctls */
#ifndef CRYPTO2DEV_IOC_INIT
#define CRYPTO2DEV_IOC_INIT     _IOW(CRYPTO2DEV_IOC_MAGIC, 1,  struct crypto2dev_init_op)
#define CRYPTO2DEV_IOC_SET_IV   _IOW(CRYPTO2DEV_IOC_MAGIC, 2,  struct crypto2dev_iv_op)
#define CRYPTO2DEV_IOC_SET_AAD  _IOW(CRYPTO2DEV_IOC_MAGIC, 3,  struct crypto2dev_aad_op)
#define CRYPTO2DEV_IOC_GET_TAG  _IOR(CRYPTO2DEV_IOC_MAGIC, 4,  struct crypto2dev_tag_op)
#define CRYPTO2DEV_IOC_SET_TAG  _IOW(CRYPTO2DEV_IOC_MAGIC, 5,  struct crypto2dev_tag_op)
#define CRYPTO2DEV_IOC_RESET    _IO( CRYPTO2DEV_IOC_MAGIC, 19)
#define CRYPTO2DEV_IOC_REQUIRE_FIPS _IO(CRYPTO2DEV_IOC_MAGIC, 20)
#define CRYPTO2DEV_IOC_FINALIZE _IO( CRYPTO2DEV_IOC_MAGIC, 21)
#define CRYPTO2DEV_IOC_DO_KDF   _IOWR(CRYPTO2DEV_IOC_MAGIC, 22, struct crypto2dev_kdf_op)
#endif

/* Asymmetric ioctls */
#ifndef CRYPTO2DEV_IOC_KEY_GENERATE
#define CRYPTO2DEV_IOC_KEY_GENERATE \
    _IOW(CRYPTO2DEV_IOC_MAGIC, 12, struct crypto2dev_key_generate_op)
#define CRYPTO2DEV_IOC_DO_SIGN   _IOWR(CRYPTO2DEV_IOC_MAGIC, 16, struct crypto2dev_sign_op)
#define CRYPTO2DEV_IOC_DO_VERIFY _IOWR(CRYPTO2DEV_IOC_MAGIC, 17, struct crypto2dev_verify_op)
#define CRYPTO2DEV_IOC_DO_AGREE  _IOWR(CRYPTO2DEV_IOC_MAGIC, 18, struct crypto2dev_agree_op)
#endif

struct crypto2dev_init_op {
    char          algo    [CRYPTO2DEV_ALGO_MAXLEN];
    char          provider[CRYPTO2DEV_PROVIDER_MAXLEN];
    unsigned int  op;
    unsigned int  keylen;
    unsigned char key[CRYPTO2DEV_KEY_MAXLEN];
    int           key_fd;
    unsigned char _pad[4];
};

struct crypto2dev_iv_op {
    unsigned char iv[CRYPTO2DEV_IV_MAXLEN];
    unsigned int  ivlen;
};

struct crypto2dev_aad_op {
    unsigned char aad[CRYPTO2DEV_AAD_MAXLEN];
    unsigned int  aadlen;
};

struct crypto2dev_tag_op {
    unsigned char tag[CRYPTO2DEV_TAG_MAXLEN];
    unsigned int  taglen;
};

struct crypto2dev_sign_op {
    int           key_fd;
    unsigned char _pad[4];
    char          hash_algo[CRYPTO2DEV_ALGO_MAXLEN];
    unsigned int  digest_len;
    unsigned char digest[CRYPTO2DEV_HASH_MAXLEN];
    unsigned int  sig_len;
    unsigned char sig[CRYPTO2DEV_SIG_MAXLEN];
};

struct crypto2dev_verify_op {
    int           key_fd;
    unsigned char _pad[4];
    char          hash_algo[CRYPTO2DEV_ALGO_MAXLEN];
    unsigned int  digest_len;
    unsigned char digest[CRYPTO2DEV_HASH_MAXLEN];
    unsigned int  sig_len;
    unsigned char sig[CRYPTO2DEV_SIG_MAXLEN];
};

struct crypto2dev_agree_op {
    int           key_fd;
    unsigned char _pad[4];
    unsigned int  peer_pubkey_len;
    unsigned char peer_pubkey[CRYPTO2DEV_PUBKEY_MAXLEN];
    unsigned int  salt_len;
    unsigned char salt[CRYPTO2DEV_KDF_SALT_MAXLEN];
    unsigned int  info_len;
    unsigned char info[CRYPTO2DEV_KDF_INFO_MAXLEN];
    unsigned int  okm_len;
    unsigned char okm[CRYPTO2DEV_PUBKEY_MAXLEN];
};

struct crypto2dev_key_generate_op {
    char          algo    [CRYPTO2DEV_ALGO_MAXLEN];
    char          provider[CRYPTO2DEV_PROVIDER_MAXLEN];
    unsigned int  exportable;
    unsigned char _pad[4];
};

struct crypto2dev_kdf_op {
    char          algo    [CRYPTO2DEV_ALGO_MAXLEN];
    char          out_algo[CRYPTO2DEV_ALGO_MAXLEN];
    unsigned char salt    [CRYPTO2DEV_KDF_SALT_MAXLEN];
    unsigned int  salt_len;
    unsigned char info    [CRYPTO2DEV_KDF_INFO_MAXLEN];
    unsigned int  info_len;
    unsigned int  okm_len;
    unsigned int  iterations;
    int           ikm_fd;
    unsigned char exportable;
    unsigned char _pad[3];
};

/* Per-object context structs for devCtx fields.
 * Allocated with XMALLOC(DYNAMIC_TYPE_TMP_BUFFER), freed in FREE callback. */

typedef struct {
    byte   key[32];   /* raw AES key bytes; AES-128=16, AES-192=24, AES-256=32 */
    word32 keySz;
} Crypto2DevAesCtx;

typedef struct {
    byte   key[128];  /* raw HMAC key bytes (up to SHA-384/SHA-512 block size = 128 bytes) */
    word32 keySz;
    char   algo[CRYPTO2DEV_ALGO_MAXLEN]; /* e.g., "hmac(sha256)" */
    /* Streaming accumulation buffer — appended on each Update, flushed on Final. */
    byte*  data;
    word32 dataSz;
} Crypto2DevHmacCtx;

typedef struct {
    int  op_fd;                           /* open OPERATION fd; -1 = not started */
    int  pool_slot;                       /* pool slot index for op_fd */
    char algo[CRYPTO2DEV_ALGO_MAXLEN];    /* e.g., "sha256" */
} Crypto2DevHashCtx;

/* Ensure error codes are distinct — crypto2dev relies on this. */
wc_static_assert2(WC_HW_E != CRYPTOCB_UNAVAILABLE,
    "WC_HW_E and CRYPTOCB_UNAVAILABLE must be distinct; "
    "crypto2dev_port relies on this for hardware-error vs. fallback semantics");

#define CRYPTO2DEV_PATH  "/dev/crypto2dev"

/* Forward declarations for SETKEY helpers called from crypto2dev_setkey(). */
#ifdef WOLF_CRYPTO_CB_SETKEY
static int crypto2dev_aes_setkey_ctx(const wc_CryptoInfo* info);
#ifndef NO_HMAC
static int crypto2dev_hmac_setkey_ctx(const wc_CryptoInfo* info);
#endif
#endif /* WOLF_CRYPTO_CB_SETKEY */

/* Map a Linux errno from a crypto2dev ioctl failure to a wolfSSL error code.
 *
 * The caller is responsible for deciding whether the resulting code should
 * be returned directly (hard failure) or converted to CRYPTOCB_UNAVAILABLE
 * (software fallback). Specifically:
 *   NOT_COMPILED_IN  — algo/op not supported: caller should return
 *                      CRYPTOCB_UNAVAILABLE to allow software fallback.
 *   BAD_FUNC_ARG     — invalid argument; also used for ENOENT (algo absent),
 *                      which the caller may promote to CRYPTOCB_UNAVAILABLE.
 */
static int crypto2dev_to_wc_err(int errnum)
{
    switch (errnum) {
        case EINVAL:     return BAD_FUNC_ARG;
        case ENOENT:     return BAD_FUNC_ARG;
        case EACCES:     return FIPS_NOT_ALLOWED_E;
        case ENODEV:     return BAD_STATE_E;
        case EBUSY:      return BAD_STATE_E;
        case EOPNOTSUPP: return NOT_COMPILED_IN;
        case ENOSYS:     return NOT_COMPILED_IN;
        case EMSGSIZE:   return BUFFER_E;
        case EBADMSG:    return AES_GCM_AUTH_E;
        case EIO:        return WC_HW_E;
        case ENOMEM:     return MEMORY_E;
        case EFAULT:     return BAD_FUNC_ARG;
        default:         return WC_HW_E;
    }
}

/* Global device fd. -1 = not open. */
static int g_crypto2dev_fd = -1;

#ifndef WOLFSSL_CRYPTO2DEV_POOL_SIZE
#define WOLFSSL_CRYPTO2DEV_POOL_SIZE 8
#endif

typedef struct {
    int fd;       /* -1 = slot is empty/closed; >= 0 = unset fd ready to lease */
    int in_use;   /* 0 = available; 1 = currently leased to a caller */
} Crypto2DevPoolSlot;

typedef struct {
    Crypto2DevPoolSlot* slots;
    int capacity;
    wolfSSL_Mutex lock;
} Crypto2DevPool;

static Crypto2DevPool g_pool;
static int g_pool_inited = 0;

/* When non-zero, WC_ALGO_TYPE_HASH returns CRYPTOCB_UNAVAILABLE so that TLS
 * transcript-hash objects fall through to software. This avoids the
 * wc_Sha256Copy failure that occurs when hardware holds streaming state.
 * Set by wc_crypto2dev_assign_devid(). HMAC, CIPHER, and PK are unaffected.
 *
 * Single-threaded initialisation: this flag is written by
 * wc_crypto2dev_assign_devid() and must be set before any concurrent thread
 * invokes the registered callback. */
static int g_tls_safe_mode = 0;

static wolfSSL_Mutex g_ecdsa_fd_lock;
static int           g_ecdsa_fd_lock_inited = 0;

static int crypto2dev_pool_init(Crypto2DevPool* pool, int capacity)
{
    int i;
    int ret;

    pool->slots = (Crypto2DevPoolSlot*)XMALLOC(
        (word32)(capacity * (int)sizeof(Crypto2DevPoolSlot)),
        NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pool->slots == NULL)
        return MEMORY_E;

    for (i = 0; i < capacity; i++) {
        pool->slots[i].fd     = open(CRYPTO2DEV_PATH, O_RDWR | O_CLOEXEC);
        pool->slots[i].in_use = 0;
        if (pool->slots[i].fd < 0) {
            int j;
            for (j = 0; j < i; j++)
                close(pool->slots[j].fd);
            XFREE(pool->slots, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            pool->slots = NULL;
            return WC_HW_E;
        }
    }
    pool->capacity = capacity;

    ret = wc_InitMutex(&pool->lock);
    if (ret != 0) {
        for (i = 0; i < capacity; i++)
            close(pool->slots[i].fd);
        XFREE(pool->slots, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        pool->slots = NULL;
        return ret;
    }

    return 0;
}

static void crypto2dev_pool_cleanup(Crypto2DevPool* pool)
{
    int i;

    if (pool->slots == NULL)
        return;

    wc_LockMutex(&pool->lock);
    for (i = 0; i < pool->capacity; i++) {
        if (pool->slots[i].fd >= 0) {
            close(pool->slots[i].fd);
            pool->slots[i].fd = -1;
        }
    }
    wc_UnLockMutex(&pool->lock);

    wc_FreeMutex(&pool->lock);
    XFREE(pool->slots, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    pool->slots    = NULL;
    pool->capacity = 0;
}

/* Lease an unset fd from the pool.
 * Returns the fd on success (>= 0) and writes the slot index to *out_slot_idx.
 * Returns -1 on failure. */
static int crypto2dev_pool_acquire(Crypto2DevPool* pool, int* out_slot_idx)
{
    int i;
    int fd = -1;

    if (pool->slots == NULL || out_slot_idx == NULL)
        return -1;

    if (wc_LockMutex(&pool->lock) != 0)
        return -1;
    for (i = 0; i < pool->capacity; i++) {
        if (pool->slots[i].in_use)
            continue;
        if (pool->slots[i].fd < 0) {
            /* Attempt to recover a slot that failed to reopen at release time. */
            pool->slots[i].fd = open(CRYPTO2DEV_PATH, O_RDWR | O_CLOEXEC);
            if (pool->slots[i].fd < 0)
                continue;
        }
        pool->slots[i].in_use = 1;
        fd = pool->slots[i].fd;
        *out_slot_idx = i;
        break;
    }
    wc_UnLockMutex(&pool->lock);

    return fd;
}

/* Return a slot to the pool by slot index (not by fd value).
 * Opens a fresh unset fd for the slot outside the mutex to avoid blocking. */
static void crypto2dev_pool_release(Crypto2DevPool* pool, int slot_idx)
{
    int new_fd;

    if (pool->slots == NULL)
        return;
    if (slot_idx < 0 || slot_idx >= pool->capacity)
        return;

    /* Open the replacement fd outside the mutex — open() can block. */
    new_fd = open(CRYPTO2DEV_PATH, O_RDWR | O_CLOEXEC);

    wc_LockMutex(&pool->lock);
    if (new_fd < 0) {
        /* Re-open failed: mark slot available; will retry at next acquire if device is available again. */
        WOLFSSL_MSG("crypto2dev: pool slot re-open failed, will retry at next acquire if device is available again");
        pool->slots[slot_idx].fd     = -1;
        pool->slots[slot_idx].in_use = 0;
    } else {
        pool->slots[slot_idx].fd     = new_fd;
        pool->slots[slot_idx].in_use = 0;
    }
    wc_UnLockMutex(&pool->lock);
}

#ifdef WOLF_CRYPTO_CB_SETKEY
/* Import raw key bytes into a new KEY fd.
 * On success, returns the new fd (>= 0) which caller stores in devCtx.
 * On failure, returns a negative wolfSSL error code. */
static int crypto2dev_key_import(const char* algo, unsigned int key_type,
                                  const byte* key_bytes, word32 key_len)
{
    int fd = -1;
    int ret = 0;
    ssize_t nw;
    struct crypto2dev_key_import_op op;

    if (algo == NULL || key_bytes == NULL || key_len == 0 ||
            key_len > CRYPTO2DEV_KEY_IMPORT_MAXLEN)
        return BAD_FUNC_ARG;

    fd = open(CRYPTO2DEV_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return WC_HW_E;

    nw = write(fd, key_bytes, key_len);
    if (nw != (ssize_t)key_len) {
        ret = (nw < 0) ? crypto2dev_to_wc_err(errno) : WC_HW_E;
        goto done;
    }

    XMEMSET(&op, 0, sizeof(op));
    XSTRNCPY(op.algo, algo, sizeof(op.algo) - 1);
    op.algo[sizeof(op.algo) - 1] = '\0';
    op.key_type  = key_type;
    op.exportable = 0;
    op.keylen    = key_len;

    if (ioctl(fd, CRYPTO2DEV_IOC_KEY_IMPORT, &op) < 0) {
        ret = crypto2dev_to_wc_err(errno);
        goto done;
    }

done:
    if (ret != 0 && fd >= 0) {
        close(fd);
        fd = -1;
    }
    return (ret != 0) ? ret : fd;
}

static int crypto2dev_setkey(const wc_CryptoInfo* info)
{
    void** devctx_ptr = NULL;
    int    new_fd     = -1;
    int    ret        = 0;

    switch (info->setkey.type) {
        case WC_SETKEY_ECC_PRIV: {
            ecc_key* key = (ecc_key*)info->setkey.obj;
            ecc_key* src = (ecc_key*)info->setkey.key;
            word32 field_sz = info->setkey.keySz;
            byte raw[ECC_MAXSIZE];
            if (key == NULL || src == NULL || field_sz == 0 ||
                    field_sz > ECC_MAXSIZE)
                return BAD_FUNC_ARG;
            ret = wc_ecc_export_private_only(src, raw, &field_sz);
            if (ret != 0)
                return ret;
            devctx_ptr = (void**)&key->devCtx;
            new_fd = crypto2dev_key_import("ecdsa", CRYPTO2DEV_KEY_PRIVATE,
                                            raw, field_sz);
            ForceZero(raw, sizeof(raw));
            if (new_fd < 0) {
                if (*devctx_ptr != NULL) {
                    close((int)(intptr_t)*devctx_ptr);
                    *devctx_ptr = NULL;
                }
                return new_fd;
            }
            break;
        }
        case WC_SETKEY_ECC_PUB: {
            ecc_key* key = (ecc_key*)info->setkey.obj;
            ecc_key* src = (ecc_key*)info->setkey.key;
            byte raw[1 + 2 * ECC_MAXSIZE];
            word32 raw_len = sizeof(raw);
            if (key == NULL || src == NULL)
                return BAD_FUNC_ARG;
            ret = wc_ecc_export_x963(src, raw, &raw_len);
            if (ret != 0)
                return ret;
            devctx_ptr = (void**)&key->devCtx;
            new_fd = crypto2dev_key_import("ecdsa", CRYPTO2DEV_KEY_PUBLIC,
                                            raw, raw_len);
            ForceZero(raw, sizeof(raw));
            if (new_fd < 0) {
                if (*devctx_ptr != NULL) {
                    close((int)(intptr_t)*devctx_ptr);
                    *devctx_ptr = NULL;
                }
                return new_fd;
            }
            break;
        }
        case WC_SETKEY_RSA_PRIV: {
            RsaKey* key = (RsaKey*)info->setkey.obj;
            byte*   der = (byte*)info->setkey.key;
            word32  der_len = info->setkey.keySz;
            if (key == NULL || der == NULL || der_len == 0)
                return BAD_FUNC_ARG;
            devctx_ptr = (void**)&key->devCtx;
            new_fd = crypto2dev_key_import("rsa", CRYPTO2DEV_KEY_PRIVATE,
                                            der, der_len);
            if (new_fd < 0) {
                if (*devctx_ptr != NULL) {
                    close((int)(intptr_t)*devctx_ptr);
                    *devctx_ptr = NULL;
                }
                return new_fd;
            }
            break;
        }
        case WC_SETKEY_RSA_PUB: {
            RsaKey* key = (RsaKey*)info->setkey.obj;
            byte*   der = (byte*)info->setkey.key;
            word32  der_len = info->setkey.keySz;
            if (key == NULL || der == NULL || der_len == 0)
                return BAD_FUNC_ARG;
            devctx_ptr = (void**)&key->devCtx;
            new_fd = crypto2dev_key_import("rsa", CRYPTO2DEV_KEY_PUBLIC,
                                            der, der_len);
            if (new_fd < 0) {
                if (*devctx_ptr != NULL) {
                    close((int)(intptr_t)*devctx_ptr);
                    *devctx_ptr = NULL;
                }
                return new_fd;
            }
            break;
        }
        case WC_SETKEY_AES:
            return crypto2dev_aes_setkey_ctx(info);
#ifndef NO_HMAC
        case WC_SETKEY_HMAC:
            return crypto2dev_hmac_setkey_ctx(info);
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }

    /* If an old fd is stored, close it before storing the new one. */
    if (*devctx_ptr != NULL) {
        close((int)(intptr_t)*devctx_ptr);
    }
    *devctx_ptr = (void*)(intptr_t)new_fd;
    return 0;
}
#endif /* WOLF_CRYPTO_CB_SETKEY */

#ifdef WOLF_CRYPTO_CB_FREE
static int crypto2dev_free_pk(const wc_CryptoInfo* info)
{
    void** devctx_ptr = NULL;
    int    fd;

    switch (info->free.type) {
        case WC_PK_TYPE_ECDSA_SIGN:
        case WC_PK_TYPE_ECDSA_VERIFY:
        case WC_PK_TYPE_ECDH:
        case WC_PK_TYPE_EC_KEYGEN: {
            ecc_key* key = (ecc_key*)info->free.obj;
            if (key == NULL)
                return 0;
            devctx_ptr = (void**)&key->devCtx;
            break;
        }
        case WC_PK_TYPE_RSA:
        case WC_PK_TYPE_RSA_GET_SIZE: {
            RsaKey* key = (RsaKey*)info->free.obj;
            if (key == NULL)
                return 0;
            devctx_ptr = (void**)&key->devCtx;
            break;
        }
        default:
            return 0;
    }

    if (devctx_ptr != NULL && *devctx_ptr != NULL) {
        fd = (int)(intptr_t)*devctx_ptr;
        close(fd);
        *devctx_ptr = NULL;
    }
    return 0;
}
#endif /* WOLF_CRYPTO_CB_FREE */

#ifdef WOLF_CRYPTO_CB_SETKEY
static int crypto2dev_aes_setkey_ctx(const wc_CryptoInfo* info)
{
    Aes* aes = (Aes*)info->setkey.obj;
    const byte* key = (const byte*)info->setkey.key;
    word32 keySz = info->setkey.keySz;
    Crypto2DevAesCtx* ctx;

    if (aes == NULL || key == NULL || keySz == 0 || keySz > 32)
        return BAD_FUNC_ARG;

    if (aes->devCtx != NULL) {
        ForceZero(aes->devCtx, sizeof(Crypto2DevAesCtx));
        XFREE(aes->devCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        aes->devCtx = NULL;
    }

    ctx = (Crypto2DevAesCtx*)XMALLOC(sizeof(Crypto2DevAesCtx),
                                       NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL)
        return MEMORY_E;

    XMEMCPY(ctx->key, key, keySz);
    ctx->keySz = keySz;
    aes->devCtx = ctx;
    aes->keylen = (int)keySz;

    /* wc_AesSetKey() returns immediately when SETKEY returns 0, skipping the
     * software path that copies iv into aes->reg.  AES-CBC reads aes->reg for
     * the IV at encryption time, so we must mirror that copy here. */
    XMEMSET(aes->reg, 0, AES_BLOCK_SIZE);
    if (info->setkey.aux != NULL && info->setkey.auxSz > 0 &&
            info->setkey.auxSz <= AES_BLOCK_SIZE)
        XMEMCPY(aes->reg, info->setkey.aux, info->setkey.auxSz);

    return 0;
}
#endif /* WOLF_CRYPTO_CB_SETKEY */

static int crypto2dev_cipher(const wc_CryptoInfo* info)
{
    const Aes* aes = NULL;
    const Crypto2DevAesCtx* ctx = NULL;
    const char* algo = NULL;
    int op_fd = -1;
    int pool_slot = -1;
    int ret = 0;
    struct crypto2dev_init_op init_op;
    struct crypto2dev_iv_op iv_op;
    struct crypto2dev_aad_op aad_op;
    struct crypto2dev_tag_op tag_op;
    ssize_t nw, nr;
    const byte* iv = NULL;
    word32 ivSz = 0;
    int is_enc = info->cipher.enc;

    switch (info->cipher.type) {
#ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
            aes  = info->cipher.aescbc.aes;
            algo = "cbc(aes)";
            iv   = (const byte*)info->cipher.aescbc.aes->reg;
            ivSz = AES_BLOCK_SIZE;
            break;
#endif
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
            if (is_enc) {
                aes  = info->cipher.aesgcm_enc.aes;
                iv   = info->cipher.aesgcm_enc.iv;
                ivSz = info->cipher.aesgcm_enc.ivSz;
            } else {
                aes  = info->cipher.aesgcm_dec.aes;
                iv   = info->cipher.aesgcm_dec.iv;
                ivSz = info->cipher.aesgcm_dec.ivSz;
            }
            algo = "gcm(aes)";
            break;
#endif
#ifdef WOLFSSL_AES_COUNTER
        case WC_CIPHER_AES_CTR:
            aes  = info->cipher.aesctr.aes;
            algo = "ctr(aes)";
            iv   = info->cipher.aesctr.aes->reg;
            ivSz = AES_BLOCK_SIZE;
            break;
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }

    if (aes == NULL)
        return BAD_FUNC_ARG;

    ctx = (const Crypto2DevAesCtx*)aes->devCtx;
    if (ctx == NULL || ctx->keySz == 0)
        return CRYPTOCB_UNAVAILABLE;

    op_fd = crypto2dev_pool_acquire(&g_pool, &pool_slot);
    if (op_fd < 0)
        return WC_HW_E;

    XMEMSET(&init_op, 0, sizeof(init_op));
    XSTRNCPY(init_op.algo, algo, sizeof(init_op.algo) - 1);
    init_op.op     = is_enc ? CRYPTO2DEV_OP_ENCRYPT : CRYPTO2DEV_OP_DECRYPT;
    init_op.keylen = ctx->keySz;
    XMEMCPY(init_op.key, ctx->key, ctx->keySz);
    init_op.key_fd = -1;
    if (ioctl(op_fd, CRYPTO2DEV_IOC_INIT, &init_op) < 0) {
        ret = crypto2dev_to_wc_err(errno);
        goto done;
    }

    if (iv != NULL && ivSz > 0 && ivSz <= CRYPTO2DEV_IV_MAXLEN) {
        XMEMSET(&iv_op, 0, sizeof(iv_op));
        XMEMCPY(iv_op.iv, iv, ivSz);
        iv_op.ivlen = ivSz;
        if (ioctl(op_fd, CRYPTO2DEV_IOC_SET_IV, &iv_op) < 0) {
            ret = crypto2dev_to_wc_err(errno);
            goto done;
        }
    }

#ifdef HAVE_AESGCM
    if (info->cipher.type == WC_CIPHER_AES_GCM) {
        const byte* authIn  = is_enc ? info->cipher.aesgcm_enc.authIn
                                      : info->cipher.aesgcm_dec.authIn;
        word32 authInSz     = is_enc ? info->cipher.aesgcm_enc.authInSz
                                      : info->cipher.aesgcm_dec.authInSz;
        const byte* authTag = is_enc ? NULL : info->cipher.aesgcm_dec.authTag;
        word32 authTagSz    = is_enc ? info->cipher.aesgcm_enc.authTagSz
                                      : info->cipher.aesgcm_dec.authTagSz;

        if (authIn != NULL && authInSz > 0 &&
                authInSz <= CRYPTO2DEV_AAD_MAXLEN) {
            XMEMSET(&aad_op, 0, sizeof(aad_op));
            XMEMCPY(aad_op.aad, authIn, authInSz);
            aad_op.aadlen = authInSz;
            if (ioctl(op_fd, CRYPTO2DEV_IOC_SET_AAD, &aad_op) < 0) {
                ret = crypto2dev_to_wc_err(errno);
                goto done;
            }
        }

        if (!is_enc && authTag != NULL && authTagSz > 0 &&
                authTagSz <= CRYPTO2DEV_TAG_MAXLEN) {
            XMEMSET(&tag_op, 0, sizeof(tag_op));
            XMEMCPY(tag_op.tag, authTag, authTagSz);
            tag_op.taglen = authTagSz;
            if (ioctl(op_fd, CRYPTO2DEV_IOC_SET_TAG, &tag_op) < 0) {
                ret = crypto2dev_to_wc_err(errno);
                goto done;
            }
        }
    }
#endif /* HAVE_AESGCM */

    {
        const byte* in_buf = NULL;
        byte* out_buf = NULL;
        word32 data_sz = 0;

        switch (info->cipher.type) {
#ifdef HAVE_AES_CBC
            case WC_CIPHER_AES_CBC:
                in_buf  = info->cipher.aescbc.in;
                out_buf = info->cipher.aescbc.out;
                data_sz = info->cipher.aescbc.sz;
                break;
#endif
#ifdef HAVE_AESGCM
            case WC_CIPHER_AES_GCM:
                in_buf  = is_enc ? info->cipher.aesgcm_enc.in
                                 : info->cipher.aesgcm_dec.in;
                out_buf = is_enc ? info->cipher.aesgcm_enc.out
                                 : info->cipher.aesgcm_dec.out;
                data_sz = is_enc ? info->cipher.aesgcm_enc.sz
                                 : info->cipher.aesgcm_dec.sz;
                break;
#endif
#ifdef WOLFSSL_AES_COUNTER
            case WC_CIPHER_AES_CTR:
                in_buf  = info->cipher.aesctr.in;
                out_buf = info->cipher.aesctr.out;
                data_sz = info->cipher.aesctr.sz;
                break;
#endif
            default:
                ret = WC_HW_E;
                goto done;
        }

        /* AES-GCM allows zero-length plaintext (tag-only). Other modes
         * require non-NULL buffers and non-zero length. */
#ifdef HAVE_AESGCM
        if (info->cipher.type == WC_CIPHER_AES_GCM) {
            if (data_sz != 0 && (in_buf == NULL || out_buf == NULL)) {
                ret = BAD_FUNC_ARG;
                goto done;
            }
        } else
#endif
        {
            if (in_buf == NULL || out_buf == NULL || data_sz == 0) {
                ret = BAD_FUNC_ARG;
                goto done;
            }
        }

        if (data_sz > 0) {
            nw = write(op_fd, in_buf, data_sz);
            if (nw != (ssize_t)data_sz) {
                ret = (nw < 0) ? crypto2dev_to_wc_err(errno) : WC_HW_E;
                goto done;
            }
        }

        if (ioctl(op_fd, CRYPTO2DEV_IOC_FINALIZE, NULL) < 0) {
            ret = crypto2dev_to_wc_err(errno);
            goto done;
        }

        if (data_sz > 0) {
            nr = read(op_fd, out_buf, data_sz);
            if (nr != (ssize_t)data_sz) {
                ret = (nr < 0) ? crypto2dev_to_wc_err(errno) : WC_HW_E;
                goto done;
            }

#ifdef HAVE_AES_CBC
            if (info->cipher.type == WC_CIPHER_AES_CBC) {
                const byte* src = is_enc ? out_buf : in_buf;
                XMEMCPY((byte*)((Aes*)aes)->reg,
                        src + data_sz - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            }
#endif
#ifdef WOLFSSL_AES_COUNTER
            if (info->cipher.type == WC_CIPHER_AES_CTR) {
                word32 blocks = (data_sz + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
                byte* ctr = (byte*)((Aes*)aes)->reg;
                word32 b;
                for (b = 0; b < blocks; b++) {
                    int ci;
                    for (ci = AES_BLOCK_SIZE - 1; ci >= 0; ci--) {
                        if (++ctr[ci])
                            break;
                    }
                }
            }
#endif
        }
    }

#ifdef HAVE_AESGCM
    if (info->cipher.type == WC_CIPHER_AES_GCM && is_enc) {
        byte* authTag    = info->cipher.aesgcm_enc.authTag;
        word32 authTagSz = info->cipher.aesgcm_enc.authTagSz;
        if (authTag != NULL && authTagSz > 0 &&
                authTagSz <= CRYPTO2DEV_TAG_MAXLEN) {
            XMEMSET(&tag_op, 0, sizeof(tag_op));
            tag_op.taglen = authTagSz;
            if (ioctl(op_fd, CRYPTO2DEV_IOC_GET_TAG, &tag_op) < 0) {
                ret = crypto2dev_to_wc_err(errno);
                goto done;
            }
            if (tag_op.taglen != authTagSz) {
                ret = WC_HW_E;
                goto done;
            }
            XMEMCPY(authTag, tag_op.tag, authTagSz);
        }
    }
#endif /* HAVE_AESGCM */

done:
    if (op_fd >= 0) {
        close(op_fd);
        crypto2dev_pool_release(&g_pool, pool_slot);
    }
    ForceZero(&init_op, sizeof(init_op));
    return ret;
}

static int crypto2dev_hash(wc_CryptoInfo* info)
{
    const char* algo = NULL;
    word32 digest_sz = 0;
    Crypto2DevHashCtx** devctx_ptr = NULL;
    Crypto2DevHashCtx* ctx = NULL;
    int ret = 0;
    ssize_t nw, nr;

    switch (info->hash.type) {
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256:
            algo       = "sha256";
            digest_sz  = WC_SHA256_DIGEST_SIZE;
            devctx_ptr = (Crypto2DevHashCtx**)&info->hash.sha256->devCtx;
            break;
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            algo       = "sha384";
            digest_sz  = WC_SHA384_DIGEST_SIZE;
            devctx_ptr = (Crypto2DevHashCtx**)&info->hash.sha384->devCtx;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            algo       = "sha512";
            digest_sz  = WC_SHA512_DIGEST_SIZE;
            devctx_ptr = (Crypto2DevHashCtx**)&info->hash.sha512->devCtx;
            break;
#endif
#ifdef WOLFSSL_SHA3
        case WC_HASH_TYPE_SHA3_256:
            algo       = "sha3-256";
            digest_sz  = WC_SHA3_256_DIGEST_SIZE;
            devctx_ptr = (Crypto2DevHashCtx**)&info->hash.sha3->devCtx;
            break;
        case WC_HASH_TYPE_SHA3_384:
            algo       = "sha3-384";
            digest_sz  = WC_SHA3_384_DIGEST_SIZE;
            devctx_ptr = (Crypto2DevHashCtx**)&info->hash.sha3->devCtx;
            break;
        case WC_HASH_TYPE_SHA3_512:
            algo       = "sha3-512";
            digest_sz  = WC_SHA3_512_DIGEST_SIZE;
            devctx_ptr = (Crypto2DevHashCtx**)&info->hash.sha3->devCtx;
            break;
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }

    if (devctx_ptr == NULL)
        return BAD_FUNC_ARG;

    if (*devctx_ptr == NULL) {
        struct crypto2dev_init_op init_op;
        int pool_slot = -1;
        int op_fd = crypto2dev_pool_acquire(&g_pool, &pool_slot);
        if (op_fd < 0)
            return WC_HW_E;

        XMEMSET(&init_op, 0, sizeof(init_op));
        XSTRNCPY(init_op.algo, algo, sizeof(init_op.algo) - 1);
        init_op.op     = CRYPTO2DEV_OP_HASH;
        init_op.keylen = 0;
        init_op.key_fd = -1;
        if (ioctl(op_fd, CRYPTO2DEV_IOC_INIT, &init_op) < 0) {
            int err = crypto2dev_to_wc_err(errno);
            close(op_fd);
            crypto2dev_pool_release(&g_pool, pool_slot);
            ForceZero(&init_op, sizeof(init_op));
            return err;
        }

        ctx = (Crypto2DevHashCtx*)XMALLOC(sizeof(Crypto2DevHashCtx),
                                            NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (ctx == NULL) {
            close(op_fd);
            crypto2dev_pool_release(&g_pool, pool_slot);
            return MEMORY_E;
        }
        ctx->op_fd     = op_fd;
        ctx->pool_slot = pool_slot;
        XSTRNCPY(ctx->algo, algo, sizeof(ctx->algo) - 1);
        ctx->algo[sizeof(ctx->algo) - 1] = '\0';
        *devctx_ptr = ctx;
    } else {
        ctx = *devctx_ptr;
    }

    if (info->hash.in != NULL && info->hash.inSz > 0) {
        nw = write(ctx->op_fd, info->hash.in, info->hash.inSz);
        if (nw != (ssize_t)info->hash.inSz) {
            ret = (nw < 0) ? crypto2dev_to_wc_err(errno) : WC_HW_E;
            goto hash_error;
        }
    }

    if (info->hash.digest != NULL) {
        if (ioctl(ctx->op_fd, CRYPTO2DEV_IOC_FINALIZE, NULL) < 0) {
            ret = crypto2dev_to_wc_err(errno);
            goto hash_error;
        }
        nr = read(ctx->op_fd, info->hash.digest, digest_sz);
        if (nr != (ssize_t)digest_sz) {
            ret = (nr < 0) ? crypto2dev_to_wc_err(errno) : WC_HW_E;
            goto hash_error;
        }

        close(ctx->op_fd);
        crypto2dev_pool_release(&g_pool, ctx->pool_slot);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        *devctx_ptr = NULL;
    }

    return 0;

hash_error:
    if (ctx != NULL) {
        close(ctx->op_fd);
        crypto2dev_pool_release(&g_pool, ctx->pool_slot);
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        *devctx_ptr = NULL;
    }
    return ret;
}

#ifndef NO_HMAC
#ifdef WOLF_CRYPTO_CB_SETKEY
static int crypto2dev_hmac_setkey_ctx(const wc_CryptoInfo* info)
{
    Hmac* hmac = (Hmac*)info->setkey.obj;
    const byte* key = (const byte*)info->setkey.key;
    word32 keySz = info->setkey.keySz;
    const char* algo = NULL;
    Crypto2DevHmacCtx* ctx;

    if (hmac == NULL || key == NULL || keySz == 0)
        return BAD_FUNC_ARG;
    if (keySz > (word32)sizeof(((Crypto2DevHmacCtx*)0)->key))
        return CRYPTOCB_UNAVAILABLE; /* oversized key: fall through to software */

    switch (hmac->macType) {
        case WC_SHA256: algo = "hmac(sha256)"; break;
        case WC_SHA384: algo = "hmac(sha384)"; break;
        case WC_SHA512: algo = "hmac(sha512)"; break;
        default: return CRYPTOCB_UNAVAILABLE;
    }

    if (hmac->devCtx != NULL) {
        Crypto2DevHmacCtx* old_ctx = (Crypto2DevHmacCtx*)hmac->devCtx;
        /* Free any pending accumulation buffer before zeroing the struct. */
        if (old_ctx->data != NULL) {
            XMEMSET(old_ctx->data, 0, old_ctx->dataSz);
            XFREE(old_ctx->data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        ForceZero(hmac->devCtx, sizeof(Crypto2DevHmacCtx));
        XFREE(hmac->devCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        hmac->devCtx = NULL;
    }

    ctx = (Crypto2DevHmacCtx*)XMALLOC(sizeof(Crypto2DevHmacCtx),
                                        NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL)
        return MEMORY_E;
    XMEMSET(ctx, 0, sizeof(Crypto2DevHmacCtx));

    XMEMCPY(ctx->key, key, keySz);
    ctx->keySz = keySz;
    XSTRNCPY(ctx->algo, algo, sizeof(ctx->algo) - 1);
    ctx->algo[sizeof(ctx->algo) - 1] = '\0';
    /* ctx->data = NULL; ctx->dataSz = 0; — already zeroed by XMEMSET above */
    hmac->devCtx = ctx;
    return 0;
}
#endif /* WOLF_CRYPTO_CB_SETKEY */

static int crypto2dev_hmac(const wc_CryptoInfo* info)
{
    Hmac* hmac = (Hmac*)info->hmac.hmac;
    Crypto2DevHmacCtx* ctx;
    int op_fd = -1;
    int pool_slot = -1;
    int ret = 0;
    struct crypto2dev_init_op init_op;
    ssize_t nw, nr;

    if (hmac == NULL)
        return BAD_FUNC_ARG;

    ctx = (Crypto2DevHmacCtx*)hmac->devCtx;
    if (ctx == NULL || ctx->keySz == 0)
        return CRYPTOCB_UNAVAILABLE;

    /*
     * wolfSSL CryptoCb dispatches HMAC as two callbacks:
     *   Update: wc_HmacUpdate -> (in=data, inSz>0, digest=NULL)
     *   Final:  wc_HmacFinal  -> (in=NULL, inSz=0, digest=buf)
     * Accumulate data on Update; flush to hardware on Final.
     */
    if (info->hmac.digest == NULL) {
        /* Update phase — append to accumulation buffer. */
        byte* new_data;
        if (info->hmac.in == NULL)
            return (info->hmac.inSz == 0) ? 0 : BAD_FUNC_ARG;

        if (info->hmac.inSz > (word32)(0xFFFFFFFFu - ctx->dataSz))
            return BAD_FUNC_ARG;
        new_data = (byte*)XMALLOC(ctx->dataSz + info->hmac.inSz,
                                   NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (new_data == NULL)
            return MEMORY_E;
        if (ctx->data != NULL) {
            XMEMCPY(new_data, ctx->data, ctx->dataSz);
            XMEMSET(ctx->data, 0, ctx->dataSz);
            XFREE(ctx->data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
        XMEMCPY(new_data + ctx->dataSz, info->hmac.in, info->hmac.inSz);
        ctx->data   = new_data;
        ctx->dataSz += info->hmac.inSz;
        return 0;
    }

    /* Final phase — flush accumulated data to hardware and read MAC. */
    op_fd = crypto2dev_pool_acquire(&g_pool, &pool_slot);
    if (op_fd < 0)
        return WC_HW_E;

    XMEMSET(&init_op, 0, sizeof(init_op));
    XMEMCPY(init_op.algo, ctx->algo, sizeof(init_op.algo)); /* already zeroed */
    init_op.op     = CRYPTO2DEV_OP_HASH;
    init_op.keylen = ctx->keySz;
    XMEMCPY(init_op.key, ctx->key, ctx->keySz);
    init_op.key_fd = -1;
    if (ioctl(op_fd, CRYPTO2DEV_IOC_INIT, &init_op) < 0) {
        ret = crypto2dev_to_wc_err(errno);
        goto done;
    }

    if (ctx->dataSz > 0) {
        nw = write(op_fd, ctx->data, ctx->dataSz);
        if (nw != (ssize_t)ctx->dataSz) {
            ret = (nw < 0) ? crypto2dev_to_wc_err(errno) : WC_HW_E;
            goto done;
        }
    }

    if (ioctl(op_fd, CRYPTO2DEV_IOC_FINALIZE, NULL) < 0) {
        ret = crypto2dev_to_wc_err(errno);
        goto done;
    }

    {
        word32 mac_sz;
        switch (info->hmac.macType) {
            case WC_SHA256: mac_sz = WC_SHA256_DIGEST_SIZE; break;
            case WC_SHA384: mac_sz = WC_SHA384_DIGEST_SIZE; break;
            case WC_SHA512: mac_sz = WC_SHA512_DIGEST_SIZE; break;
            default:
                ret = BAD_FUNC_ARG;
                goto done;
        }
        nr = read(op_fd, info->hmac.digest, mac_sz);
        if (nr != (ssize_t)mac_sz) {
            ret = (nr < 0) ? crypto2dev_to_wc_err(errno) : WC_HW_E;
            goto done;
        }
    }

done:
    if (op_fd >= 0) {
        close(op_fd);
        crypto2dev_pool_release(&g_pool, pool_slot);
    }
    /* Zero and free the accumulation buffer regardless of success/failure. */
    if (ctx->data != NULL) {
        XMEMSET(ctx->data, 0, ctx->dataSz);
        XFREE(ctx->data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        ctx->data   = NULL;
        ctx->dataSz = 0;
    }
    ForceZero(&init_op, sizeof(init_op));
    return ret;
}
#endif /* NO_HMAC */

#ifdef WOLF_CRYPTO_CB_FREE
static int crypto2dev_free_cipher(const wc_CryptoInfo* info)
{
    Aes* aes = (Aes*)info->free.obj;
    if (aes == NULL || aes->devCtx == NULL)
        return 0;
    ForceZero(aes->devCtx, sizeof(Crypto2DevAesCtx));
    XFREE(aes->devCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    aes->devCtx = NULL;
    return 0;
}

static int crypto2dev_free_hash(const wc_CryptoInfo* info)
{
    void** devctx_ptr = NULL;

    switch (info->free.type) {
#ifndef NO_SHA256
        case WC_HASH_TYPE_SHA256: {
            wc_Sha256* sha = (wc_Sha256*)info->free.obj;
            if (sha == NULL) return 0;
            devctx_ptr = &sha->devCtx;
            break;
        }
#endif
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384: {
            wc_Sha384* sha = (wc_Sha384*)info->free.obj;
            if (sha == NULL) return 0;
            devctx_ptr = &sha->devCtx;
            break;
        }
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512: {
            wc_Sha512* sha = (wc_Sha512*)info->free.obj;
            if (sha == NULL) return 0;
            devctx_ptr = &sha->devCtx;
            break;
        }
#endif
#ifdef WOLFSSL_SHA3
        case WC_HASH_TYPE_SHA3_256:
        case WC_HASH_TYPE_SHA3_384:
        case WC_HASH_TYPE_SHA3_512: {
            wc_Sha3* sha = (wc_Sha3*)info->free.obj;
            if (sha == NULL) return 0;
            devctx_ptr = &sha->devCtx;
            break;
        }
#endif
        default:
            return 0;
    }

    if (devctx_ptr != NULL && *devctx_ptr != NULL) {
        Crypto2DevHashCtx* ctx = (Crypto2DevHashCtx*)*devctx_ptr;
        if (ctx->op_fd >= 0) {
            close(ctx->op_fd);
            crypto2dev_pool_release(&g_pool, ctx->pool_slot);
        }
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        *devctx_ptr = NULL;
    }
    return 0;
}

#ifndef NO_HMAC
static int crypto2dev_free_hmac(const wc_CryptoInfo* info)
{
    Hmac* hmac = (Hmac*)info->free.obj;
    Crypto2DevHmacCtx* ctx;
    if (hmac == NULL || hmac->devCtx == NULL)
        return 0;
    ctx = (Crypto2DevHmacCtx*)hmac->devCtx;
    /* Free any pending accumulation buffer (abandoned before Final). */
    if (ctx->data != NULL) {
        XMEMSET(ctx->data, 0, ctx->dataSz);
        XFREE(ctx->data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        ctx->data   = NULL;
        ctx->dataSz = 0;
    }
    ForceZero(hmac->devCtx, sizeof(Crypto2DevHmacCtx));
    XFREE(hmac->devCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    hmac->devCtx = NULL;
    return 0;
}
#endif /* NO_HMAC */
#endif /* WOLF_CRYPTO_CB_FREE */

/* Infer the hash algorithm name from digest length, for DigestInfo construction
 * in RSA PKCS#1 v1.5 sign/verify and for ECDSA sign/verify. */
static const char* crypto2dev_hash_algo_name(word32 digest_len)
{
    switch (digest_len) {
        case WC_SHA256_DIGEST_SIZE: return "sha256";
        case WC_SHA384_DIGEST_SIZE: return "sha384";
        case WC_SHA512_DIGEST_SIZE: return "sha512";
        default:                    return NULL;
    }
}

static int crypto2dev_rsa(const wc_CryptoInfo* info)
{
    (void)info;
    /*
     * RSA via crypto2dev is not currently supported. wc_CryptoCb_Rsa() passes
     * the post-padding DigestInfo block rather than the raw digest; the
     * DO_SIGN/DO_VERIFY ioctl expects a raw digest. Correct implementation
     * requires WOLF_CRYPTO_CB_RSA_PAD support (tracked: wolfssl-tm1).
     * Fall back to software.
     */
    return CRYPTOCB_UNAVAILABLE;
}

static int crypto2dev_ecdsa(const wc_CryptoInfo* info)
{
    int ret = 0;

    if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
        const ecc_key* key = info->pk.eccsign.key;
        struct crypto2dev_sign_op sign_op;
        int key_fd;

        if (key == NULL)
            return BAD_FUNC_ARG;
        if (key->devCtx == NULL)
            return CRYPTOCB_UNAVAILABLE;

        key_fd = (int)(intptr_t)key->devCtx;

        XMEMSET(&sign_op, 0, sizeof(sign_op));
        sign_op.key_fd = key_fd;
        {
            const char* hash_algo =
                crypto2dev_hash_algo_name(info->pk.eccsign.inlen);
            if (hash_algo == NULL) {
                ret = BAD_FUNC_ARG;
                goto ecdsa_sign_done;
            }
            XSTRNCPY(sign_op.hash_algo, hash_algo,
                     sizeof(sign_op.hash_algo) - 1);
        }
        sign_op.digest_len = info->pk.eccsign.inlen;
        if (sign_op.digest_len > CRYPTO2DEV_HASH_MAXLEN) {
            ret = BAD_FUNC_ARG;
            goto ecdsa_sign_done;
        }
        XMEMCPY(sign_op.digest, info->pk.eccsign.in, sign_op.digest_len);

        wc_LockMutex(&g_ecdsa_fd_lock);
        if (g_crypto2dev_fd < 0) {
            wc_UnLockMutex(&g_ecdsa_fd_lock);
            ret = WC_HW_E;
            goto ecdsa_sign_done;
        }
        if (ioctl(g_crypto2dev_fd, CRYPTO2DEV_IOC_DO_SIGN, &sign_op) < 0) {
            ret = crypto2dev_to_wc_err(errno);
            wc_UnLockMutex(&g_ecdsa_fd_lock);
            goto ecdsa_sign_done;
        }
        wc_UnLockMutex(&g_ecdsa_fd_lock);

        if (sign_op.sig_len > *info->pk.eccsign.outlen) {
            ret = BUFFER_E;
            goto ecdsa_sign_done;
        }
        XMEMCPY(info->pk.eccsign.out, sign_op.sig, sign_op.sig_len);
        *info->pk.eccsign.outlen = sign_op.sig_len;

ecdsa_sign_done:
        XMEMSET(&sign_op, 0, sizeof(sign_op));
        return ret;
    }

    if (info->pk.type == WC_PK_TYPE_ECDSA_VERIFY) {
        const ecc_key* key = info->pk.eccverify.key;
        struct crypto2dev_verify_op verify_op;
        int key_fd;

        if (key == NULL)
            return BAD_FUNC_ARG;
        if (key->devCtx == NULL)
            return CRYPTOCB_UNAVAILABLE;

        key_fd = (int)(intptr_t)key->devCtx;

        XMEMSET(&verify_op, 0, sizeof(verify_op));
        verify_op.key_fd = key_fd;
        {
            const char* hash_algo =
                crypto2dev_hash_algo_name(info->pk.eccverify.hashlen);
            if (hash_algo == NULL)
                return BAD_FUNC_ARG;
            XSTRNCPY(verify_op.hash_algo, hash_algo,
                     sizeof(verify_op.hash_algo) - 1);
        }
        verify_op.digest_len = info->pk.eccverify.hashlen;
        if (verify_op.digest_len > CRYPTO2DEV_HASH_MAXLEN) {
            ret = BAD_FUNC_ARG;
            goto ecdsa_verify_done;
        }
        XMEMCPY(verify_op.digest, info->pk.eccverify.hash, verify_op.digest_len);
        verify_op.sig_len = info->pk.eccverify.siglen;
        if (verify_op.sig_len > CRYPTO2DEV_SIG_MAXLEN) {
            ret = BUFFER_E;
            goto ecdsa_verify_done;
        }
        XMEMCPY(verify_op.sig, info->pk.eccverify.sig, verify_op.sig_len);

        wc_LockMutex(&g_ecdsa_fd_lock);
        if (g_crypto2dev_fd < 0) {
            wc_UnLockMutex(&g_ecdsa_fd_lock);
            ret = WC_HW_E;
            goto ecdsa_verify_done;
        }
        if (ioctl(g_crypto2dev_fd, CRYPTO2DEV_IOC_DO_VERIFY, &verify_op) < 0) {
            ret = (errno == EBADMSG) ? SIG_VERIFY_E
                                     : crypto2dev_to_wc_err(errno);
            wc_UnLockMutex(&g_ecdsa_fd_lock);
            goto ecdsa_verify_done;
        }
        wc_UnLockMutex(&g_ecdsa_fd_lock);
        if (info->pk.eccverify.res == NULL) {
            ret = BAD_FUNC_ARG;
            goto ecdsa_verify_done;
        }
        *info->pk.eccverify.res = 1;

ecdsa_verify_done:
        XMEMSET(&verify_op, 0, sizeof(verify_op));
        return ret;
    }

    return CRYPTOCB_UNAVAILABLE;
}

static int crypto2dev_pk(const wc_CryptoInfo* info)
{
    switch (info->pk.type) {
        case WC_PK_TYPE_RSA:
            return crypto2dev_rsa(info);
        case WC_PK_TYPE_ECDSA_SIGN:
        case WC_PK_TYPE_ECDSA_VERIFY:
            return crypto2dev_ecdsa(info);
        case WC_PK_TYPE_ECDH:
            /* ECDH unavailable: crypto2dev DO_AGREE always applies HKDF and
             * returns derived key material (OKM), not the raw shared secret (Z).
             * wolfSSL's TLS ECDH callback requires raw Z for its own KDF.
             * Fall through to software ECDH. */
            return CRYPTOCB_UNAVAILABLE;
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

/* wolfssl-1rl: HKDF and PBKDF2 via DO_KDF.
 *
 * wolfSSL's standard CryptoCb framework does not have a WC_ALGO_TYPE_KDF
 * dispatch entry. HKDF and PBKDF2 calls in wolfSSL go through the software
 * path directly and are not routed through the CryptoCb callback.
 * crypto2dev's DO_KDF ioctl is available (CRYPTO2DEV_IOC_DO_KDF) but cannot
 * be invoked via the standard CryptoCb API without wolfSSL changes.
 * See wolfssl-1rl for resolution options. */

int wc_crypto2dev_init(void)
{
    int ret;

    if (g_crypto2dev_fd >= 0)
        return 0; /* already open */
    g_crypto2dev_fd = open(CRYPTO2DEV_PATH, O_RDWR | O_CLOEXEC);
    if (g_crypto2dev_fd < 0) {
        WOLFSSL_MSG("crypto2dev: failed to open " CRYPTO2DEV_PATH);
        return WC_HW_E;
    }

#ifdef WOLFSSL_CRYPTO2DEV_REQUIRE_FIPS
    {
        int fips_probe_fd = open(CRYPTO2DEV_PATH, O_RDWR | O_CLOEXEC);
        if (fips_probe_fd < 0) {
            close(g_crypto2dev_fd);
            g_crypto2dev_fd = -1;
            return WC_HW_E;
        }
        if (ioctl(fips_probe_fd, CRYPTO2DEV_IOC_REQUIRE_FIPS, NULL) < 0) {
            close(fips_probe_fd);
            close(g_crypto2dev_fd);
            g_crypto2dev_fd = -1;
            WOLFSSL_MSG("crypto2dev: FIPS provider not available");
            return FIPS_NOT_ALLOWED_E;
        }
        close(fips_probe_fd);
    }
#endif /* WOLFSSL_CRYPTO2DEV_REQUIRE_FIPS */

    if (!g_ecdsa_fd_lock_inited) {
        if (wc_InitMutex(&g_ecdsa_fd_lock) != 0) {
            close(g_crypto2dev_fd);
            g_crypto2dev_fd = -1;
            return BAD_MUTEX_E;
        }
        g_ecdsa_fd_lock_inited = 1;
    }

    if (!g_pool_inited) {
        ret = crypto2dev_pool_init(&g_pool, WOLFSSL_CRYPTO2DEV_POOL_SIZE);
        if (ret != 0) {
            close(g_crypto2dev_fd);
            g_crypto2dev_fd = -1;
            return ret;
        }
        g_pool_inited = 1;
    }

    return 0;
}

int wc_crypto2dev_cleanup(void)
{
    wc_CryptoCb_UnRegisterDevice(WOLF_CRYPTO2DEV_DEVID);
    if (g_pool_inited) {
        crypto2dev_pool_cleanup(&g_pool);
        g_pool_inited = 0;
    }
    if (g_ecdsa_fd_lock_inited) {
        wc_LockMutex(&g_ecdsa_fd_lock);
        if (g_crypto2dev_fd >= 0) {
            close(g_crypto2dev_fd);
            g_crypto2dev_fd = -1;
        }
        wc_UnLockMutex(&g_ecdsa_fd_lock);
        wc_FreeMutex(&g_ecdsa_fd_lock);
        g_ecdsa_fd_lock_inited = 0;
    }
    /* Reset TLS-safe mode so a reinitialised port starts with hardware hash
     * enabled rather than inheriting the previous session's setting. */
    g_tls_safe_mode = 0;
    return 0;
}

int wc_crypto2dev_cb(int devId, wc_CryptoInfo* info, void* ctx)
{
    if (info == NULL)
        return BAD_FUNC_ARG;
    (void)devId;
    (void)ctx;

    switch (info->algo_type) {
        case WC_ALGO_TYPE_CIPHER:
            return crypto2dev_cipher(info);
        case WC_ALGO_TYPE_HASH:
            if (g_tls_safe_mode)
                return CRYPTOCB_UNAVAILABLE;
            return crypto2dev_hash(info);
#ifndef NO_HMAC
        case WC_ALGO_TYPE_HMAC:
            return crypto2dev_hmac(info);
#endif
        case WC_ALGO_TYPE_PK:
            return crypto2dev_pk(info);
#ifdef WOLF_CRYPTO_CB_SETKEY
        case WC_ALGO_TYPE_SETKEY:
            return crypto2dev_setkey(info);
#endif
#ifdef WOLF_CRYPTO_CB_FREE
        case WC_ALGO_TYPE_FREE:
            switch (info->free.algo) {
                case WC_ALGO_TYPE_CIPHER:
                    return crypto2dev_free_cipher(info);
                case WC_ALGO_TYPE_HASH:
                    return crypto2dev_free_hash(info);
#ifndef NO_HMAC
                case WC_ALGO_TYPE_HMAC:
                    return crypto2dev_free_hmac(info);
#endif
                case WC_ALGO_TYPE_PK:
                    return crypto2dev_free_pk(info);
                default:
                    return 0;
            }
#endif
#ifdef WOLF_CRYPTO_CB_COPY
        case WC_ALGO_TYPE_COPY:
            /* crypto2dev has no session-snapshot ioctl. Returning
             * CRYPTOCB_UNAVAILABLE causes wolfSSL to fall back to a software
             * copy of the hash state.
             *
             * Implication for TLS: wc_Sha256Copy is called for the Transcript-
             * Hash during TLS 1.3 key derivation. Because the software state
             * is empty (all data was written to the hardware fd), the software
             * copy will produce wrong results.  To avoid this, TLS transcript
             * hash objects (wc_Sha256, wc_Sha384) MUST use INVALID_DEVID.
             * Only one-shot hash and HMAC-SHA256 for Finished can use hardware.
             * See the TLS integration helper (wolfssl-2ed) for devId assignment.
             *
             * Option A (transcript replay buffer) is available via
             * WOLFSSL_CRYPTO2DEV_HASH_REPLAY_COPY at a cost of O(transcript)
             * memory per hash object. */
            return CRYPTOCB_UNAVAILABLE;
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

int wc_crypto2dev_assign_devid(WOLFSSL_CTX* ctx)
{
    int ret;

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    {
        int prev_safe_mode = g_tls_safe_mode;
        g_tls_safe_mode = 1;
        ret = wc_CryptoCb_RegisterDevice(WOLF_CRYPTO2DEV_DEVID,
                                         wc_crypto2dev_cb, NULL);
        if (ret != 0) {
            g_tls_safe_mode = prev_safe_mode;
            return ret;
        }

        ret = wolfSSL_CTX_SetDevId(ctx, WOLF_CRYPTO2DEV_DEVID);
        if (ret != WOLFSSL_SUCCESS) {
            wc_CryptoCb_UnRegisterDevice(WOLF_CRYPTO2DEV_DEVID);
            g_tls_safe_mode = prev_safe_mode;
            return ret;
        }
    }
    return 0;
}

int wc_crypto2dev_assign_devid_ssl(WOLFSSL* ssl)
{
    int ret;

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    {
        int prev_safe_mode = g_tls_safe_mode;
        g_tls_safe_mode = 1;
        ret = wc_CryptoCb_RegisterDevice(WOLF_CRYPTO2DEV_DEVID,
                                         wc_crypto2dev_cb, NULL);
        if (ret != 0) {
            g_tls_safe_mode = prev_safe_mode;
            return ret;
        }

        ret = wolfSSL_SetDevId(ssl, WOLF_CRYPTO2DEV_DEVID);
        if (ret != WOLFSSL_SUCCESS) {
            wc_CryptoCb_UnRegisterDevice(WOLF_CRYPTO2DEV_DEVID);
            g_tls_safe_mode = prev_safe_mode;
            return ret;
        }
    }
    return 0;
}

#endif /* WOLFSSL_CRYPTO2DEV && WOLF_CRYPTO_CB */
