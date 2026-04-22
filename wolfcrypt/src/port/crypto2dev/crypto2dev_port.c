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
 *   wc_crypto2dev_init(0);  (0 = use compile-time default pool size)
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

/* Wire structs and ioctl request codes shared with the software simulator.
 * Both files include this header so the _IOW/_IOR macros encode the same
 * sizeof(struct), guaranteeing matching ioctl request codes. */
#include <wolfssl/wolfcrypt/port/crypto2dev/crypto2dev_wire.h>

#ifdef WOLFSSL_CRYPTO2DEV_SIM
#include <wolfssl/wolfcrypt/port/crypto2dev/crypto2dev_sim.h>
#endif

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
    /* Streaming state: op_fd is the pool fd held from the first wc_HmacUpdate
     * through wc_HmacFinal.  Sentinels: HMAC_OP_FD_UNINIT (-1) = no Update
     * called yet; HMAC_OP_FD_ERROR (-2) = an Update failed; Final returns
     * WC_HW_E.  op_fd >= 0 = active fd, pool_slot is its pool index. */
    int    op_fd;
    int    pool_slot;
    /* Anti-aliasing guard: set to the owning Hmac* at allocation time.
     * Detected in crypto2dev_free_hmac and the SETKEY re-key path to prevent
     * double-free when wc_HmacCopy shallow-copies devCtx without calling the
     * CryptoCb COPY handler.  See wolfssl-qsi.2. */
    void*  owner;
} Crypto2DevHmacCtx;

/* op_fd sentinels for Crypto2DevHmacCtx */
#define HMAC_OP_FD_UNINIT (-1) /* no Update called yet */
#define HMAC_OP_FD_ERROR  (-2) /* an Update failed; Final must return WC_HW_E */

typedef struct {
    int  op_fd;      /* open OPERATION fd; -1 = not started */
    int  pool_slot;  /* pool slot index for op_fd */
    /* algo name not stored: INIT is sent once at ctx creation using a local
     * variable; subsequent writes/reads use op_fd directly. */
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
 *   NOT_COMPILED_IN  — algo/op not supported (EOPNOTSUPP, ENOSYS) or no
 *                      provider registered for this algo (ENOENT): callers
 *                      in cipher/hash INIT paths promote this to
 *                      CRYPTOCB_UNAVAILABLE for software fallback.
 *                      HMAC Final callers promote it to WC_HW_E instead to
 *                      prevent a MAC bypass (Updates already claimed).
 *   BAD_FUNC_ARG     — invalid argument passed to the ioctl (EINVAL, EFAULT).
 */
static int crypto2dev_to_wc_err(int errnum)
{
    int ret;
    switch (errnum) {
        /* Expected-fallback signals: do not log — these are normal operational
         * paths (algo not compiled in, device gracefully declines). */
        case ENOENT:     return NOT_COMPILED_IN; /* no provider for this algo */
        case EOPNOTSUPP: return NOT_COMPILED_IN;
        case ENOSYS:     return NOT_COMPILED_IN;
        /* Authentication tag mismatch on GCM decrypt: expected and handled by
         * the caller; not a hardware fault. */
        case EBADMSG:    return AES_GCM_AUTH_E;
        /* Hard errors: log with errno so support can distinguish FIPS degradation
         * (EACCES → FIPS_NOT_ALLOWED_E), resource exhaustion (ENOMEM), device
         * faults (EIO), etc. without a debugger. */
        case EACCES:  ret = FIPS_NOT_ALLOWED_E; break;
        case ENODEV:  ret = BAD_STATE_E;        break;
        case EBUSY:   ret = BAD_STATE_E;        break;
        case EMSGSIZE:ret = BUFFER_E;           break;
        case EIO:     ret = WC_HW_E;            break;
        case ENOMEM:  ret = MEMORY_E;           break;
        case EINVAL:  ret = BAD_FUNC_ARG;       break;
        case EFAULT:  ret = BAD_FUNC_ARG;       break;
        default:      ret = WC_HW_E;            break;
    }
    if (ret == FIPS_NOT_ALLOWED_E) {
        WOLFSSL_MSG_EX("crypto2dev: FIPS not allowed — device blocked operation "
                       "(EACCES errno=%d)", errnum);
    } else {
        WOLFSSL_MSG_EX("crypto2dev: ioctl failed errno=%d (wc_err=%d)", errnum, ret);
    }
    return ret;
}

/* Number of pre-opened operation fds held ready for cipher and hash calls.
 * Each concurrent AES/hash operation consumes one slot; if all slots are in
 * use the call fails with WC_HW_E immediately (no blocking wait).
 *
 * Sizing guidance:
 *   - Set this to the maximum number of AES/hash ops that may be in flight
 *     simultaneously across all threads.
 *   - A TLS server handling N sessions concurrently needs at least N slots
 *     for record-layer AES-GCM (each in-flight record holds one slot).
 *   - Streaming hash (SHA-256/384/512 with hardware hash enabled) holds a
 *     slot from Init to Final.  Each in-progress wc_Sha256Update/Final cycle
 *     occupies one slot.  Add these to the AES count when sizing.
 *     NOTE: in TLS-safe mode (wc_crypto2dev_assign_devid was called), hash
 *     ops return CRYPTOCB_UNAVAILABLE immediately and do NOT consume pool
 *     slots, so only AES slots need to be counted for TLS use cases.
 *   - Under-sizing causes WC_HW_E returns that look like hardware failures;
 *     increase the value and recompile to fix.  Slots cost one open fd each. */
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

/* Per-devId configuration, heap-allocated at registration time and passed as
 * the ctx parameter to wc_CryptoCb_RegisterDevice().  The callback receives it
 * back as ctx, providing O(1) per-devId state access without a table lookup.
 * tls_safe == 1: WC_ALGO_TYPE_HASH returns CRYPTOCB_UNAVAILABLE for this devId
 *   so TLS 1.3 transcript hashing falls back to software (where wc_Sha256Copy
 *   works) while HMAC, CIPHER, and PK remain on hardware. */
typedef struct {
    int tls_safe;
} Crypto2DevConfig;

/* Cleanup tracking table: records each {devId, cfg*} registered by this port
 * so wc_crypto2dev_cleanup() can unregister and free them.  Only devIds
 * registered through wc_crypto2dev_register_ex() or
 * wc_crypto2dev_assign_devid_ex() appear here; devIds the application
 * registered directly via wc_CryptoCb_RegisterDevice() are untouched. */
typedef struct {
    int              devId;
    Crypto2DevConfig* cfg;
} Crypto2DevIdEntry;
static Crypto2DevIdEntry g_devid_table[WOLFSSL_CRYPTO2DEV_MAX_DEVIDS];
static int g_devid_count = 0;

static int crypto2dev_find_devid(int devId)
{
    int i;
    for (i = 0; i < g_devid_count; i++) {
        if (g_devid_table[i].devId == devId)
            return i;
    }
    return -1;
}

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
    int empty_slot = -1;

    if (out_slot_idx == NULL)
        return -1;
    if (pool->slots == NULL) {
        /* Pool was never initialised or was destroyed by wc_crypto2dev_cleanup().
         * Log a specific message so support can distinguish this from a full
         * pool (all slots in use).  A full pool returns -1 silently here and
         * the caller logs "pool exhausted"; a destroyed pool logs this message
         * and the caller message is suppressed by the g_pool.slots != NULL
         * guard at each call site. */
        WOLFSSL_MSG("crypto2dev: pool not initialised — call wc_crypto2dev_init() "
                    "before use; or wc_crypto2dev_cleanup() was called while "
                    "objects with active devCtx are still live");
        return -1;
    }

    if (wc_LockMutex(&pool->lock) != 0)
        return -1;

    /* Prefer a slot with a ready fd (fast path). */
    for (i = 0; i < pool->capacity; i++) {
        if (pool->slots[i].in_use)
            continue;
        if (pool->slots[i].fd >= 0) {
            pool->slots[i].in_use = 1;
            fd = pool->slots[i].fd;
            /* Clear fd so that a concurrent cleanup() sees -1 and does
             * not double-close the fd we just handed to the caller. */
            pool->slots[i].fd = -1;
            *out_slot_idx = i;
            break;
        }
        /* Remember first empty slot for potential recovery below. */
        if (empty_slot < 0)
            empty_slot = i;
    }

    if (fd < 0 && empty_slot >= 0) {
        /* Reserve the slot so no other thread claims it while we open
         * outside the mutex.  open() may block; don't hold the lock.
         * Transient exhaustion: during the open() call below, this slot
         * is marked in_use=1 with fd==-1.  A concurrent acquire() that
         * finds all slots in_use returns -1 (WC_HW_E) even though one is
         * only temporarily unavailable.  This is expected: the caller
         * sees a full pool for the duration of the open() syscall.  It is
         * not a persistent failure — retrying at the next operation will
         * succeed once the slot is released. */
        pool->slots[empty_slot].in_use = 1;
    }

    wc_UnLockMutex(&pool->lock);

    if (fd < 0 && empty_slot >= 0) {
        int new_fd = open(CRYPTO2DEV_PATH, O_RDWR | O_CLOEXEC);
        if (new_fd >= 0) {
            fd = new_fd;
            *out_slot_idx = empty_slot;
            /* fd is not stored in the slot (double-close protection);
             * it will be returned to the caller directly. */
        } else {
            /* Open failed: release the reservation for the next attempt. */
            wc_LockMutex(&pool->lock);
            pool->slots[empty_slot].in_use = 0;
            wc_UnLockMutex(&pool->lock);
        }
    }

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
            /* FIPS 140-3 IG D.1: minimum approved curve for ECDSA is P-256
             * (32-byte field).  P-192 (24) and P-224 (28) are not approved;
             * fall back to software so the FIPS policy stays at wolfCrypt. */
            if (field_sz < 32)
                return CRYPTOCB_UNAVAILABLE;
            ret = wc_ecc_export_private_only(src, raw, &field_sz);
            if (ret != 0) {
                ForceZero(raw, sizeof(raw));
                return ret;
            }
            devctx_ptr = (void**)&key->devCtx;
            new_fd = crypto2dev_key_import("ecdsa", CRYPTO2DEV_KEY_PRIVATE,
                                            raw, field_sz);
            ForceZero(raw, sizeof(raw));
            if (new_fd < 0)
                return new_fd; /* preserve existing key fd; new import failed */
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
            /* FIPS 140-3 IG D.1: minimum approved curve for ECDSA is P-256.
             * P-256 uncompressed point: 0x04 || 32-byte X || 32-byte Y = 65.
             * P-224 = 57, P-192 = 49.  Reject below 65 bytes. */
            if (raw_len < 65) {
                ForceZero(raw, sizeof(raw));
                return CRYPTOCB_UNAVAILABLE;
            }
            devctx_ptr = (void**)&key->devCtx;
            new_fd = crypto2dev_key_import("ecdsa", CRYPTO2DEV_KEY_PUBLIC,
                                            raw, raw_len);
            ForceZero(raw, sizeof(raw));
            if (new_fd < 0)
                return new_fd; /* preserve existing key fd; new import failed */
            break;
        }
        case WC_SETKEY_RSA_PRIV:
        case WC_SETKEY_RSA_PUB:
            /* RSA is not implemented in this port: crypto2dev_rsa() always
             * returns CRYPTOCB_UNAVAILABLE because wc_CryptoCb_Rsa() passes
             * a pre-padded DigestInfo block, not the raw digest that
             * CRYPTO2DEV_IOC_DO_SIGN expects (see crypto2dev_rsa comment below).
             * Do not import the key to the device — there is no operation
             * that would use the resulting fd, and leaving an open fd in
             * key->devCtx would mislead callers into thinking hardware RSA
             * is active.  Fall back to software for the full RSA lifecycle. */
            return CRYPTOCB_UNAVAILABLE;
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

    /* Return CRYPTOCB_UNAVAILABLE so wolfSSL also runs the software key
     * schedule.  This sets aes->rounds, which wc_AesGcmSetKey needs in order
     * to pre-compute the GCM H-subkey.  Without it, any caller using the
     * standard wc_AesGcmSetKey + wc_AesGcmEncrypt pattern would get
     * KEYUSAGE_E at the first encrypt with no obvious diagnostic.
     * The hardware cipher path (crypto2dev_cipher) checks devCtx first and
     * uses the device regardless of what the software schedule set. */
    return CRYPTOCB_UNAVAILABLE;
}
#endif /* WOLF_CRYPTO_CB_SETKEY */

static int crypto2dev_cipher(const wc_CryptoInfo* info)
{
    Aes* aes = NULL;
    const Crypto2DevAesCtx* ctx = NULL;
    const char* algo = NULL;
    const byte* in_buf  = NULL;
    byte*       out_buf = NULL;
    word32      data_sz = 0;
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
            aes     = info->cipher.aescbc.aes;
            algo    = "cbc(aes)";
            iv      = (const byte*)info->cipher.aescbc.aes->reg;
            ivSz    = AES_BLOCK_SIZE;
            in_buf  = info->cipher.aescbc.in;
            out_buf = info->cipher.aescbc.out;
            data_sz = info->cipher.aescbc.sz;
            break;
#endif
#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
            if (is_enc) {
                aes     = info->cipher.aesgcm_enc.aes;
                iv      = info->cipher.aesgcm_enc.iv;
                ivSz    = info->cipher.aesgcm_enc.ivSz;
                in_buf  = info->cipher.aesgcm_enc.in;
                out_buf = info->cipher.aesgcm_enc.out;
                data_sz = info->cipher.aesgcm_enc.sz;
            } else {
                aes     = info->cipher.aesgcm_dec.aes;
                iv      = info->cipher.aesgcm_dec.iv;
                ivSz    = info->cipher.aesgcm_dec.ivSz;
                in_buf  = info->cipher.aesgcm_dec.in;
                out_buf = info->cipher.aesgcm_dec.out;
                data_sz = info->cipher.aesgcm_dec.sz;
            }
            algo = "gcm(aes)";
            break;
#endif
#ifdef WOLFSSL_AES_COUNTER
        case WC_CIPHER_AES_CTR:
            aes     = info->cipher.aesctr.aes;
            algo    = "ctr(aes)";
            iv      = (const byte*)info->cipher.aesctr.aes->reg;
            ivSz    = AES_BLOCK_SIZE;
            in_buf  = info->cipher.aesctr.in;
            out_buf = info->cipher.aesctr.out;
            data_sz = info->cipher.aesctr.sz;
            break;
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }

    if (aes == NULL)
        return BAD_FUNC_ARG;

#ifdef HAVE_AESGCM
    if (info->cipher.type == WC_CIPHER_AES_GCM) {
        /* AES-GCM requires a 96-bit (12-byte) nonce per NIST SP 800-38D.
         * Reject non-standard nonce lengths rather than passing them to the
         * kernel, which may accept silently (wrong auth) or return EINVAL. */
        if (ivSz != GCM_NONCE_MID_SZ)
            return CRYPTOCB_UNAVAILABLE;
        {
            /* FIPS 140-3 SP 800-38D Table 1: minimum GCM authentication tag
             * is 96 bits (12 bytes).  Tags shorter than 12 bytes reduce the
             * forgery-resistance bound below FIPS-approved levels; fall back
             * to software so the FIPS policy decision stays at wolfCrypt.
             * authTagSz == 0 is handled later (decrypt rejects it with
             * BUFFER_E; encrypt silently skips GET_TAG as caller asked for
             * no tag).
             *
             * Maximum tag check: also reject oversized tags here, before pool
             * acquisition.  Without this early check, the encrypt path
             * completes write/FINALIZE/read (ciphertext lands in out_buf)
             * before hitting BUFFER_E, leaving unauthenticated ciphertext
             * visible to a caller that does not check the return code.  The
             * decrypt path checks this condition before SET_TAG (after pool
             * acquire but before write); checking both directions early is
             * symmetric and avoids pointless hardware work on invalid input. */
            word32 chk_tagSz = is_enc ? info->cipher.aesgcm_enc.authTagSz
                                      : info->cipher.aesgcm_dec.authTagSz;
            if (chk_tagSz > 0 && chk_tagSz < 12)
                return CRYPTOCB_UNAVAILABLE;
            if (chk_tagSz > CRYPTO2DEV_TAG_MAXLEN)
                return BUFFER_E;
        }
    }
#endif

#ifdef HAVE_AES_CBC
    /* CBC input must be AES_BLOCK_SIZE-aligned.  Enforce before pool
     * acquisition: a non-aligned data_sz causes word32 underflow in the
     * IV update (src + data_sz - AES_BLOCK_SIZE), reading from an
     * arbitrary memory address.  wc_AesCbcEncrypt only checks alignment
     * when WOLFSSL_AES_CBC_LENGTH_CHECKS is defined, which is not the
     * default. */
    if (info->cipher.type == WC_CIPHER_AES_CBC &&
            data_sz % AES_BLOCK_SIZE != 0)
        return BAD_FUNC_ARG;
#endif

    ctx = (const Crypto2DevAesCtx*)aes->devCtx;
    if (ctx == NULL || ctx->keySz == 0)
        return CRYPTOCB_UNAVAILABLE;

    op_fd = crypto2dev_pool_acquire(&g_pool, &pool_slot);
    if (op_fd < 0) {
        if (g_pool.slots != NULL)
            WOLFSSL_MSG("crypto2dev: cipher pool exhausted — increase "
                        "WOLFSSL_CRYPTO2DEV_POOL_SIZE");
        return WC_HW_E;
    }

    XMEMSET(&init_op, 0, sizeof(init_op));
    XSTRNCPY(init_op.algo, algo, sizeof(init_op.algo) - 1);
    init_op.op     = is_enc ? CRYPTO2DEV_OP_ENCRYPT : CRYPTO2DEV_OP_DECRYPT;
    init_op.keylen = ctx->keySz;
    XMEMCPY(init_op.key, ctx->key, ctx->keySz);
    init_op.key_fd = -1;
    if (ioctl(op_fd, CRYPTO2DEV_IOC_INIT, &init_op) < 0) {
        ret = crypto2dev_to_wc_err(errno);
        /* EOPNOTSUPP/ENOSYS/ENOENT → NOT_COMPILED_IN: device lacks this algo
         * (no provider registered, or provider not FIPS-validated).
         * Promote to CRYPTOCB_UNAVAILABLE so wolfSSL falls back to software
         * rather than aborting the operation with a hard error. */
        if (ret == NOT_COMPILED_IN)
            ret = CRYPTOCB_UNAVAILABLE;
        goto done;
    }

    if (iv != NULL && ivSz > 0) {
        /* Reject oversized IV: silently skipping SET_IV would use whatever
         * IV the device last saw (or a zero IV) — wrong ciphertext/plaintext
         * with no error signal.  Return BUFFER_E, matching the AAD guard. */
        if (ivSz > CRYPTO2DEV_IV_MAXLEN) {
            ret = BUFFER_E;
            goto done;
        }
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

        if (authIn != NULL && authInSz > 0) {
            /* Reject oversized AAD: silently skipping SET_AAD would cause
             * the device to authenticate with empty AAD instead of the
             * provided one — an authentication bypass for the caller. */
            if (authInSz > CRYPTO2DEV_AAD_MAXLEN) {
                ret = BUFFER_E;
                goto done;
            }
            XMEMSET(&aad_op, 0, sizeof(aad_op));
            XMEMCPY(aad_op.aad, authIn, authInSz);
            aad_op.aadlen = authInSz;
            if (ioctl(op_fd, CRYPTO2DEV_IOC_SET_AAD, &aad_op) < 0) {
                ret = crypto2dev_to_wc_err(errno);
                goto done;
            }
        }

        if (!is_enc) {
            /* Reject missing or oversized auth tag: skipping SET_TAG on
             * decrypt causes the device to authenticate against no tag —
             * an authentication bypass for the caller.  Match the hard
             * BUFFER_E pattern used for oversized AAD above. */
            if (authTag == NULL || authTagSz == 0 ||
                    authTagSz > CRYPTO2DEV_TAG_MAXLEN) {
                ret = BUFFER_E;
                goto done;
            }
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
            XMEMCPY((byte*)aes->reg,
                    src + data_sz - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        }
#endif
#ifdef WOLFSSL_AES_COUNTER
        if (info->cipher.type == WC_CIPHER_AES_CTR) {
            /* Advance aes->reg (big-endian 128-bit counter) by the number of
             * 128-bit blocks just consumed.  Single-pass carry-ripple from the
             * rightmost byte: add `blocks` as a word32 carry and propagate.
             * Terminates after at most 4 bytes for blocks < 2^32; typically
             * 1-2 bytes for TLS record sizes.  Matches wolfSSL's own
             * IncrementAesCounter() semantics and the Linux kernel's crypto_inc()
             * used by the hardware driver. */
            word32 blocks = (data_sz + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
            byte* ctr = (byte*)aes->reg;
            word32 carry = blocks;
            int ci;
            for (ci = AES_BLOCK_SIZE - 1; ci >= 0 && carry != 0; ci--) {
                carry += (word32)ctr[ci];
                ctr[ci] = (byte)(carry & 0xFF);
                carry >>= 8;
            }
        }
#endif
    }

#ifdef HAVE_AESGCM
    if (info->cipher.type == WC_CIPHER_AES_GCM && is_enc) {
        byte* authTag    = info->cipher.aesgcm_enc.authTag;
        word32 authTagSz = info->cipher.aesgcm_enc.authTagSz;
        /* authTagSz > CRYPTO2DEV_TAG_MAXLEN is already rejected by the early
         * check before pool acquire (line ~707).  No second check needed here. */
        if (authTag != NULL && authTagSz > 0) {
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
            /* Unsupported hash type: fall through to software. */
            return CRYPTOCB_UNAVAILABLE;
    }
    /* devctx_ptr is always set by the non-default cases above. */

    /* API contract: callers must call wc_Sha256Init() (or equivalent) before
     * reusing a hash object after wc_Sha256Final().  Final frees the hardware
     * context and sets devCtx = NULL; a subsequent Update without an Init
     * silently restarts the hash.  This matches wolfSSL's own software-path
     * behaviour and is not defended against here. */
    if (*devctx_ptr == NULL) {
        struct crypto2dev_init_op init_op;
        int pool_slot = -1;
        int op_fd = crypto2dev_pool_acquire(&g_pool, &pool_slot);
        if (op_fd < 0) {
            if (g_pool.slots != NULL)
                WOLFSSL_MSG("crypto2dev: hash pool exhausted — increase "
                            "WOLFSSL_CRYPTO2DEV_POOL_SIZE");
            return WC_HW_E;
        }

        XMEMSET(&init_op, 0, sizeof(init_op));
        XSTRNCPY(init_op.algo, algo, sizeof(init_op.algo) - 1);
        init_op.op     = CRYPTO2DEV_OP_HASH;
        init_op.keylen = 0;
        init_op.key_fd = -1;
        if (ioctl(op_fd, CRYPTO2DEV_IOC_INIT, &init_op) < 0) {
            int err = crypto2dev_to_wc_err(errno);
            /* EOPNOTSUPP/ENOSYS/ENOENT → NOT_COMPILED_IN: device lacks this hash
             * (no provider registered, or provider not FIPS-validated).
             * Promote to CRYPTOCB_UNAVAILABLE so wolfSSL falls back to software. */
            if (err == NOT_COMPILED_IN)
                err = CRYPTOCB_UNAVAILABLE;
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
    /* FIPS SP 800-107 §5.3: HMAC key must be >= 14 bytes (112-bit security).
     * Return CRYPTOCB_UNAVAILABLE so wolfSSL's own key-length validation runs.
     * Must NOT return 0 here: wc_HmacSetKey returns immediately when the port
     * returns 0, skipping the wolfSSL software key-size check entirely.
     * Must NOT return WC_HW_E: that would hard-fail non-FIPS builds that
     * legitimately use short keys.  CRYPTOCB_UNAVAILABLE lets wolfSSL decide. */
    if (keySz < 14)
        return CRYPTOCB_UNAVAILABLE;

    switch (hmac->macType) {
        case WC_SHA256: algo = "hmac(sha256)"; break;
        case WC_SHA384: algo = "hmac(sha384)"; break;
        case WC_SHA512: algo = "hmac(sha512)"; break;
        default: return CRYPTOCB_UNAVAILABLE;
    }

    if (hmac->devCtx != NULL) {
        Crypto2DevHmacCtx* old_ctx = (Crypto2DevHmacCtx*)hmac->devCtx;
        if (old_ctx->owner != (void*)hmac) {
            /* Aliased from wc_HmacCopy — don't free; just release our reference. */
            hmac->devCtx = NULL;
        }
        else {
            /* Close any active hardware op before re-keying. */
            if (old_ctx->op_fd >= 0) {
                close(old_ctx->op_fd);
                crypto2dev_pool_release(&g_pool, old_ctx->pool_slot);
            }
            ForceZero(hmac->devCtx, sizeof(Crypto2DevHmacCtx));
            XFREE(hmac->devCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            hmac->devCtx = NULL;
        }
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
    ctx->owner     = hmac;
    ctx->op_fd     = HMAC_OP_FD_UNINIT; /* XMEMSET zeros to 0, not -1; set explicitly */
    ctx->pool_slot = -1;
    hmac->devCtx   = ctx;
    return 0;
}
#endif /* WOLF_CRYPTO_CB_SETKEY */

static int crypto2dev_hmac(const wc_CryptoInfo* info)
{
    Hmac* hmac = (Hmac*)info->hmac.hmac;
    Crypto2DevHmacCtx* ctx;
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
     * Stream data to hardware on Update; FINALIZE on Final.
     */
    if (info->hmac.digest == NULL) {
        /* Update phase — stream this chunk directly to the hardware op fd. */
        if (info->hmac.in == NULL)
            return (info->hmac.inSz == 0) ? 0 : BAD_FUNC_ARG;

        if (ctx->op_fd == HMAC_OP_FD_ERROR)
            return WC_HW_E;

        if (ctx->op_fd == HMAC_OP_FD_UNINIT) {
            /* First Update: acquire pool fd and INIT with key. */
            ctx->op_fd = crypto2dev_pool_acquire(&g_pool, &ctx->pool_slot);
            if (ctx->op_fd < 0) {
                if (g_pool.slots != NULL)
                    WOLFSSL_MSG("crypto2dev: HMAC pool exhausted — increase "
                                "WOLFSSL_CRYPTO2DEV_POOL_SIZE");
                ctx->op_fd = HMAC_OP_FD_ERROR;
                return WC_HW_E;
            }
            XMEMSET(&init_op, 0, sizeof(init_op));
            XMEMCPY(init_op.algo, ctx->algo, sizeof(init_op.algo));
            init_op.op     = CRYPTO2DEV_OP_HASH;
            init_op.keylen = ctx->keySz;
            XMEMCPY(init_op.key, ctx->key, ctx->keySz);
            init_op.key_fd = -1;
            if (ioctl(ctx->op_fd, CRYPTO2DEV_IOC_INIT, &init_op) < 0) {
                ret = crypto2dev_to_wc_err(errno);
                /* EOPNOTSUPP/ENOSYS/ENOENT: device lacks this HMAC algo.
                 * Must NOT return CRYPTOCB_UNAVAILABLE: SETKEY already
                 * returned 0 (claimed), so a software fallback would compute
                 * HMAC with an all-zeros key.  Return WC_HW_E. */
                if (ret == NOT_COMPILED_IN)
                    ret = WC_HW_E;
                ForceZero(&init_op, sizeof(init_op));
                close(ctx->op_fd);
                crypto2dev_pool_release(&g_pool, ctx->pool_slot);
                ctx->op_fd     = HMAC_OP_FD_ERROR;
                ctx->pool_slot = -1;
                return ret;
            }
            ForceZero(&init_op, sizeof(init_op));
        }

        if (info->hmac.inSz > 0) {
            nw = write(ctx->op_fd, info->hmac.in, info->hmac.inSz);
            if (nw != (ssize_t)info->hmac.inSz) {
                ret = (nw < 0) ? crypto2dev_to_wc_err(errno) : WC_HW_E;
                close(ctx->op_fd);
                crypto2dev_pool_release(&g_pool, ctx->pool_slot);
                ctx->op_fd     = HMAC_OP_FD_ERROR;
                ctx->pool_slot = -1;
                return ret;
            }
        }
        return 0;
    }

    /* Final phase — FINALIZE and read the MAC. */
    if (ctx->op_fd == HMAC_OP_FD_ERROR) {
        ret = WC_HW_E;
        goto done;
    }

    if (ctx->op_fd == HMAC_OP_FD_UNINIT) {
        /* Final with no prior Updates: HMAC of empty message.
         * Acquire pool fd and INIT with key before FINALIZE. */
        ctx->op_fd = crypto2dev_pool_acquire(&g_pool, &ctx->pool_slot);
        if (ctx->op_fd < 0) {
            if (g_pool.slots != NULL)
                WOLFSSL_MSG("crypto2dev: HMAC pool exhausted — increase "
                            "WOLFSSL_CRYPTO2DEV_POOL_SIZE");
            ret = WC_HW_E;
            goto done;
        }
        XMEMSET(&init_op, 0, sizeof(init_op));
        XMEMCPY(init_op.algo, ctx->algo, sizeof(init_op.algo));
        init_op.op     = CRYPTO2DEV_OP_HASH;
        init_op.keylen = ctx->keySz;
        XMEMCPY(init_op.key, ctx->key, ctx->keySz);
        init_op.key_fd = -1;
        if (ioctl(ctx->op_fd, CRYPTO2DEV_IOC_INIT, &init_op) < 0) {
            ret = crypto2dev_to_wc_err(errno);
            if (ret == NOT_COMPILED_IN)
                ret = WC_HW_E;
            goto done;
        }
    }

    if (ioctl(ctx->op_fd, CRYPTO2DEV_IOC_FINALIZE, NULL) < 0) {
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
        nr = read(ctx->op_fd, info->hmac.digest, mac_sz);
        if (nr != (ssize_t)mac_sz) {
            ret = (nr < 0) ? crypto2dev_to_wc_err(errno) : WC_HW_E;
            goto done;
        }
    }

done:
    if (ctx->op_fd >= 0) {
        close(ctx->op_fd);
        crypto2dev_pool_release(&g_pool, ctx->pool_slot);
    }
    /* Free the HmacCtx struct and clear the pointer.
     *
     * wolfSSL's wc_HmacFree() does NOT dispatch WC_ALGO_TYPE_FREE for
     * HMAC objects.  Instead it calls this callback with digest != NULL
     * as its cleanup signal (see wc_HmacFree in wolfcrypt/src/hmac.c).
     * Freeing here covers both the normal wc_HmacFinal path and the
     * "abandoned before Final" case that wc_HmacFree triggers.
     *
     * Setting devCtx = NULL also prevents wc_HmacFree from issuing a
     * second spurious Final call (it checks devCtx != NULL before
     * calling the callback). */
    ForceZero(ctx, sizeof(Crypto2DevHmacCtx));
    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    hmac->devCtx = NULL;
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
    /* Detect aliased devCtx from wc_HmacCopy.  wolfSSL does not dispatch COPY
     * through CryptoCb for HMAC (only for hash objects), so two Hmac structs
     * created by wc_HmacCopy share the same ctx pointer.  Freeing here would
     * double-free the owner's allocation; instead, release our reference.
     *
     * If the owner's FREE fires first, ForceZero already zeroed ctx->owner to
     * NULL before XFREE; reading ctx->owner here is technically UB, but in
     * practice the allocator has not yet recycled the block and the NULL is
     * still readable.  The mismatch (NULL != hmac) is detected and we bail. */
    if (ctx->owner != (void*)hmac) {
        WOLFSSL_MSG("crypto2dev: HMAC devCtx aliased by wc_HmacCopy — "
                    "skipping free (see wolfssl-qsi.2)");
        hmac->devCtx = NULL;
        return 0;
    }
    /* Close any open hardware op (abandoned before Final). */
    if (ctx->op_fd >= 0) {
        close(ctx->op_fd);
        crypto2dev_pool_release(&g_pool, ctx->pool_slot);
    }
    ForceZero(hmac->devCtx, sizeof(Crypto2DevHmacCtx));
    XFREE(hmac->devCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    hmac->devCtx = NULL;
    return 0;
}
#endif /* NO_HMAC */
#endif /* WOLF_CRYPTO_CB_FREE */

/* Map ECDSA digest length to hash algorithm name for DO_SIGN/DO_VERIFY.
 *
 * THIS FUNCTION IS ECDSA-ONLY.  It works because the three NIST curves
 * used with ECDSA (P-256/P-384/P-521) pair with exactly one hash each:
 *   32 bytes → SHA-256 (P-256)
 *   48 bytes → SHA-384 (P-384)
 *   64 bytes → SHA-512 (P-521)
 * and those three sizes are distinct.
 *
 * Do NOT add SHA-3 cases here: SHA3-256 produces 32 bytes — same as
 * SHA-256 — so the dispatch would silently use the wrong algorithm.
 * If ECDSA with SHA-3 digests is ever needed, pass the algorithm name
 * through the SETKEY path (e.g., store it in key->devCtx) rather than
 * inferring it from digest length. */
static const char* crypto2dev_ecdsa_hash_algo_name(word32 digest_len)
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
     * requires WOLF_CRYPTO_CB_RSA_PAD support (not yet in wolfSSL CryptoCb API).
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
            /* Digest length → hash algo name (P-256=32→sha256, P-384=48→sha384,
             * P-521=64→sha512).  SHA-3 excluded: SHA3-256 also produces 32
             * bytes, colliding with SHA-256.  See crypto2dev_ecdsa_hash_algo_name()
             * comment for full rationale before adding cases here. */
            const char* hash_algo =
                crypto2dev_ecdsa_hash_algo_name(info->pk.eccsign.inlen);
            if (hash_algo == NULL) {
                ret = BAD_FUNC_ARG;
                goto ecdsa_sign_done;
            }
            XSTRNCPY(sign_op.hash_algo, hash_algo,
                     sizeof(sign_op.hash_algo) - 1);
        }
        if (info->pk.eccsign.in == NULL) {
            ret = BAD_FUNC_ARG;
            goto ecdsa_sign_done;
        }
        sign_op.digest_len = info->pk.eccsign.inlen;
        if (sign_op.digest_len > CRYPTO2DEV_HASH_MAXLEN) {
            ret = BAD_FUNC_ARG;
            goto ecdsa_sign_done;
        }
        XMEMCPY(sign_op.digest, info->pk.eccsign.in, sign_op.digest_len);

        {
            int op_fd;
            int pool_slot = -1;
            op_fd = crypto2dev_pool_acquire(&g_pool, &pool_slot);
            if (op_fd < 0) {
                if (g_pool.slots != NULL)
                    WOLFSSL_MSG("crypto2dev: ECDSA sign pool exhausted — increase "
                                "WOLFSSL_CRYPTO2DEV_POOL_SIZE");
                ret = WC_HW_E;
                goto ecdsa_sign_done;
            }
            if (ioctl(op_fd, CRYPTO2DEV_IOC_DO_SIGN, &sign_op) < 0)
                ret = crypto2dev_to_wc_err(errno);
            close(op_fd);
            crypto2dev_pool_release(&g_pool, pool_slot);
        }
        if (ret != 0)
            goto ecdsa_sign_done;

        if (sign_op.sig_len > CRYPTO2DEV_SIG_MAXLEN) {
            ret = BUFFER_E;
            goto ecdsa_sign_done;
        }
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

        /* Validate all output pointers before acquiring a pool slot. */
        if (key == NULL || info->pk.eccverify.res == NULL ||
                info->pk.eccverify.hash == NULL || info->pk.eccverify.sig == NULL)
            return BAD_FUNC_ARG;
        if (key->devCtx == NULL)
            return CRYPTOCB_UNAVAILABLE;

        key_fd = (int)(intptr_t)key->devCtx;

        XMEMSET(&verify_op, 0, sizeof(verify_op));
        verify_op.key_fd = key_fd;
        {
            /* Same SHA-3 exclusion as sign path above. */
            const char* hash_algo =
                crypto2dev_ecdsa_hash_algo_name(info->pk.eccverify.hashlen);
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

        {
            int op_fd;
            int pool_slot = -1;
            op_fd = crypto2dev_pool_acquire(&g_pool, &pool_slot);
            if (op_fd < 0) {
                if (g_pool.slots != NULL)
                    WOLFSSL_MSG("crypto2dev: ECDSA verify pool exhausted — increase "
                                "WOLFSSL_CRYPTO2DEV_POOL_SIZE");
                ret = WC_HW_E;
                goto ecdsa_verify_done;
            }
            if (ioctl(op_fd, CRYPTO2DEV_IOC_DO_VERIFY, &verify_op) < 0)
                ret = (errno == EBADMSG) ? SIG_VERIFY_E
                                         : crypto2dev_to_wc_err(errno);
            close(op_fd);
            crypto2dev_pool_release(&g_pool, pool_slot);
        }
        if (ret == 0)
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

/* NOTE: HKDF and PBKDF2 hardware offload via DO_KDF is not yet possible.
 *
 * wolfSSL's CryptoCb framework has no WC_ALGO_TYPE_KDF dispatch entry; HKDF
 * and PBKDF2 calls go directly through the software path without passing
 * through the CryptoCb callback.  crypto2dev's DO_KDF ioctl is available
 * (CRYPTO2DEV_IOC_DO_KDF) but cannot be invoked via the standard CryptoCb
 * API without adding WC_ALGO_TYPE_KDF dispatch to wolfSSL upstream. */

int wc_crypto2dev_init(int pool_size)
{
    int ret;
    int cap;

    /* NOT thread-safe: must be called from a single thread before spawning
     * any threads that will use the crypto2dev port.  The g_pool_inited
     * check below is not atomic; two threads racing here both pass the check
     * and both call crypto2dev_pool_init() — double-init of the pool mutex
     * is undefined behavior on pthreads.  This mirrors wolfSSL's own
     * wolfSSL_Init() contract: single-threaded init, then concurrent use. */
    if (g_pool_inited)
        return 0; /* already initialised */

    cap = (pool_size > 0) ? pool_size : WOLFSSL_CRYPTO2DEV_POOL_SIZE;

#ifdef WOLFSSL_CRYPTO2DEV_REQUIRE_FIPS
    {
        /* Verify that a FIPS provider is currently loaded by issuing
         * REQUIRE_FIPS on a probe fd.  If it fails (no FIPS provider
         * registered), reject init entirely.
         *
         * Why a probe fd is sufficient:
         *   The kernel registry maintains a global fips_provider_count.
         *   While that count is > 0, crypto2dev_lookup_algo() silently
         *   skips all non-FIPS providers for EVERY fd, process-wide.
         *   Additionally, fips_gate() is called at the top of every write()
         *   and read() handler on initialized fds: if the FIPS provider
         *   unloads or fails its self-test AFTER init, the next write() or
         *   read() on any pool fd returns -EACCES immediately.
         *
         *   Setting REQUIRE_FIPS on individual pool fds would be redundant:
         *   the global registry filter already ensures the same guarantee.
         *   The probe simply checks that we are in FIPS mode at startup;
         *   the kernel enforces it for all subsequent operations on all fds. */
        int fips_probe_fd = open(CRYPTO2DEV_PATH, O_RDWR | O_CLOEXEC);
        if (fips_probe_fd < 0)
            return WC_HW_E;
        if (ioctl(fips_probe_fd, CRYPTO2DEV_IOC_REQUIRE_FIPS, NULL) < 0) {
            close(fips_probe_fd);
            WOLFSSL_MSG("crypto2dev: FIPS provider not available");
            return FIPS_NOT_ALLOWED_E;
        }
        close(fips_probe_fd);
    }
#endif /* WOLFSSL_CRYPTO2DEV_REQUIRE_FIPS */

    ret = crypto2dev_pool_init(&g_pool, cap);
    if (ret != 0)
        return ret;
    g_pool_inited = 1;

    return 0;
}

int wc_crypto2dev_cleanup(void)
{
    int i;
    for (i = 0; i < g_devid_count; i++) {
        wc_CryptoCb_UnRegisterDevice(g_devid_table[i].devId);
        XFREE(g_devid_table[i].cfg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        g_devid_table[i].devId = 0;
        g_devid_table[i].cfg   = NULL;
    }
    g_devid_count = 0;
    if (g_pool_inited) {
        crypto2dev_pool_cleanup(&g_pool);
        g_pool_inited = 0;
    }
    return 0;
}

int wc_crypto2dev_cb(int devId, wc_CryptoInfo* info, void* ctx)
{
    Crypto2DevConfig* cfg = (Crypto2DevConfig*)ctx;
    if (info == NULL)
        return BAD_FUNC_ARG;
    (void)devId;

    switch (info->algo_type) {
        case WC_ALGO_TYPE_CIPHER:
            return crypto2dev_cipher(info);
        case WC_ALGO_TYPE_HASH:
            if (cfg != NULL && cfg->tls_safe)
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
            /* info->free.algo identifies the object type being freed
             * (WC_ALGO_TYPE_CIPHER, WC_ALGO_TYPE_HASH, etc.) so we can
             * dispatch to the right free helper. */
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
            /* crypto2dev has no session-snapshot ioctl.
             *
             * When a hash object has active hardware state (devCtx != NULL,
             * meaning an op_fd is open and data has been written to it),
             * a software fallback copy (XMEMCPY of the struct) would alias
             * the devCtx pointer in both src and dst.  Whichever object is
             * Finalized or Freed first closes the op_fd and frees the ctx;
             * the other then holds a dangling pointer — use-after-free and
             * double-close of the fd (which the OS may have reused).
             * Return WC_HW_E to surface a hard error rather than silently
             * creating a corrupt copy.
             *
             * When devCtx == NULL (no active hardware state — object was
             * Init'd but not yet Update'd, or already Final'd), XMEMCPY is
             * safe: the NULL pointer is copied, so neither copy owns any
             * hardware resource.  Return CRYPTOCB_UNAVAILABLE to allow it.
             *
             * Implication for TLS: wc_Sha256Copy is called for the Transcript-
             * Hash during TLS 1.3 key derivation. TLS-safe mode
             * (wc_crypto2dev_assign_devid_ex) prevents hardware hash for objects
             * whose devId has tls_safe == 1, so this path is never reached in
             * normal TLS use.  See wc_crypto2dev_assign_devid_ex() header comment. */
            /* Guard cipher COPY: if the source Aes has active hardware state
             * (devCtx != NULL, meaning SETKEY stored a key-fd handle), a plain
             * XMEMCPY aliases devCtx in both src and dst.  Whichever object is
             * freed first runs ForceZero+XFREE on the block; the other then holds
             * a dangling pointer — use-after-free and double-free (wolfssl-yjw.5).
             * Return WC_HW_E to surface a hard error rather than corrupt state.
             * When devCtx == NULL the copy is safe; fall through to CRYPTOCB_UNAVAILABLE. */
            if (info->copy.algo == WC_ALGO_TYPE_CIPHER) {
                const Aes* src = (const Aes*)info->copy.src;
                if (src != NULL && src->devCtx != NULL)
                    return WC_HW_E;
            }
#ifndef NO_HMAC
            /* Guard HMAC COPY: wolfSSL's wc_HmacCopy does not dispatch through
             * CryptoCb (unlike wc_Sha256Copy), so this case is not currently
             * reached from the standard wolfSSL API.  It is here as primary
             * defense so that if upstream ever adds CryptoCb COPY dispatch for
             * HMAC, the port immediately returns WC_HW_E rather than silently
             * aliasing the streaming accumulation buffer.
             * The FREE-path owner guard (wolfssl-qsi.2) is secondary defense
             * for the case where the copy slips through (COPY returns
             * CRYPTOCB_UNAVAILABLE and wolfSSL does the XMEMCPY itself). */
            if (info->copy.algo == WC_ALGO_TYPE_HMAC) {
                const Hmac* src = (const Hmac*)info->copy.src;
                if (src != NULL && src->devCtx != NULL)
                    return WC_HW_E;
            }
#endif /* NO_HMAC */
            if (info->copy.algo == WC_ALGO_TYPE_HASH) {
                void* src_devctx = NULL;
                switch (info->copy.type) {
#ifndef NO_SHA256
                    case WC_HASH_TYPE_SHA256: {
                        const wc_Sha256* s = (const wc_Sha256*)info->copy.src;
                        if (s != NULL) src_devctx = s->devCtx;
                        break;
                    }
#endif
#ifdef WOLFSSL_SHA384
                    case WC_HASH_TYPE_SHA384: {
                        const wc_Sha384* s = (const wc_Sha384*)info->copy.src;
                        if (s != NULL) src_devctx = s->devCtx;
                        break;
                    }
#endif
#ifdef WOLFSSL_SHA512
                    case WC_HASH_TYPE_SHA512: {
                        const wc_Sha512* s = (const wc_Sha512*)info->copy.src;
                        if (s != NULL) src_devctx = s->devCtx;
                        break;
                    }
#endif
#ifdef WOLFSSL_SHA3
                    case WC_HASH_TYPE_SHA3_256:
                    case WC_HASH_TYPE_SHA3_384:
                    case WC_HASH_TYPE_SHA3_512: {
                        const wc_Sha3* s = (const wc_Sha3*)info->copy.src;
                        if (s != NULL) src_devctx = s->devCtx;
                        break;
                    }
#endif
                    default:
                        break;
                }
                if (src_devctx != NULL)
                    return WC_HW_E;
            }
#if defined(HAVE_ECC) && defined(WOLF_CRYPTO_CB_SETKEY)
            /* Guard ECC key COPY: wolfSSL does not currently dispatch
             * wc_CryptoCb_Copy for PK objects — only hash copy functions
             * (sha256.c / sha512.c / sha3.c / sha.c) call wc_CryptoCb_Copy.
             * This guard is defensive: if wolfSSL ever adds CryptoCb COPY
             * dispatch for wc_ecc_copy_key, an ecc_key with devCtx set
             * (hardware key fd) would alias the fd between src and dst.
             * Whichever object is freed first closes the fd; the other then
             * holds an invalid fd and calls ioctl() at sign/verify time.
             * Return WC_HW_E when devCtx is set; fall through when NULL. */
            if (info->copy.algo == WC_ALGO_TYPE_PK) {
                if (info->copy.type == WC_PK_TYPE_ECDSA_SIGN  ||
                    info->copy.type == WC_PK_TYPE_ECDSA_VERIFY ||
                    info->copy.type == WC_PK_TYPE_ECDH         ||
                    info->copy.type == WC_PK_TYPE_EC_KEYGEN) {
                    const ecc_key* src_ecc = (const ecc_key*)info->copy.src;
                    if (src_ecc != NULL && src_ecc->devCtx != NULL)
                        return WC_HW_E;
                }
            }
#endif /* HAVE_ECC && WOLF_CRYPTO_CB_SETKEY */
            return CRYPTOCB_UNAVAILABLE;
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

/* Register wc_crypto2dev_cb under a caller-supplied devId without enabling
 * TLS-safe mode.  Hardware hash (WC_ALGO_TYPE_HASH) remains active.
 * wc_crypto2dev_cleanup() unregisters all devIds registered here.
 * Idempotent: a second call with the same devId returns 0.
 * Returns BUFFER_E if WOLFSSL_CRYPTO2DEV_MAX_DEVIDS slots are occupied. */
int wc_crypto2dev_register_ex(int devId)
{
    int ret;
    Crypto2DevConfig* cfg;
    if (crypto2dev_find_devid(devId) >= 0)
        return 0;
    if (g_devid_count >= WOLFSSL_CRYPTO2DEV_MAX_DEVIDS)
        return BUFFER_E;
    cfg = (Crypto2DevConfig*)XMALLOC(sizeof(Crypto2DevConfig), NULL,
                                     DYNAMIC_TYPE_TMP_BUFFER);
    if (cfg == NULL)
        return MEMORY_E;
    cfg->tls_safe = 0;
    ret = wc_CryptoCb_RegisterDevice(devId, wc_crypto2dev_cb, cfg);
    if (ret == 0) {
        g_devid_table[g_devid_count].devId = devId;
        g_devid_table[g_devid_count].cfg   = cfg;
        g_devid_count++;
    }
    else {
        XFREE(cfg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}

/* Register wc_crypto2dev_cb under WOLF_CRYPTO2DEV_DEVID without TLS-safe mode.
 * For TLS, use wc_crypto2dev_assign_devid() instead. */
int wc_crypto2dev_register(void)
{
    return wc_crypto2dev_register_ex(WOLF_CRYPTO2DEV_DEVID);
}

/* set_fn assigns devId to the CTX/SSL object; returns WOLFSSL_SUCCESS. */
typedef int (*crypto2dev_setid_fn)(void* obj, int devId);

static int crypto2dev_assign_devid_impl(int devId, crypto2dev_setid_fn set_fn,
                                        void* obj)
{
    int ret;
    int idx;
    int was_registered;
    int prev_tls_safe;
    Crypto2DevConfig* cfg;

    idx            = crypto2dev_find_devid(devId);
    was_registered = (idx >= 0);

    if (!was_registered) {
        if (g_devid_count >= WOLFSSL_CRYPTO2DEV_MAX_DEVIDS)
            return BUFFER_E;
        cfg = (Crypto2DevConfig*)XMALLOC(sizeof(Crypto2DevConfig), NULL,
                                         DYNAMIC_TYPE_TMP_BUFFER);
        if (cfg == NULL)
            return MEMORY_E;
        cfg->tls_safe = 0;
        ret = wc_CryptoCb_RegisterDevice(devId, wc_crypto2dev_cb, cfg);
        if (ret != 0) {
            XFREE(cfg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
        idx = g_devid_count;
        g_devid_table[idx].devId = devId;
        g_devid_table[idx].cfg   = cfg;
        g_devid_count++;
    }

    cfg           = g_devid_table[idx].cfg;
    prev_tls_safe = cfg->tls_safe;
    if (!prev_tls_safe) {
        cfg->tls_safe = 1;
        WOLFSSL_MSG("crypto2dev: TLS-safe mode enabled for devId — "
                    "WC_ALGO_TYPE_HASH falls back to software");
    }

    ret = set_fn(obj, devId);
    if (ret != WOLFSSL_SUCCESS) {
        cfg->tls_safe = prev_tls_safe;
        if (!was_registered) {
            wc_CryptoCb_UnRegisterDevice(devId);
            g_devid_count--;
            XFREE(cfg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            g_devid_table[g_devid_count].devId = 0;
            g_devid_table[g_devid_count].cfg   = NULL;
        }
        return ret;
    }
    return 0;
}

static int assign_ctx_setid(void* obj, int devId)
{
    return wolfSSL_CTX_SetDevId((WOLFSSL_CTX*)obj, devId);
}

static int assign_ssl_setid(void* obj, int devId)
{
    return wolfSSL_SetDevId((WOLFSSL*)obj, devId);
}

int wc_crypto2dev_assign_devid_ex(WOLFSSL_CTX* ctx, int devId)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;
    return crypto2dev_assign_devid_impl(devId, assign_ctx_setid, ctx);
}

int wc_crypto2dev_assign_devid_ssl_ex(WOLFSSL* ssl, int devId)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;
    return crypto2dev_assign_devid_impl(devId, assign_ssl_setid, ssl);
}

int wc_crypto2dev_assign_devid(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;
    return crypto2dev_assign_devid_impl(WOLF_CRYPTO2DEV_DEVID,
                                        assign_ctx_setid, ctx);
}

int wc_crypto2dev_assign_devid_ssl(WOLFSSL* ssl)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;
    return crypto2dev_assign_devid_impl(WOLF_CRYPTO2DEV_DEVID,
                                        assign_ssl_setid, ssl);
}

#endif /* WOLFSSL_CRYPTO2DEV && WOLF_CRYPTO_CB */
