/* crypto2dev_sim.c — software simulator for /dev/crypto2dev
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
 * This file implements a software substitute for the /dev/crypto2dev kernel
 * driver, used for unit testing without hardware.  Activate by defining
 * WOLFSSL_CRYPTO2DEV_SIM at compile time.
 *
 * The simulator intercepts open/close/read/write/ioctl via macros defined in
 * crypto2dev_sim.h.  Each "file descriptor" is an index into a static slot
 * table.  Simulated fd values are offset by SIM_FD_BASE so they do not
 * collide with real fds the process may hold.
 *
 * Supported operations:
 *   OPERATION fds: sha256, sha384, sha512 hashing; cbc(aes) / gcm(aes) / ctr(aes) cipher
 *   KEY fds:       raw key import; ECDSA P-256 sign/verify
 *   HMAC:          hmac(sha256) / hmac(sha384) / hmac(sha512)
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_CRYPTO2DEV) && defined(WOLF_CRYPTO_CB) && \
    defined(WOLFSSL_CRYPTO2DEV_SIM)

/* Include system headers BEFORE the wire/sim headers so we get real
 * prototypes.  crypto2dev_wire.h also includes <sys/ioctl.h> but listing
 * it here first is harmless and makes the dependency explicit. */
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

/* Wire structs and ioctl request codes — shared with crypto2dev_port.c via
 * this header.  Both files compute _IOW/_IOR from the same struct definitions,
 * guaranteeing that ioctl request codes match on both sides. */
#include <wolfssl/wolfcrypt/port/crypto2dev/crypto2dev_wire.h>

/* Must come last — redefines open/close/read/write/ioctl. */
#include <wolfssl/wolfcrypt/port/crypto2dev/crypto2dev_sim.h>

#if defined(WOLFSSL_CRYPTO2DEV_REQUIRE_FIPS) && defined(WOLFSSL_CRYPTO2DEV_SIM)
#error "WOLFSSL_CRYPTO2DEV_REQUIRE_FIPS and WOLFSSL_CRYPTO2DEV_SIM are incompatible: " \
       "the simulator does not implement the REQUIRE_FIPS ioctl."
#endif

/* Verify that sign_op and verify_op have identical wire layout (they share
 * the same field set and the sim ioctl dispatch casts between them). */
wc_static_assert2(sizeof(struct crypto2dev_sign_op) ==
                  sizeof(struct crypto2dev_verify_op),
    "sign_op and verify_op must be the same size");

/* ---------------------------------------------------------------------- */
/* Slot table                                                               */
/* ---------------------------------------------------------------------- */

/* SIM_MAX_DATA: maximum bytes per in_buf / out_buf in SimFdSlot.
 * This is a simulator constraint (each slot is SIM_MAX_DATA*2 bytes of stack
 * memory) — the wire protocol itself has no fixed data-size limit. */
#define SIM_MAX_DATA  65536

#define MAX_SIM_FDS   16
#define SIM_FD_BASE   1000  /* simulated fds start here to avoid real-fd collisions */

#define SIM_FD_UNSET      0
#define SIM_FD_OPERATION  1
#define SIM_FD_KEY        2

/* Hash algorithm sub-type for the operation fd.
 * SIM_HASH_HMAC is a distinct sub-type so that sim_finalize can dispatch
 * explicitly rather than relying on the implicit keySz>0 heuristic. */
#define SIM_HASH_NONE      0
#define SIM_HASH_SHA256    1
#define SIM_HASH_SHA384    2
#define SIM_HASH_SHA512    3
#define SIM_HASH_SHA3_256  4
#define SIM_HASH_SHA3_384  5
#define SIM_HASH_SHA3_512  6
#define SIM_HASH_HMAC      7

/* Cipher algorithm sub-type for the operation fd. */
#define SIM_CIPHER_NONE  0
#define SIM_CIPHER_CBC   1
#define SIM_CIPHER_GCM   2
#define SIM_CIPHER_CTR   3

typedef struct {
    int    used;
    int    fd_type;       /* SIM_FD_UNSET, SIM_FD_OPERATION, SIM_FD_KEY */

    /* OPERATION state */
    int    op;            /* CRYPTO2DEV_OP_ENCRYPT / DECRYPT / HASH */
    int    hash_type;     /* SIM_HASH_* */
    int    cipher_type;   /* SIM_CIPHER_* */
    char   algo[CRYPTO2DEV_ALGO_MAXLEN];

    /* Inline key (for cipher/hmac OPERATION fds) */
    byte   key[CRYPTO2DEV_KEY_MAXLEN];
    word32 keySz;

    /* IV and AAD */
    byte   iv[CRYPTO2DEV_IV_MAXLEN];
    word32 ivSz;
    byte   aad[CRYPTO2DEV_AAD_MAXLEN];
    word32 aadSz;

    /* Accumulated input buffer */
    byte   in_buf[SIM_MAX_DATA];
    word32 in_len;

    /* Computed output */
    byte   out_buf[SIM_MAX_DATA];
    word32 out_len;
    word32 out_pos;   /* read cursor */
    int    finalized;

    /* GCM tag */
    byte   tag[CRYPTO2DEV_TAG_MAXLEN];
    word32 tagSz;
    byte   expected_tag[CRYPTO2DEV_TAG_MAXLEN];
    word32 expected_tagSz;

    /* KEY fd state */
    byte   key_bytes[CRYPTO2DEV_KEY_IMPORT_MAXLEN];
    word32 key_len;
    char   key_algo[CRYPTO2DEV_ALGO_MAXLEN];
    int    key_type;  /* CRYPTO2DEV_KEY_PRIVATE / PUBLIC / SYMMETRIC */

    /* ECC key (decoded on import for ECDSA sim) */
#ifdef HAVE_ECC
    ecc_key ecc;
    int     ecc_inited;
#endif
} SimFdSlot;

static SimFdSlot g_sim_slots[MAX_SIM_FDS];
static int       g_sim_inited = 0;

/* Fault injection: when > 0, the next N calls to crypto2dev_sim_ioctl
 * return -1 with errno=ENODEV.  Single-threaded test use only. */
static int g_sim_ioctl_fail_count = 0;

void crypto2dev_sim_set_ioctl_fail(int count)
{
    g_sim_ioctl_fail_count = count;
}

static void sim_ensure_init(void)
{
    if (!g_sim_inited) {
        XMEMSET(g_sim_slots, 0, sizeof(g_sim_slots));
        g_sim_inited = 1;
    }
}

/* Allocate a slot; returns slot index [0, MAX_SIM_FDS) or -1. */
static int sim_alloc_slot(void)
{
    int i;
    sim_ensure_init();
    for (i = 0; i < MAX_SIM_FDS; i++) {
        if (!g_sim_slots[i].used) {
            XMEMSET(&g_sim_slots[i], 0, sizeof(SimFdSlot));
            g_sim_slots[i].used = 1;
            return i;
        }
    }
    return -1;
}

/* Translate a simulated fd to a slot pointer; returns NULL on bad fd. */
static SimFdSlot* sim_slot(int fd)
{
    int idx;
    sim_ensure_init();
    idx = fd - SIM_FD_BASE;
    if (idx < 0 || idx >= MAX_SIM_FDS)
        return NULL;
    if (!g_sim_slots[idx].used)
        return NULL;
    return &g_sim_slots[idx];
}

/* ---------------------------------------------------------------------- */
/* Finalize helpers — run the actual cryptographic operation               */
/* ---------------------------------------------------------------------- */

static int sim_finalize_hash(SimFdSlot* slot)
{
    int ret = 0;

    switch (slot->hash_type) {
        case SIM_HASH_SHA256: {
            wc_Sha256 sha;
            ret = wc_InitSha256_ex(&sha, NULL, INVALID_DEVID);
            if (ret != 0) return ret;
            ret = wc_Sha256Update(&sha, slot->in_buf, slot->in_len);
            if (ret == 0)
                ret = wc_Sha256Final(&sha, slot->out_buf);
            wc_Sha256Free(&sha);
            if (ret != 0) return ret;
            slot->out_len = WC_SHA256_DIGEST_SIZE;
            break;
        }
#ifdef WOLFSSL_SHA384
        case SIM_HASH_SHA384: {
            wc_Sha384 sha;
            ret = wc_InitSha384_ex(&sha, NULL, INVALID_DEVID);
            if (ret != 0) return ret;
            ret = wc_Sha384Update(&sha, slot->in_buf, slot->in_len);
            if (ret == 0)
                ret = wc_Sha384Final(&sha, slot->out_buf);
            wc_Sha384Free(&sha);
            if (ret != 0) return ret;
            slot->out_len = WC_SHA384_DIGEST_SIZE;
            break;
        }
#endif
#ifdef WOLFSSL_SHA512
        case SIM_HASH_SHA512: {
            wc_Sha512 sha;
            ret = wc_InitSha512_ex(&sha, NULL, INVALID_DEVID);
            if (ret != 0) return ret;
            ret = wc_Sha512Update(&sha, slot->in_buf, slot->in_len);
            if (ret == 0)
                ret = wc_Sha512Final(&sha, slot->out_buf);
            wc_Sha512Free(&sha);
            if (ret != 0) return ret;
            slot->out_len = WC_SHA512_DIGEST_SIZE;
            break;
        }
#endif
#ifdef WOLFSSL_SHA3
        case SIM_HASH_SHA3_256: {
            wc_Sha3 sha;
            ret = wc_InitSha3_256(&sha, NULL, INVALID_DEVID);
            if (ret != 0) return ret;
            ret = wc_Sha3_256_Update(&sha, slot->in_buf, slot->in_len);
            if (ret == 0)
                ret = wc_Sha3_256_Final(&sha, slot->out_buf);
            wc_Sha3_256_Free(&sha);
            if (ret != 0) return ret;
            slot->out_len = WC_SHA3_256_DIGEST_SIZE;
            break;
        }
        case SIM_HASH_SHA3_384: {
            wc_Sha3 sha;
            ret = wc_InitSha3_384(&sha, NULL, INVALID_DEVID);
            if (ret != 0) return ret;
            ret = wc_Sha3_384_Update(&sha, slot->in_buf, slot->in_len);
            if (ret == 0)
                ret = wc_Sha3_384_Final(&sha, slot->out_buf);
            wc_Sha3_384_Free(&sha);
            if (ret != 0) return ret;
            slot->out_len = WC_SHA3_384_DIGEST_SIZE;
            break;
        }
        case SIM_HASH_SHA3_512: {
            wc_Sha3 sha;
            ret = wc_InitSha3_512(&sha, NULL, INVALID_DEVID);
            if (ret != 0) return ret;
            ret = wc_Sha3_512_Update(&sha, slot->in_buf, slot->in_len);
            if (ret == 0)
                ret = wc_Sha3_512_Final(&sha, slot->out_buf);
            wc_Sha3_512_Free(&sha);
            if (ret != 0) return ret;
            slot->out_len = WC_SHA3_512_DIGEST_SIZE;
            break;
        }
#endif /* WOLFSSL_SHA3 */
        default:
            return -1;
    }
    return 0;
}

static int sim_finalize_hmac(SimFdSlot* slot)
{
    int type;
    Hmac hmac;
    int ret;

    if (XSTRNCMP(slot->algo, "hmac(sha256)", sizeof(slot->algo)) == 0)
        type = WC_SHA256;
    else if (XSTRNCMP(slot->algo, "hmac(sha384)", sizeof(slot->algo)) == 0)
        type = WC_SHA384;
    else if (XSTRNCMP(slot->algo, "hmac(sha512)", sizeof(slot->algo)) == 0)
        type = WC_SHA512;
    else
        return -1;

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) return ret;
    ret = wc_HmacSetKey(&hmac, type, slot->key, slot->keySz);
    if (ret == 0)
        ret = wc_HmacUpdate(&hmac, slot->in_buf, slot->in_len);
    if (ret == 0)
        ret = wc_HmacFinal(&hmac, slot->out_buf);
    wc_HmacFree(&hmac);
    if (ret != 0) return ret;

    switch (type) {
        case WC_SHA256: slot->out_len = WC_SHA256_DIGEST_SIZE; break;
        case WC_SHA384: slot->out_len = WC_SHA384_DIGEST_SIZE; break;
        case WC_SHA512: slot->out_len = WC_SHA512_DIGEST_SIZE; break;
        default:        return -1;
    }
    return 0;
}

static int sim_finalize_cipher_cbc(SimFdSlot* slot)
{
    Aes aes;
    int ret;

    if (slot->keySz == 0 || slot->ivSz == 0)
        return -1;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) return ret;

    if (slot->op == CRYPTO2DEV_OP_ENCRYPT) {
        ret = wc_AesSetKey(&aes, slot->key, slot->keySz,
                           slot->iv, AES_ENCRYPTION);
        if (ret == 0)
            ret = wc_AesCbcEncrypt(&aes, slot->out_buf,
                                   slot->in_buf, slot->in_len);
    } else {
        ret = wc_AesSetKey(&aes, slot->key, slot->keySz,
                           slot->iv, AES_DECRYPTION);
        if (ret == 0)
            ret = wc_AesCbcDecrypt(&aes, slot->out_buf,
                                   slot->in_buf, slot->in_len);
    }
    wc_AesFree(&aes);
    if (ret != 0) return ret;
    slot->out_len = slot->in_len;
    return 0;
}

static int sim_finalize_cipher_gcm(SimFdSlot* slot)
{
    Aes aes;
    int ret;

    if (slot->keySz == 0 || slot->ivSz == 0)
        return -1;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) return ret;

    ret = wc_AesGcmSetKey(&aes, slot->key, slot->keySz);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ret;
    }

    if (slot->op == CRYPTO2DEV_OP_ENCRYPT) {
        ret = wc_AesGcmEncrypt(&aes,
                               slot->out_buf,
                               slot->in_buf, slot->in_len,
                               slot->iv, slot->ivSz,
                               slot->tag, AES_BLOCK_SIZE,
                               slot->aad, slot->aadSz);
        if (ret == 0) {
            slot->tagSz  = AES_BLOCK_SIZE;
            slot->out_len = slot->in_len;
        }
    } else {
        ret = wc_AesGcmDecrypt(&aes,
                               slot->out_buf,
                               slot->in_buf, slot->in_len,
                               slot->iv, slot->ivSz,
                               slot->expected_tag, slot->expected_tagSz,
                               slot->aad, slot->aadSz);
        if (ret == 0)
            slot->out_len = slot->in_len;
    }
    wc_AesFree(&aes);
    return ret;
}

#ifdef WOLFSSL_AES_COUNTER
static int sim_finalize_cipher_ctr(SimFdSlot* slot)
{
    Aes aes;
    int ret;

    if (slot->keySz == 0 || slot->ivSz == 0)
        return -1;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) return ret;

    /* CTR mode: encrypt and decrypt are the same operation. */
    ret = wc_AesSetKey(&aes, slot->key, slot->keySz, slot->iv, AES_ENCRYPTION);
    if (ret == 0)
        ret = wc_AesCtrEncrypt(&aes, slot->out_buf, slot->in_buf, slot->in_len);
    wc_AesFree(&aes);
    if (ret != 0) return ret;
    slot->out_len = slot->in_len;
    return 0;
}
#endif /* WOLFSSL_AES_COUNTER */

static int sim_finalize(SimFdSlot* slot)
{
    if (slot->finalized)
        return 0;

    if (slot->op == CRYPTO2DEV_OP_HASH) {
        int ret;
        if (slot->hash_type == SIM_HASH_HMAC)
            ret = sim_finalize_hmac(slot);
        else
            ret = sim_finalize_hash(slot);
        if (ret != 0) return ret;
    } else {
        int ret;
        if (slot->cipher_type == SIM_CIPHER_CBC)
            ret = sim_finalize_cipher_cbc(slot);
        else if (slot->cipher_type == SIM_CIPHER_GCM)
            ret = sim_finalize_cipher_gcm(slot);
#ifdef WOLFSSL_AES_COUNTER
        else if (slot->cipher_type == SIM_CIPHER_CTR)
            ret = sim_finalize_cipher_ctr(slot);
#endif
        else
            return -1;
        if (ret != 0) return ret;
    }

    slot->finalized = 1;
    slot->out_pos   = 0;
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Sim syscall implementations                                             */
/* ---------------------------------------------------------------------- */

int crypto2dev_sim_open(const char* path, int flags)
{
    int idx;
    (void)path;
    (void)flags;

    idx = sim_alloc_slot();
    if (idx < 0) {
        errno = EMFILE;
        return -1;
    }
    g_sim_slots[idx].fd_type = SIM_FD_UNSET;
    return SIM_FD_BASE + idx;
}

int crypto2dev_sim_close(int fd)
{
    SimFdSlot* slot = sim_slot(fd);
    if (slot == NULL) {
        errno = EBADF;
        return -1;
    }
#ifdef HAVE_ECC
    if (slot->ecc_inited) {
        wc_ecc_free(&slot->ecc);
        slot->ecc_inited = 0;
    }
#endif
    XMEMSET(slot, 0, sizeof(SimFdSlot));
    return 0;
}

ssize_t crypto2dev_sim_write(int fd, const void* buf, size_t count)
{
    SimFdSlot* slot = sim_slot(fd);
    if (slot == NULL) {
        errno = EBADF;
        return -1;
    }

    if (slot->fd_type == SIM_FD_UNSET) {
        /* Pre-INIT write: buffering key bytes for KEY_IMPORT */
        if (slot->key_len + (word32)count > sizeof(slot->key_bytes)) {
            errno = EMSGSIZE;
            return -1;
        }
        XMEMCPY(slot->key_bytes + slot->key_len, buf, count);
        slot->key_len += (word32)count;
        return (ssize_t)count;
    }

    if (slot->fd_type == SIM_FD_OPERATION) {
        if (slot->in_len + (word32)count > sizeof(slot->in_buf)) {
            errno = EMSGSIZE;
            return -1;
        }
        XMEMCPY(slot->in_buf + slot->in_len, buf, count);
        slot->in_len += (word32)count;
        return (ssize_t)count;
    }

    errno = EBADF;
    return -1;
}

ssize_t crypto2dev_sim_read(int fd, void* buf, size_t count)
{
    SimFdSlot* slot = sim_slot(fd);
    word32 avail;

    if (slot == NULL) {
        errno = EBADF;
        return -1;
    }
    if (slot->fd_type != SIM_FD_OPERATION) {
        errno = EBADF;
        return -1;
    }
    if (!slot->finalized) {
        errno = EBUSY;
        return -1;
    }

    avail = slot->out_len - slot->out_pos;
    if ((word32)count > avail)
        count = avail;
    XMEMCPY(buf, slot->out_buf + slot->out_pos, count);
    slot->out_pos += (word32)count;
    return (ssize_t)count;
}

/* ---------------------------------------------------------------------- */
/* ioctl dispatch                                                          */
/* ---------------------------------------------------------------------- */

static int sim_ioctl_init(SimFdSlot* slot, void* arg)
{
    struct crypto2dev_init_op* op = (struct crypto2dev_init_op*)arg;

    if (op == NULL)
        return -1;

    slot->fd_type    = SIM_FD_OPERATION;
    slot->op         = (int)op->op;
    slot->in_len     = 0;
    slot->out_len    = 0;
    slot->out_pos    = 0;
    slot->finalized  = 0;
    slot->aadSz      = 0;
    slot->ivSz       = 0;
    slot->tagSz      = 0;
    slot->expected_tagSz = 0;

    XSTRNCPY(slot->algo, op->algo, sizeof(slot->algo) - 1);
    slot->algo[sizeof(slot->algo) - 1] = '\0';

    if (op->keylen > 0 && op->keylen <= sizeof(slot->key)) {
        XMEMCPY(slot->key, op->key, op->keylen);
        slot->keySz = op->keylen;
    } else {
        slot->keySz = 0;
    }

    /* Identify algorithm sub-type */
    slot->hash_type   = SIM_HASH_NONE;
    slot->cipher_type = SIM_CIPHER_NONE;

    if (XSTRNCMP(op->algo, "sha256", CRYPTO2DEV_ALGO_MAXLEN) == 0)
        slot->hash_type = SIM_HASH_SHA256;
    else if (XSTRNCMP(op->algo, "sha384", CRYPTO2DEV_ALGO_MAXLEN) == 0)
        slot->hash_type = SIM_HASH_SHA384;
    else if (XSTRNCMP(op->algo, "sha512", CRYPTO2DEV_ALGO_MAXLEN) == 0)
        slot->hash_type = SIM_HASH_SHA512;
#ifdef WOLFSSL_SHA3
    else if (XSTRNCMP(op->algo, "sha3-256", CRYPTO2DEV_ALGO_MAXLEN) == 0)
        slot->hash_type = SIM_HASH_SHA3_256;
    else if (XSTRNCMP(op->algo, "sha3-384", CRYPTO2DEV_ALGO_MAXLEN) == 0)
        slot->hash_type = SIM_HASH_SHA3_384;
    else if (XSTRNCMP(op->algo, "sha3-512", CRYPTO2DEV_ALGO_MAXLEN) == 0)
        slot->hash_type = SIM_HASH_SHA3_512;
#endif
    else if (XSTRNCMP(op->algo, "cbc(aes)", CRYPTO2DEV_ALGO_MAXLEN) == 0)
        slot->cipher_type = SIM_CIPHER_CBC;
    else if (XSTRNCMP(op->algo, "gcm(aes)", CRYPTO2DEV_ALGO_MAXLEN) == 0)
        slot->cipher_type = SIM_CIPHER_GCM;
#ifdef WOLFSSL_AES_COUNTER
    else if (XSTRNCMP(op->algo, "ctr(aes)", CRYPTO2DEV_ALGO_MAXLEN) == 0)
        slot->cipher_type = SIM_CIPHER_CTR;
#endif
    else if (XSTRNCMP(op->algo, "hmac(", 5) == 0)
        slot->hash_type = SIM_HASH_HMAC;
    else {
        /* Unrecognized algo — signal to the port to fall back to software. */
        errno = EOPNOTSUPP;
        return -1;
    }

    return 0;
}

static int sim_ioctl_set_iv(SimFdSlot* slot, void* arg)
{
    struct crypto2dev_iv_op* op = (struct crypto2dev_iv_op*)arg;
    if (op == NULL || op->ivlen > sizeof(slot->iv))
        return -1;
    XMEMCPY(slot->iv, op->iv, op->ivlen);
    slot->ivSz = op->ivlen;
    return 0;
}

static int sim_ioctl_set_aad(SimFdSlot* slot, void* arg)
{
    struct crypto2dev_aad_op* op = (struct crypto2dev_aad_op*)arg;
    if (op == NULL || op->aadlen > sizeof(slot->aad))
        return -1;
    XMEMCPY(slot->aad, op->aad, op->aadlen);
    slot->aadSz = op->aadlen;
    return 0;
}

static int sim_ioctl_get_tag(SimFdSlot* slot, void* arg)
{
    struct crypto2dev_tag_op* op = (struct crypto2dev_tag_op*)arg;
    if (op == NULL)
        return -1;
    if (!slot->finalized || slot->tagSz == 0) {
        errno = EBUSY;
        return -1;
    }
    if (op->taglen > slot->tagSz)
        op->taglen = slot->tagSz;
    XMEMCPY(op->tag, slot->tag, op->taglen);
    return 0;
}

static int sim_ioctl_set_tag(SimFdSlot* slot, void* arg)
{
    struct crypto2dev_tag_op* op = (struct crypto2dev_tag_op*)arg;
    if (op == NULL || op->taglen > sizeof(slot->expected_tag))
        return -1;
    XMEMCPY(slot->expected_tag, op->tag, op->taglen);
    slot->expected_tagSz = op->taglen;
    return 0;
}

static int sim_ioctl_key_import(SimFdSlot* slot, void* arg)
{
    struct crypto2dev_key_import_op* op =
        (struct crypto2dev_key_import_op*)arg;
    int ret;

    if (op == NULL)
        return -1;
    if (slot->key_len == 0 || slot->key_len > sizeof(slot->key_bytes))
        return -1;

    slot->fd_type  = SIM_FD_KEY;
    slot->key_type = (int)op->key_type;
    XSTRNCPY(slot->key_algo, op->algo, sizeof(slot->key_algo) - 1);
    slot->key_algo[sizeof(slot->key_algo) - 1] = '\0';

#ifdef HAVE_ECC
    if (XSTRNCMP(op->algo, "ecdsa", CRYPTO2DEV_ALGO_MAXLEN) == 0) {
        ret = wc_ecc_init_ex(&slot->ecc, NULL, INVALID_DEVID);
        if (ret != 0)
            return -1;
        slot->ecc_inited = 1;

        if (op->key_type == CRYPTO2DEV_KEY_PRIVATE) {
            /* Raw private scalar: import with no public key.
             * Use wc_ecc_import_private_key with NULL pub to get curve from
             * key size.  P-256 private key = 32 bytes. */
            ret = wc_ecc_import_private_key(slot->key_bytes, slot->key_len,
                                             NULL, 0, &slot->ecc);
        } else {
            /* Uncompressed public key (X9.63: 0x04 || X || Y) */
            ret = wc_ecc_import_x963(slot->key_bytes, slot->key_len,
                                     &slot->ecc);
        }
        if (ret != 0) {
            wc_ecc_free(&slot->ecc);
            slot->ecc_inited = 0;
            return -1;
        }
    }
#endif /* HAVE_ECC */

    return 0;
}

#ifdef HAVE_ECC
static int sim_ioctl_do_sign(int key_fd, void* arg)
{
    struct crypto2dev_sign_op* op = (struct crypto2dev_sign_op*)arg;
    SimFdSlot* kslot;
    WC_RNG rng;
    int ret;

    if (op == NULL)
        return -1;
    kslot = sim_slot(key_fd);
    if (kslot == NULL || kslot->fd_type != SIM_FD_KEY || !kslot->ecc_inited)
        return -1;

    ret = wc_InitRng(&rng);
    if (ret != 0)
        return -1;

    op->sig_len = CRYPTO2DEV_SIG_MAXLEN;
    ret = wc_ecc_sign_hash(op->digest, op->digest_len,
                           op->sig, &op->sig_len,
                           &rng, &kslot->ecc);
    wc_FreeRng(&rng);
    return (ret == 0) ? 0 : -1;
}

static int sim_ioctl_do_verify(int key_fd, void* arg)
{
    struct crypto2dev_verify_op* op = (struct crypto2dev_verify_op*)arg;
    SimFdSlot* kslot;
    int stat = 0;
    int ret;

    if (op == NULL)
        return -1;
    kslot = sim_slot(key_fd);
    if (kslot == NULL || kslot->fd_type != SIM_FD_KEY || !kslot->ecc_inited)
        return -1;

    ret = wc_ecc_verify_hash(op->sig, op->sig_len,
                             op->digest, op->digest_len,
                             &stat, &kslot->ecc);
    if (ret != 0 || stat != 1) {
        errno = EBADMSG;
        return -1;
    }
    return 0;
}
#else /* !HAVE_ECC */
static int sim_ioctl_do_sign(int key_fd, void* arg)
{
    (void)key_fd; (void)arg;
    errno = EOPNOTSUPP;
    return -1;
}
static int sim_ioctl_do_verify(int key_fd, void* arg)
{
    (void)key_fd; (void)arg;
    errno = EOPNOTSUPP;
    return -1;
}
#endif /* HAVE_ECC */

int crypto2dev_sim_ioctl(int fd, unsigned long request, void* arg)
{
    SimFdSlot* slot;

    if (g_sim_ioctl_fail_count > 0) {
        g_sim_ioctl_fail_count--;
        errno = ENODEV;
        return -1;
    }

    slot = sim_slot(fd);

    /* DO_SIGN and DO_VERIFY carry the key_fd as a simulated fd value.
     * They may be issued on any open sim fd (typically the global device fd). */
    if (request == CRYPTO2DEV_IOC_DO_SIGN) {
        struct crypto2dev_sign_op* op = (struct crypto2dev_sign_op*)arg;
        if (op == NULL) { errno = EINVAL; return -1; }
        return sim_ioctl_do_sign(op->key_fd, arg);
    }
    if (request == CRYPTO2DEV_IOC_DO_VERIFY) {
        struct crypto2dev_verify_op* op =
            (struct crypto2dev_verify_op*)arg;
        if (op == NULL) { errno = EINVAL; return -1; }
        return sim_ioctl_do_verify(op->key_fd, arg);
    }

    if (slot == NULL) {
        errno = EBADF;
        return -1;
    }

    if (request == CRYPTO2DEV_IOC_INIT)
        return sim_ioctl_init(slot, arg);
    if (request == CRYPTO2DEV_IOC_SET_IV)
        return sim_ioctl_set_iv(slot, arg);
    if (request == CRYPTO2DEV_IOC_SET_AAD)
        return sim_ioctl_set_aad(slot, arg);
    if (request == CRYPTO2DEV_IOC_GET_TAG)
        return sim_ioctl_get_tag(slot, arg);
    if (request == CRYPTO2DEV_IOC_SET_TAG)
        return sim_ioctl_set_tag(slot, arg);
    if (request == CRYPTO2DEV_IOC_KEY_IMPORT)
        return sim_ioctl_key_import(slot, arg);

    if (request == CRYPTO2DEV_IOC_FINALIZE) {
        int ret = sim_finalize(slot);
        if (ret != 0) {
            /* Distinguish GCM authentication failure from general I/O error
             * so the port can return AES_GCM_AUTH_E to the caller. */
            errno = (ret == AES_GCM_AUTH_E) ? EBADMSG : EIO;
            return -1;
        }
        return 0;
    }

    if (request == CRYPTO2DEV_IOC_RESET) {
        /* Sim does not support mid-stream reset; signal EBUSY so the port
         * closes and reopens the fd for a fresh operation. */
        errno = EBUSY;
        return -1;
    }

    errno = EOPNOTSUPP;
    return -1;
}

#endif /* WOLFSSL_CRYPTO2DEV && WOLF_CRYPTO_CB && WOLFSSL_CRYPTO2DEV_SIM */
