/* crypto2dev_wire.h — shared wire-protocol definitions for the
 *                     /dev/crypto2dev CryptoCb port and its software simulator.
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
 * This header defines the structs and ioctl request codes that cross the
 * port / simulator boundary.  Both crypto2dev_port.c and crypto2dev_sim.c
 * include it so that the _IOW/_IOR macros on both sides encode the same
 * sizeof(struct), guaranteeing matching ioctl request codes.
 *
 * If the actual out-of-tree uapi header
 * (~/WORK/WOLFKM/include/uapi/crypto2dev_ioctl.h) is available at build time,
 * define CRYPTO2DEV_HAVE_UAPI_HEADER and include it directly instead.
 * The definitions here replicate the minimum subset needed by the port.
 *
 * Limitation of the compile-time size guards (wolfssl-yjw.6):
 *   The wc_static_assert2 guards at the bottom of this file verify that each
 *   stub struct has the expected total size.  They protect against accidental
 *   padding or field-type changes that alter the struct size, which would
 *   silently corrupt the _IOW/_IOR request code.
 *
 *   They do NOT catch field-order changes within a struct that preserve the
 *   total size (e.g., swapping two same-sized fields).  Such changes produce a
 *   wrong ioctl ABI with no compile-time diagnostic.
 *
 *   Production builds that have access to the kernel tree MUST set
 *   CRYPTO2DEV_HAVE_UAPI_HEADER so the authoritative uapi header is included
 *   directly, making field-order divergence structurally impossible.  Builds
 *   without the kernel tree (CI, standalone wolfSSL) rely on manual sync.
 */

#ifndef WOLFSSL_PORT_CRYPTO2DEV_WIRE_H
#define WOLFSSL_PORT_CRYPTO2DEV_WIRE_H

#include <wolfssl/wolfcrypt/misc.h>  /* wc_static_assert2 */

/* ioctl magic and length limits */
#ifndef CRYPTO2DEV_IOC_MAGIC
#define CRYPTO2DEV_IOC_MAGIC         ((unsigned char)0xC2)
#endif
#ifndef CRYPTO2DEV_ALGO_MAXLEN
#define CRYPTO2DEV_ALGO_MAXLEN       64  /* matches kernel uapi CRYPTO2DEV_ALGO_MAXLEN */
#endif
#ifndef CRYPTO2DEV_PROVIDER_MAXLEN
#define CRYPTO2DEV_PROVIDER_MAXLEN   32
#endif

/* Key type constants */
#ifndef CRYPTO2DEV_KEY_PRIVATE
#define CRYPTO2DEV_KEY_PRIVATE       1
#define CRYPTO2DEV_KEY_PUBLIC        2
#define CRYPTO2DEV_KEY_PAIR          3
#define CRYPTO2DEV_KEY_SYMMETRIC     4
#endif
#ifndef CRYPTO2DEV_KEY_IMPORT_MAXLEN
#define CRYPTO2DEV_KEY_IMPORT_MAXLEN 8192
#endif

/* Operation fd size limits */
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

/* Operation direction */
#ifndef CRYPTO2DEV_OP_ENCRYPT
#define CRYPTO2DEV_OP_ENCRYPT          1
#define CRYPTO2DEV_OP_DECRYPT          2
#define CRYPTO2DEV_OP_HASH             3
#endif

/* FIPS aggregate state — returned in struct crypto2dev_status.fips_state
 * and readable via /sys/class/misc/crypto2dev/fips_state.
 * Matches the kernel uapi CRYPTO2DEV_FIPS_* constants. */
#ifndef CRYPTO2DEV_FIPS_NO_PROVIDER
#define CRYPTO2DEV_FIPS_NO_PROVIDER      0   /* no FIPS-gated provider loaded */
#define CRYPTO2DEV_FIPS_OPERATIONAL      1   /* FIPS provider(s) loaded and passing */
#define CRYPTO2DEV_FIPS_NOT_OPERATIONAL  2   /* FIPS provider loaded but failing POST */
#endif

/* ------------------------------------------------------------------ */
/* Wire structs                                                         */
/*                                                                     */
/* IMPORTANT: never reorder fields or change types without updating    */
/* the kernel driver in WOLFKM.  The _IOW/_IOR macros encode           */
/* sizeof(struct) into the ioctl request code; size changes break the  */
/* ABI silently.                                                        */
/*                                                                     */
/* Integer field types: the kernel uapi header uses __u32/__s32.       */
/* This header uses 'unsigned int'/'int' which are 32-bit on all       */
/* Linux LP32 and LP64 targets.  The compile-time size guards below    */
/* catch any mismatch at build time before it becomes a runtime ABI    */
/* break.  Do not change to 'unsigned long' (64-bit on LP64).          */
/* ------------------------------------------------------------------ */

struct crypto2dev_init_op {
    char          algo    [CRYPTO2DEV_ALGO_MAXLEN];
    char          provider[CRYPTO2DEV_PROVIDER_MAXLEN];
    unsigned int  op;
    unsigned int  keylen;
    unsigned char key[CRYPTO2DEV_KEY_MAXLEN];
    int           key_fd;
    unsigned char _pad[4]; /* pads struct to 240 bytes (multiple of 8) */
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
    unsigned char _pad[4]; /* pads 4-byte fd to 8-byte slot matching kernel uapi 64-bit layout */
    char          hash_algo[CRYPTO2DEV_ALGO_MAXLEN];
    unsigned int  digest_len;
    unsigned char digest[CRYPTO2DEV_HASH_MAXLEN];
    unsigned int  sig_len;
    unsigned char sig[CRYPTO2DEV_SIG_MAXLEN];
};

struct crypto2dev_verify_op {
    int           key_fd;
    unsigned char _pad[4]; /* pads 4-byte fd to 8-byte slot matching kernel uapi 64-bit layout */
    char          hash_algo[CRYPTO2DEV_ALGO_MAXLEN];
    unsigned int  digest_len;
    unsigned char digest[CRYPTO2DEV_HASH_MAXLEN];
    unsigned int  sig_len;
    unsigned char sig[CRYPTO2DEV_SIG_MAXLEN];
};

struct crypto2dev_agree_op {
    int           key_fd;
    unsigned char _pad[4]; /* pads 4-byte fd to 8-byte slot matching kernel uapi 64-bit layout */
    unsigned int  peer_pubkey_len;
    unsigned char peer_pubkey[CRYPTO2DEV_PUBKEY_MAXLEN];
    unsigned int  salt_len;
    unsigned char salt[CRYPTO2DEV_KDF_SALT_MAXLEN];
    unsigned int  info_len;
    unsigned char info[CRYPTO2DEV_KDF_INFO_MAXLEN];
    unsigned int  okm_len;
    unsigned char okm[CRYPTO2DEV_PUBKEY_MAXLEN];
};

struct crypto2dev_key_import_op {
    char  algo    [CRYPTO2DEV_ALGO_MAXLEN];
    char  provider[CRYPTO2DEV_PROVIDER_MAXLEN];
    unsigned int key_type;
    unsigned int exportable;
    unsigned int keylen;
    unsigned char _pad[4]; /* pads struct to 112 bytes (multiple of 8) */
};

struct crypto2dev_key_generate_op {
    char          algo    [CRYPTO2DEV_ALGO_MAXLEN];
    char          provider[CRYPTO2DEV_PROVIDER_MAXLEN];
    unsigned int  exportable;
    unsigned char _pad[4]; /* pads struct to 104 bytes (multiple of 8) */
};

/*
 * Module-level status query — CRYPTO2DEV_IOC_STATUS.
 * Not FIPS-gated; works on any open /dev/crypto2dev fd without prior INIT.
 *
 * fips_state:     one of CRYPTO2DEV_FIPS_NO_PROVIDER / _OPERATIONAL / _NOT_OPERATIONAL.
 * num_algorithms: total algorithms registered across all providers.
 * version:        crypto2dev module version string.
 * _reserved:      reserved; callers must ignore; kernel writes zero.
 */
struct crypto2dev_status {
    unsigned int  fips_state;
    unsigned int  num_algorithms;
    char          version[32];
    unsigned char _reserved[24]; /* pads struct to 64 bytes (multiple of 8) */
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
    unsigned char _pad[3]; /* pads exportable to 4-byte boundary; struct total 472 bytes */
};

/* ------------------------------------------------------------------ */
/* ioctl request codes                                                  */
/*                                                                     */
/* These are derived from the struct sizes above via _IOW/_IOR.        */
/* Both port and simulator include this header so the codes match.     */
/* ------------------------------------------------------------------ */

#include <sys/ioctl.h>

#ifndef CRYPTO2DEV_IOC_INIT
#define CRYPTO2DEV_IOC_INIT        _IOW(CRYPTO2DEV_IOC_MAGIC,  1, struct crypto2dev_init_op)
#define CRYPTO2DEV_IOC_SET_IV      _IOW(CRYPTO2DEV_IOC_MAGIC,  2, struct crypto2dev_iv_op)
#define CRYPTO2DEV_IOC_SET_AAD     _IOW(CRYPTO2DEV_IOC_MAGIC,  3, struct crypto2dev_aad_op)
#define CRYPTO2DEV_IOC_GET_TAG     _IOR(CRYPTO2DEV_IOC_MAGIC,  4, struct crypto2dev_tag_op)
#define CRYPTO2DEV_IOC_SET_TAG     _IOW(CRYPTO2DEV_IOC_MAGIC,  5, struct crypto2dev_tag_op)
/* slots 6–8 not used by this port */
#define CRYPTO2DEV_IOC_STATUS      _IOR(CRYPTO2DEV_IOC_MAGIC,  9, struct crypto2dev_status)
#define CRYPTO2DEV_IOC_KEY_IMPORT  _IOW(CRYPTO2DEV_IOC_MAGIC, 11, struct crypto2dev_key_import_op)
#define CRYPTO2DEV_IOC_KEY_GENERATE _IOW(CRYPTO2DEV_IOC_MAGIC, 12, struct crypto2dev_key_generate_op)
#define CRYPTO2DEV_IOC_DO_SIGN     _IOWR(CRYPTO2DEV_IOC_MAGIC, 16, struct crypto2dev_sign_op)
#define CRYPTO2DEV_IOC_DO_VERIFY   _IOWR(CRYPTO2DEV_IOC_MAGIC, 17, struct crypto2dev_verify_op)
#define CRYPTO2DEV_IOC_DO_AGREE    _IOWR(CRYPTO2DEV_IOC_MAGIC, 18, struct crypto2dev_agree_op)
#define CRYPTO2DEV_IOC_RESET       _IO(  CRYPTO2DEV_IOC_MAGIC, 19)
#define CRYPTO2DEV_IOC_REQUIRE_FIPS _IO( CRYPTO2DEV_IOC_MAGIC, 20)
#define CRYPTO2DEV_IOC_FINALIZE    _IO(  CRYPTO2DEV_IOC_MAGIC, 21)
#define CRYPTO2DEV_IOC_DO_KDF      _IOWR(CRYPTO2DEV_IOC_MAGIC, 22, struct crypto2dev_kdf_op)
#endif /* CRYPTO2DEV_IOC_INIT */

/* Compile-time size guards: catch struct drift before it becomes a runtime
 * ABI break.  The _IOW/_IOR macros encode sizeof(struct) into the ioctl
 * request code; a size mismatch produces ENOTTY with no other diagnostic.
 * These values must match the kernel driver's uapi header.
 * If a guard fires, update the struct AND the expected size here together. */
wc_static_assert2(sizeof(struct crypto2dev_init_op)        == 240,
    "crypto2dev_init_op size mismatch — update CRYPTO2DEV_ALGO_MAXLEN or struct fields");
wc_static_assert2(sizeof(struct crypto2dev_iv_op)          ==  36,
    "crypto2dev_iv_op size mismatch");
wc_static_assert2(sizeof(struct crypto2dev_aad_op)         == 260,
    "crypto2dev_aad_op size mismatch");
wc_static_assert2(sizeof(struct crypto2dev_tag_op)         ==  20,
    "crypto2dev_tag_op size mismatch");
wc_static_assert2(sizeof(struct crypto2dev_sign_op)        == 656,
    "crypto2dev_sign_op size mismatch");
wc_static_assert2(sizeof(struct crypto2dev_verify_op)      == 656,
    "crypto2dev_verify_op size mismatch");
wc_static_assert2(sizeof(struct crypto2dev_agree_op)       == 856,
    "crypto2dev_agree_op size mismatch");
wc_static_assert2(sizeof(struct crypto2dev_key_import_op)  == 112,
    "crypto2dev_key_import_op size mismatch");
wc_static_assert2(sizeof(struct crypto2dev_key_generate_op) == 104,
    "crypto2dev_key_generate_op size mismatch");
wc_static_assert2(sizeof(struct crypto2dev_kdf_op)         == 472,
    "crypto2dev_kdf_op size mismatch");
wc_static_assert2(sizeof(struct crypto2dev_status)         ==  64,
    "crypto2dev_status size mismatch — update version[] or _reserved[] fields");

#endif /* WOLFSSL_PORT_CRYPTO2DEV_WIRE_H */
