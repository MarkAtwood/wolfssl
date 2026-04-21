/* crypto2dev_port.h — wolfSSL CryptoCb port for Linux /dev/crypto2dev
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

#ifndef WOLFSSL_PORT_CRYPTO2DEV_H
#define WOLFSSL_PORT_CRYPTO2DEV_H

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_CRYPTO2DEV) && defined(WOLF_CRYPTO_CB)

#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/types.h>

/* Forward declarations: avoid pulling in the full TLS layer (wolfssl/ssl.h)
 * from a wolfcrypt-layer header.  The .c file includes wolfssl/ssl.h
 * directly.  Guard with WOLFSSL_SSL_H to avoid C89 redefinition if the
 * caller already included wolfssl/ssl.h. */
#ifndef WOLFSSL_SSL_H
typedef struct WOLFSSL_CTX WOLFSSL_CTX;
typedef struct WOLFSSL      WOLFSSL;
#endif

/* Device ID — "C2DV" in big-endian ASCII.
 * Unique enough to avoid collision with small positive IDs used by other ports.
 * Application code: wc_CryptoCb_RegisterDevice(WOLF_CRYPTO2DEV_DEVID,
 *                                               wc_crypto2dev_cb, NULL);
 */
#ifndef WOLF_CRYPTO2DEV_DEVID
#define WOLF_CRYPTO2DEV_DEVID  ((int)0x43324456)
#endif

/* Note: wc_AesGcmSetKey() is not compatible with a crypto2dev devId.  The
 * SETKEY callback intercepts wc_AesSetKey() before the software path computes
 * the GCM H-subkey (aes->rounds remains 0).  Use wc_AesSetKey() instead,
 * which does not compute H and is therefore safe to hand off to hardware. */
WOLFSSL_API int wc_crypto2dev_init(void);
WOLFSSL_API int wc_crypto2dev_cleanup(void);
WOLFSSL_API int wc_crypto2dev_cb(int devId, wc_CryptoInfo* info, void* ctx);

/* TLS integration helpers: register the device, enable TLS-safe mode (hash
 * ops fall back to software), and assign WOLF_CRYPTO2DEV_DEVID to ctx/ssl.
 *
 * Why hash ops fall back to software (TLS-safe mode):
 *   wc_Sha256Copy() fails when hardware holds streaming state because it
 *   cannot duplicate an in-flight kernel-side hash context.  The TLS 1.3
 *   handshake calls wc_Sha256Copy() to snapshot the transcript hash at
 *   multiple points; if that copy fails the handshake is silently corrupted.
 *   Returning CRYPTOCB_UNAVAILABLE for all WC_ALGO_TYPE_HASH ops forces
 *   wolfSSL to run transcript hashing in software where wc_Sha256Copy works.
 *   HMAC, CIPHER, and PK operations are unaffected and still use hardware.
 *
 * Single-threaded initialisation requirement:
 *   wc_crypto2dev_init(), wc_crypto2dev_cleanup(), and
 *   wc_crypto2dev_assign_devid*() write global state and are not thread-safe.
 *   All three MUST be called before any concurrent thread begins using
 *   the registered callback.  Adding a mutex is not warranted because
 *   wolfSSL's own CryptoCb registration is itself single-threaded at setup
 *   time. */
WOLFSSL_API int wc_crypto2dev_assign_devid(WOLFSSL_CTX* ctx);
WOLFSSL_API int wc_crypto2dev_assign_devid_ssl(WOLFSSL* ssl);

#ifdef WOLFSSL_CRYPTO2DEV_TEST
WOLFSSL_API int wc_crypto2dev_test(void);
#endif

#endif /* WOLFSSL_CRYPTO2DEV && WOLF_CRYPTO_CB */
#endif /* WOLFSSL_PORT_CRYPTO2DEV_H */
